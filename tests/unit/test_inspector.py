import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "inspector" / "inspect.py"
spec = importlib.util.spec_from_file_location("mint_inspector_run", SCRIPT)
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)

SERVER = r'''
import json, subprocess, sys

mode = sys.argv[1] if len(sys.argv) > 1 else "ok"


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def tool(i, pad=0):
    return {"name": "t%d" % i, "description": "x" * pad, "inputSchema": {"type": "object"}}


def main():
    if mode == "crash":
        text = "ValueError: GHIDRA_INSTALL_DIR is not set"
        sys.stderr.write("x" * 5000 + text + chr(7) + chr(10))
        sys.exit(3)
    if mode == "child":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        open(sys.argv[2], "w").write(str(child.pid))
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg or mode in ("hang", "child"):
            continue
        if msg["method"] == "initialize":
            send({"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "serverInfo": {"name": "fake", "version": "1"}}})
        elif mode == "paged":
            cursor = (msg.get("params") or {}).get("cursor")
            start = int(cursor or 0)
            result = {"tools": [tool(start), tool(start + 1)]}
            if start < 4:
                result["nextCursor"] = str(start + 2)
            send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
        elif mode == "loop":
            send({"jsonrpc": "2.0", "id": msg["id"],
                  "result": {"tools": [tool(1)], "nextCursor": "same"}})
        elif mode == "big":
            send({"jsonrpc": "2.0", "id": msg["id"],
                  "result": {"tools": [tool(1, 1200000)]}})
        else:
            count = int(mode.split(":")[1]) if mode.startswith("many:") else 2
            send({"jsonrpc": "2.0", "id": msg["id"],
                  "result": {"tools": [tool(i) for i in range(count)]}})
'''


class InspectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        name = "fakemcp-1.0-py3-none-any.whl"
        pack_dir = self.root / "stage"
        pack_dir.mkdir()
        wheel = pack_dir / name
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("fakemcp.py", SERVER)
        manifest = {
            "schema": 1,
            "entry": "fakemcp:main",
            "files": [
                {
                    "name": name,
                    "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                    "size": wheel.stat().st_size,
                }
            ],
        }
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.pack = hashlib.sha256(raw.encode()).hexdigest()
        (pack_dir / "manifest.json").write_text(raw, encoding="utf-8")
        pack_dir.rename(self.root / self.pack)

    def run_pack(self, argv, timeout=30):
        request = {
            "pack_sha256": self.pack,
            "entry": "fakemcp:main",
            "argv": argv,
            "timeout_seconds": timeout,
        }
        return inspector.inspect(request, packs=self.root)

    def test_ok(self):
        result = self.run_pack(["ok"])
        self.assertEqual((result["status"], result["complete"]), ("ok", True))
        self.assertEqual([t["name"] for t in result["tools"]], ["t0", "t1"])

    def test_pages_follow_next_cursor(self):
        result = self.run_pack(["paged"])
        self.assertTrue(result["complete"])
        self.assertEqual(len(result["tools"]), 6)

    def test_repeated_cursor_is_incomplete(self):
        result = self.run_pack(["loop"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["tools"], [])

    def test_two_hundred_tools_ok_and_more_is_not(self):
        self.assertTrue(self.run_pack(["many:200"])["complete"])
        over = self.run_pack(["many:201"])
        self.assertFalse(over["complete"])
        self.assertEqual(over["tools"], [])

    def test_one_mebibyte_limit(self):
        result = self.run_pack(["big"])
        self.assertEqual((result["status"], result["complete"]), ("incomplete", False))
        self.assertEqual(result["tools"], [])

    def test_timeout(self):
        started = time.monotonic()
        result = self.run_pack(["hang"], timeout=1)
        self.assertEqual(result["reason"], "TIMEOUT")
        self.assertLess(time.monotonic() - started, 10)

    def test_a_server_that_exits_at_start_leaves_its_reason(self):
        result = self.run_pack(["crash"])
        detail = result["detail"]
        self.assertEqual(result["reason"], "INSPECTION_FAILED")
        self.assertEqual((detail["stage"], detail["exit_code"]), ("start", 3))
        self.assertIn("GHIDRA_INSTALL_DIR is not set", detail["stderr_tail"])
        self.assertLessEqual(len(detail["stderr_tail"]), 2048)
        self.assertNotIn(chr(7), detail["stderr_tail"])

    def test_a_good_run_has_no_detail(self):
        self.assertIsNone(self.run_pack(["ok"])["detail"])

    def test_a_hung_server_reports_the_stage_it_stopped_in(self):
        self.assertEqual(self.run_pack(["hang"], timeout=1)["detail"]["stage"], "initialize")

    def test_wrong_entry_is_refused(self):
        request = {"pack_sha256": self.pack, "entry": "other:main", "argv": []}
        self.assertFalse(inspector.inspect(request, packs=self.root)["complete"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "프로세스 그룹은 Linux에서만")
    def test_child_process_is_killed(self):
        pid_file = self.root / "child.pid"
        result = self.run_pack(["child", str(pid_file)], timeout=1)
        self.assertEqual(result["reason"], "TIMEOUT")
        pid = int(pid_file.read_text())
        for _ in range(30):
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if state == "Z":
                return
            time.sleep(0.1)
        os.kill(pid, 9)
        self.fail("자식 프로세스가 남아 있다")


if __name__ == "__main__":
    unittest.main()
