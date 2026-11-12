"""비용 비교 스크립트: 가짜 서버·가짜 결정 서버로 한 바퀴 돌려 측정 항목이 맞게 나오는지 본다."""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from kit_loader import KIT
from test_kit_broker import Server

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="서버 실행기")

spec = importlib.util.spec_from_file_location(
    "endpoint_cost", Path(__file__).parents[2] / "bench" / "endpoint_cost.py"
)
bench = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bench
spec.loader.exec_module(bench)

FAKE_SERVER = r'''
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"], "capabilities": {}}
    else:
        with open(msg["params"]["arguments"]["path"], "a") as out:
            out.write("x\n")
        result = {"content": [], "isError": False}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_percentile_uses_the_nearest_rank():
    assert bench.percentile([], 95) is None
    assert bench.percentile(list(range(1, 101)), 95) == 95
    assert bench.percentile([5, 1, 3], 99) == 5 and bench.percentile([5, 1, 3], 50) == 3


def test_the_comparison_counts_wrong_decisions_effects_revocation_and_storage(tmp_path):
    script = tmp_path / "server.py"
    script.write_text(FAKE_SERVER)
    contract = {
        "schema_version": 1, "identity_kind": "stdio", "executable": sys.executable,
        "argv": [str(script)], "cwd": None, "executable_sha256": sha(sys.executable),
        "script_sha256": sha(script), "env": {}, "secret_refs": {},
    }  # fmt: skip
    contracts = tmp_path / "contracts.json"
    contracts.write_text(json.dumps({"servers": {"srv": contract}}))
    key = tmp_path / "key"
    key.write_text("sk-k")
    revoked, size = tmp_path / "revoked", tmp_path / "size"
    size.write_text("1000")

    def decide(sent):
        size.write_text(str(int(size.read_text()) + 100))
        deny = revoked.exists() or sent["arguments"]["path"].endswith("blocked")
        return {"decision": "deny" if deny else "allow", "reference": "ref-1"}

    srv = Server(answer=decide)
    workload = tmp_path / "w.json"
    workload.write_text(json.dumps({
        "server": {"name": "srv", "argv": [sys.executable, str(script)]},
        "cases": [
            {"id": "a", "tool": "write", "expect": "allow",
             "arguments": {"path": str(tmp_path / "ok")}, "effect_file": str(tmp_path / "ok")},
            {"id": "b", "tool": "write", "expect": "block",
             "arguments": {"path": str(tmp_path / "blocked")},
             "effect_file": str(tmp_path / "blocked")},
        ],
    }))  # fmt: skip
    out = tmp_path / "out.json"
    try:
        code = bench.main([
            "--workload", str(workload), "--agent", str(KIT / "mint_agent.py"),
            "--url", srv.url.rsplit("/mint/", 1)[0], "--key-file", str(key),
            "--contracts", str(contracts), "--state-dir", str(tmp_path / "state"),
            "--no-keepalive", "--repeat", "3", "--starts", "2", "--poll", "0.05",
            "--revoke-cmd", f"touch {revoked}", "--restore-cmd", f"rm {revoked}",
            "--storage-cmd", f"cat {size}", "--output", str(out),
        ])  # fmt: skip
    finally:
        srv.close()
    report = json.loads(out.read_text())
    direct, mint = report["direct"], report["mint"]
    assert code == 0
    # 대조군은 막지 못한다: 차단해야 할 호출이 모두 실행되고 효과가 남는다.
    assert (direct["wrong_allow"], direct["wrong_block"], direct["success_rate"]) == (3, 0, 1.0)
    assert direct["effect_mismatches"] == 3 and direct["decision_ms"]["n"] == 0
    assert (mint["wrong_allow"], mint["wrong_block"], mint["success_rate"]) == (0, 0, 1.0)
    assert (mint["effects_total"], mint["effect_mismatches"]) == (3, 0)
    assert mint["start_ms"]["n"] == 2 and mint["decision_ms"]["n"] == 6
    assert mint["storage"]["hook_calls"] == 9 and mint["storage"]["bytes_grown"] == 900
    assert mint["revocation"]["propagated"] is True and not revoked.exists()
