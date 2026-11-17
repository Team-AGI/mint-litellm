"""공유 볼륨의 검사 요청을 오프라인으로 처리한다."""

import hashlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

PACKS = Path("/packs")
REQUESTS = Path("/inspect")
LIMIT = 1024 * 1024


def _extract(archive, target, total=0):
    with zipfile.ZipFile(archive) as wheel:
        entries = wheel.infolist()
        if len(entries) > 10000:
            raise ValueError("wheel limit")
        for info in entries:
            path = PurePosixPath(info.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in info.filename
                or (info.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("unsafe wheel path")
            parts = path.parts
            if len(parts) > 1 and parts[0].endswith(".data"):
                if parts[1] not in ("purelib", "platlib"):
                    continue
                parts = parts[2:]
            if not parts or info.is_dir():
                continue
            total += info.file_size
            if total > 512 * LIMIT:
                raise ValueError("wheel limit")
            dest = target.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with wheel.open(info) as source, dest.open("xb") as output:
                shutil.copyfileobj(source, output)
    return total


def inspect(request, packs=PACKS):
    pack = request.get("pack_sha256", "")
    result = {
        "status": "incomplete",
        "reason": None,
        "tools": [],
        "complete": False,
        "pack_sha256": pack,
        "inspector": {"image": "python:3.12-slim", "python": sys.version.split()[0]},
        "finished_at": None,
    }
    process = None
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", pack):
            raise ValueError("invalid pack")
        raw = (packs / pack / "manifest.json").read_bytes()
        manifest = json.loads(raw)
        canonical = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        if (
            hashlib.sha256(canonical).hexdigest() != pack
            or request.get("entry") != manifest["entry"]
        ):
            raise ValueError("pack mismatch")
        entry = manifest["entry"]
        if not re.fullmatch(
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", entry
        ):
            raise ValueError("invalid entry")
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            extracted = 0
            for item in manifest["files"]:
                name = item["name"]
                if Path(name).name != name or not name.endswith(".whl"):
                    raise ValueError("invalid wheel")
                wheel = packs / pack / name
                if (
                    wheel.stat().st_size != item["size"]
                    or hashlib.sha256(wheel.read_bytes()).hexdigest() != item["sha256"]
                ):
                    raise ValueError("wheel mismatch")
                extracted = _extract(wheel, target, extracted)
            module, function = entry.split(":")
            code = (
                "import importlib,runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
                "m,f=sys.argv.pop(1).split(':');"
                "runpy.run_module(m,run_name='__main__') if f=='__main__' else "
                "sys.exit(__import__('functools').reduce(getattr,f.split('.'),importlib.import_module(m))())"
            )
            argv = request.get("argv", [])
            if not isinstance(argv, list) or any(not isinstance(a, str) for a in argv):
                raise ValueError("invalid argv")
            if function == "__main__" and len(argv) >= 2 and argv[:2] == ["-m", module]:
                argv = argv[2:]
            process = subprocess.Popen(
                [sys.executable, "-I", "-c", code, temp, entry, *argv],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            lines = queue.Queue(maxsize=2)

            def read_output():
                while True:
                    line = process.stdout.readline(LIMIT + 1)
                    lines.put(line)
                    if not line or len(line) > LIMIT:
                        return

            threading.Thread(target=read_output, daemon=True).start()
            deadline = time.monotonic() + min(30, max(1, int(request.get("timeout_seconds", 30))))
            total = 0

            def call(identifier, method, params):
                nonlocal total
                message = {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}
                process.stdin.write((json.dumps(message) + "\n").encode())
                process.stdin.flush()
                while True:
                    line = lines.get(timeout=max(0, deadline - time.monotonic()))
                    total += len(line)
                    if not line or total > LIMIT:
                        raise ValueError("output limit")
                    response = json.loads(line)
                    if response.get("id") == identifier:
                        if "error" in response or not isinstance(response.get("result"), dict):
                            raise ValueError("protocol error")
                        return response["result"]

            call(
                1,
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mint-inspector", "version": "1"},
                },
            )
            process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
            process.stdin.flush()
            cursor, seen, identifier = None, set(), 2
            while True:
                page = call(identifier, "tools/list", {"cursor": cursor} if cursor else {})
                tools = page.get("tools")
                if not isinstance(tools, list) or any(not isinstance(t, dict) for t in tools):
                    raise ValueError("invalid tools")
                result["tools"].extend(tools)
                if len(result["tools"]) > 200:
                    raise ValueError("tool limit")
                cursor = page.get("nextCursor")
                if not cursor:
                    break
                if not isinstance(cursor, str) or cursor in seen:
                    raise ValueError("invalid cursor")
                seen.add(cursor)
                identifier += 1
            result.update(status="ok", complete=True)
    except queue.Empty:
        result["reason"] = "TIMEOUT"
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, json.JSONDecodeError):
        result["reason"] = "INSPECTION_FAILED"
    finally:
        if process is not None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(process.pid, signal.SIGKILL)
                else:  # 개발용 Windows: 프로세스 그룹이 없다
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()
            process.stdin.close()
            process.stdout.close()
        if not result["complete"]:
            result["tools"] = []
        result["finished_at"] = datetime.now(timezone.utc).isoformat()  # noqa: UP017
    return result


def main():
    while True:
        for request in REQUESTS.glob("*/request.json"):
            output = request.with_name("result.json")
            if output.exists():
                continue
            try:
                result = inspect(json.loads(request.read_text(encoding="utf-8")))
                temporary = output.with_suffix(".tmp")
                temporary.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
                temporary.replace(output)
            except (OSError, ValueError):
                continue
        time.sleep(1)


if __name__ == "__main__":
    main()
