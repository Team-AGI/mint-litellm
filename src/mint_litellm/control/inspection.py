"""검사 요청과 결과를 공유 볼륨으로 주고받는다."""

import json
import os
import time
import uuid
from pathlib import Path


def inspect_pack(
    pack_sha256: str, entry: str, argv: list[str], *, directory=None, timeout: float = 60
) -> dict:
    root = Path(directory or os.environ.get("MINT_INSPECT_DIR", "/var/lib/mint/inspect"))
    request_dir = root / str(uuid.uuid4())
    request_dir.mkdir(parents=True)
    request = {"pack_sha256": pack_sha256, "entry": entry, "argv": argv, "timeout_seconds": 30}
    temporary = request_dir / "request.tmp"
    temporary.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
    temporary.replace(request_dir / "request.json")
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            result = json.loads((request_dir / "result.json").read_text(encoding="utf-8"))
            if result.get("pack_sha256") == pack_sha256:
                return result
            break
        except FileNotFoundError:
            time.sleep(min(0.2, max(0, end - time.monotonic())))
        except (ValueError, OSError):
            break
    return {
        "status": "incomplete",
        "reason": "INSPECTION_UNAVAILABLE",
        "tools": [],
        "complete": False,
        "pack_sha256": pack_sha256,
    }
