"""사용자에게 내려보낼 키트 묶음(tar.gz)을 만든다. 같은 입력이면 같은 바이트이다."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from pathlib import Path

from mint_litellm.endpoint.decide import LocalServer

HERE = Path(__file__).resolve().parent
FILES = (
    ("install.sh", HERE / "kit" / "install.sh", 0o755),
    ("mint_kit.py", HERE / "kit" / "mint_kit.py", 0o644),
    ("hook.py", HERE / "hook.py", 0o644),
)


def _text(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def kit_version() -> str:
    """키트 프로그램 파일 내용의 해시. 사용자 키·서버 목록과 무관하다."""
    digest = hashlib.sha256()
    for name, path, _ in FILES:
        digest.update(name.encode() + b"\0" + _text(path))
    return digest.hexdigest()


def approved_servers(servers: Mapping[str, LocalServer]) -> list[dict]:
    """승인된 로컬 서버를 하네스의 MCP 설정 항목으로 옮긴다. 비밀은 담지 않는다."""
    return [
        {
            "name": name,
            "command": entry.contract.executable,
            "args": list(entry.contract.argv),
            "env": dict(entry.contract.env),
        }
        for name, entry in sorted(servers.items())
    ]


def build_kit(
    servers: Mapping[str, LocalServer], *, decide_url: str, key: str, ca_pem: str | None = None
) -> bytes:
    config = {
        "kit_version": kit_version(),
        "decide_url": decide_url,
        "key": key,
        "ca_pem": ca_pem,
        "servers": approved_servers(servers),
    }
    members = [(name, _text(path), mode) for name, path, mode in FILES]
    members.append(("kit.json", json.dumps(config, indent=1).encode(), 0o600))
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as packed:
        with tarfile.open(fileobj=packed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, data, mode in members:
                info = tarfile.TarInfo(f"mint-kit/{name}")
                info.size, info.mode, info.mtime = len(data), mode, 0
                archive.addfile(info, io.BytesIO(data))
    return raw.getvalue()
