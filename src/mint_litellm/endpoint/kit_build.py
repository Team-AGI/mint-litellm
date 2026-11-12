"""사용자에게 내려보낼 단말 설치 묶음(tar.gz)을 만든다. 같은 입력이면 같은 바이트이다."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from mint_litellm.types.exec_contract import ExecContract

KIT = Path(__file__).resolve().parent / "kit"
FILES = (
    ("install.sh", KIT / "install.sh", 0o755),
    ("mint_kit.py", KIT / "mint_kit.py", 0o644),
    ("mint_agent.py", KIT / "mint_agent.py", 0o644),
)


def _text(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def kit_version() -> str:
    """묶음 프로그램 파일 내용의 해시. 사용자 키·서버 목록과 무관하다."""
    digest = hashlib.sha256()
    for name, path, _ in FILES:
        digest.update(name.encode() + b"\0" + _text(path))
    return digest.hexdigest()


def approved_contracts(documents: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """서버 이름 -> 승인된 실행 계약 필드. 비밀은 계약에 값이 없고 참조만 있다."""
    return {
        name: ExecContract.model_validate(
            {k: v for k, v in document.items() if k != "identity_kind"}
        ).model_dump(mode="json")
        for name, document in sorted(documents.items())
    }


def build_kit(
    documents: Mapping[str, Mapping[str, Any]],
    *,
    decide_url: str,
    key: str,
    ca_pem: str | None = None,
) -> bytes:
    config = {
        "kit_version": kit_version(),
        "decide_url": decide_url,
        "key": key,
        "ca_pem": ca_pem,
        "servers": approved_contracts(documents),
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
