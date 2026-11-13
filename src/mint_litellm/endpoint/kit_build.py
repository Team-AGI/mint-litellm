"""단말 설치 묶음(Linux는 tar.gz, Windows는 zip)을 만든다. 같은 입력이면 같은 바이트이다."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from mint_litellm.types.exec_contract import ExecContract

KIT = Path(__file__).resolve().parent / "kit"
PROGRAMS = (
    ("mint_kit.py", KIT / "mint_kit.py", 0o644),
    ("mint_agent.py", KIT / "mint_agent.py", 0o644),
)
# 운영체제마다 설치기 진입 파일이 다르다. 판본은 모든 파일의 해시라 어느 쪽을 받아도 같다.
LAUNCHERS = {
    "linux": (("install.sh", KIT / "install.sh", 0o755),),
    "windows": (
        ("install.cmd", KIT / "install.cmd", 0o644),
        ("install.ps1", KIT / "install.ps1", 0o644),
    ),
}
FILES = tuple(item for launchers in LAUNCHERS.values() for item in launchers) + PROGRAMS
HARNESSES = ("claude", "codex")


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
    platform: str = "linux",
    harnesses: Sequence[str] = ("claude",),
    allow_unsandboxed: bool = False,
) -> bytes:
    if platform not in LAUNCHERS or not harnesses or not set(harnesses) <= set(HARNESSES):
        raise ValueError("unknown platform or harness")
    config = {
        "kit_version": kit_version(),
        "harnesses": [h for h in HARNESSES if h in harnesses],
        "decide_url": decide_url,
        "key": key,
        "ca_pem": ca_pem,
        "servers": approved_contracts(documents),
    }
    if allow_unsandboxed:
        config["allow_unsandboxed"] = True  # 관리형 단말이 격리 없이 서버를 시작해도 된다.
    members = [(name, _text(path), mode) for name, path, mode in (*LAUNCHERS[platform], *PROGRAMS)]
    members.append(("kit.json", json.dumps(config, indent=1).encode(), 0o600))
    raw = io.BytesIO()
    if platform == "windows":
        with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data, _ in members:
                info = zipfile.ZipInfo(f"mint-kit/{name}", date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        return raw.getvalue()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as packed:
        with tarfile.open(fileobj=packed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, data, mode in members:
                info = tarfile.TarInfo(f"mint-kit/{name}")
                info.size, info.mode, info.mtime = len(data), mode, 0
                archive.addfile(info, io.BytesIO(data))
    return raw.getvalue()
