"""내보내기 파일의 경로·서명·원자적 쓰기·검증. DB를 모른다.

모든 파일은 JSON 객체이고 본문 필드에 ``key_id``(HMAC 키 SHA-256의 앞 8바이트 16진)와
``hmac``(``hmac`` 필드를 뺀 정규 JSON의 HMAC-SHA256)가 붙는다. 정규 JSON은 키를 정렬하고 공백 없이
UTF-8로 쓴다.
"""

import hashlib
import hmac as hmac_module
import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mint_litellm.types.frozen import no_floats

FORMAT = 1

# 서명 입력은 ``hmac`` 필드를 뺀 본문 전체이고, 배열은 저장 순서, 시각은 UTC ISO 8601 초 단위 ``Z``,
# 자료형은 문자열·정수·참거짓·null·배열·객체뿐이다.


class ExportUnverified(Exception):
    """읽을 수 없거나 키·서명이 맞지 않는 파일."""


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


# 정규 JSON(봉인 해시·HMAC·내용 해시가 모두 쓰는 유일한 정의): 키 정렬, 구분자 `,`·`:`,
# 비ASCII 그대로, UTF-8. 실수 값은 표기가 구현마다 달라 거부한다
# (정수·문자열·불리언·null·배열·객체만).
CANONICAL_JSON = {"sort_keys": True, "separators": (",", ":"), "ensure_ascii": False}


def canonical_json(value: Any) -> bytes:
    try:
        no_floats(value)
    except ValueError:
        raise ValueError("정규 JSON은 실수 값을 받지 않습니다.") from None
    return json.dumps(value, **CANONICAL_JSON).encode("utf-8")


def canonical(document: dict[str, Any]) -> bytes:
    return canonical_json(document)


def content_sha256(document: dict[str, Any]) -> str:
    """서명 봉투(``key_id``·``hmac``)를 뺀 내용의 해시. 키를 교체해도 변하지 않는다."""
    content = {k: v for k, v in document.items() if k not in ("key_id", "hmac")}
    return hashlib.sha256(canonical(content)).hexdigest()


def sign(document: dict[str, Any], key: bytes) -> dict[str, Any]:
    body = {k: v for k, v in document.items() if k != "hmac"}
    body["key_id"] = key_id(key)
    body["hmac"] = hmac_module.new(key, canonical(body), hashlib.sha256).hexdigest()
    return body


def verify(document: Any, keys: Sequence[bytes]) -> None:
    """``key_id``가 가진 키와 HMAC이 맞아야 한다. 어떤 이유로든 아니면 ``ExportUnverified``."""
    try:
        _verify(document, keys)
    except ExportUnverified:
        raise
    except Exception as error:  # 형식이 틀린 문서·키는 모두 미검증이다(차단 쪽으로 닫는다)
        raise ExportUnverified(f"verify failed: {type(error).__name__}") from None


def _verify(document: Any, keys: Sequence[bytes]) -> None:
    if not isinstance(document, dict):
        raise ExportUnverified("not an object")
    by_id = {key_id(k): k for k in keys}
    key = by_id.get(document.get("key_id"))
    if key is None:
        raise ExportUnverified("unknown key_id")
    body = {k: v for k, v in document.items() if k != "hmac"}
    expected = hmac_module.new(key, canonical(body), hashlib.sha256).hexdigest()
    if not hmac_module.compare_digest(expected, str(document.get("hmac", ""))):
        raise ExportUnverified("hmac mismatch")


def read_verified(path: Path, keys: Sequence[bytes]) -> dict[str, Any]:
    """파일이 없으면 ``FileNotFoundError``, 그 밖의 읽기·파싱·서명 실패는 ``ExportUnverified``."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError) as error:
        raise ExportUnverified(f"read failed: {type(error).__name__}") from None
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        raise ExportUnverified("not json") from None
    verify(document, keys)
    return document


def document_bytes(document: dict[str, Any]) -> bytes:
    """파일에 실제로 쓰는 바이트(해시를 미리 계산하는 데도 쓴다)."""
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False).encode() + b"\n"


def atomic_write(path: Path, document: dict[str, Any]) -> None:
    """임시 파일에 쓰고 fsync한 뒤 이름을 바꾼다. 읽는 쪽은 옛 파일이나 새 파일만 본다."""
    atomic_write_bytes(path, document_bytes(document))


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """바이트를 같은 방식(임시 파일·fsync·이름 바꾸기)으로 쓴다. 표지 파일도 이것을 쓴다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(temp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    if os.name == "posix":  # 이름 바꾸기 자체를 디스크에 남긴다
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def latest_path(export_dir: Path, instance_id: str) -> Path:
    return export_dir / instance_id / "latest.json"


def negative_path(export_dir: Path, instance_id: str, epoch: int) -> Path:
    return export_dir / instance_id / "negative" / f"{epoch}.json"


def checkpoint_path(export_dir: Path, instance_id: str, moment: datetime) -> Path:
    stamp = moment.astimezone(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return export_dir / instance_id / "checkpoint" / f"{stamp}.json"


def newest_negative(export_dir: Path, instance_id: str) -> Path | None:
    """가장 큰 ``state_epoch``의 부정 상태 파일. 파일 이름의 숫자로 고른다."""
    folder = export_dir / instance_id / "negative"
    try:
        names = [p for p in folder.iterdir() if p.suffix == ".json" and p.stem.isdigit()]
    except (FileNotFoundError, NotADirectoryError):
        return None
    return max(names, key=lambda p: int(p.stem), default=None)


def file_sha256(path: Path) -> str:
    """파일 바이트의 SHA-256. 파일이 없으면 ``absent``(복원 요청의 결속값)."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return "absent"


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
