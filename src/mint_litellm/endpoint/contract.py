"""로컬(stdio) 서버의 최소 실행 계약과 서버 쪽 일치 판정.

계약은 URL 해시 칸과 따로 둔다. 일치 여부는 MINT 서버가 승인본과 보고본으로 계산하며,
클라이언트가 보낸 참/거짓은 입력으로 받지 않는다. 문자열은 정규화하지 않고 바이트 그대로
비교한다(유니코드 정규화·심볼릭 링크 해석·환경 확장은 하지 않는다).
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mint_litellm.types.canonical import canonical_text

SHA256 = r"^[0-9a-f]{64}$"
FIELDS = (
    "schema_version",
    "identity_kind",
    "executable",
    "argv",
    "cwd",
    "executable_sha256",
    "script_sha256",
    "env",
    "secret_refs",
)


class LocalExecContract(BaseModel):
    """승인 대상 로컬 서버의 실행 계약. 비밀 값은 담지 않고 참조 ID만 담는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    identity_kind: Literal["stdio"] = "stdio"
    executable: str = Field(min_length=1, max_length=1024)
    argv: tuple[str, ...] = Field(max_length=64)
    cwd: str = Field(min_length=1, max_length=1024)
    executable_sha256: str = Field(pattern=SHA256)
    script_sha256: str | None = Field(default=None, pattern=SHA256)
    env: dict[str, str] = Field(default_factory=dict, max_length=64)
    secret_refs: dict[str, str] = Field(default_factory=dict, max_length=64)

    @field_validator("executable", "cwd")
    @classmethod
    def _absolute_normal_path(cls, value: str) -> str:
        if "\0" in value or not posixpath.isabs(value) or posixpath.normpath(value) != value:
            raise ValueError("path must be absolute and normalized")
        return value

    @field_validator("argv")
    @classmethod
    def _argv_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\0" in item or len(item) > 4096 for item in value):
            raise ValueError("argv element is not acceptable")
        return value

    def canonical(self) -> str:
        return canonical_text(self.model_dump(mode="json"))

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()


def mismatched_fields(approved: LocalExecContract, reported: LocalExecContract) -> tuple[str, ...]:
    """승인본과 보고본이 다른 필드 이름. 비어 있으면 일치(``exec_definition_match``)이다."""
    return tuple(name for name in FIELDS if getattr(approved, name) != getattr(reported, name))


def strict_json(raw: bytes) -> Any:
    """중복 키·비유한 숫자를 거부하는 JSON 해석. 모호한 본문은 판정하지 않는다."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise ValueError(f"non-finite number {name}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
