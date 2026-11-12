"""로컬 실행(stdio) 서버의 실행 계약. URL 해시와 따로 서버 식별에 쓴다.

비밀 값은 담지 않고 참조 ID만 담는다. 문자열은 정규화하지 않고 바이트 그대로 비교한다
(유니코드 정규화·심볼릭 링크 해석·환경 확장은 하지 않는다). 일치 판정은 MINT 서버가 계약 해시를
계산해 승인본과 비교하며, 클라이언트가 보낸 참/거짓은 입력으로 받지 않는다.
"""

import hashlib
import posixpath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mint_litellm.types.canonical import canonical_text
from mint_litellm.types.decision import ResolvedServer

SCHEMA_VERSION = 1
_SHA256 = r"^[0-9a-f]{64}$"


class ExecContract(BaseModel):
    """승인 대상 로컬 서버의 실행 계약. 판본이 바뀌면 필드를 더하고 ``schema_version``을 올린다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = SCHEMA_VERSION
    executable: str = Field(min_length=1, max_length=1024)
    argv: tuple[str, ...] = Field(default=(), max_length=64)
    # 비어 있으면 작업 디렉터리를 비교하지 않는다(하네스가 세션 디렉터리에서 서버를 띄운다).
    cwd: str | None = Field(default=None, min_length=1, max_length=1024)
    executable_sha256: str = Field(pattern=_SHA256)
    script_sha256: str | None = Field(default=None, pattern=_SHA256)
    env: dict[str, str] = Field(default_factory=dict, max_length=64)
    secret_refs: dict[str, str] = Field(default_factory=dict, max_length=64)

    @field_validator("executable", "cwd")
    @classmethod
    def _absolute_normal_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if "\0" in value or not posixpath.isabs(value) or posixpath.normpath(value) != value:
            raise ValueError("path must be absolute and normalized")
        return value

    @field_validator("argv")
    @classmethod
    def _argv_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\0" in item or len(item) > 4096 for item in value):
            raise ValueError("argv element is not acceptable")
        return value

    def document(self) -> dict:
        """정본 문자열과 사건 본문에 쓰는 JSON 값."""
        return {"identity_kind": "stdio", **self.model_dump(mode="json")}

    def canonical(self) -> str:
        return canonical_text(self.document())

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def resolved(self, server_id: str) -> ResolvedServer:
        """판정 단계가 서버 행과 비교할 값. 해시는 이 계약에서 계산한다."""
        return ResolvedServer(
            server_id=server_id,
            identity_kind="stdio",
            exec_contract_sha256=self.sha256(),
            exec_contract_version=self.schema_version,
            transport="stdio",
            auth_type="none",
            candidates_with_same_name=1,
        )
