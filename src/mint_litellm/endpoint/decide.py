"""호출 전 훅이 부르는 결정 경로와 호출 뒤 훅이 부르는 결과 보고 경로.

판정은 LiteLLM 사전 훅과 같은 ``evaluate_request``가 하고, 이 모듈은 요청 본문을 판정 요청으로
바꾸는 접점만 가진다. 호출자의 사용자·조직은 본문이 아니라 인증 객체에서만 얻고(본문에 그런
필드가 있으면 거부한다), 서버 이름은 MINT에 등록된 로컬 서버의 식별자이다. 보고된 실행 계약의
해시는 MINT가 계산해 서버 행과 비교하며 클라이언트가 보낸 참/거짓은 받지 않는다. 결과 보고는
호출자가 판정 사건을 만든 키와 같을 때만 받고, 사건의 값으로 응답 관측과 같은 기록을 남긴다.
보고는 단말의 주장이며 MINT가 관측한 사실이 아니다.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from mint_litellm.compat.litellm_1_106 import HookData
from mint_litellm.endpoint import apps, intake_text, kit_sign
from mint_litellm.endpoint.routes import (
    ACCESS_REQUEST_CANCEL_PATH,
    ACCESS_REQUESTS_PATH,
    APP_PATH,
    APPS_PATH,
    DECIDE_PATH,
    INSPECTION_RESULT_PATH,
    INSPECTION_START_PATH,
    INTAKES_PATH,
    ME_PATH,
    OUTCOMES_PATH,
    PACKS_PATH,
    REPORT_PATH,
    RESULT_PATH,
)
from mint_litellm.plugin.pipeline import CallRequest, build_request, evaluate_request
from mint_litellm.plugin.result import observe_response, observe_unknown_outcome
from mint_litellm.types.canonical import canonical_text
from mint_litellm.types.decision import (
    BUILTIN_EXEC_SHA256,
    OperationType,
    ResolvedServer,
    is_builtin_server,
)
from mint_litellm.types.errors import DispatchState, MintError
from mint_litellm.types.exec_contract import ExecContract
from mint_litellm.types.identity import Principal

log = logging.getLogger("mint_litellm.endpoint")

MAX_BODY_BYTES = 64 * 1024
# 경로마다 정상 본문이 이보다 작다(결과 보고는 참조와 결과 종류, 설치 보고는 서버 이름 목록).
BODY_LIMITS = {DECIDE_PATH: MAX_BODY_BYTES, RESULT_PATH: 4 * 1024, REPORT_PATH: 192 * 1024,
    OUTCOMES_PATH: 1024, INTAKES_PATH: 256 * 1024,
    APPS_PATH: 1024, ACCESS_REQUESTS_PATH: 2048}
INSPECTION_BODY_BYTES = 256 * 1024
MAX_INSPECTION_TOOLS = 200
NOT_READY_CODE = "MINT-ENDPOINT-NOT-READY"
_REFERENCE = re.compile(r"^([0-9a-f-]{36}):([1-9][0-9]{0,8})$")


class DecideBody(BaseModel):
    """훅이 보내는 결정 요청. 사용자·조직·키 필드는 두지 않는다(알 수 없는 필드는 거부)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    # 내장 도구(가상 서버 builtin:*)는 실행 계약이 없고, 그 밖의 서버는 반드시 있다.
    contract: ExecContract | None = None
    tool_use_id: str | None = Field(default=None, max_length=128)
    # 호출 주체 표시(앱이 단말 중개로 부르면 ``app:<이름>``). 옛 단말은 보내지 않는다.
    client: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9:_.-]+$")

    @model_validator(mode="after")
    def _contract_fits_server(self) -> DecideBody:
        if is_builtin_server(self.server) != (self.contract is None):
            raise ValueError("contract is required exactly for registered servers")
        return self


class ResultBody(BaseModel):
    """호출 뒤 훅이 보내는 결과 보고. 결과 본문은 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reference: str = Field(pattern=_REFERENCE.pattern)
    # unknown: 훅이 도구가 실행됐는지 모른다고 보고(중단·시간 초과 등)
    outcome: Literal["success", "error", "unknown"]
    size_bytes: int | None = Field(default=None, ge=0, le=2**40)
    # 단말이 그 서버에 대해 받아 둔 결정 버전(옛 단말은 보내지 않는다: 최신 버전으로 본다).
    decision_version: int | None = Field(default=None, ge=1, le=2**31)


class OutcomesBody(BaseModel):
    """승인 결과 조회. ``since``는 앞서 받은 ``cursor``이고, 처음에는 비워 커서만 받는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    since: datetime | None = None


class AccessRequestBody(BaseModel):
    """PC에서 여는 권한 요청. 사유 코드는 거부 응답의 코드(없으면 DB가 활성 차단 여부로 정한다)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: UUID
    server: str = Field(min_length=1, max_length=128)
    tool: str | None = Field(default=None, min_length=1, max_length=256)
    reason_code: str | None = Field(default=None, pattern=r"^[A-Z][A-Z_]{2,63}$")
    note: str = Field(default="", max_length=500)


class ProcessItem(BaseModel):
    """단말에서 실행 중인 묶음 실행기 프로세스(서버 이름별 개수)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    count: int = Field(ge=1, le=100000)
    # 서버 프로세스의 격리 상태(단말의 주장). 이전 묶음은 보내지 않는다.
    sandbox: Literal["bwrap", "appcontainer", "none", "unsupported"] | None = None
    # 허용 호스트 밖이라 중계가 거절한 접속 수(``network: hosts`` 서버만). 이전 묶음은 안 보낸다.
    egress_refused: int | None = Field(default=None, ge=0, le=10**9)
    # Windows에서 호스트 허용 목록을 거르지 못한 채 실행 중이면 참. 이전 묶음은 안 보낸다.
    egress_unfiltered: bool | None = None
    # Windows에서 방화벽 규칙이 호스트 허용 목록을 집행하고 있으면 참. 이전 묶음은 안 보낸다.
    egress_filtered: bool | None = None


class OutsideProcessItem(BaseModel):
    """묶음 실행기 밖에서 직접 돈 MCP 서버 패키지(패키지 식별자만, 인자·경로는 받지 않는다)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package: str = Field(pattern=r"^[A-Za-z0-9@][A-Za-z0-9@._:/-]{0,200}$")
    ecosystem: Literal["npm", "pypi", "container"]
    count: int = Field(ge=1, le=100000)


class AutostartItem(BaseModel):
    """MCP 실행기·서버를 가리키는 자동 시작 항목. ``server``는 항목이 시작하는 서버 이름이다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["systemd", "autostart", "cron", "run_key", "scheduled_task", "startup_folder"]
    name: str = Field(min_length=1, max_length=256)
    server: str | None = Field(default=None, min_length=1, max_length=128)


class RemovedItem(BaseModel):
    """관리형 묶음이 폐기 서버 때문에 지웠다고 보고하는 항목(경로는 받지 않는다)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["config", "process", "autostart"]
    server: str = Field(min_length=1, max_length=128)
    # 설정 항목이면 도구 이름(claude·codex), 자동 시작 항목이면 항목 이름
    target: str | None = Field(default=None, max_length=256)


# 실행 파일 이름·호스트에는 자격 증명이 들어갈 자리(사용자 정보, 경로, 질의, 인자)가 없다.
_TARGET = r"^[A-Za-z0-9._-]{1,128}$"
_PACKAGE = r"^(@[a-z0-9._-]{1,64}/)?[a-z0-9._-]{1,64}(@[A-Za-z0-9._-]{1,32})?$"


ClientName = Literal[
    "claude", "codex", "cursor", "grok", "gemini", "antigravity", "windsurf", "vscode",
    "claude_desktop", "cline", "lmstudio",
]


class AiClientItem(BaseModel):
    """단말에서 찾은 AI 도구 하나와 그 연결·보장 상태(단말의 주장)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    client: ClientName
    version: str | None = Field(default=None, max_length=64)
    connection: Literal["hook", "mediated", "config", "none", "failed"]
    coverage: Literal["pre_call", "local_only", "unmanaged", "unknown", "scan_failed"]
    servers: int = Field(ge=0, le=256)
    unmanaged: int = Field(ge=0, le=256)
    restart_needed: bool = False


class PlaintextKeyItem(BaseModel):
    """MCP 설정에 평문으로 든 키의 위치. 종류와 위치만 받고 값은 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    client: ClientName
    entry: str = Field(min_length=1, max_length=128)
    kind: Literal[
        "openai", "anthropic", "google", "github", "aws", "slack", "huggingface", "generic"
    ]
    where: Literal["env", "headers", "args", "url"]


class OfflineCallItem(BaseModel):
    """결정 서비스에 닿지 못해 단말이 스스로 통과시킨 호출(뒤늦게 한꺼번에 보고, 단말의 주장)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    harness: str = Field(min_length=1, max_length=32)
    at: datetime
    count: int = Field(ge=1, le=10000)


class LocalMcpItem(BaseModel):
    """하네스 설정에 있는, 관리 대상이 아닌 MCP 항목. 인자·환경 변수·토큰은 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    harness: ClientName
    name: str = Field(min_length=1, max_length=128)
    kind: Literal["stdio", "http", "sse"]
    target: str = Field(pattern=_TARGET)  # stdio는 실행 파일 이름, 원격은 호스트
    package: str | None = Field(default=None, pattern=_PACKAGE, max_length=140)


TOOL_SCHEMA_BYTES = 8 * 1024


class ToolItem(BaseModel):
    """서버가 ``tools/list``로 알린 도구 하나(이름·설명·입력 정의). 호출 인자·결과는 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)
    input_schema: dict[str, Any]

    @field_validator("input_schema")
    @classmethod
    def _small(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value)) > TOOL_SCHEMA_BYTES:
            raise ValueError("input schema too large")
        return value


class ToolListItem(BaseModel):
    """단말이 본 로컬 서버의 도구 목록(단말의 주장). 바뀐 목록만 보낸다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool = False
    tools: list[ToolItem] = Field(max_length=100)


_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_PACKAGE_NAME = r"^(@[a-z0-9][a-z0-9._-]{0,100}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
_INTEGRITY = r"^sha512-[A-Za-z0-9+/]{86}==$"
_SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?"
MAX_OBSERVED_TOOLS = 200


class IntakeSpec(BaseModel):
    """신청할 PyPI 패키지(또는 커밋으로 고정한 저장소)와 실행 명령. 인자 값에 비밀을 넣지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    index: Literal["pypi", "git", "npm"]
    git: str | None = Field(
        default=None,
        pattern=r"^https://(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)"
                r"/[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")
    name: str = Field(pattern=_PACKAGE_NAME)
    version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}$")
    # npm 출처: 레지스트리 무결성 해시(필수)와 소스 커밋(선택, 소스 검사에 쓴다).
    integrity: str | None = Field(default=None, pattern=_INTEGRITY)
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    extras: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]] = Field(
        default_factory=list, max_length=16
    )
    command: str = Field(min_length=1, max_length=128)
    argv: list[Annotated[str, Field(max_length=512)]] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def _source_is_pinned(self) -> IntakeSpec:
        if self.index == "npm":
            if not self.integrity or not re.fullmatch(_SEMVER, self.version):
                raise ValueError("an npm source needs an exact version and its sha512 integrity")
            return self
        if self.integrity or self.commit or self.name.startswith("@"):
            raise ValueError("integrity and commit are for npm sources only")
        if (self.index == "pypi") != (self.git is None) or (
                self.index != "pypi" and not re.fullmatch(r"[0-9a-f]{40}", self.version)):
            raise ValueError("a repository source needs its address and a 40-character commit")
        return self


class FileAccessItem(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    mode: str = Field(min_length=1, max_length=16)


class IntakeBody(BaseModel):
    """단말 신청. 사용자·조직·키 필드는 받지 않는다(알 수 없는 필드는 거부)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: UUID
    server_id: str = Field(pattern=_NAME)
    spec: IntakeSpec
    file_access: list[FileAccessItem] = Field(default_factory=list, max_length=64)
    network: Literal["none", "hosts"] | None = None  # 지정하지 않으면 자동(막지 않음)
    allowed_hosts: list[Annotated[str, Field(min_length=1, max_length=253)]] = Field(
        default_factory=list, max_length=64
    )
    env_names: list[Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]] = Field(
        default_factory=list, max_length=64
    )
    # 비밀이 아닌 환경 변수 값. 허용 여부(제어 변수·비밀 이름·경로 값)는 서버가 판정한다.
    env: dict[
        Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")],
        Annotated[str, Field(max_length=1024)],
    ] = Field(default_factory=dict, max_length=32)
    purpose: str = Field(min_length=1, max_length=2000)
    data_grade: str = Field(min_length=1, max_length=64)
    resources: list[Annotated[str, Field(min_length=1, max_length=256)]] = Field(
        default_factory=list, max_length=32
    )
    # 단말이 본 도구 목록(참고용, 단말의 주장).
    observed_tools: list[ToolItem] | None = Field(default=None, max_length=MAX_OBSERVED_TOOLS)

    @model_validator(mode="after")
    def _hosts_match_network(self) -> IntakeBody:
        if (self.network == "hosts") != bool(self.allowed_hosts):
            raise ValueError("allowed_hosts does not match network")
        return self


class RemoteIntakeBody(BaseModel):
    """단말의 원격 서버 신청. 주소와 목적만 받고 나머지는 서버가 채운다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: UUID
    server_id: str = Field(pattern=_NAME)
    url: str = Field(min_length=1, max_length=2048)
    transport: Literal["http", "sse"] = "http"
    purpose: str = Field(min_length=1, max_length=256)

    @field_validator("url")
    @classmethod
    def _plain_https(cls, value: str) -> str:
        parts = urlsplit(value)
        try:
            port = parts.port
        except ValueError:
            port = 0
        if (parts.scheme != "https" or not parts.hostname or port == 0
                or parts.username is not None or parts.password is not None
                or any(c in value for c in "?#\\")
                or any(c.isspace() or ord(c) < 32 for c in value)):
            raise ValueError("url must be a plain https address")
        return value

    def payload(self) -> dict[str, Any]:
        """DB 함수 입력. 등급은 내부, 자원은 비움(관리자가 정한다)."""
        contract = {"url": self.url, "transport": self.transport, "auth_type": "none",
                    "issuer": None, "oauth_scopes": [], "allowed_tools": None,
                    "image_digest": None, "source_commit": None}
        return {"server_id": self.server_id, "url": self.url, "transport": self.transport,
                "purpose": self.purpose, "data_grade": "internal", "resources": [],
                "provider": urlsplit(self.url).hostname, "contract": canonical_text(contract)}


class IntakeRequest(RootModel[IntakeBody | RemoteIntakeBody]):
    """``INTAKES_PATH``의 본문: 로컬 실행(spec) 또는 원격 주소(url)."""


class InspectionDetail(BaseModel):
    """검사 실패 상세(관리자에게만 보인다)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: str | None = Field(default=None, max_length=32)
    exit_code: int | None = Field(default=None, ge=-(2**31), le=2**31)
    stderr_tail: str = Field(default="", max_length=2048)


class InspectionResultBody(BaseModel):
    """단말이 검사용 승인으로 올리는 결과. 목록은 서버가 단말의 주장으로만 본다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    complete: StrictBool
    tools: list[dict[str, Any]] = Field(max_length=MAX_INSPECTION_TOOLS)
    detail: InspectionDetail | None = None

    def document(self) -> dict[str, Any]:
        out: dict[str, Any] = {"pack_sha256": self.pack_sha256, "complete": self.complete,
                               "tools": self.tools}
        if self.detail is not None:
            out["detail"] = self.detail.model_dump()
        return out


class StartFailureItem(BaseModel):
    """도구 목록을 내기 전에 죽은 로컬 서버와 짧은 사유(단말의 주장)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=80)


class ReportBody(BaseModel):
    """설치 묶음이 설치·제거를 마치고 보내는 상태 보고. 파일 경로나 키는 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kit_version: str = Field(min_length=1, max_length=128)
    action: Literal["installed", "removed"]
    mode: Literal["managed", "user", "none"]
    claude_version: str | None = Field(default=None, max_length=64)
    mcp_servers: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=256
    )
    # 이전 묶음은 보내지 않는다(None = 보고 없음). 단말의 주장이며 MINT가 관측한 값이 아니다.
    processes: list[ProcessItem] | None = Field(default=None, max_length=64)
    autostart: list[AutostartItem] | None = Field(default=None, max_length=64)
    # 실행기를 거치지 않고 직접 돈 MCP 서버 패키지. 이전 묶음은 보내지 않는다(None = 보고 없음).
    outside_processes: list[OutsideProcessItem] | None = Field(default=None, max_length=64)
    removed: list[RemovedItem] | None = Field(default=None, max_length=256)
    local_mcp: list[LocalMcpItem] | None = Field(default=None, max_length=64)
    # 실행기가 서버의 ``tools/list`` 응답에서 본 도구 목록. 이전 묶음은 보내지 않는다.
    tool_lists: list[ToolListItem] | None = Field(default=None, max_length=8)
    start_failures: list[StartFailureItem] | None = Field(default=None, max_length=8)
    # 사용자 수준 Codex 훅을 Codex가 신뢰했는가(단말 설정에서 읽은 값). 이전 묶음은 보내지 않는다.
    hook_trust: Literal["trusted", "untrusted"] | None = None
    # 제거 보고에만: 같은 PC에 새로 설치한 키의 해시(앱 자격을 그 키로 옮긴다). 단말의 주장이다.
    replaced_by: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    # 서버 이름 -> 단말이 받아 둔 결정 버전. 옛 단말은 보내지 않는다(최신 버전으로 본다).
    decision_versions: dict[str, Annotated[int, Field(ge=1, le=2**31)]] | None = Field(
        default=None, max_length=256
    )
    # 키트가 할 수 있는 일(예: 검사용 승인 수행). 모르는 이름은 무시한다.
    capabilities: list[Annotated[str, Field(min_length=1, max_length=32)]] | None = Field(
        default=None, max_length=8
    )
    # 단말이 서명된 키트 갱신을 받을 수 있는가(고정 공개 키가 있다). 직전 갱신 실패 사유(있을 때만).
    kit_update: bool | None = None
    update_error: str | None = Field(default=None, max_length=80)
    # PC 이름과 OS(단말의 주장, 목록에서 PC를 알아보는 데만 쓴다). 옛 단말은 보내지 않는다.
    host: str | None = Field(default=None, max_length=255, pattern=r"^[^\x00-\x1f]*$")
    os: str | None = Field(default=None, max_length=64, pattern=r"^[^\x00-\x1f]*$")
    # AI 도구별 보장 현황·평문 키 위치·검사 실패·장애 중 통과 호출. 이전 묶음은 보내지 않는다.
    ai_clients: list[AiClientItem] | None = Field(default=None, max_length=16)
    plaintext_keys: list[PlaintextKeyItem] | None = Field(default=None, max_length=32)
    scan_errors: list[ClientName] | None = Field(default=None, max_length=16)
    offline_calls: list[OfflineCallItem] | None = Field(default=None, max_length=64)
    # 단말이 적용한 연결 중지 세대.
    paused_ack: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _mode_matches_action(self) -> ReportBody:
        if (self.action == "installed") == (self.mode == "none"):
            raise ValueError("mode does not match the action")
        return self

    def install_mode(self) -> str:
        return "removed" if self.action == "removed" else self.mode


def strict_json(raw: bytes) -> Any:
    """중복 키·비유한 숫자를 거부하는 JSON 해석. 모호한 본문은 판정하지 않는다."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in items}) != len(items):
            raise ValueError("duplicate key")
        return dict(items)

    def constant(name: str) -> Any:
        raise ValueError(f"non-finite number {name}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def local_request(
    body: DecideBody,
    auth: Any,
    *,
    instance_id: str,
    principal_factory: Callable[..., Principal],
) -> CallRequest:
    """결정 요청 본문을 ``build_request``의 주입 지점으로 채워 판정 요청을 만든다."""

    def parse(_: Mapping[str, Any]) -> HookData:
        return HookData(
            server_name=body.server,
            tool_name=body.tool,
            arguments=body.arguments,
            litellm_call_id=body.tool_use_id,
            logging_obj=None,
            client=body.client,
        )

    resolved = (
        ResolvedServer(
            server_id=body.server, identity_kind="stdio", exec_contract_sha256=BUILTIN_EXEC_SHA256,
            exec_contract_version=1, transport="builtin", auth_type="none",
            candidates_with_same_name=1,
        )
        if body.contract is None
        else body.contract.resolved(body.server)
    )
    return build_request(
        {},
        auth,
        operation=OperationType.TOOL_CALL,
        instance_id=instance_id,
        hook_parser=parse,
        # 서버 행과의 대조는 판정 단계의 상태 검사가 한다(등록 안 됨·종류 다름·계약 다름 모두 차단).
        resolver=lambda _hook: resolved,
        principal_factory=principal_factory,
    )


PAUSED_CODE = "MINT-ENDPOINT-PAUSED"
PAUSED_GUIDANCE = (
    "관리자가 이 PC의 관리 AI 연결을 중지했습니다. 재개되면 바로 다시 호출하십시오."
)
# 판정마다 DB를 읽지 않도록 키별로 잠깐 기억한다(중지·재개는 이 초만큼 늦게 닿는다).
# 중지 직후 열린 실행기의 호출이 한 번 더 지나가는 틈을 줄이려 짧게 둔다(QA-BUG-302).
_PAUSE_TTL = 1.0
_pause_seen: dict[str, tuple[float, bool]] = {}


async def _paused(runtime: Any, key_id: str) -> bool:
    now = time.monotonic()
    hit = _pause_seen.get(key_id)
    if hit is not None and hit[0] > now:
        return hit[1]
    try:
        paused = bool(await runtime.database.endpoint_paused(runtime.config.instance_id, key_id))
    except Exception:  # 가용성 우선: 읽지 못하면 막지 않는다
        return False
    if len(_pause_seen) > 4096:
        _pause_seen.clear()
    _pause_seen[key_id] = (now + _PAUSE_TTL, paused)
    return paused


async def _legacy_network(body: DecideBody, runtime: Any) -> DecideBody:
    """옛 신청의 승인 계약은 network none으로 저장돼 있고 단말은 그 값을 뺀 계약을 보낸다.
    저장된 해시가 network none을 더한 계약의 해시와 같으면 저장된 쪽으로 맞춘다."""
    contract = body.contract
    if contract is None or contract.network is not None:
        return body
    try:
        rows = await runtime.database.registered_servers(runtime.config.instance_id)
    except Exception:  # 가용성 우선: 조회 실패는 원래 계약 그대로 판정한다
        return body
    stored = {r.server_id: r.exec_contract_sha256 for r in rows}.get(body.server)
    if stored is None or stored == contract.sha256():
        return body
    legacy = contract.model_copy(update={"network": "none"})
    return body.model_copy(update={"contract": legacy}) if legacy.sha256() == stored else body


def result_context(payload: Mapping[str, Any]) -> dict[str, Any]:
    """판정 사건 본문에서 응답 관측이 읽는 호출 컨텍스트를 다시 만든다(단말 값은 쓰지 않는다)."""
    principal = payload.get("principal") or {}
    consumed = payload.get("consumed_call_approval_id")
    is_user = principal.get("principal_type") == "user"
    return {
        "invocation_id": payload["invocation_id"],
        "attempt_id": payload["attempt_id"],
        "decision_ref": payload["decision_ref"],
        "consumed_call_approval": None if consumed is None else {"id": consumed},
        "allowed": payload.get("enforced_action") == "allow",
        "state_epoch": payload.get("state_epoch"),
        "server_id": payload.get("resolved_server_id"),
        "tool": payload.get("tool"),
        "approval_id": payload.get("selected_approval_id"),
        "relation_id": None,
        "key_id": principal.get("key_id"),
        "user_id": principal.get("principal_id") if is_user else None,
        "team_id": principal.get("team_id"),
        "org_id": principal.get("org_id"),
    }


async def _read_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail="request body too large")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _body(request: Request, model: type[BaseModel], limit: int | None = None) -> Any:
    raw = await _read_limited(request, limit or BODY_LIMITS[request.url.path])
    if b"\u0000" in raw or b"\x00" in raw:  # NUL 문자는 DB 텍스트에 들어갈 수 없다
        raise HTTPException(status_code=422, detail="invalid request")
    try:
        return model.model_validate(strict_json(raw))
    except (ValueError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="invalid request") from exc


def make_router(
    *,
    auth_dependency: Callable[..., Any],
    runtime_provider: Callable[[], Any],
    principal_factory: Callable[..., Principal],
) -> APIRouter:
    """결정·결과 보고 경로. 인증은 호출자 키로 ``auth_dependency``(LiteLLM의 키 인증)가 한다."""
    router = APIRouter()

    def ready(*, verified: bool = True) -> Any:
        """기동을 마치지 못한 워커는 요청을 받지 않는다(코드가 있는 503). 판정은 ``verified``를
        요구하지 않고 파이프라인이 사유와 사건을 남기며 막는다."""
        runtime = runtime_provider()
        if runtime is None or (verified and not runtime.verified):
            detail = {"error": {"code": NOT_READY_CODE, "message": "MINT is still starting"}}
            raise HTTPException(status_code=503, detail=json.dumps(detail))
        return runtime

    @router.post(DECIDE_PATH)
    async def decide(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = ready(verified=False)
        body = await _body(request, DecideBody)
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is not None and await _paused(runtime, who.key_id):
            error = MintError(
                code=PAUSED_CODE, dispatch_state=DispatchState.NOT_DISPATCHED, retry_safe=True,
                reference="endpoint-paused", guidance=PAUSED_GUIDANCE, retry_after=60)
            return {"decision": "deny", "reference": error.reference,
                    "error": json.loads(error.detail())}
        body = await _legacy_network(body, runtime)
        call = local_request(
            body, auth, instance_id=runtime.config.instance_id, principal_factory=principal_factory
        )
        outcome = await evaluate_request(call, runtime.deps)
        answer: dict[str, Any] = {
            "decision": "allow" if outcome.allowed else "deny",
            "reference": outcome.snapshot.decision_ref,
        }
        if outcome.error is not None:
            answer["error"] = json.loads(outcome.error.detail())
        return answer

    @router.post(RESULT_PATH)
    async def result(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = ready()
        body = await _body(request, ResultBody)
        match = _REFERENCE.fullmatch(body.reference)
        if match is None:
            raise HTTPException(status_code=422, detail="invalid request")
        try:
            payload = await runtime.database.read_decision(
                runtime.config.instance_id, UUID(match[1]), int(match[2])
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="decision store is not ready") from exc
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        # 허용된 로컬 서버 호출의 판정을 만든 키만 그 결과를 보고할 수 있다.
        if (
            payload is None
            or payload.get("enforced_action") != "allow"
            or payload.get("resolved_identity_kind") != "stdio"
            or (payload.get("principal") or {}).get("key_id") != who.key_id
        ):
            raise HTTPException(status_code=404, detail="no such allowed decision")
        ctx = result_context(payload)
        if body.outcome == "success" and ctx["server_id"]:
            try:
                await runtime.database.record_delivery(
                    runtime.config.instance_id, who.key_id, "first_response", [ctx["server_id"]],
                    {ctx["server_id"]: body.decision_version} if body.decision_version else None)
            except Exception:
                log.exception("delivery receipt could not be stored")
        if body.outcome == "unknown":
            await observe_unknown_outcome(
                ctx, exception_type="client_report", http_status=None, deps=runtime.result_deps
            )
        else:
            await observe_response(
                ctx,
                is_error=body.outcome == "error",
                size_bytes=body.size_bytes,
                deps=runtime.result_deps,
            )
        return {"recorded": True}

    @router.post(REPORT_PATH)
    async def report(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = ready()
        body = await _body(request, ReportBody)
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        try:
            # 설치 묶음에 발급한 키(해제되지 않은 것)의 보고만 받는다.
            outcome = "unknown" if who.key_id is None else await runtime.database.report_install(
                runtime.config.instance_id,
                who.key_id,
                mode=body.install_mode(),
                kit_version=body.kit_version,
                claude_version=body.claude_version,
                mcp_servers=body.mcp_servers,
                processes=_dump(body.processes),
                autostart=_dump(body.autostart),
                outside_processes=_dump(body.outside_processes),
                removed=_dump(body.removed),
                local_mcp=_dump(body.local_mcp),
                tool_lists=_dump(body.tool_lists),
                hook_trust=body.hook_trust,
                update_error=body.update_error,
                host=body.host, os=body.os,
                ai_clients=_dump(body.ai_clients),
                plaintext_keys=_dump(body.plaintext_keys),
                scan_errors=body.scan_errors,
                offline_calls=_dump(body.offline_calls, json_mode=True),
                paused_ack=body.paused_ack,
            )
        except Exception as exc:
            log.exception("install report could not be stored")
            raise HTTPException(status_code=503, detail="install store is not ready") from exc
        if outcome == "unknown":
            raise HTTPException(status_code=404, detail="no such kit key")
        if outcome == "expired":
            raise HTTPException(status_code=403, detail="kit key expired; ask an admin to reissue")
        if body.action == "removed":
            # 이 PC에서 제거했거나 같은 PC에 새 키로 다시 설치했다: 이 키만 해제한다.
            try:
                issuer = apps.issuer()
            except apps.AppRefused:
                issuer = None
                log.warning("kit issuer key is missing; a removed install keeps its key")
            try:
                retired = await runtime.database.retire_install(
                    runtime.config.instance_id, who.key_id, issuer, body.replaced_by)
            except Exception:
                log.exception("removed install could not be retired")
                retired = False
            return {"recorded": True, "retired": retired}
        if body.action == "installed":
            seen = {
                "device_received": body.mcp_servers,
                "started": [i.server for i in body.processes or ()],
                "discovered": [i.server for i in body.tool_lists or ()],
            }
            for stage, names in seen.items():
                try:
                    await runtime.database.record_delivery(
                        runtime.config.instance_id, who.key_id, stage, names,
                        body.decision_versions)
                except Exception:
                    log.exception("delivery receipt could not be stored")  # 보고 자체는 받는다
        if body.action == "installed" and body.start_failures:
            try:
                await runtime.database.record_delivery(
                    runtime.config.instance_id, who.key_id, "start_failed",
                    [i.server for i in body.start_failures], body.decision_versions,
                    {i.server: i.reason for i in body.start_failures})
            except Exception:
                log.exception("start failure receipt could not be stored")
        try:
            retired = await runtime.database.retired_servers(
                runtime.config.instance_id,
                [*body.mcp_servers, *(i.server for i in body.processes or ()),
                 *(i.server for i in body.autostart or () if i.server)],
            )
        except Exception:
            retired = None  # 목록을 못 만들면 싣지 않는다(단말은 마지막 목록을 그대로 쓴다)
        try:
            desired = await runtime.database.desired_servers(
                runtime.config.instance_id, who.key_id
            )
        except Exception:
            desired = None  # 마찬가지로 못 만들면 싣지 않는다(단말은 설정을 바꾸지 않는다)
        answer: dict[str, Any] = {"recorded": True, "renewed": outcome == "renewed"}
        try:
            answer.update(await runtime.database.endpoint_control(
                runtime.config.instance_id, who.key_id, "clients" in (body.capabilities or ())))
        except Exception:
            log.exception("endpoint control state could not be read")  # 싣지 않으면 단말은 유지
        try:
            policy = await runtime.database.offline_policy(
                runtime.config.instance_id, who.key_id,
                sorted(getattr(runtime.config, "high_risk_tools", ()) or ()))
            if policy is not None:
                answer["offline_policy"] = policy
        except Exception:
            log.exception("offline policy could not be built")  # 단말은 마지막 정책 유지
        bundle = kit_sign.update_bundle()
        if bundle:
            answer["kit_version"] = bundle["version"]
            if body.kit_update and body.kit_version != bundle["version"]:
                answer["kit_update"] = bundle  # 판본이 다른 단말만 서명된 묶음을 받는다
        if "inspect" in (body.capabilities or ()):
            try:
                answer["inspections"] = [
                    {"id": str(i["id"]), "intake_id": str(i["intake_id"]), "server": i["server_id"],
                     "pack_sha256": i["pack_sha256"], "contract": i["contract"],
                     "expires_at": _iso(i["expires_at"])}
                    for i in await runtime.database.endpoint_inspections(
                        runtime.config.instance_id, who.key_id)
                ]
            except Exception:
                log.exception("inspection list could not be built")
        if retired is not None:
            answer["retired"] = retired
        if desired is not None:
            answer["desired"] = desired
            try:
                answer["revoke"] = await runtime.database.revoke_servers(
                    runtime.config.instance_id,
                    [*body.mcp_servers, *(i.server for i in body.processes or ()),
                     *(i.server for i in body.autostart or () if i.server)],
                    [d["name"] for d in desired],
                )
            except Exception:
                log.exception("revoke list could not be built")
        return answer

    @router.post(OUTCOMES_PATH)
    async def outcomes(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        """키에 묶인 사용자 본인의 호출별 승인 결과(승인·거부)만 돌려준다. 인자 값은 싣지 않는다."""
        runtime = ready()
        body = await _body(request, OutcomesBody)
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.principal_type != "user" or not who.principal_id:
            raise HTTPException(status_code=404, detail="no such kit key")
        try:
            cursor, items = await runtime.database.call_approval_outcomes(
                runtime.config.instance_id, who.principal_id, body.since
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="approval store is not ready") from exc
        return {"cursor": cursor, "items": items}

    @router.get(ME_PATH)
    async def me(auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        """키가 닿는 묶음 서버와 최근 신청 20건."""
        runtime = ready()
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None:
            raise HTTPException(status_code=404, detail="no such kit key")
        try:
            scope = await runtime.database.endpoint_scope(runtime.config.instance_id, who.key_id)
            rows = await runtime.database.endpoint_my_intakes(
                runtime.config.instance_id, who.key_id
            )
        except Exception as exc:
            log.exception("endpoint scope could not be read")
            raise HTTPException(status_code=503, detail="endpoint store is not ready") from exc
        try:  # 원격 승인은 게이트웨이 키 권한과 같은 질의로 읽는다(못 읽으면 로컬 묶음만 낸다)
            remote = await runtime.database.endpoint_remote_servers(
                runtime.config.instance_id, who.key_id)
        except Exception:
            log.exception("remote servers could not be read")
            remote = []
        try:  # 검사 권한이 열린 신청은 사유·다음 할 일을 단말 검사 기준으로 낸다
            open_checks = {
                str(i["intake_id"]) for i in await runtime.database.endpoint_inspections(
                    runtime.config.instance_id, who.key_id)
            }
        except Exception:
            open_checks = set()
        rows = [{**r, "inspect": str(r["id"]) in open_checks} for r in rows]
        try:
            asks = await runtime.database.endpoint_access_mine(who.key_id)
            live = await runtime.database.endpoint_live_servers(who.key_id)
            rows = [{**r, "ended": r["server_id"] not in live} for r in rows]
        except Exception:  # 옛 DB(권한 요청 함수 전)여도 나머지는 낸다
            asks = []
        return {
            "user": who.principal_id if who.principal_type == "user" else None,
            "servers": [
                {"server_id": r["server_id"], "pack_sha256": r["pack_sha256"],
                 "permit_until": _iso(r["permit_until"]), "status": "approved",
                 **({"pack_windows": w} if (w := _windows_ref(r)) else {})}
                for r in scope
            ],
            "remote_servers": remote,
            "intakes": [
                {"id": str(r["id"]), "server_id": r["server_id"], "status": r["status"],
                 "decision": r["decision"], "reason": intake_text.reason_of(r),
                 "stage": intake_text.stage_of(r), "next": intake_text.next_of(r),
                 "created_at": _iso(r["created_at"])}
                for r in rows[:20]
            ],
            "access_requests": [
                {"id": str(r["id"]), "server_id": r["server_id"], "tool": r["tool"],
                 "reason_code": r["reason_code"], "status": r["status"],
                 "resolution": r["resolution"], "decision_note": r["decision_note"],
                 "created_at": _iso(r["created_at"]), "decided_at": _iso(r["decided_at"])}
                for r in asks
            ],
        }

    @router.post(ACCESS_REQUESTS_PATH, status_code=201)
    async def access_open(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        """설치 키 주인의 권한 요청을 연다(직원 화면의 요청과 같은 표·같은 승인 센터 탭)."""
        from mint_litellm.control.services.access_requests import SUGGESTED

        runtime = ready()
        body = await _body(request, AccessRequestBody)
        if body.reason_code is not None and body.reason_code not in SUGGESTED:
            raise HTTPException(status_code=422, detail="this reason cannot be requested")
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None:
            raise HTTPException(status_code=404, detail="no such kit key")
        try:
            made = await runtime.database.endpoint_access_open(
                who.key_id, body.request_id, body.server, body.tool, body.reason_code, body.note)
        except Exception as exc:
            status = _intake_status(exc)
            if status is None:
                log.exception("endpoint access request could not be stored")
                raise HTTPException(status_code=503, detail="request store is not ready") from exc
            raise HTTPException(status_code=status, detail=_intake_detail(exc)) from exc
        return {"id": str(made), "reused": made != body.request_id}

    @router.post(ACCESS_REQUEST_CANCEL_PATH)
    async def access_cancel(
        request_id: UUID, auth: Any = Depends(auth_dependency)
    ) -> dict[str, Any]:
        runtime = ready()
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None:
            raise HTTPException(status_code=404, detail="no such kit key")
        try:
            done = await runtime.database.endpoint_access_cancel(who.key_id, request_id)
        except Exception as exc:
            status = _intake_status(exc)
            if status is None:
                log.exception("endpoint access request could not be cancelled")
                raise HTTPException(status_code=503, detail="request store is not ready") from exc
            raise HTTPException(status_code=status, detail=_intake_detail(exc)) from exc
        if not done:
            raise HTTPException(status_code=404, detail="no open request")
        return {"id": str(request_id), "cancelled": True}

    @router.post(INTAKES_PATH, status_code=201)
    async def intakes(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = ready()
        body = (await _body(request, IntakeRequest)).root
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None:
            raise HTTPException(status_code=404, detail="no such kit key")
        try:
            if isinstance(body, RemoteIntakeBody):
                made = await runtime.database.endpoint_submit_remote_intake(
                    who.key_id, body.request_id, body.payload()
                )
            else:
                payload = body.model_dump(mode="json", exclude={"request_id"}, exclude_none=True)
                made = await runtime.database.endpoint_submit_intake(
                    who.key_id, body.request_id, payload
                )
        except Exception as exc:
            status = _intake_status(exc)
            if status is None:
                log.exception("endpoint intake could not be stored")
                raise HTTPException(status_code=503, detail="intake store is not ready") from exc
            raise HTTPException(status_code=status, detail=_intake_detail(exc)) from exc
        return {"id": str(made)}

    @router.post(APPS_PATH, status_code=201)
    async def app_new(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        """직원이 만든 프로그램에 줄 자격(키)을 발급한다. 키 값은 이 응답에만 있다."""
        runtime = ready()
        body = await _body(request, apps.AppBody)
        who = _install_principal(principal_factory, auth, runtime)
        try:
            made = await runtime.database.endpoint_app_create(
                runtime.config.instance_id, who.key_id, body.name, body.days, apps.issuer())
        except apps.AppRefused as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
        except Exception as exc:
            log.exception("endpoint app could not be issued")
            raise HTTPException(status_code=503, detail="app store is not ready") from exc
        base, mcp = apps.urls()
        return {
            "id": made["id"], "name": made["name"], "key": made["key"],
            "key_alias": made["key_alias"], "expires_at": _iso(made["expires_at"]),
            "base_url": base, "mcp_url": mcp, "servers": made["servers"],
        }

    @router.get(APPS_PATH)
    async def app_list(auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = ready()
        who = _install_principal(principal_factory, auth, runtime)
        try:
            rows = await runtime.database.endpoint_apps_list(
                runtime.config.instance_id, who.key_id)
        except Exception as exc:
            log.exception("endpoint apps could not be read")
            raise HTTPException(status_code=503, detail="app store is not ready") from exc
        return apps.listing(rows)

    @router.delete(APP_PATH)
    async def app_revoke(app_id: UUID, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        """본인의 앱 자격을 회수한다(이미 회수된 앱도 같은 응답)."""
        runtime = ready()
        who = _install_principal(principal_factory, auth, runtime)
        try:
            found = await runtime.database.endpoint_app_revoke(
                runtime.config.instance_id, who.key_id, app_id, apps.issuer())
        except apps.AppRefused as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
        except Exception as exc:
            log.exception("endpoint app could not be revoked")
            raise HTTPException(status_code=503, detail="app store is not ready") from exc
        if not found:
            raise HTTPException(status_code=404, detail="no such app")
        return {"id": str(app_id), "revoked": True}

    @router.post(INSPECTION_START_PATH)
    async def inspection_start(
        inspection_id: UUID, auth: Any = Depends(auth_dependency)
    ) -> dict[str, Any]:
        """검사용 승인의 실행권을 원자적으로 한 번 소비한다(같은 키만)."""
        runtime = ready()
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None:
            raise HTTPException(status_code=404, detail="no such kit key")
        await _inspection_call(runtime.database.endpoint_inspection_start(
            runtime.config.instance_id, who.key_id, inspection_id))
        return {"started": True}

    @router.post(INSPECTION_RESULT_PATH)
    async def inspection_result(
        inspection_id: UUID, request: Request, auth: Any = Depends(auth_dependency)
    ) -> dict[str, Any]:
        """소비된 검사용 승인의 결과를 받는다. 같은 본문의 재전송은 같은 응답이다."""
        runtime = ready()
        body = await _body(request, InspectionResultBody, INSPECTION_BODY_BYTES)
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None:
            raise HTTPException(status_code=404, detail="no such kit key")
        await _inspection_call(runtime.database.endpoint_inspection_submit(
            runtime.config.instance_id, who.key_id, inspection_id, body.document()))
        return {"recorded": True}

    @router.get(PACKS_PATH)
    async def pack_file(
        server_id: str, pack_sha256: str, file: str, auth: Any = Depends(auth_dependency)
    ) -> FileResponse:
        """범위에 닿는 (서버, 묶음) 쌍의 manifest 또는 manifest에 적힌 파일만 보낸다."""
        runtime = ready()
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        if who.key_id is None or not _SHA256.fullmatch(pack_sha256):
            raise HTTPException(status_code=404, detail="no such pack")
        try:
            scope = await runtime.database.endpoint_scope(runtime.config.instance_id, who.key_id)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="endpoint store is not ready") from exc
        row = next(
            (r for r in scope if r["server_id"] == server_id and r["pack_sha256"] == pack_sha256),
            None,
        ) or _windows_row(
            next((r for r in scope if r["server_id"] == server_id
                  and _windows_sha(r) == pack_sha256), None))
        if row is None:  # 범위가 아니면 이 키·이 묶음의 유효한 검사용 승인이 있는가
            try:
                row = await runtime.database.endpoint_inspection_pack(
                    runtime.config.instance_id, who.key_id, server_id, pack_sha256)
            except Exception as exc:
                raise HTTPException(status_code=503, detail="endpoint store is not ready") from exc
        path = _pack_path(row, file)
        if path is None:
            raise HTTPException(status_code=404, detail="no such pack")
        kind = "application/json" if file == "manifest.json" else "application/octet-stream"
        return FileResponse(path, media_type=kind)

    return router


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PACKS_ROOT_ENV = "MINT_PACKS_DIR"
DEFAULT_PACKS_ROOT = "/var/lib/mint/packs"


def _install_principal(
    principal_factory: Callable[..., Principal], auth: Any, runtime: Any
) -> Principal:
    """설치 키의 주체. 사용자 키가 아니거나 키가 없으면 404."""
    who = principal_factory(auth, instance_id=runtime.config.instance_id)
    if who.key_id is None or who.principal_type != "user":
        raise HTTPException(status_code=404, detail="no such kit key")
    return who


def _iso(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else value


def _windows_ref(row: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """계약의 Windows 묶음 항목(해시 또는 「없음」 표시). 없으면 ``None``."""
    pack = (row.get("exec_contract") or {}).get("pack")
    windows = pack.get("windows") if isinstance(pack, Mapping) else None
    return windows if isinstance(windows, Mapping) else None


def _windows_sha(row: Mapping[str, Any]) -> str | None:
    """계약에 적힌 Windows 묶음 해시(없으면 ``None``)."""
    sha = (_windows_ref(row) or {}).get("sha256")
    return sha if isinstance(sha, str) and _SHA256.fullmatch(sha) else None


def _windows_row(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """계약의 Windows 묶음을 Linux 묶음과 같은 모양의 행으로(manifest는 저장소 디스크의 것)."""
    sha = _windows_sha(row) if row else None
    if sha is None:
        return None
    root = Path(os.environ.get(PACKS_ROOT_ENV, DEFAULT_PACKS_ROOT)).resolve()
    try:
        manifest = json.loads((root / sha / "manifest.json").read_bytes())
    except (OSError, ValueError):
        return None
    return {**row, "pack_sha256": sha, "pack_manifest": manifest}


def _pack_path(row: Mapping[str, Any] | None, file: str) -> Path | None:
    """묶음 파일의 실제 경로. 이름이 manifest에 없거나 볼륨 밖으로 나가면 ``None``."""
    if row is None:
        return None
    files = (row.get("pack_manifest") or {}).get("files") or ()
    names = {"manifest.json", *(f.get("name") for f in files if isinstance(f, Mapping))}
    if file not in names or file != Path(file).name or file in ("", ".", ".."):
        return None
    base = Path(os.environ.get(PACKS_ROOT_ENV, DEFAULT_PACKS_ROOT)).resolve() / row["pack_sha256"]
    path = (base / file).resolve()
    return path if path.is_relative_to(base) and path.is_file() else None


_INTAKE_SQLSTATE = {"23505": 409, "MT429": 429, "42501": 404, "23514": 400, "P0002": 404}


def _intake_status(exc: Exception) -> int | None:
    """DB 함수가 낸 예외의 종류. 충돌 409, 한도 429, 키 없음 404, 그 밖의 MINT 예외는 형식 400."""
    text = str(exc)
    if "MINT-" not in text:
        return None
    return _INTAKE_SQLSTATE.get(getattr(exc, "sqlstate", None) or "") or next(
        (status for marker, status in (("MINT-CONFLICT", 409), ("MINT-QUOTA", 429),
                                       ("MINT-KEY", 404), ("MINT-NOTFOUND", 404))
         if marker in text), 400)


def _intake_detail(exc: Exception) -> str:
    """예외 본문에서 MINT 코드가 든 줄만 돌려준다(SQL 문맥은 싣지 않는다)."""
    line = next((ln for ln in str(exc).splitlines() if "MINT-" in ln), "invalid request")
    return line.strip()[:200]


async def _inspection_call(call: Any) -> None:
    """검사용 승인 DB 함수의 예외를 응답 코드로 바꾼다(없음 404, 충돌 409, 형식 400)."""
    try:
        await call
    except Exception as exc:
        status = _intake_status(exc)
        if status is None:
            log.exception("endpoint inspection could not be stored")
            raise HTTPException(status_code=503, detail="inspection store is not ready") from exc
        raise HTTPException(status_code=status, detail=_intake_detail(exc)) from exc


def _dump(items: list[Any] | None, json_mode: bool = False) -> list[dict[str, Any]] | None:
    mode = "json" if json_mode else "python"
    return None if items is None else [item.model_dump(mode=mode) for item in items]


def install(app: Any, router: APIRouter) -> bool:
    """앱에 경로를 한 번만 붙인다. 이미 붙어 있으면 아무것도 하지 않고 거짓을 돌려준다."""
    if getattr(app.state, "mint_endpoint_installed", False):
        return False
    app.include_router(router)
    app.state.mint_endpoint_installed = True
    return True


ENABLE_ENV = "MINT_ENDPOINT_ROUTES"


def install_from_env(env: Mapping[str, str]) -> bool:
    """``MINT_ENDPOINT_ROUTES=true``이면 결정·결과 경로를 LiteLLM 앱에 붙인다."""
    if env.get(ENABLE_ENV, "").lower() not in ("1", "true", "yes"):
        return False
    from mint_litellm.compat import litellm_1_106 as compat
    from mint_litellm.plugin.selfcheck import get_runtime

    router = make_router(
        auth_dependency=compat.key_auth_dependency(),
        runtime_provider=get_runtime,
        principal_factory=compat.principal_from_auth,
    )
    return install(compat.proxy_app(), router)
