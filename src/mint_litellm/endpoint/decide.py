"""호출 전 훅이 부르는 결정 경로와 로컬 요청 어댑터.

판정은 LiteLLM 사전 훅과 같은 ``evaluate_request``가 하고, 이 모듈은 요청 본문을 판정 요청으로
바꾸는 접점만 가진다. 호출자의 사용자·조직은 본문이 아니라 인증 객체에서만 얻는다(본문에
그런 필드가 있으면 거부한다). 서버 실행 계약은 서버가 승인본과 비교하고, 일치하지 않으면
서버 식별 불일치로 차단한다.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mint_litellm.compat.litellm_1_106 import HookData, ServerResolutionError
from mint_litellm.endpoint.contract import LocalExecContract, mismatched_fields, strict_json
from mint_litellm.plugin.pipeline import CallRequest, build_request, evaluate_request
from mint_litellm.types.decision import OperationType, ResolvedServer, url_sha256
from mint_litellm.types.identity import Principal
from mint_litellm.types.reason_codes import Reason

log = logging.getLogger("mint_litellm.endpoint")

DECIDE_PATH = "/mint/v1/decide"
MAX_BODY_BYTES = 64 * 1024


class DecideBody(BaseModel):
    """훅이 보내는 결정 요청. 사용자·조직·키 필드는 두지 않는다(알 수 없는 필드는 거부)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    contract: LocalExecContract
    tool_use_id: str | None = Field(default=None, max_length=128)


class EndpointReport(BaseModel):
    """설치기가 보내는 설치 상태 보고. 단말의 주장이며 MINT가 관측한 사실이 아니다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kit_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    action: Literal["installed", "removed"]
    mode: Literal["managed", "user", "none"]
    managed: bool
    files: dict[str, str] = Field(default_factory=dict, max_length=32)
    mcp_servers: list[str] = Field(default_factory=list, max_length=64)
    claude_version: str | None = Field(default=None, max_length=64)


@dataclass(frozen=True)
class KitSettings:
    """키트 내려받기와 설치 보고에 필요한 값. 보고는 탐색용으로 줄 단위 JSON 파일에 덧붙인다."""

    public_url: str
    reports_path: Path
    ca_pem: str | None = None


@dataclass(frozen=True)
class LocalServer:
    """승인된 로컬 서버. ``standin_url``은 LiteLLM 레지스트리에 대신 올려 둔 자리 서버의 주소이다.

    자리 서버가 있으면 등록·승인·자가 점검이 기존 경로 그대로 동작하고, 서버 행의 URL 해시와
    전송 방식이 자리 서버 값이 된다. 없으면 서버 ID에서 만든 고정 값과 ``stdio``를 쓴다.
    """

    server_id: str
    contract: LocalExecContract
    standin_url: str | None = None
    transport: str = "stdio"


class ContractRegistry:
    """서버 이름 → 승인된 로컬 서버(서버 ID·실행 계약).

    탐색용으로 JSON 파일에서 읽는다. 본개발에서는 서버 등록·스냅숏이 이 자리를 대신한다.
    """

    def __init__(self, servers: Mapping[str, LocalServer]) -> None:
        self._servers = dict(servers)

    @classmethod
    def load(cls, path: Path) -> ContractRegistry:
        document = strict_json(path.read_bytes())
        return cls(
            {
                item["name"]: LocalServer(
                    item["server_id"],
                    LocalExecContract.model_validate(item["contract"]),
                    item.get("standin_url"),
                    item.get("transport", "http" if item.get("standin_url") else "stdio"),
                )
                for item in document["servers"]
            }
        )

    def get(self, name: str) -> LocalServer | None:
        return self._servers.get(name)

    def servers(self) -> Mapping[str, LocalServer]:
        return dict(self._servers)


def stdio_identity_hash(server_id: str) -> str:
    """서버 행의 URL 해시 칸에 들어가는 자리 값. 실행 계약 자체의 해시가 아니다.

    로컬 서버는 URL이 없어 이 칸을 쓸 수 없으므로 서버 ID에서 만든 고정 값으로 채운다. 실행
    계약의 일치는 ``mismatched_fields``가 따로 판정한다.
    """
    return hashlib.sha256(f"stdio:{server_id}".encode()).hexdigest()


def local_request(
    body: DecideBody,
    auth: Any,
    *,
    registry: ContractRegistry,
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
        )

    def resolve(hook: HookData) -> ResolvedServer:
        entry = registry.get(body.server)
        if entry is None:
            raise ServerResolutionError(Reason.SERVER_UNRESOLVED, "no local registry entry")
        differing = mismatched_fields(entry.contract, body.contract)
        if differing:
            raise ServerResolutionError(
                Reason.SERVER_IDENTITY_MISMATCH, "exec contract differs: " + ",".join(differing)
            )
        return ResolvedServer(
            server_id=entry.server_id,
            url_sha256=(
                url_sha256(entry.standin_url)
                if entry.standin_url
                else stdio_identity_hash(entry.server_id)
            ),
            transport=entry.transport,
            auth_type="none",
            candidates_with_same_name=1,
        )

    return build_request(
        {},
        auth,
        operation=OperationType.TOOL_CALL,
        instance_id=instance_id,
        hook_parser=parse,
        resolver=resolve,
        principal_factory=principal_factory,
    )


async def _read_limited(request: Request, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


def make_router(
    *,
    auth_dependency: Callable[..., Any],
    runtime_provider: Callable[[], Any],
    registry: ContractRegistry,
    principal_factory: Callable[..., Principal],
    kit: KitSettings | None = None,
) -> APIRouter:
    """결정 경로. 인증은 호출자 키로 ``auth_dependency``(LiteLLM의 키 인증)가 한다."""
    router = APIRouter()
    if kit is not None:
        _add_kit_routes(router, auth_dependency, runtime_provider, registry, principal_factory, kit)

    @router.post(DECIDE_PATH)
    async def decide(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = runtime_provider()
        if runtime is None:
            raise HTTPException(status_code=503, detail="decision runtime is not ready")
        raw = await _read_limited(request, MAX_BODY_BYTES)
        try:
            body = DecideBody.model_validate(strict_json(raw))
        except (ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail="invalid decision request") from exc
        call = local_request(
            body,
            auth,
            registry=registry,
            instance_id=runtime.config.instance_id,
            principal_factory=principal_factory,
        )
        outcome = await evaluate_request(call, runtime.deps)
        answer: dict[str, Any] = {
            "decision": "allow" if outcome.allowed else "deny",
            "reference": outcome.snapshot.decision_ref,
        }
        if outcome.error is not None:
            answer["error"] = json.loads(outcome.error.detail())
        return answer

    return router


def _add_kit_routes(router, auth_dependency, runtime_provider, registry, principal_factory, kit):
    from mint_litellm.endpoint.kit_build import build_kit

    @router.get("/mint/v1/kit")
    async def download_kit(request: Request, auth: Any = Depends(auth_dependency)) -> Response:
        """로그인(키 인증)한 사용자에게 그 사람의 키가 묶인 키트를 준다."""
        header = request.headers.get("authorization", "")
        key = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if not key:
            raise HTTPException(status_code=400, detail="Authorization: Bearer key is required")
        data = build_kit(registry.servers(), decide_url=kit.public_url, key=key, ca_pem=kit.ca_pem)
        return Response(
            data,
            media_type="application/gzip",
            headers={"Content-Disposition": 'attachment; filename="mint-kit.tar.gz"'},
        )

    @router.post("/mint/v1/endpoint/report")
    async def endpoint_report(request: Request, auth: Any = Depends(auth_dependency)) -> dict:
        runtime = runtime_provider()
        if runtime is None:
            raise HTTPException(status_code=503, detail="decision runtime is not ready")
        raw = await _read_limited(request, MAX_BODY_BYTES)
        try:
            report = EndpointReport.model_validate(strict_json(raw))
        except (ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail="invalid report") from exc
        who = principal_factory(auth, instance_id=runtime.config.instance_id)
        line = {
            "ts": time.time(),
            "user_id": who.user_id,
            "team_id": who.team_id,
            "key_id": who.key_id,
            **report.model_dump(),
        }
        with open(kit.reports_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(line) + "\n")
        return {"ok": True, "managed": report.managed}


def install(app: Any, router: APIRouter) -> bool:
    """앱에 결정 경로를 한 번만 붙인다. 이미 붙어 있으면 아무것도 하지 않고 거짓을 돌려준다."""
    if getattr(app.state, "mint_decide_installed", False):
        return False
    app.include_router(router)
    app.state.mint_decide_installed = True
    return True
