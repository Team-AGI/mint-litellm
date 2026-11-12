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
import re
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from mint_litellm.compat.litellm_1_106 import HookData
from mint_litellm.endpoint.routes import DECIDE_PATH, REPORT_PATH, RESULT_PATH
from mint_litellm.plugin.pipeline import CallRequest, build_request, evaluate_request
from mint_litellm.plugin.result import observe_response, observe_unknown_outcome
from mint_litellm.types.decision import OperationType
from mint_litellm.types.exec_contract import ExecContract
from mint_litellm.types.identity import Principal

log = logging.getLogger("mint_litellm.endpoint")

MAX_BODY_BYTES = 64 * 1024
_REFERENCE = re.compile(r"^([0-9a-f-]{36}):([1-9][0-9]{0,8})$")


class DecideBody(BaseModel):
    """훅이 보내는 결정 요청. 사용자·조직·키 필드는 두지 않는다(알 수 없는 필드는 거부)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    server: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    contract: ExecContract
    tool_use_id: str | None = Field(default=None, max_length=128)


class ResultBody(BaseModel):
    """호출 뒤 훅이 보내는 결과 보고. 결과 본문은 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reference: str = Field(pattern=_REFERENCE.pattern)
    # unknown: 훅이 도구가 실행됐는지 모른다고 보고(중단·시간 초과 등)
    outcome: Literal["success", "error", "unknown"]
    size_bytes: int | None = Field(default=None, ge=0, le=2**40)


class ReportBody(BaseModel):
    """설치 묶음이 설치·제거를 마치고 보내는 상태 보고. 파일 경로나 키는 받지 않는다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kit_version: str = Field(min_length=1, max_length=128)
    action: Literal["installed", "removed"]
    mode: Literal["managed", "user", "none"]
    claude_version: str | None = Field(default=None, max_length=64)
    mcp_servers: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=64
    )

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
        )

    return build_request(
        {},
        auth,
        operation=OperationType.TOOL_CALL,
        instance_id=instance_id,
        hook_parser=parse,
        # 서버 행과의 대조는 판정 단계의 상태 검사가 한다(등록 안 됨·종류 다름·계약 다름 모두 차단).
        resolver=lambda _hook: body.contract.resolved(body.server),
        principal_factory=principal_factory,
    )


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
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail="request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _body(request: Request, model: type[BaseModel]) -> Any:
    raw = await _read_limited(request, MAX_BODY_BYTES)
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

    def ready() -> Any:
        runtime = runtime_provider()
        if runtime is None:
            raise HTTPException(status_code=503, detail="decision runtime is not ready")
        return runtime

    @router.post(DECIDE_PATH)
    async def decide(request: Request, auth: Any = Depends(auth_dependency)) -> dict[str, Any]:
        runtime = ready()
        body = await _body(request, DecideBody)
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
            found = who.key_id is not None and await runtime.database.report_install(
                runtime.config.instance_id,
                who.key_id,
                mode=body.install_mode(),
                kit_version=body.kit_version,
                claude_version=body.claude_version,
                mcp_servers=body.mcp_servers,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="install store is not ready") from exc
        if not found:
            raise HTTPException(status_code=404, detail="no such kit key")
        return {"recorded": True}

    return router


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
