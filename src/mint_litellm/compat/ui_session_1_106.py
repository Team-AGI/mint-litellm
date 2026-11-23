"""MINT 콘솔에서 넘어온 사람에게 LiteLLM 1.106.6 화면 세션을 열어 주는 어댑터.

LiteLLM 프록시 안에 두 경로를 붙인다. ``GET /mint-ui/enter?code=``는 콘솔이 만든
1회용 인계 코드를 서명 호출로 소비해 누구의 세션인지 받고, 그 사용자의 LiteLLM
행 역할로 화면 세션 키를 만들어 ``token`` 쿠키와 함께 ``/ui``로 보낸다(비밀번호
로그인·SSO가 쓰는 것과 같은 함수, 같은 JWT 모양). 마스터 키는 프록시 안에서만
쓰이고 콘솔에 전달되지 않는다. ``POST /mint-ui/revoke``는 콘솔의 서명 호출로 MINT
세션에서 연 화면 세션 키를 지운다. LiteLLM 비공개 심볼은 모두 ``LiteLLMBackend``에
있고 호출 시점에 가져온다.
"""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Mapping
from typing import Any, Protocol

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from mint_litellm.types import ui_handoff
from mint_litellm.types.fingerprint import decode_fingerprint_key

log = logging.getLogger("mint_litellm.ui_session")

DASHBOARD_TEAM = "litellm-dashboard"
ALIAS_PREFIX = "mint-ui-"
ENV_CONSOLE_URL = "MINT_CONSOLE_INTERNAL_URL"
DEFAULT_CONSOLE_URL = "http://console:8080"
ENV_KEY = "MINT_EXPORT_HMAC_KEY"
ENV_SWITCH = "MINT_UI_HANDOFF"
# 사람으로 인정하는 LiteLLM 역할(콘솔 쪽 운영자 등록과 같은 집합)
HUMAN_ROLES = frozenset(
    {"proxy_admin", "proxy_admin_viewer", "internal_user", "internal_user_viewer", "org_admin"}
)


class Backend(Protocol):
    async def find_user(self, user_id: str) -> dict[str, Any] | None: ...

    async def open_session(
        self, request: Request, user: dict[str, Any], session_hash: str, seconds: int
    ) -> Response: ...

    async def delete_sessions(self, session_hash: str) -> int: ...

    async def count_sessions(self, session_hash: str) -> int: ...


class LiteLLMBackend:
    """LiteLLM 1.106.6의 화면 로그인 함수를 그대로 쓴다(``/v2/login``·SSO 콜백과 같은 경로)."""

    @staticmethod
    def _server() -> Any:
        import importlib

        return importlib.import_module("litellm.proxy.proxy_server")

    async def find_user(self, user_id: str) -> dict[str, Any] | None:
        client = self._server().prisma_client
        if client is None:
            return None
        row = await client.db.litellm_usertable.find_unique(where={"user_id": user_id})
        if row is None:
            return None
        return {"user_id": row.user_id, "user_email": row.user_email, "user_role": row.user_role}

    async def open_session(
        self, request: Request, user: dict[str, Any], session_hash: str, seconds: int
    ) -> Response:
        import litellm
        from fastapi.responses import RedirectResponse
        from litellm.constants import LITELLM_UI_SESSION_DURATION
        from litellm.litellm_core_utils.duration_parser import duration_in_seconds
        from litellm.proxy.auth.login_utils import (
            LoginResult,
            create_ui_token_object,
            encode_ui_session_jwt,
        )
        from litellm.proxy.management_endpoints.key_management_endpoints import (
            generate_key_helper_fn,
        )
        from litellm.proxy.management_endpoints.sso_helper_utils import (
            check_is_admin_only_access,
            has_admin_ui_access,
        )
        from litellm.proxy.management_endpoints.ui_sso import set_session_token_cookie
        from litellm.proxy.utils import get_custom_url

        server = self._server()
        role = user["user_role"]
        mode = server.general_settings.get("ui_access_mode")
        if check_is_admin_only_access(mode or {}) and not has_admin_ui_access(role):
            raise HTTPException(status_code=403, detail="LiteLLM 화면은 관리자만 쓸 수 있습니다.")
        duration = min(seconds, duration_in_seconds(LITELLM_UI_SESSION_DURATION))
        created = await generate_key_helper_fn(
            llm_router=None, request_type="key", user_role=role, duration=f"{duration}s",
            key_max_budget=litellm.max_ui_session_budget, spend=0, user_id=user["user_id"],
            team_id=DASHBOARD_TEAM, table_name="key",
            key_alias=f"{ALIAS_PREFIX}{session_hash}-{secrets.token_hex(4)}",
        )
        login = LoginResult(
            user_id=user["user_id"], key=created["token"], user_email=user["user_email"],
            user_role=role, login_method="sso",
        )
        token = create_ui_token_object(
            login_result=login, general_settings=server.general_settings,
            premium_user=server.premium_user,
        )
        jwt = encode_ui_session_jwt(token, server.master_key or "")
        target = get_custom_url(str(request.base_url), route="ui/") + "?login=success"
        response = RedirectResponse(target, status_code=303)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        set_session_token_cookie(response, request, jwt)
        return response

    async def count_sessions(self, session_hash: str) -> int:
        client = self._server().prisma_client
        if client is None:
            raise HTTPException(status_code=503, detail="database not connected")
        return await client.db.litellm_verificationtoken.count(
            where={"team_id": DASHBOARD_TEAM,
                   "key_alias": {"startswith": ALIAS_PREFIX + session_hash}}
        )

    async def delete_sessions(self, session_hash: str) -> int:
        from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
        from litellm.proxy.management_endpoints.key_management_endpoints import (
            delete_verification_tokens,
        )

        server = self._server()
        client = server.prisma_client
        if client is None:
            raise HTTPException(status_code=503, detail="database not connected")
        rows = await client.db.litellm_verificationtoken.find_many(
            where={
                "team_id": DASHBOARD_TEAM,
                "key_alias": {"startswith": ALIAS_PREFIX + session_hash},
            }
        )
        tokens = [r.token for r in rows if r.token]
        if not tokens:
            return 0
        await delete_verification_tokens(
            tokens=tokens, user_api_key_cache=server.user_api_key_cache,
            user_api_key_dict=UserAPIKeyAuth(user_role=LitellmUserRoles.PROXY_ADMIN),
        )
        return len(tokens)


def make_router(
    backend: Backend, key: bytes, console_url: str, *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> APIRouter:
    router = APIRouter()

    async def redeem(code: str) -> dict[str, Any] | None:
        body = json.dumps({"code": code}).encode()
        headers = {**ui_handoff.sign(key, ui_handoff.REDEEM_PATH, body),
                   "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
                reply = await client.post(
                    f"{console_url.rstrip('/')}{ui_handoff.REDEEM_PATH}", content=body,
                    headers=headers,
                )
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="MINT 콘솔에 연결할 수 없습니다.") from None
        if reply.status_code == 404:
            return None
        if reply.status_code != 200:
            raise HTTPException(status_code=503, detail="MINT 콘솔이 코드를 처리하지 못했습니다.")
        return reply.json()

    @router.get(ui_handoff.ENTER_PATH, include_in_schema=False)
    async def enter(request: Request, code: str = "") -> Response:
        grant = await redeem(code) if code else None
        if grant is None:
            raise HTTPException(status_code=403, detail="인계 코드가 올바르지 않거나 사용했습니다.")
        user = await backend.find_user(grant["user_id"])
        if user is None or user.get("user_role") not in HUMAN_ROLES:
            raise HTTPException(status_code=403, detail="LiteLLM 사용자를 확인할 수 없습니다.")
        return await backend.open_session(
            request, user, grant["session_hash"], max(int(grant["seconds_left"]), 1)
        )

    async def signed_session_hash(request: Request, path: str) -> str | Response:
        body = await request.body()
        if not ui_handoff.verify(key, path, body, dict(request.headers)):
            return JSONResponse({"error": "invalid signature"}, status_code=403)
        try:
            session_hash = json.loads(body)["session_hash"]
            if not isinstance(session_hash, str) or len(session_hash) != 64:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"error": "invalid request"}, status_code=400)
        return session_hash

    @router.post(ui_handoff.REVOKE_PATH, include_in_schema=False)
    async def revoke(request: Request) -> Response:
        got = await signed_session_hash(request, ui_handoff.REVOKE_PATH)
        if isinstance(got, Response):
            return got
        return JSONResponse({"deleted": await backend.delete_sessions(got)})

    @router.post(ui_handoff.ALIVE_PATH, include_in_schema=False)
    async def alive(request: Request) -> Response:
        """LiteLLM 화면에서 로그아웃하면 화면 세션 키가 지워진다. 남은 개수를 콘솔에 알린다."""
        got = await signed_session_hash(request, ui_handoff.ALIVE_PATH)
        if isinstance(got, Response):
            return got
        return JSONResponse({"open": await backend.count_sessions(got)})

    return router


def install_from_env(app: Any, env: Mapping[str, str]) -> bool:
    """서명 키가 있고 끄지 않았으면 어댑터 경로를 LiteLLM 앱에 한 번만 붙인다."""
    if env.get(ENV_SWITCH, "on").strip().lower() in ("0", "off", "false", "no"):
        return False
    raw = (env.get(ENV_KEY) or "").strip()
    if not raw or getattr(app.state, "mint_ui_session_installed", False):
        return False
    router = make_router(
        LiteLLMBackend(), decode_fingerprint_key(raw),
        (env.get(ENV_CONSOLE_URL) or DEFAULT_CONSOLE_URL).strip(),
    )
    app.include_router(router)
    app.state.mint_ui_session_installed = True
    return True
