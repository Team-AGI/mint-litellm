"""SSO(OIDC) 로그인 경로: 인증 서버로 보내고, 돌아온 결과를 검증해 관리자·직원 세션을 연다.

세션과 쿠키는 키 로그인과 같다. 사용자 존재·사람 역할은 제어 평면 키로 LiteLLM에서 읽고(데이터베이스
직접 조회 없음), 직원 세션의 팀도 LiteLLM 사용자 정보에서 읽는다.
"""

import psycopg
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response

from mint_litellm.console import oidc
from mint_litellm.console.core import (
    COOKIE,
    COOKIE_OPTIONS,
    STAFF_COOKIE,
    config_of,
    db,
    too_many_attempts,
)
from mint_litellm.console.login import LoginRefused
from mint_litellm.console.oidc import login_context
from mint_litellm.console.staff_pages import start_staff_session
from mint_litellm.console.templating import render
from mint_litellm.control import ledger
from mint_litellm.control.db.connection import connect
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.operators import HUMAN_ROLES
from mint_litellm.control.services import console_sessions
from mint_litellm.types.events import EventKind

router = APIRouter()

TOO_MANY = "로그인 시도가 너무 많습니다. 잠시 뒤 다시 시도하십시오."
PAGES = {"admin": ("login.html", "/login"), "staff": ("staff_login.html", "/staff/login")}


def _client(request: Request) -> oidc.OidcClient:
    client = request.app.state.oidc
    if client is None:
        raise AdminError(AdminCode.NOT_FOUND, "SSO가 설정되어 있지 않습니다.")
    return client


def _refuse(request: Request, target: str, message: str, status: int) -> Response:
    response = render(request, PAGES[target][0], login_context(request, message), status=status)
    response.delete_cookie(oidc.STATE_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response


@router.get("/auth/oidc/login")
def oidc_login(request: Request, target: str = "admin") -> Response:
    client = _client(request)
    target = target if target in PAGES else "admin"
    if too_many_attempts(request):
        return _refuse(request, target, TOO_MANY, 429)
    try:
        return client.begin(request, target)
    except LoginRefused as refused:
        return _refuse(request, target, str(refused), 503)


def _human_user(config, user_id: str) -> dict:
    """제어 평면 키로 LiteLLM 사용자를 읽는다. 없거나 사람 역할이 아니면 거부한다."""
    if config.litellm_admin is None:
        raise LoginRefused("SSO 로그인에는 제어 평면 키(MINT_LITELLM_KEY)가 필요합니다.")
    try:
        user = config.litellm_admin.get_user(user_id)
    except LiteLLMError:
        raise LoginRefused("LiteLLM에 연결할 수 없습니다. 잠시 뒤 다시 시도하십시오.") from None
    if user is None:
        raise LoginRefused("LiteLLM에 등록된 사용자가 아닙니다.")
    if user.get("user_role") not in HUMAN_ROLES:
        raise LoginRefused("사람 사용자가 아닙니다.")
    return user


@router.get("/auth/oidc/callback")
def oidc_callback(
    request: Request, code: str = "", state: str = "", error: str = "",
    conn: psycopg.Connection = Depends(db),
) -> Response:
    client = _client(request)
    config = config_of(request)
    target = oidc.saved_target(request)
    if too_many_attempts(request):
        return _refuse(request, target, TOO_MANY, 429)
    try:
        if error:
            raise LoginRefused("SSO 서버가 로그인을 허용하지 않았습니다.")
        identity = client.finish(request, code, state)
        target = identity.target if identity.target in PAGES else "admin"
        user = _human_user(config, identity.user_id)
        via = {"method": "oidc", "issuer": identity.issuer, "idp_subject": identity.subject}
        if target == "admin":
            session_id, _ = console_sessions.create(
                conn, config.instance_id, config.stage2, user_id=identity.user_id,
                key_token=identity.key_token, via=via,
            )
            cookie = COOKIE
        else:
            if not config.staff_database_url:
                raise AdminError(AdminCode.NOT_FOUND, "직원 화면이 설정되어 있지 않습니다.")
            with connect(config.staff_database_url) as staff_conn:
                session_id = start_staff_session(
                    config, conn, staff_conn, identity.user_id, identity.key_token,
                    console_sessions.teams_of_user(user),
                )
            ledger.record(
                conn, config.instance_id, EventKind.CONSOLE_SESSION_STARTED,
                entity_id=console_sessions.hash_id("sso:" + session_id), state_version=1,
                actor=identity.user_id, payload={"subject": "staff", **via},
            )
            cookie = STAFF_COOKIE
    except LoginRefused as refused:
        return _refuse(request, target, str(refused), 401)
    except AdminError as refused:
        return _refuse(request, target, refused.message, 403)
    response = RedirectResponse("/" if target == "admin" else "/staff", status_code=303)
    response.set_cookie(cookie, session_id, **COOKIE_OPTIONS)
    response.delete_cookie(oidc.STATE_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response
