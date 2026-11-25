"""SSO(OIDC) 로그인 경로: 인증 서버로 보내고, 돌아온 결과를 검증해 관리자·직원 세션을 연다.

세션과 쿠키는 키 로그인과 같다. 사용자 존재·사람 역할은 제어 평면 키로 LiteLLM에서 읽고(데이터베이스
직접 조회 없음), 직원 세션의 팀도 LiteLLM 사용자 정보에서 읽는다.
"""

import psycopg
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response

from mint_litellm.console import oidc
from mint_litellm.console.cookies import delete_cookie, set_cookie
from mint_litellm.console.core import COOKIE, STAFF_COOKIE, config_of, db, too_many_attempts
from mint_litellm.console.login import LoginRefused
from mint_litellm.console.oidc import login_context
from mint_litellm.console.staff_pages import start_staff_session
from mint_litellm.console.templating import render
from mint_litellm.control import directory, ledger
from mint_litellm.control.db.connection import connect
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.operators import HUMAN_ROLES
from mint_litellm.control.services import console_sessions
from mint_litellm.types.events import EventKind

router = APIRouter()

TOO_MANY = "로그인 시도가 너무 많습니다. 잠시 뒤 다시 시도하십시오."
# 로그인 화면은 하나다. auto는 로그인한 사람의 역할로 관리자·직원 화면을 고른다.
PAGES = {
    "auto": ("login.html", "/login"), "admin": ("login.html", "/login"),
    "staff": ("login.html", "/login"),
}


def _client(request: Request) -> oidc.OidcClient:
    client = request.app.state.oidc
    if client is None:
        raise AdminError(AdminCode.NOT_FOUND, "SSO가 설정되어 있지 않습니다.")
    return client


def _refuse(request: Request, target: str, message: str, status: int) -> Response:
    response = render(request, PAGES[target][0], login_context(request, message), status=status)
    delete_cookie(response, request, oidc.STATE_COOKIE, samesite="lax")
    return response


@router.get("/auth/oidc/login")
def oidc_login(request: Request, target: str = "auto") -> Response:
    client = _client(request)
    target = target if target in PAGES else "auto"
    if too_many_attempts(request):
        return _refuse(request, target, TOO_MANY, 429)
    try:
        return client.begin(request, target)
    except LoginRefused as refused:
        return _refuse(request, target, str(refused), 503)


def human_user(config, user_id: str) -> dict:
    """제어 평면 키로 LiteLLM 사용자를 읽는다. 없거나 사람 역할이 아니면 거부한다."""
    if config.litellm_admin is None:
        raise LoginRefused("로그인 설정이 끝나지 않았습니다. 관리자에게 문의하십시오.")
    try:
        user = config.litellm_admin.get_user(user_id)
    except LiteLLMError:
        raise LoginRefused("LiteLLM에 연결할 수 없습니다. 잠시 뒤 다시 시도하십시오.") from None
    if user is None:
        raise LoginRefused("LiteLLM에 등록된 사용자가 아닙니다.")
    if user.get("user_role") not in HUMAN_ROLES:
        raise LoginRefused("사람 사용자가 아닙니다.")
    return user


def open_session(
    config, conn: psycopg.Connection, target: str, user_id: str, key_token: str, user: dict,
    via: dict,
) -> tuple[str, str]:
    """로그인 수단과 무관하게 관리자·직원 세션을 연다. (쿠키 이름, 세션 식별자)를 돌려준다."""
    directory.record_login(conn, config.instance_id, user_id, key_token, user)
    if target == "admin":
        session_id, _ = console_sessions.create(
            conn, config.instance_id, config.stage2, user_id=user_id, key_token=key_token,
            via=via,
        )
        return COOKIE, session_id
    if not config.staff_database_url:
        raise AdminError(AdminCode.NOT_FOUND, "직원 화면이 설정되어 있지 않습니다.")
    with connect(config.staff_database_url) as staff_conn:
        session_id = start_staff_session(
            config, conn, staff_conn, user_id, key_token, console_sessions.teams_of_user(user),
        )
    ledger.record(
        conn, config.instance_id, EventKind.CONSOLE_SESSION_STARTED,
        entity_id=console_sessions.hash_id("sso:" + session_id), state_version=1,
        actor=user_id, payload={"subject": "staff", **via},
    )
    return STAFF_COOKIE, session_id


def open_sessions(
    config, conn: psycopg.Connection, target: str, user_id: str, key_token: str, user: dict,
    via: dict,
) -> list[tuple[str, str]]:
    """로그인 한 번에 맞는 세션을 연다. auto는 운영자이면 관리자·직원 세션을, 아니면 직원 세션을."""
    if target != "auto":
        return [open_session(config, conn, target, user_id, key_token, user, via)]
    try:
        opened = [open_session(config, conn, "admin", user_id, key_token, user, via)]
    except AdminError as refused:
        if refused.code != AdminCode.FORBIDDEN:
            raise
        return [open_session(config, conn, "staff", user_id, key_token, user, via)]
    try:  # 운영자가 직원 화면 링크를 눌러도 다시 로그인하지 않게 한다
        opened.append(open_session(config, conn, "staff", user_id, key_token, user, via))
    except AdminError:
        pass  # 직원 화면을 쓰지 않는 배포
    return opened


def landing(opened: list[tuple[str, str]]) -> str:
    return "/" if opened[0][0] == COOKIE else "/staff"


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
        target = identity.target if identity.target in PAGES else "auto"
        user = human_user(config, identity.user_id)
        via = {"method": "oidc", "issuer": identity.issuer, "idp_subject": identity.subject}
        opened = open_sessions(
            config, conn, target, identity.user_id, identity.key_token, user, via)
    except LoginRefused as refused:
        return _refuse(request, target, str(refused), 401)
    except AdminError as refused:
        return _refuse(request, target, refused.message, 403)
    response = RedirectResponse(landing(opened), status_code=303)
    for cookie, session_id in opened:
        set_cookie(response, request, cookie, session_id)
    delete_cookie(response, request, oidc.STATE_COOKIE, samesite="lax")
    return response
