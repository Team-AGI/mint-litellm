"""아이디·비밀번호 로그인: LiteLLM 관리 화면과 같은 자격으로 들어온다.

비밀번호는 콘솔이 LiteLLM의 화면 로그인 API(``POST /v2/login``)에 서버에서 서버로 그대로 넘기고,
저장하지도 기록하지도 않는다. 응답의 화면 토큰은 LiteLLM이 같은 연결로 직접 돌려준 값이므로
서명을 다시 확인하지 않고(콘솔에는 마스터 키가 없다) 사용자 식별자와 상태 확인용 클레임만 읽는다.
그 사용자가 사람인지는 제어 평면 키로 ``/user/info``를 다시 읽어 확인하고, 관리자 콘솔은 운영자
행이 있어야 열린다.
"""

import base64
import hashlib
import json

import httpx
import psycopg
from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from mint_litellm.console.cookies import DEFAULT_PASSWORD, set_cookie
from mint_litellm.console.core import config_of, too_many_attempts
from mint_litellm.console.login import LoginRefused
from mint_litellm.console.oidc import login_context
from mint_litellm.console.sso_pages import PAGES, TOO_MANY, human_user, landing, open_sessions
from mint_litellm.console.templating import render
from mint_litellm.control import default_admin, signup
from mint_litellm.control.errors import AdminError
from mint_litellm.control.services import console_sessions

UNAVAILABLE = "LiteLLM에 연결할 수 없습니다. 잠시 뒤 다시 시도하십시오."
WRONG = "아이디 또는 비밀번호가 올바르지 않습니다."
# 환경 변수 계정(UI_USERNAME·마스터 키)의 사용자 식별자. 사람 행이 아니다.
ENV_ADMIN_ID = "default_user_id"


def _claims(token: object) -> dict:
    """화면 토큰(JWT)의 본문. 서명은 확인하지 않는다(모듈 설명 참고)."""
    try:
        body = str(token).split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (IndexError, ValueError):
        raise LoginRefused("LiteLLM 응답을 해석할 수 없습니다.") from None
    if not isinstance(claims, dict):
        raise LoginRefused("LiteLLM 응답을 해석할 수 없습니다.")
    return claims


def login_claims(
    litellm_url: str, username: str, password: str, client_host: str = "", wrong: str = WRONG
) -> dict:
    """받아들인 아이디·비밀번호이면 화면 토큰의 클레임을, 아니면 ``LoginRefused``를 낸다."""
    username = username.strip()
    if not username or not password:
        raise LoginRefused("아이디와 비밀번호를 입력하십시오.")
    # LiteLLM은 실패를 주소별로 세므로 실제 접속 주소를 알려 준다(신뢰하도록 설정한 때만 쓰인다).
    headers = {"X-Forwarded-For": client_host} if client_host else {}
    try:
        response = httpx.post(
            f"{litellm_url.rstrip('/')}/v2/login",
            headers=headers,
            timeout=10.0,
            json={"username": username, "password": password},
        )
    except httpx.HTTPError:
        raise LoginRefused(UNAVAILABLE) from None
    if response.status_code == 429:
        raise LoginRefused(TOO_MANY)
    if response.status_code == 403:
        raise LoginRefused("LiteLLM이 비밀번호 로그인을 막아 두었습니다. SSO로 로그인하십시오.")
    if response.status_code != 200:
        raise LoginRefused(wrong)
    try:
        return _claims(response.json().get("token"))
    except (ValueError, AttributeError):
        raise LoginRefused("LiteLLM 응답을 해석할 수 없습니다.") from None


def verify(litellm_url: str, username: str, password: str, client_host: str = "") -> str:
    """LiteLLM이 받아들인 아이디·비밀번호이면 사용자 식별자를, 아니면 ``LoginRefused``를 낸다."""
    claims = login_claims(litellm_url, username, password, client_host)
    user_id = claims.get("user_id")
    if not isinstance(user_id, str) or not user_id:
        raise LoginRefused("LiteLLM 응답을 해석할 수 없습니다.")
    # 환경 변수 관리자 계정은 이름 있는 사람이 아니어서 책임자 분리와 감사에 쓸 수 없다.
    if user_id == ENV_ADMIN_ID or not claims.get("user_email"):
        raise LoginRefused(
            "환경 변수 관리자(마스터 키) 계정으로는 들어올 수 없습니다. 이름이 있는 관리자 "
            "계정으로 로그인하십시오."
        )
    if claims.get("password_reset_required"):
        raise LoginRefused("LiteLLM 관리 화면에서 비밀번호를 먼저 바꾼 뒤 로그인하십시오.")
    return user_id


def sign_in(
    request: Request, conn: psycopg.Connection, target: str, username: str, password: str
) -> Response:
    """아이디·비밀번호 제출을 처리해 세션을 열거나 거부 화면을 돌려준다."""
    config = config_of(request)

    def refuse(message: str, status: int) -> Response:
        return render(request, PAGES[target][0], login_context(request, message), status=status)

    if too_many_attempts(request):
        return refuse(TOO_MANY, 429)
    host = request.client.host if request.client else ""
    first = default_admin.is_default(username, password)
    try:
        user_id = verify(config.litellm_url, username, password, host)
        user = human_user(config, user_id)
        token = hashlib.sha256(f"{config.litellm_url}\0{user_id}".encode()).hexdigest()
        opened = open_sessions(
            config,
            conn,
            target,
            user_id,
            console_sessions.PASSWORD_PREFIX + token,
            user,
            {"method": "password"},
        )
    except LoginRefused as refused:
        hint = signup.login_hint(conn, config.instance_id, username)
        return refuse(hint or str(refused), 401)
    except AdminError as refused:
        return refuse(refused.message, 403)
    finally:
        password = ""  # 비밀번호는 여기서 버린다
    response = RedirectResponse(landing(opened), status_code=303)
    for cookie, session_id in opened:
        set_cookie(response, request, cookie, session_id)
    if first:
        set_cookie(response, request, DEFAULT_PASSWORD, "1")
    return response


REJECTED = (
    "새 비밀번호를 받아들이지 않았습니다. 더 길고 복잡하게 정하십시오. "
    "다른 곳에서 유출된 비밀번호도 쓸 수 없습니다."
)


def change_password(
    litellm_url: str, email: str, current: str, new: str, client_host: str = ""
) -> None:
    """현재 비밀번호로 LiteLLM에 로그인해 받은 키로 비밀번호를 바꾼다. 실패하면 ``LoginRefused``."""
    claims = login_claims(
        litellm_url, email, current, client_host, "현재 비밀번호가 올바르지 않습니다."
    )
    key = claims.get("key")
    if not isinstance(key, str) or not key:
        raise LoginRefused("LiteLLM 응답을 해석할 수 없습니다.")
    try:
        response = httpx.post(
            f"{litellm_url.rstrip('/')}/user/password/change",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10.0,
            json={"current_password": current, "new_password": new},
        )
    except httpx.HTTPError:
        raise LoginRefused(UNAVAILABLE) from None
    if response.status_code in (400, 422):
        raise LoginRefused(REJECTED)
    if response.status_code == 401:
        raise LoginRefused("현재 비밀번호가 올바르지 않습니다.")
    if response.status_code != 200:
        raise LoginRefused("LiteLLM이 비밀번호 변경을 처리하지 못했습니다.")


def has_password(key_token: str) -> bool:
    """LiteLLM 아이디·비밀번호로 연 세션인가(키·SSO 세션에는 바꿀 비밀번호가 없다)."""
    return key_token.startswith(console_sessions.PASSWORD_PREFIX)


NO_ACCOUNT = "LiteLLM 계정 비밀번호가 없습니다."


def submit(request: Request, user_id: str, key_token: str, current: str, new: str, again: str):
    """폼 제출 처리. (오류 문구 또는 None, 상태 코드). 평문은 저장·기록하지 않는다."""
    config = config_of(request)
    if not has_password(key_token):
        return NO_ACCOUNT, 409
    if new != again:
        return "새 비밀번호와 확인이 다릅니다.", 400
    if new == current:
        return "현재 비밀번호와 다른 비밀번호를 입력하십시오.", 400
    if too_many_attempts(request):
        return TOO_MANY, 429
    host = request.client.host if request.client else ""
    try:
        user = human_user(config, user_id)
        email = user.get("user_email")
        if not email:
            return NO_ACCOUNT, 409
        change_password(config.litellm_url, email, current, new, host)
    except LoginRefused as refused:
        return str(refused), 400
    return None, 200
