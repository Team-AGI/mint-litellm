"""「LiteLLM 콘솔」 버튼: MINT 로그인 한 번으로 본인 LiteLLM 화면을 연다.

버튼은 로그인한 세션에 묶인 1회용 인계 코드(60초, SHA-256만 저장)를 만들어 LiteLLM 안의 어댑터
(``/mint-ui/enter``)로 보낸다. 어댑터는 서버 간 서명 호출로 코드를 소비해 누구의 세션인지 받고,
그 사용자의 현재 LiteLLM 역할로 화면 세션을 열어 ``token`` 쿠키를 심는다.
콘솔 쿠키는 ``__Host-mint_*``라 LiteLLM의 ``token`` 쿠키와 겹치지 않는다.
비밀번호·키·SSO로 연 세션 모두 같은 길이다.
MINT 로그아웃·세션 만료 때는 그 세션으로 열린 LiteLLM 화면 세션을 어댑터에 서명 호출로 지운다.
"""

import hashlib
import json
import logging
import secrets
from urllib.parse import quote, urlsplit

import psycopg
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from mint_litellm.console.core import Actor, ConsoleConfig, config_of, db, page_actor
from mint_litellm.console.staff_pages import StaffActor, staff_actor
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.types import ui_handoff

log = logging.getLogger(__name__)

router = APIRouter()
# 서버 간 호출. 세션 쿠키가 아니라 서명으로 인증하므로 CSRF 검사 밖에 둔다.
internal = APIRouter()


def ui_origin(config: ConsoleConfig) -> str | None:
    """LiteLLM이 브라우저에 공개된 주소(MINT_LITELLM_UI_URL에서 경로를 뗀 것)."""
    if not config.litellm_ui_url:
        return None
    parts = urlsplit(config.litellm_ui_url)
    return f"{parts.scheme}://{parts.netloc}"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def issue(conn: psycopg.Connection, config: ConsoleConfig, session_hash: str, user_id: str) -> str:
    """세션에 묶인 인계 코드를 만들어 어댑터 주소를 돌려준다."""
    origin = ui_origin(config)
    if origin is None:
        raise AdminError(AdminCode.NOT_FOUND, "LiteLLM 콘솔 주소가 설정되어 있지 않습니다.")
    code = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO mint.ui_handoffs (code_hash, instance_id, session_hash, user_id, expires_at)"
        " VALUES (%s, %s, %s, %s, now() + make_interval(secs => %s))",
        (_hash(code), config.instance_id, session_hash, user_id, ui_handoff.CODE_SECONDS),
    )
    return f"{origin}{ui_handoff.ENTER_PATH}?code={quote(code)}"


def _go(request: Request, conn: psycopg.Connection, session_hash: str, user_id: str) -> Response:
    # 다른 사이트가 연 이동에는 쿠키가 실리지 않지만(Strict) 헤더로도 한 번 더 막는다.
    if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        raise AdminError(AdminCode.FORBIDDEN, "다른 출처에서 보낸 요청입니다.")
    target = issue(conn, config_of(request), session_hash, user_id)
    return RedirectResponse(target, status_code=303)


@router.get("/litellm/open")
def open_admin(
    request: Request, actor: Actor = Depends(page_actor), conn: psycopg.Connection = Depends(db)
) -> Response:
    return _go(request, conn, actor.session.id_hash, actor.session.user_id)


@router.get("/staff/litellm/open")
def open_staff(
    request: Request, actor: StaffActor = Depends(staff_actor),
    conn: psycopg.Connection = Depends(db),
) -> Response:
    return _go(request, conn, actor.id_hash, actor.user_id)


async def _raw_body(request: Request) -> bytes:
    return await request.body()


@internal.post(ui_handoff.REDEEM_PATH, include_in_schema=False)
def redeem(
    request: Request, body: bytes = Depends(_raw_body), conn: psycopg.Connection = Depends(db)
) -> Response:
    """어댑터가 코드를 소비한다. 유효한 세션에 묶인 미사용·미만료 코드만 한 번 받아들인다."""
    config = config_of(request)
    if not ui_handoff.verify(
        config.stage2.export_hmac_key, ui_handoff.REDEEM_PATH, body, dict(request.headers)
    ):
        return JSONResponse({"error": "invalid signature"}, status_code=403)
    try:
        code = json.loads(body)["code"]
        if not isinstance(code, str) or not code:
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return JSONResponse({"error": "invalid request"}, status_code=400)
    row = fetchone(
        conn,
        "UPDATE mint.ui_handoffs h SET consumed_at = now()"
        " WHERE h.code_hash = %s AND h.instance_id = %s AND h.consumed_at IS NULL"
        " AND h.expires_at > now() AND EXISTS (SELECT 1 FROM mint.console_sessions s"
        "  WHERE s.id_hash = h.session_hash AND s.instance_id = h.instance_id"
        "  AND s.user_id = h.user_id AND s.revoked_at IS NULL AND s.idle_expiry > now()"
        "  AND s.absolute_expiry > now())"
        " RETURNING h.session_hash, h.user_id,"
        "  (SELECT EXTRACT(EPOCH FROM s.absolute_expiry - now()) FROM mint.console_sessions s"
        "   WHERE s.id_hash = h.session_hash) AS seconds_left",
        (_hash(code), config.instance_id),
    )
    if row is None:
        return JSONResponse({"error": "unknown or used code"}, status_code=404)
    return JSONResponse(
        {"user_id": row["user_id"], "session_hash": row["session_hash"],
         "seconds_left": int(row["seconds_left"])},
        headers={"Cache-Control": "no-store"},
    )
