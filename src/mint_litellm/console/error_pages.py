"""화면 밖에서 나는 오류를 사이드바가 있는 화면으로 보인다(API 경로는 JSON 그대로)."""

import logging
from urllib.parse import unquote

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from mint_litellm.console.core import COOKIE, Actor, config_of, is_staff_path
from mint_litellm.console.templating import MENU, render
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import connect
from mint_litellm.control.services import console_sessions

log = logging.getLogger(__name__)

TITLES = {
    400: "요청 값이 올바르지 않습니다",
    401: "로그인이 필요합니다",
    403: "이 작업을 할 수 있는 역할이 아닙니다",
    404: "찾을 수 없습니다",
    409: "지금은 처리할 수 없는 상태입니다",
}


def wants_page(request: Request) -> bool:
    """브라우저가 화면을 기대하는 요청인가(API 경로와 JSON 클라이언트는 제외)."""
    path = request.url.path
    if path.startswith(("/api/", "/chat/", "/static/")):
        return False
    return "text/html" in request.headers.get("accept", "") or "hx-request" in request.headers


def _back(request: Request) -> tuple[str, str]:
    """오류가 난 화면이 속한 메뉴로 돌아가는 링크(없으면 대시보드)."""
    path = unquote(request.url.path)
    if is_staff_path(request):
        return "/staff", "내 서버로"
    best = ("/", "대시보드로")
    for _, items in MENU:
        for href, name, _key in items:
            if (
                href != "/"
                and (path == href or path.startswith(href + "/"))
                and len(href) > len(best[0])
            ):
                best = (href, f"{name} 화면으로")
    if path.startswith("/link/"):
        best = ("/approvals", "승인 센터로")
    return best


def _shell(request: Request, context: dict, status: int) -> Response | None:
    """로그인한 운영자에게는 메뉴가 있는 화면으로. 세션을 확인할 수 없으면 None."""
    session_id = request.cookies.get(COOKIE)
    if not session_id or is_staff_path(request):
        return None
    config = config_of(request)
    with connect(config.database_url) as conn:
        info = console_sessions.lookup(conn, config.instance_id, config.stage2, session_id)
        if info is None:
            return None
        operator = Operator(info.operator_name, info.role, info.user_id)
        actor = Actor(
            Context(conn, config.instance_id, operator),
            info,
            session_id,
            config,
            request.state.request_id,
        )
        return render(request, "error.html", context, actor=actor, status=status)


def error_page(
    request: Request, status: int, message: str, reference: str | None = None
) -> Response:
    href, name = _back(request)
    context = {
        "status": status,
        "title": TITLES.get(status, "요청을 처리하지 못했습니다"),
        "message": message,
        "reference": reference or getattr(request.state, "request_id", ""),
        "back_href": href,
        "back_name": name,
    }
    try:
        page = _shell(request, context, status)
    except Exception:  # 메뉴를 그리지 못하면 메뉴 없는 화면으로
        log.exception("오류 화면의 메뉴를 그리지 못했습니다")
        page = None
    if page is None:
        page = render(request, "error_bare.html", context, status=status)
    return page


def error_reply(
    request: Request,
    status: int,
    body: dict,
    headers: dict[str, str] | None = None,
) -> Response:
    """브라우저 요청이면 오류 화면, 아니면 같은 내용의 JSON."""
    if wants_page(request):
        try:
            return error_page(request, status, body.get("message", ""), body.get("reference"))
        except Exception:
            log.exception("오류 화면을 그리지 못했습니다")
    return JSONResponse(body, status_code=status, headers=headers)
