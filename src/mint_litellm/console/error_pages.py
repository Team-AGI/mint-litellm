"""화면 밖에서 나는 오류를 사이드바가 있는 화면으로 보인다(API 경로는 JSON 그대로)."""

import logging
from urllib.parse import unquote

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from mint_litellm.console import labels
from mint_litellm.console.core import (
    COOKIE,
    Actor,
    _particle,
    config_of,
    is_staff_path,
    read_cookie,
)
from mint_litellm.console.templating import MENU, is_root, render
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import connect
from mint_litellm.control.errors import AdminCode
from mint_litellm.control.services import console_sessions, reads

log = logging.getLogger(__name__)

TITLES = {
    400: "요청 값이 올바르지 않습니다",
    401: "로그인이 필요합니다",
    403: "이 작업을 할 수 있는 역할이 아닙니다",
    404: "찾을 수 없습니다",
    405: "지원하지 않는 요청입니다",
    409: "지금은 처리할 수 없는 상태입니다",
    500: "시스템 오류가 났습니다",
    503: "지금은 처리할 수 없습니다",
}
# 403이어도 역할·규칙이 막은 것이 아닌 문구(화면이 낡았거나 출처를 확인하지 못함)
NOT_POLICY = ("요청을 확인할 수 없습니다", "다른 출처에서 보낸 요청")
RULES = {
    AdminCode.SEPARATION_OF_DUTIES: "직무 분리: 같은 사람이 요청과 승인을 함께 할 수 없습니다",
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


def _area(request: Request) -> tuple[str, str]:
    """요청 경로가 속한 메뉴 이름과 그 아래 대상 식별자(없으면 빈 문자열)."""
    path = unquote(request.url.path)
    best = ("", "", "")
    for _, items in MENU:
        for href, name, _key in items:
            if href != "/" and (path == href or path.startswith(href + "/")) and len(href) > len(
                best[0]
            ):
                best = (href, name, path[len(href):].strip("/").split("/")[0])
    return best[1], best[2]


def _required_role(message: str) -> str:
    """거부 문구에서 필요한 역할 이름을 읽는다(문구에 없으면 일반 표현)."""
    if "관리자" in message:
        return "관리자"
    if "승인자" in message:
        return "승인자"
    return "권한이 있는 운영자"


def _frame(request: Request, status: int, message: str, reference: str, code: str | None) -> dict:
    """오류 화면의 내용. 403은 거부 화면, 400·404·5xx는 오류 화면, 나머지는 단순 틀이다."""
    href, name = _back(request)
    title = TITLES.get(status, "요청을 처리하지 못했습니다")
    if status == 403 and message.startswith(NOT_POLICY):
        title = "요청을 확인하지 못했습니다"
    if message.rstrip(". ") == title.rstrip(". "):  # 제목과 같은 문장은 되풀이하지 않는다
        message = ""
    frame = {
        "status": status, "title": title, "message": message, "reference": reference,
        "back_href": href, "back_name": name, "kind": "plain",
    }
    area, target = _area(request)
    if status == 403 and not message.startswith(NOT_POLICY):
        role = _required_role(message)
        frame.update(
            kind="denied", required_role=role, grantors=[],
            title=f"이 작업은 {role}{_particle(role, '이')} 할 수 있습니다",
            rule=RULES.get(code or "", "역할별 권한 규칙"),
            scope=" · ".join(x for x in (area or "콘솔", target) if x),
            role_label="로그인하지 않음",
        )
    elif status in (400, 403, 404, 405, 500, 503):
        verb = "화면을 여는" if request.method == "GET" else "요청을 처리하는"
        frame.update(
            kind="failed", doing=f"{area or '콘솔'}에서 {verb} 중이었습니다",
            retry_href=request.url.path + (f"?{request.url.query}" if request.url.query else "")
            if request.method == "GET" else None,
        )
    return frame


def _request_text(frame: dict, who: str, role: str) -> str:
    return (
        f"[MINT 권한 요청] {who}({role})이(가) 「{frame['scope']}」 작업을 하려 했으나 막혔습니다. "
        f"필요 역할: {frame['required_role']}. 참조 번호 {frame['reference']}. "
        "권한을 주시거나 대신 처리해 주십시오."
    )


def _shell(request: Request, frame: dict, status: int) -> Response | None:
    """로그인한 운영자에게는 메뉴가 있는 화면으로. 세션을 확인할 수 없으면 None."""
    session_id = read_cookie(request, COOKIE)
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
        if frame["kind"] == "denied":
            role = "Root" if is_root(actor) else labels.pick(labels.ROLE, actor.role)
            frame["role_label"] = f"{info.operator_name} · {role}"
            need = {"관리자": ("admin",), "승인자": ("admin", "approver")}.get(
                frame["required_role"], ("admin",)
            )
            frame["grantors"] = [
                o["name"] for o in reads.operators(conn, config.instance_id) if o["role"] in need
            ][:5]
            frame["request_text"] = _request_text(frame, info.operator_name, role)
        return render(request, "error.html", {"frame": frame}, actor=actor, status=status)


def error_page(
    request: Request, status: int, message: str, reference: str | None = None,
    code: str | None = None,
) -> Response:
    reference = reference or getattr(request.state, "request_id", "")
    frame = _frame(request, status, message, reference, code)
    if status == 401:
        frame.update(back_href="/login", back_name="로그인 화면으로")
    if frame["kind"] == "denied":
        frame["request_text"] = _request_text(frame, "로그인 전 사용자", "역할 없음")
    try:
        page = _shell(request, frame, status)
    except Exception:  # 메뉴를 그리지 못하면 메뉴 없는 화면으로
        log.exception("오류 화면의 메뉴를 그리지 못했습니다")
        page = None
    if page is None:
        page = render(request, "error_bare.html", {"frame": frame}, status=status)
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
            return error_page(
                request, status, body.get("message", ""), body.get("reference"), body.get("code")
            )
        except Exception:
            log.exception("오류 화면을 그리지 못했습니다")
    return JSONResponse(body, status_code=status, headers=headers)
