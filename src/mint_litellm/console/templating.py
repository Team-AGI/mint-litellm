"""Jinja2 환경과 화면 공통 맥락(메뉴, 표시 시각, 상태 표시)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from mint_litellm.console import labels, setup_state
from mint_litellm.console.cookies import DEFAULT_PASSWORD, read_cookie
from mint_litellm.console.core import DEFAULT_TIME_ZONE, can, can_attach
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.services import reads
from mint_litellm.plugin.policy.sensitive_scan import mask_text
from mint_litellm.types.contracts import ACTION_DENIAL_PREFIX

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")

# (그룹 이름, ((경로, 이름, 배지 키), ...)). 그룹 이름이 None이면 구분선 없이 맨 위에 둔다.
# 순서·이름은 새 정보 구조(B.2)를 따른다. 「시작하기」는 필수 항목이 남았을 때만 맨 위에 보인다.
MENU = (
    (None, (("/", "대시보드", None), ("/setup", "시작하기", "setup"))),
    ("처리할 일", (("/approvals", "승인 센터", "approvals"), ("/alerts", "경보", "alerts"))),
    ("MCP 서버", (("/servers", "MCP 서버", "servers"), ("/intakes", "도입 신청", "intakes"),
            ("/access", "접근 통제", None), ("/builtin-tools", "하네스 기본 기능", None))),
    ("사람·단말", (("/people", "사람", None), ("/endpoints", "단말", "endpoints"),
               ("/signup-requests", "가입 요청", "signup"))),
    ("감사", (("/ledger", "호출 기록", None), ("/reports/audit", "감사 보고서", None),
            ("/reports/usage", "사용량", None))),
    ("설정", (("/policy", "정책", None), ("/admin", "설정·운영자", None))),
)
# Root 그룹. 화면이 있는 경로만 그리고(라우트가 생길 때까지 숨김), 역할은 MENU_MIN_ROLE을 따른다.
ROOT_MENU = ("Root", (("/root", "긴급 통제", None), ("/root/actions", "강제 조치 기록", None)))
ROLE_RANK = {"viewer": 0, "approver": 1, "admin": 2}
# 이 역할 이상에게만 메뉴에 그린다(B.2). 적히지 않은 항목은 모든 역할에게 보인다.
MENU_MIN_ROLE = {
    "/setup": "admin", "/approvals": "approver", "/builtin-tools": "admin", "/people": "admin",
    "/signup-requests": "admin", "/policy": "admin", "/admin": "admin", "/root/actions": "admin",
}
STAFF_MENU = (
    (None, (
        ("/staff", "내 MCP 서버", None),
        ("/staff/intakes", "서버 신청", None),
        ("/staff/confirmations", "내 요청", "staff_requests"),
        ("/staff/usage", "내 사용량", None),
        ("/staff/endpoint", "내 PC", None),
    )),
)
RANGES = (("1h", "1시간"), ("24h", "24시간"), ("7d", "7일"), ("30d", "30일"))
ICONS = {"ok": "✓", "wait": "◷", "error": "▲", "block": "⊘", "off": "–",
         # 경보 심각도는 상태와 겹치지 않게 색 점으로 보인다(글자가 함께 나온다).
         "sev-critical": "●", "sev-high": "●", "sev-medium": "●", "sev-low": "●"}


def zone_name(request: Request | None) -> str:
    """요청을 받은 콘솔 앱의 표시 시간대 이름(설정이 없으면 기본값)."""
    config = getattr(getattr(getattr(request, "app", None), "state", None), "config", None)
    return getattr(config, "time_zone", DEFAULT_TIME_ZONE)


def local_time(value: Any, zone: str = DEFAULT_TIME_ZONE) -> str:
    """``연-월-일 시:분`` 형식으로 조직 시간대의 시각을 돌려준다."""
    if value is None or value == "":
        return "—"
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return f"{value.astimezone(ZoneInfo(zone)):%Y-%m-%d %H:%M}"


@pass_context
def when(context: Any, value: Any) -> str:
    return local_time(value, zone_name(context.get("request")))


def countdown(value: Any) -> str:
    """기한까지 남은 시간(지났으면 「기한 지남」)."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime):
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    left = (value - datetime.now(UTC)).total_seconds()
    return "기한 지남" if left <= 0 else f"{int(left // 3600)}시간 {int(left % 3600 // 60)}분 남음"


def span(seconds: Any) -> str:
    """대기 시간을 한국어로(초·분·시간·일)."""
    if seconds is None:
        return "—"
    seconds = int(seconds)
    for limit, unit, size in ((60, "초", 1), (3600, "분", 60), (86400, "시간", 3600)):
        if seconds < limit:
            return f"{seconds // size}{unit}"
    return f"{seconds // 86400}일"


def blank(value: Any) -> Any:
    return "—" if value in (None, "", [], ()) else value


def join(values: Any) -> str:
    return ", ".join(values) if values else "—"


def clip(value: Any, limit: int = 256) -> str:
    """표시 값은 필드당 256자까지만 화면에 낸다."""
    if isinstance(value, dict):
        value = ", ".join(f"{k}: {v}" for k, v in value.items())
    elif isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    text = "—" if value is None or value == "" else str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def masked(value: Any, limit: int = 256) -> str:
    """승인 화면에 내는 인자 표시. 저장된 값에 남은 비밀·개인정보도 한 번 더 가리고 잘라서 낸다."""
    return clip(mask_text(str(value)) if value not in (None, "") else value, limit)


def tool_names(value: Any) -> str:
    """승인·거부의 도구 목록 표시: 「*」은 모든 도구, `action:<유형>`은 「행위: 삭제」."""
    names = [
        "모든 도구" if t == "*"
        else f"행위: {labels.pick(labels.ACTION, t[len(ACTION_DENIAL_PREFIX):])}"
        if str(t).startswith(ACTION_DENIAL_PREFIX) else str(t)
        for t in value or []
    ]
    return ", ".join(names) if names else "—"


def yes_no(value: Any) -> Any:
    return ("예" if value else "아니오") if isinstance(value, bool) else blank(value)


def to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


templates.env.filters.update(
    span=span, when=when, blank=blank, join=join, to_json=to_json, clip=clip, yes_no=yes_no,
    masked=masked, tool_names=tool_names,
    who=labels.actor, who_short=labels.actor_short, countdown=countdown,
)
templates.env.globals.update(can=can)
templates.env.tests["can_attach"] = lambda key, actor: can_attach(actor, key)
templates.env.globals.update(L=labels, ICONS=ICONS, MENU=MENU, STAFF_MENU=STAFF_MENU, RANGES=RANGES)


def nav_active(path: str, href: str) -> bool:
    """좌측 메뉴 강조. 경로가 같거나 하위 경로이면 켠다(대시보드는 정확히 같을 때만)."""
    return path == href or (href not in ("/", "/staff") and path.startswith(href))


templates.env.globals["nav_active"] = nav_active


def is_root(actor: Any) -> bool:
    """Root 운영자인가: 기본 계정 root이거나 설정의 Root 표지(root_operators)에 든 관리자."""
    from mint_litellm.control.services.root_controls import root_names

    session = getattr(actor, "session", None)
    ctx = getattr(actor, "ctx", None)
    name = getattr(session, "operator_name", None) or getattr(
        getattr(ctx, "operator", None), "name", None
    )
    if getattr(actor, "role", None) != "admin" or not name:
        return False
    if name == "root":
        return True
    try:
        return name in root_names(ctx.conn, ctx.instance_id)
    except Exception:  # 표지를 못 읽으면 Root로 보지 않는다(메뉴만 덜 그린다)
        return False


def has_route(request: Any, path: str) -> bool:
    """이 앱에 그 경로의 화면이 있는가(아직 없는 화면의 메뉴를 그리지 않는 스위치)."""
    return any(getattr(r, "path", None) == path for r in request.app.routes)


@pass_context
def menu_for(context: Any, actor: Any, badges: Any = None) -> list[tuple[str | None, list]]:
    """이 운영자가 들어갈 수 있는 메뉴만 그룹째로 돌려준다(빈 그룹은 뺀다)."""
    request = context.get("request")
    rank = ROLE_RANK.get(getattr(actor, "role", None), 0)
    root = is_root(actor)

    def shown(href: str) -> bool:
        need = MENU_MIN_ROLE.get(href)
        if href == "/root":
            return root and request is not None and has_route(request, href)
        if href.startswith("/root/") and not (request and has_route(request, href)):
            return False
        return need is None or rank >= ROLE_RANK[need]

    groups = [(g, [i for i in items if shown(i[0])]) for g, items in MENU]
    if not (badges or {}).get("setup"):  # 필수 항목을 마쳤으면 「시작하기」는 설정 그룹으로
        top = [i for i in groups[0][1] if i[0] == "/setup"]
        groups[0] = (None, [i for i in groups[0][1] if i[0] != "/setup"])
        groups[-1] = (groups[-1][0], groups[-1][1] + top)
    groups.append((ROOT_MENU[0], [i for i in ROOT_MENU[1] if shown(i[0])]))
    return [(g, items) for g, items in groups if items]


templates.env.globals.update(menu_for=menu_for, is_root=is_root)


def _endpoint_problems(actor: Any) -> int:
    """보고가 끊겼거나 격리 위반이 있는 단말 수."""
    from mint_litellm.console.pages.endpoints_admin import endpoint_view
    from mint_litellm.control import endpoint_kits

    rows = endpoint_kits.installs(actor.conn, actor.instance)
    view = endpoint_view(rows, [], datetime.now(UTC))
    return sum(1 for r in view["rows"] if r["group"] and (r["group"] == "stale" or r["violations"]))


def render(
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    status: int = 200,
    actor: Any = None,
) -> HTMLResponse:
    notice = labels.NOTICES.get(request.query_params.get("ok", ""))
    zone = zone_name(request)
    base = {
        "actor": actor, "path": request.url.path, "notice": notice, "error": None,
        "zone_label": labels.pick(labels.TIME_ZONE, zone),
        "default_password": read_cookie(request, DEFAULT_PASSWORD) == "1",
        "root_open": actor is not None and not name.startswith("staff")
        and is_root(actor) and has_route(request, "/root"),
        "litellm_open": bool(
            getattr(getattr(request.app.state, "config", None), "litellm_ui_url", None)
        ),
    }
    if actor is not None and not name.startswith("staff"):
        base["badges"] = {
            "alerts": reads.urgent_alert_count(actor.conn, actor.instance),
            **reads.menu_counts(actor.conn, actor.instance),
            "endpoints": _endpoint_problems(actor),
            "setup": setup_state.pending(setup_state.steps(actor, base["default_password"])),
        }
        if actor.role == "admin":
            count = fetchone(actor.conn, "SELECT count(*) AS n FROM mint.signup_requests"
                             " WHERE instance_id = %s AND status = 'pending'"
                             " AND decided_at IS NULL",
                             (actor.instance,))
            base["badges"]["signup"] = count["n"]
    return templates.TemplateResponse(
        request, name, {**base, **(context or {})}, status_code=status
    )
