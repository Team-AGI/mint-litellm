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
from mint_litellm.console.core import DEFAULT_TIME_ZONE
from mint_litellm.control.services import reads
from mint_litellm.plugin.policy.sensitive_scan import mask_text

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")

# (그룹 이름, ((경로, 이름, 배지 키), ...)). 그룹 이름이 None이면 구분선 없이 맨 위에 둔다.
MENU = (
    (None, (("/", "대시보드", None), ("/setup", "시작하기", "setup"))),
    ("처리할 일", (("/approvals", "승인 센터", "approvals"), ("/alerts", "경보", "alerts"))),
    ("서버", (("/servers", "서버", "servers"), ("/intakes", "도입 신청", "intakes"),
            ("/access", "접근 통제", None))),
    ("단말", (("/endpoints", "엔드포인트", "endpoints"),)),
    ("감사", (("/ledger", "호출 기록", None), ("/policy", "정책", None))),
    ("관리", (("/admin", "운영자·조직", None),)),
)
STAFF_MENU = (
    (None, (
        ("/staff", "내 서버", None),
        ("/staff/confirmations", "내 요청", "staff_requests"),
        ("/staff/endpoint", "내 단말", None),
    )),
)
RANGES = (("1h", "1시간"), ("24h", "24시간"), ("7d", "7일"), ("30d", "30일"))
ICONS = {"ok": "✓", "wait": "◷", "error": "▲", "block": "⊘", "off": "–"}


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
    text = "—" if value is None or value == "" else str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def masked(value: Any, limit: int = 256) -> str:
    """승인 화면에 내는 인자 표시. 저장된 값에 남은 비밀·개인정보도 한 번 더 가리고 잘라서 낸다."""
    return clip(mask_text(str(value)) if value not in (None, "") else value, limit)


def yes_no(value: Any) -> Any:
    return ("예" if value else "아니오") if isinstance(value, bool) else blank(value)


def to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


templates.env.filters.update(
    span=span, when=when, blank=blank, join=join, to_json=to_json, clip=clip, yes_no=yes_no,
    masked=masked,
    who=labels.actor, countdown=countdown,
)
templates.env.globals.update(L=labels, ICONS=ICONS, MENU=MENU, STAFF_MENU=STAFF_MENU, RANGES=RANGES)


def nav_active(path: str, href: str) -> bool:
    """좌측 메뉴 강조. 경로가 같거나 하위 경로이면 켠다(대시보드는 정확히 같을 때만)."""
    return path == href or (href not in ("/", "/staff") and path.startswith(href))


templates.env.globals["nav_active"] = nav_active


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
    }
    if actor is not None and not name.startswith("staff"):
        base["badges"] = {
            "alerts": reads.urgent_alert_count(actor.conn, actor.instance),
            **reads.menu_counts(actor.conn, actor.instance),
            "endpoints": _endpoint_problems(actor),
            "setup": setup_state.pending(setup_state.steps(actor)),
        }
    return templates.TemplateResponse(
        request, name, {**base, **(context or {})}, status_code=status
    )
