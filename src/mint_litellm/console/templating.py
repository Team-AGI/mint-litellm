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

from mint_litellm.console import labels
from mint_litellm.console.core import DEFAULT_TIME_ZONE
from mint_litellm.control.services import reads

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")

MENU = (
    ("/", "개요"),
    ("/servers", "MCP 서버"),
    ("/intakes", "신청·수용검증"),
    ("/approvals", "승인 대기열"),
    ("/contracts", "계약 변경"),
    ("/revocations", "거부·철회"),
    ("/call-approvals", "호출별 승인"),
    ("/endpoints", "단말 설치"),
    ("/alerts", "경보"),
    ("/ledger", "원장"),
    ("/policy", "정책·관측 설정"),
    ("/admin", "운영자·조직"),
)
STAFF_MENU = (
    ("/staff", "사용 가능한 서버·도구"),
    ("/staff/confirmations", "본인 확인 요청"),
    ("/staff/endpoint", "단말 설치"),
    ("/staff/consents", "동의 관리·내 기록"),
)
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


def yes_no(value: Any) -> Any:
    return ("예" if value else "아니오") if isinstance(value, bool) else blank(value)


def to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


templates.env.filters.update(
    span=span, when=when, blank=blank, join=join, to_json=to_json, clip=clip, yes_no=yes_no,
    who=labels.actor, countdown=countdown,
)
templates.env.globals.update(L=labels, ICONS=ICONS, MENU=MENU, STAFF_MENU=STAFF_MENU)


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
        base["alert_badge"] = reads.urgent_alert_count(actor.conn, actor.instance)
    return templates.TemplateResponse(
        request, name, {**base, **(context or {})}, status_code=status
    )
