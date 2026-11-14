"""개요·호출 기록·경보·정책 화면."""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Query, Request

from mint_litellm.console import alert_view
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control import jobs
from mint_litellm.control import status as control_status
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import alerts as alert_service
from mint_litellm.control.services import policy as policy_service
from mint_litellm.control.services import reads
from mint_litellm.control.services import settings as settings_service
from mint_litellm.types.settings import Mode

router = APIRouter(dependencies=[Depends(require_csrf)])


# --- 개요 -----------------------------------------------------------------------------------


@router.get("/")
def overview(request: Request, actor: Actor = Depends(page_actor)):
    data = reads.overview(
        actor.conn, actor.instance, sorted(jobs.HANDLERS), actor.config.time_zone
    )
    data["workers"] = control_status.enforcement_states(actor.ctx)
    chart = {
        "days": [d["day"] for d in data["decisions_by_day"]],
        "allowed": [d["allowed"] for d in data["decisions_by_day"]],
        "blocked": [d["blocked"] for d in data["decisions_by_day"]],
    }
    return render(request, "overview.html", {"o": data, "chart": chart}, actor=actor)


# --- 원장 -----------------------------------------------------------------------------------


@router.get("/ledger")
def ledger(
    request: Request,
    since: str = "",
    until: str = "",
    kind: str = "",
    actor_name: str = Query("", alias="actor"),
    server_id: str = "",
    result: str = "",
    ref: str = "",
    invocation: str = "",
    page: int = 1,
    actor: Actor = Depends(page_actor),
):
    zone = actor.config.zone

    def day(text: str, end: bool = False) -> datetime | None:
        if not text:
            return None
        parsed = datetime.fromisoformat(text)
        parsed = parsed.replace(tzinfo=zone) if parsed.tzinfo is None else parsed.astimezone(zone)
        return (parsed + timedelta(days=1)) if end and "T" not in text else parsed

    error = None
    try:
        begin, finish = day(since), day(until, end=True)
    except ValueError:
        begin = finish = None
        since = until = ""
        error = "날짜는 연-월-일 형식으로 입력하십시오."
    try:
        invocation_id = str(UUID(invocation)) if invocation else None
    except ValueError:
        invocation_id, invocation = None, ""
        error = "호출 식별자 형식이 올바르지 않습니다."
    first = datetime.now(zone) - timedelta(days=reads.LEDGER_DEFAULT_DAYS)
    start = begin or first.replace(hour=0, minute=0, second=0, microsecond=0)
    ref = ref.strip()
    try:
        if ref:
            reads.parse_ref(ref)
    except ValueError:
        ref = ""
        error = "판정 참조 형식이 올바르지 않습니다."
    # 판정 참조로 찾을 때 기간을 바꾸지 않았다면 기간 제한 없이 찾는다.
    unbounded = bool(ref) and (not begin or since == first.strftime("%Y-%m-%d"))
    rows = reads.ledger(
        actor.conn, actor.instance, since=None if unbounded else start, until=finish,
        kind=kind or None, actor=actor_name or None, server_id=server_id or None,
        result=result or None, ref=ref or None, page=page,
        invocation_id=invocation_id,
    )
    query = {
        "since": since, "until": until, "kind": kind, "actor": actor_name, "server_id": server_id,
        "result": result, "ref": ref, "invocation": invocation,
    }
    ctx = {
        "rows": rows,
        "filters": reads.ledger_filters(actor.conn, actor.instance),
        "q": query,
        "start": start,
        "start_day": start.strftime("%Y-%m-%d"),
        "page": page,
        "servers": [s["server_id"] for s in reads.servers(actor.conn, actor.instance)],
        "error": error,
    }
    return render(request, "ledger.html", ctx, actor=actor, status=400 if error else 200)


# --- 경보 -----------------------------------------------------------------------------------


@router.get("/alerts")
def alerts_list(
    request: Request,
    status: str = "",
    severity: str = "",
    kind: str = "",
    server_id: str = "",
    page: int = 1,
    open_id: str = Query("", alias="open"),
    actor: Actor = Depends(page_actor),
):
    if open_id:
        return alert_page(request, actor, open_id)
    rows = reads.alerts(
        actor.conn, actor.instance, status=status, severity=severity, kind=kind,
        server_id=server_id, page=page,
    )
    zone = actor.config.time_zone
    for row in rows:
        row["summary"] = alert_view.summary(row["kind"], row["subject"])
        row["link"] = alert_view.link(row["kind"], row["subject"])
    ctx = {
        "rows": rows, "page": page, "zone": zone,
        "filters": reads.alert_filters(actor.conn, actor.instance),
        "q": {"status": status, "severity": severity, "kind": kind, "server_id": server_id},
    }
    return render(request, "alerts.html", ctx, actor=actor)


def alert_page(request: Request, actor: Actor, alert_id: str, error=None, status=200):
    try:
        row = reads.alert(actor.conn, actor.instance, str(UUID(alert_id)))
    except ValueError:
        row = None
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, "경보를 찾을 수 없습니다.")
    ctx = {
        "a": row, "error": error,
        "summary": alert_view.summary(row["kind"], row["subject"]),
        "fields": alert_view.subject_rows(row["subject"], actor.config.time_zone),
        "link": alert_view.link(row["kind"], row["subject"]),
    }
    return render(request, "alert_detail.html", ctx, actor=actor, status=status)


@router.post("/alerts/{alert_id}/acknowledge")
def alert_acknowledge(alert_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return act(
        actor, lambda: alert_service.acknowledge(actor.ctx, alert_id), "alert_acknowledged",
        f"/alerts/{alert_id}", lambda **kw: alert_page(request, actor, alert_id, **kw),
    )


# --- 정책·관측 설정 ---------------------------------------------------------------------------


def policy_page(request: Request, actor: Actor, error=None, status=200):
    shadow = reads.policy_shadow(actor.conn, actor.instance)
    ctx = {
        "versions": reads.policy_versions(actor.conn, actor.instance),
        "shadow": shadow,
        "shadow_day": shadow and f"{shadow['set_at'].astimezone(actor.config.zone):%Y-%m-%d}",
        "s": reads.settings(actor.conn, actor.instance),
        "ceiling": actor.config.control.mode_ceiling.value,
        "error": error,
    }
    return render(request, "policy.html", ctx, actor=actor, status=status)


@router.get("/policy")
def policy(request: Request, actor: Actor = Depends(page_actor)):
    return policy_page(request, actor)


@router.post("/policy/shadow/apply")
def apply_shadow(
    request: Request, version: str = Form(...), actor: Actor = Depends(page_actor)
):
    def action():
        source = actor.config.policy_source
        if source is None:
            raise ControlError("이 콘솔에서는 정책 판본을 적용할 수 없습니다.")
        policy_service.activate(actor.ctx, actor.config.database_url, version, source)

    return act(
        actor, action, "policy_applied", "/policy", lambda **kw: policy_page(request, actor, **kw)
    )


@router.post("/policy/shadow/cancel")
def cancel_shadow(request: Request, actor: Actor = Depends(page_actor)):
    return act(
        actor, lambda: policy_service.shadow_cancel(actor.ctx), "shadow_cancelled", "/policy",
        lambda **kw: policy_page(request, actor, **kw),
    )


@router.post("/policy/mode")
def set_mode(
    request: Request,
    mode: str = Form(...),
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: settings_service.set_mode(
            actor.ctx, Mode(mode), actor.config.control.mode_ceiling, expected_version=state_version
        ),
        "mode_set", "/policy", lambda **kw: policy_page(request, actor, **kw),
    )
