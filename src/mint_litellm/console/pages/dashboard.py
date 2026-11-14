"""대시보드·호출 기록·경보·정책 화면."""

from datetime import datetime, timedelta
from urllib.parse import quote, urlencode
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Query, Request

from mint_litellm.console import alert_view, audit_report, labels
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.labels import Status
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import RANGES, local_time, render, span
from mint_litellm.control import jobs
from mint_litellm.control import status as control_status
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import alerts as alert_service
from mint_litellm.control.services import approval_metrics, dashboard_reads, reads
from mint_litellm.control.services import policy as policy_service
from mint_litellm.control.services import settings as settings_service
from mint_litellm.types.settings import Mode

router = APIRouter(dependencies=[Depends(require_csrf)])

SLOW_WAIT_SECONDS = 300
RANGE_BY_HOURS = {dashboard_reads.HOURS[key]: text for key, text in RANGES}


# --- 공통 -----------------------------------------------------------------------------------


def choices(path: str, params: dict[str, str], key: str, options, current: str):
    """한 가지 값을 고르는 링크 묶음. 다른 조건은 그대로 두고 ``key``만 바꾼다."""
    out = []
    for value, text in options:
        merged = {k: v for k, v in params.items() if v and k != key}
        if value:
            merged[key] = value
        query = urlencode(merged)
        out.append((text, f"{path}?{query}" if query else path, value == current))
    return out


def percent(part: int, whole: int) -> str:
    return f"{round(100 * part / whole)}%" if whole else "—"


def card(label, value, href=None, note=None, level=None, trend=None):
    return {
        "label": label,
        "value": value,
        "href": href,
        "note": note,
        "level": level,
        "trend": trend,
    }


def range_name(value: str, default: str = dashboard_reads.DEFAULT_RANGE) -> str:
    return value if value in dashboard_reads.HOURS else default


def trend_chart(series: dict, previous: dict | None = None, links: bool = True) -> dict:
    chart = {
        "kind": "stacked",
        "labels": series["labels"],
        "series": [
            {"name": labels.OUTCOME_BUCKET[b], "data": series[b], "decision": b}
            for b in dashboard_reads.BUCKETS
        ],
    }
    if previous:
        chart["previous"] = previous["total"]
    if links and series["unit"] == "day":
        chart["links"] = [f"/ledger?since={d}&until={d}" for d in series["days"]]
    return chart


def reason_donut(reasons: list[dict], blocked: int) -> dict:
    merged: dict[str, int] = {}
    for r in reasons:
        name = labels.outcome_reason(r["code"])
        merged[name] = merged.get(name, 0) + r["n"]
    items = [
        {"name": name, "value": n, "href": "/ledger?result=deny"}
        for name, n in sorted(merged.items(), key=lambda kv: -kv[1])[:8]
    ]
    rest = blocked - sum(i["value"] for i in items)
    if rest > 0:
        items.append({"name": "기타", "value": rest, "href": "/ledger?result=deny"})
    return {"kind": "donut", "items": items}


# --- 대시보드 -------------------------------------------------------------------------------


def dashboard_cards(o, series, previous, coverage, workers, wait, hours):
    total, blocked = sum(series["total"]), sum(series["block"])
    before, blocked_before = sum(previous["total"]), sum(previous["block"])
    alerts = o["alerts"]
    urgent = alerts.get("critical", 0) + alerts.get("high", 0)
    if total >= 5 and before >= 5:
        rate_note = f"전 기간 대비 {100 * blocked / total - 100 * blocked_before / before:+.0f}%p"
    else:
        rate_note = f"호출 {total}건 중 {blocked}건" if total else "호출 없음"
    waiting = o["pending_calls"] + o["pending_servers"] + o["pending_intakes"] + o["reapproval"]
    slow = (wait["average_seconds"] or 0) >= SLOW_WAIT_SECONDS
    return [
        card(
            "승인 대기",
            waiting,
            "/approvals",
            f"호출 {o['pending_calls']} · 서버 {o['pending_servers']}"
            f" · 신청 {o['pending_intakes']} · 갱신 {o['reapproval']}",
            "wait" if slow else None,
        ),
        card(
            "열린 경보(치명·높음)",
            urgent,
            "/alerts?status=open",
            f"전체 {sum(alerts.values())}",
            "danger" if alerts.get("critical") else ("wait" if urgent else None),
        ),
        card(
            "차단률",
            percent(blocked, total),
            "/ledger?result=deny",
            rate_note,
        ),
        card(
            f"호출 수({RANGE_BY_HOURS.get(hours, '')})",
            total,
            "/ledger",
            f"전 기간 {before}" if before else None,
            None,
            series["total"],
        ),
        card(
            "적용 엔드포인트",
            percent(coverage["managed"], coverage["total"]),
            "/endpoints",
            f"{coverage['managed']}/{coverage['total']}대" if coverage["total"] else None,
        ),
    ]


def status_dots(o, workers, zone):
    def stamp(value):
        return Status(local_time(value, zone), "ok") if value else Status("기록 없음", "wait")

    dots = []
    workers, stale = control_status.split_live_workers(workers)
    unverified = sum(1 for w in workers if not w["passed"])
    if workers:
        verified = len(workers) - unverified
        dots.append(
            {
                "name": "집행 워커",
                "status": Status(
                    (
                        f"{verified}/{len(workers)} 정상"
                        if not unverified
                        else f"{unverified}개 확인 불가"
                    )
                    + (f" · 이전 실행 {stale}개" if stale else ""),
                    "error" if unverified else "ok",
                ),
                "title": "",
            }
        )
        # 같은 LiteLLM이 워커마다 반복되므로 한 줄로 합치고, 문제가 있는 쪽을 보인다.
        found = [w["litellm"] for w in workers if w["litellm"]]
        if found:
            worst = next((x for x in found if labels.litellm_missing(x)), found[0])
            dots.insert(
                0,
                {
                    "name": "LiteLLM",
                    "status": labels.litellm_badge(worst),
                    "title": labels.litellm_missing(worst),
                },
            )
    dots.append({"name": "원장 봉인", "status": stamp(o["last_seal"]), "title": ""})
    dots.append({"name": "내보내기", "status": stamp(o["last_export"]), "title": ""})
    late = o["unhandled_jobs"]
    if o["jobs_failed"]:
        queue = Status(f"실패 {o['jobs_failed']}", "error")
    elif late:
        queue = Status(f"지연 {late}", "error")
    else:
        queue = Status(f"대기 {o['jobs_pending']}", "ok")
    longest = f"최장 대기 {span(o['unhandled_oldest_seconds'])}" if late else ""
    dots.append({"name": "작업", "status": queue, "title": longest})
    return dots


@router.get("/")
def dashboard(
    request: Request,
    range_value: str = Query(dashboard_reads.DEFAULT_RANGE, alias="range"),
    actor: Actor = Depends(page_actor),
):
    name = range_name(range_value)
    hours = dashboard_reads.hours_of(name)
    zone, conn, instance = actor.config.time_zone, actor.conn, actor.instance
    o = reads.overview(conn, instance, sorted(jobs.HANDLERS), zone)
    workers = control_status.enforcement_states(actor.ctx)
    series = dashboard_reads.decision_series(conn, instance, hours, zone)
    previous = dashboard_reads.decision_series(conn, instance, hours, zone, shift=hours)
    wait = dashboard_reads.pending_wait(conn, instance)
    metrics = approval_metrics.collect(
        conn, instance, name if name in approval_metrics.RANGES else "24h", zone
    )
    top = dashboard_reads.top_servers(conn, instance, hours)
    order = ("critical", "high", "medium", "low")
    alert_bars = {
        "kind": "bars",
        "horizontal": True,
        "labels": [labels.ALERT_SEVERITY[k].text for k in order],
        "values": [o["alerts"].get(k, 0) for k in order],
        "links": [f"/alerts?status=open&severity={k}" for k in order],
    }
    ctx = {
        "range": name,
        "ranges": choices("/", {}, "range", RANGES, name),
        "cards": dashboard_cards(
            o,
            series,
            previous,
            dashboard_reads.endpoint_coverage(conn, instance),
            workers,
            wait,
            hours,
        ),
        "trend": trend_chart(series, previous),
        "trend_has_data": sum(series["total"]) > 0,
        "reasons": reason_donut(
            dashboard_reads.block_reasons(conn, instance, hours), sum(series["block"])
        ),
        "servers": {
            "kind": "bars",
            "horizontal": True,
            "labels": [r["server_id"] for r in top],
            "values": [r["calls"] for r in top],
            "links": [f"/ledger?server_id={quote(r['server_id'])}" for r in top],
        },
        "alert_bars": alert_bars,
        "alert_total": sum(alert_bars["values"]),
        "approval_cards": [
            card(
                "대기",
                wait["count"],
                "/approvals",
                f"최장 {span(wait['oldest_seconds'])}" if wait["count"] else None,
                "wait" if (wait["average_seconds"] or 0) >= SLOW_WAIT_SECONDS else None,
            ),
            card(
                "중앙 처리 시간",
                span(metrics["median_seconds"]),
                None,
                f"90%는 {span(metrics['p90_seconds'])} 이내" if metrics["p90_seconds"] else None,
            ),
            card("오늘 처리", dashboard_reads.decided_today(conn, instance, zone), "/approvals"),
            card(
                "기간 요청",
                metrics["opened"],
                None,
                f"사람 {metrics['approved_by_person']} · 규칙 {metrics['approved_by_rule']}",
                None,
                metrics["series"]["values"],
            ),
        ],
        "dots": status_dots(o, workers, zone),
    }
    return render(request, "dashboard.html", ctx, actor=actor)


# --- 호출 기록 ------------------------------------------------------------------------------


def ledger_cards(series, previous):
    total, blocked = sum(series["total"]), sum(series["block"])
    before, blocked_before = sum(previous["total"]), sum(previous["block"])
    surge = (
        total >= 5 and before >= 5 and 100 * blocked / total - 100 * blocked_before / before >= 20
    )
    return [
        card(
            "호출 수", total, None, f"전 기간 {before}" if before else None, None, series["total"]
        ),
        card(
            "차단",
            blocked,
            "/ledger?result=deny",
            percent(blocked, total) if total >= 5 else None,
            "danger" if surge else None,
        ),
        card("승인 필요", sum(series["approve"]), None),
    ]


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
    range_value: str = Query("", alias="range"),
    open_id: str = Query("", alias="open"),
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
    now = datetime.now(zone)
    first = now - timedelta(days=reads.LEDGER_DEFAULT_DAYS)
    picked = range_value if range_value in dashboard_reads.HOURS and not begin else ""
    if picked:
        start = now - timedelta(hours=dashboard_reads.hours_of(picked))
    else:
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
        actor.conn,
        actor.instance,
        since=None if unbounded else start,
        until=finish,
        kind=kind or None,
        actor=actor_name or None,
        server_id=server_id or None,
        result=result or None,
        ref=ref or None,
        page=page,
        invocation_id=invocation_id,
    )
    query = {
        "since": since,
        "until": until,
        "kind": kind,
        "actor": actor_name,
        "server_id": server_id,
        "result": result,
        "ref": ref,
        "invocation": invocation,
    }
    params = {**query, "range": picked}
    qs = urlencode({k: v for k, v in params.items() if v})
    # 시간대 차트는 지금까지의 같은 길이 기간이다. 날짜를 직접 정했으면 그 날짜부터 지금까지다.
    if picked:
        hours = dashboard_reads.hours_of(picked)
    elif begin:
        hours = dashboard_reads.since_hours(start, now)
    else:
        hours = dashboard_reads.hours_of(dashboard_reads.DEFAULT_RANGE)
    current = picked or ("" if begin else dashboard_reads.DEFAULT_RANGE)
    conn, instance, name = actor.conn, actor.instance, actor.config.time_zone
    series = dashboard_reads.decision_series(conn, instance, hours, name)
    previous = dashboard_reads.decision_series(conn, instance, hours, name, shift=hours)
    blocked = sum(series["block"])
    shown = None
    if open_id:
        try:
            shown = dashboard_reads.event(conn, instance, str(UUID(open_id)))
        except ValueError:
            shown = None
        if shown is None:
            raise AdminError(AdminCode.NOT_FOUND, "기록을 찾을 수 없습니다.")
        day_text = f"{shown['inserted_at'].astimezone(zone):%Y-%m-%d}"
        shown["same_call"] = (
            f"/ledger?{urlencode({'invocation': shown['invocation_id'], 'since': day_text})}"
            if shown.get("invocation_id")
            else None
        )
    ctx = {
        "rows": rows,
        "filters": reads.ledger_filters(actor.conn, actor.instance),
        "q": query,
        "start": start,
        "start_day": start.strftime("%Y-%m-%d"),
        "page": page,
        "servers": [s["server_id"] for s in reads.servers(actor.conn, actor.instance)],
        "error": error,
        "qs": qs,
        "range": current,
        "ranges": choices("/ledger", params, "range", RANGES, current),
        "results": choices(
            "/ledger", params, "result", [("", "전체"), *labels.RESULT_FILTER.items()], result
        ),
        "cards": ledger_cards(series, previous),
        "trend": trend_chart(series, previous),
        "trend_has_data": sum(series["total"]) > 0,
        "reasons": reason_donut(dashboard_reads.block_reasons(conn, instance, hours), blocked),
        "ev": shown,
    }
    return render(request, "ledger.html", ctx, actor=actor, status=400 if error else 200)


# --- 경보 -----------------------------------------------------------------------------------


def alerts_page(
    request: Request,
    actor: Actor,
    q: dict[str, str],
    page: int = 1,
    open_id: str = "",
    error=None,
    status=200,
):
    rows = reads.alerts(
        actor.conn,
        actor.instance,
        status=q["status"],
        severity=q["severity"],
        kind=q["kind"],
        server_id=q["server_id"],
        page=page,
    )
    zone = actor.config.time_zone
    for row in rows:
        row["summary"] = alert_view.summary(row["kind"], row["subject"])
    qs = urlencode({k: v for k, v in q.items() if v})
    stats = dashboard_reads.alert_stats(actor.conn, actor.instance)
    order = ("critical", "high", "medium", "low")
    ctx = {
        "rows": rows,
        "page": page,
        "zone": zone,
        "qs": qs,
        "error": error,
        "filters": reads.alert_filters(actor.conn, actor.instance),
        "q": q,
        "statuses": choices(
            "/alerts",
            q,
            "status",
            [("", "전체"), *((k, v.text) for k, v in labels.ALERT_STATUS.items())],
            q["status"],
        ),
        "severities": choices(
            "/alerts",
            q,
            "severity",
            [("", "전체"), *((k, labels.ALERT_SEVERITY[k].text) for k in order)],
            q["severity"],
        ),
        "cards": [
            card(
                labels.ALERT_SEVERITY[k].text,
                stats["severity"].get(k, 0),
                f"/alerts?status=open&severity={k}",
                None,
                "danger"
                if k == "critical" and stats["severity"].get(k)
                else ("wait" if k == "high" and stats["severity"].get(k) else None),
            )
            for k in order
        ]
        + [card("가장 오래 열린 경보", span(stats["oldest_seconds"]), "/alerts?status=open")],
        "kinds": {
            "kind": "bars",
            "horizontal": True,
            "labels": [labels.pick(labels.ALERT_KIND, r["kind"]) for r in stats["kinds"]],
            "values": [r["n"] for r in stats["kinds"]],
            "links": [f"/alerts?status=open&kind={r['kind']}" for r in stats["kinds"]],
        },
        "stats": stats,
    }
    if open_id:
        try:
            row = reads.alert(actor.conn, actor.instance, str(UUID(open_id)))
        except ValueError:
            row = None
        if row is None:
            raise AdminError(AdminCode.NOT_FOUND, "경보를 찾을 수 없습니다.")
        ctx.update(
            a=row,
            summary=alert_view.summary(row["kind"], row["subject"]),
            fields=alert_view.subject_rows(row["subject"], zone),
            link=alert_view.link(row["kind"], row["subject"]),
        )
    return render(request, "alerts.html", ctx, actor=actor, status=status)


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
    q = {"status": status, "severity": severity, "kind": kind, "server_id": server_id}
    return alerts_page(request, actor, q, page, open_id)


@router.post("/alerts/{alert_id}/acknowledge")
def alert_acknowledge(alert_id: str, request: Request, actor: Actor = Depends(page_actor)):
    empty = {"status": "", "severity": "", "kind": "", "server_id": ""}
    return act(
        actor,
        lambda: alert_service.acknowledge(actor.ctx, alert_id),
        "alert_acknowledged",
        f"/alerts?open={alert_id}",
        lambda **kw: alerts_page(request, actor, empty, 1, alert_id, **kw),
    )


# --- 정책 -----------------------------------------------------------------------------------


def policy_names(actor: Actor) -> dict[str, str]:
    """정책 식별자 -> 운영자가 읽는 이름(정책 목록의 규칙 설명)."""
    root = actor.config.policy_source.root if actor.config.policy_source else None
    catalog = audit_report.load_catalog(root) or {}
    return {r["id"]: r["description"] for r in catalog.get("rules", []) if r.get("description")}


def policy_page(request: Request, actor: Actor, error=None, status=200):
    name = range_name(request.query_params.get("range", ""))
    hours = dashboard_reads.hours_of(name)
    shadow = reads.policy_shadow(actor.conn, actor.instance)
    setting = reads.settings(actor.conn, actor.instance)
    totals = dashboard_reads.decision_totals(actor.conn, actor.instance, hours)
    ceiling = actor.config.control.mode_ceiling.value
    cards = [
        card("판정", totals["total"], "/ledger"),
        card("차단", totals["block"], "/ledger?result=deny"),
        card("승인 필요", totals["approve"], None),
        card(
            "모드",
            labels.pick(labels.MODE, setting["mode"]) if setting else "—",
            None,
            f"환경 상한 {labels.pick(labels.MODE, ceiling)}",
        ),
    ]
    tiles = None
    if shadow:
        t, st = shadow["totals"], shadow["stats"]
        tiles = [
            card(
                "허용에서 차단",
                t["allow_to_deny"],
                None,
                f"평가 {st['evaluated']}건",
                "danger" if t["allow_to_deny"] else None,
            ),
            card("차단에서 허용", t["deny_to_allow"], None),
            card("그 밖의 변경", t["other"], None),
            card(
                "평가 오류",
                st["errors"],
                None,
                f"건너뜀 {st['skipped']}건",
                "wait" if st["errors"] else None,
            ),
        ]
    ctx = {
        "versions": reads.policy_versions(actor.conn, actor.instance),
        "shadow": shadow,
        "shadow_day": shadow and f"{shadow['set_at'].astimezone(actor.config.zone):%Y-%m-%d}",
        "s": setting,
        "ceiling": ceiling,
        "error": error,
        "range": name,
        "ranges": choices("/policy", {}, "range", RANGES, name),
        "cards": cards,
        "tiles": tiles,
        "effect": dashboard_reads.policy_effect(actor.conn, actor.instance, hours),
        "names": policy_names(actor),
    }
    return render(request, "policy.html", ctx, actor=actor, status=status)


@router.get("/policy")
def policy(request: Request, actor: Actor = Depends(page_actor)):
    return policy_page(request, actor)


@router.post("/policy/shadow/apply")
def apply_shadow(request: Request, version: str = Form(...), actor: Actor = Depends(page_actor)):
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
        actor,
        lambda: policy_service.shadow_cancel(actor.ctx),
        "shadow_cancelled",
        "/policy",
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
        "mode_set",
        "/policy",
        lambda **kw: policy_page(request, actor, **kw),
    )
