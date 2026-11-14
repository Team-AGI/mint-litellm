"""승인·호출별 승인·거부·허용 목록 화면."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from mint_litellm.console import api
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act, lines, page_number, see_other
from mint_litellm.console.templating import render
from mint_litellm.control import dormant
from mint_litellm.control.approvals import DEFAULT_CALL_WINDOW
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import allowlists as allowlist_service
from mint_litellm.control.services import approval_metrics, dashboard_reads, reads
from mint_litellm.control.services import approvals as approval_service
from mint_litellm.control.services import call_approval_rules as call_approval_rule_service
from mint_litellm.control.services import call_approvals as call_approval_service
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import recert as recert_service
from mint_litellm.control.services import renewals as renewal_service
from mint_litellm.types.contracts import ONE_SHOT_ACTIONS

router = APIRouter(dependencies=[Depends(require_csrf)])


# --- 승인 대기열·상세 -------------------------------------------------------------------------


def _with_recert(actor: Actor, rows: list[dict]) -> list[dict]:
    """활성 승인마다 재확인 기한과 상태(기한 내·필요·기한 초과·보류)를 붙인다."""
    settings = actor.config.stage2
    period = timedelta(days=settings.recert_days)
    grace = timedelta(days=settings.recert_grace_days)
    now = datetime.now(UTC)
    return [
        {**r, "recert": recert_service.state(r, now, period, grace),
         "recert_due": recert_service.due_at(r, period)}
        for r in rows
    ]


def _focus(request: Request) -> str | None:
    """링크로 미리 고른 항목(없으면 None). 형식이 틀리면 ``ValueError``(잘못된 입력)이다."""
    value = request.query_params.get("focus")
    return str(uuid.UUID(value)) if value else None


SLOW_SECONDS = 300  # 호출 승인이 이만큼 기다리면 강조한다
TABS = ("calls", "servers", "renewals", "rules")
ACCESS_TABS = ("approvals", "dormant", "denials", "allowlists")
RULE_FIELDS = {  # 규칙 칸 -> 이전 링크의 쿼리 이름
    "org_id": "rule_org", "server_id": "rule_server", "tool_pattern": "rule_tool",
    "action_class": "rule_class", "principal_type": "", "principal_id": "", "window_minutes": "",
}


def _rule_values(request: Request) -> dict[str, str]:
    query = request.query_params
    return {k: query.get(k) or (query.get(old) if old else None) or ""
            for k, old in RULE_FIELDS.items()}


def approvals_page(request: Request, actor: Actor, error=None, status=200, tab=None):
    """승인 센터: 호출·서버 도입·갱신·규칙 탭. 호출 탭이 기본이다."""
    query = request.query_params
    tab = tab or (query.get("tab") if query.get("tab") in TABS else "calls")
    focus = _focus(request)
    calls = reads.call_approvals(actor.conn, actor.instance, page=page_number(request))
    pending = [c for c in calls if c["status"] == "pending"]
    queue = reads.queue(actor.conn, actor.instance)
    renewal = renewal_service.candidates(actor.conn, actor.instance)
    rules = reads.call_approval_rules(actor.conn, actor.instance)
    ctx = {
        "tab": tab, "focus": focus, "error": error, "page": page_number(request),
        "rows": calls, "pending": pending, "queue": queue, "renewal": renewal, "rules": rules,
        "slow": sum(1 for c in pending if (c["age_seconds"] or 0) >= SLOW_SECONDS),
        "wait": dashboard_reads.pending_wait(actor.conn, actor.instance),
        "done_today": dashboard_reads.decided_today(
            actor.conn, actor.instance, actor.config.time_zone
        ),
        "tabs": [
            ("calls", "호출", len(pending)), ("servers", "서버 도입", len(queue)),
            ("renewals", "갱신", len(renewal["unchanged"]) + len(renewal["changed"])),
            ("rules", "규칙", sum(1 for r in rules if r["status"] == "active")),
        ],
        "can_grant": actor.config.litellm_admin is not None,
        "one_shot": ONE_SHOT_ACTIONS, "orgs": reads.orgs(actor.conn, actor.instance),
        "new": bool(query.get("new")), "rule": _rule_values(request), "impact": None,
        "selected": None, "history": [], "stats": None,
        "range_options": [("24h", "24시간"), ("7d", "7일"), ("30d", "30일")],
    }
    if tab == "calls":
        chosen = query.get("range", "")
        ctx["stats"] = approval_metrics.collect(
            actor.conn, actor.instance,
            chosen if chosen in approval_metrics.RANGES else approval_metrics.DEFAULT_RANGE,
            actor.config.time_zone,
        )
        if focus:
            ctx["selected"] = next((c for c in calls if str(c["id"]) == focus), None) or next(
                iter(reads.call_approvals(actor.conn, actor.instance, only_id=focus)), None
            )
        if ctx["selected"]:
            me = ctx["selected"]
            same = (me["server_id"], me["tool"], me["principal_type"], me["principal_id"])
            ctx["history"] = [
                c for c in calls if c["id"] != me["id"]
                and (c["server_id"], c["tool"], c["principal_type"], c["principal_id"]) == same
            ][:5]
    if tab == "rules" and ctx["new"] and query.get("preview") and ctx["rule"]["org_id"]:
        rule = ctx["rule"]
        ctx["impact"] = call_approval_rule_service.impact(
            actor.conn, actor.instance, org_id=rule["org_id"], action_class=rule["action_class"],
            principal_type=rule["principal_type"] or None,
            principal_id=rule["principal_id"] or None, server_id=rule["server_id"] or None,
            tool_pattern=rule["tool_pattern"] or None,
        )
    return render(request, "approval_center.html", ctx, actor=actor, status=status)


@router.get("/approvals")
def approvals(request: Request, actor: Actor = Depends(page_actor)):
    query = request.query_params
    if query.get("filter") == "dormant":
        return see_other(request, "/access", drop=("filter",), tab="dormant")
    if query.get("focus") and not query.get("tab"):
        return see_other(request, "/approvals", tab="renewals")
    return approvals_page(request, actor)


def approval_form_page(
    request: Request, actor: Actor, relation_id: str, error=None, status=200, days=None
):
    relation = reads.relation(actor.conn, actor.instance, relation_id)
    if relation is None:
        raise AdminError(AdminCode.NOT_FOUND, "이용 관계가 없습니다.")
    high = reads.high_risk_tools(actor.conn, actor.instance, relation["server_id"])
    form = {
        "relation": relation,
        "days": days or api.approval_days("standard", [], high),
        "strict_days": api.STRICT_DAYS,
        "max_exception_days": api.EXCEPTION_MAX_DAYS,
        "high": high,
        "can_grant": actor.config.litellm_admin is not None,
        "error": error,
    }
    return render(request, "approval_new.html", form, actor=actor, status=status)


@router.get("/approvals/review/{relation_id}")
def approval_form(relation_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return approval_form_page(request, actor, relation_id)


@router.post("/approvals")
def grant_approval(
    request: Request,
    relation_id: str = Form(...),
    state_version: int = Form(...),
    scope_type: str = Form(...),
    scope_id: str = Form(...),
    tools: str = Form(...),
    approval_class: str = Form("standard", alias="class"),
    basis: str = Form(""),
    requested_by: str = Form(...),
    valid_days: int | None = Form(None),
    second_approver_token: str = Form(""),
    allowed_hosts: str = Form(""),
    allowed_arg_keys: str = Form(""),
    paths_mode: str = Form("unset"),
    allowed_paths: str = Form(""),
    max_result_bytes: int | None = Form(None),
    max_result_items: int | None = Form(None),
    actor: Actor = Depends(page_actor),
):
    def action():
        body = api.ApprovalBody(
            state_version=state_version, relation_id=relation_id, scope_type=scope_type,
            scope_id=scope_id, tools=lines(tools), approval_class=approval_class,
            basis=basis.strip() or f"콘솔 승인(신청자 {requested_by})", requested_by=requested_by,
            valid_days=valid_days, second_approver_token=second_approver_token or None,
            allowed_hosts=lines(allowed_hosts), allowed_arg_keys=lines(allowed_arg_keys),
            paths_mode=paths_mode, allowed_paths=lines(allowed_paths),
            max_result_bytes=max_result_bytes, max_result_items=max_result_items,
        )
        api.grant_approval(body, actor)

    def rebuild(**kw):
        return approval_form_page(request, actor, relation_id, days=valid_days, **kw)

    return act(actor, action, "approved", "/approvals?tab=servers", rebuild)


# --- 접근 통제 --------------------------------------------------------------------------------


def access_page(request: Request, actor: Actor, error=None, status=200, tab=None):
    """접근 통제: 승인·미사용·거부·허용 목록 탭."""
    query = request.query_params
    tab = tab or (query.get("tab") if query.get("tab") in ACCESS_TABS else "approvals")
    focus = _focus(request)
    days = actor.config.stage2.dormant_days
    stale = dormant.find(actor.conn, actor.instance, days)
    denials = reads.denials(actor.conn, actor.instance)
    allowlists = reads.allowlists(actor.conn, actor.instance)
    renewal = renewal_service.candidates(actor.conn, actor.instance)
    counts = {
        "active": reads.approvals(actor.conn, actor.instance, status="active"),
        "denials": sum(1 for d in denials if not d["lifted_at"]),
        "allowlists": sum(1 for a in allowlists if a["status"] == "active"),
        "expiring": len(renewal["unchanged"]) + len(renewal["changed"]),
    }
    ctx = {
        "tab": tab, "focus": focus, "error": error, "page": page_number(request),
        "dormant_days": days, "denials": denials, "allowlists": allowlists,
        "new": bool(query.get("new")), "counts": counts, "stale": len(stale),
        "tabs": [
            ("approvals", "승인", len(counts["active"])), ("dormant", "미사용", len(stale)),
            ("denials", "거부", counts["denials"]),
            ("allowlists", "허용 목록", counts["allowlists"]),
        ],
        "rows": [],
    }
    if tab == "approvals":
        rows = reads.approvals(
            actor.conn, actor.instance, status="active", page=page_number(request), only_id=focus
        )
        ctx["rows"] = _with_recert(actor, rows)
    elif tab == "dormant":
        server = query.get("server")
        ctx["rows"] = [r for r in stale if not server or r["server_id"] == server]
    return render(request, "access.html", ctx, actor=actor, status=status)


@router.get("/access")
def access(request: Request, actor: Actor = Depends(page_actor)):
    return access_page(request, actor)


@router.post("/approvals/renew")
def renew_expiring(request: Request, actor: Actor = Depends(page_actor)):
    def action():
        _, failed = api.renew_approvals(actor)
        if failed:
            raise ControlError(f"갱신하지 못한 승인이 {len(failed)}건 있습니다. {failed[0]}")

    return act(
        actor, action, "renewed", "/approvals?tab=renewals",
        lambda **kw: approvals_page(request, actor, tab="renewals", **kw),
    )


def _dormant_action(request: Request, actor: Actor, ids: list[str], one) -> Response:
    """미사용 승인 일괄 처리. 항목 값은 ``<승인 식별자>:<상태 버전>``이고 관리자만 쓴다."""

    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "일괄 처리는 admin 역할만 할 수 있습니다.")
        for item in ids:
            approval_id, _, version = item.rpartition(":")
            one(approval_id, int(version))

    return act(actor, action, "dormant_done", "/access?tab=dormant",
               lambda **kw: access_page(request, actor, tab="dormant", **kw))


@router.post("/approvals/dormant/keep")
def keep_dormant(
    request: Request, ids: list[str] = Form(default=[]), actor: Actor = Depends(page_actor)
):
    return _dormant_action(
        request, actor, ids,
        lambda i, v: recert_service.confirm(actor.ctx, i, expected_version=v),
    )


@router.post("/approvals/dormant/revoke")
def revoke_dormant(
    request: Request, ids: list[str] = Form(default=[]), actor: Actor = Depends(page_actor)
):
    return _dormant_action(
        request, actor, ids,
        lambda i, v: approval_service.revoke(
            actor.ctx, i, "미사용 승인 정리", False, expected_version=v
        ),
    )


@router.post("/approvals/{approval_id}/recertify")
def recertify_approval(
    approval_id: str,
    request: Request,
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: recert_service.confirm(actor.ctx, approval_id, expected_version=state_version),
        "recertified", "/access?tab=approvals",
        lambda **kw: access_page(request, actor, tab="approvals", **kw),
    )


@router.post("/approvals/{approval_id}/revoke")
def revoke_approval(
    approval_id: str,
    request: Request,
    state_version: int = Form(...),
    reason: str = Form(""),
    deny: str = Form("0"),
    actor: Actor = Depends(page_actor),
):
    with_denial = deny == "1"
    return act(
        actor,
        lambda: approval_service.revoke(
            actor.ctx, approval_id, reason, with_denial, expected_version=state_version
        ),
        "revoked_denied" if with_denial else "revoked", "/access?tab=approvals",
        lambda **kw: access_page(request, actor, tab="approvals", **kw),
    )


@router.post("/denials")
def create_denial(
    request: Request,
    scope_type: str = Form(...),
    scope_id: str = Form(...),
    server_id: str = Form(""),
    tools: str = Form(""),
    reason: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: denial_service.deny(
            actor.ctx, scope_type=scope_type, scope_id=scope_id, server_id=server_id or None,
            tools=lines(tools) or None, reason=reason, org_id=None,
        ),
        "denied", "/access?tab=denials",
        lambda **kw: access_page(request, actor, tab="denials", **kw),
    )


@router.post("/denials/{denial_id}/lift")
def lift_denial(
    denial_id: str,
    request: Request,
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: denial_service.lift(actor.ctx, denial_id, expected_version=state_version),
        "lifted", "/access?tab=denials",
        lambda **kw: access_page(request, actor, tab="denials", **kw),
    )


# --- 호출별 승인 요청 -------------------------------------------------------------------------


@router.post("/call-approval-rules")
def add_call_approval_rule(
    request: Request,
    org_id: str = Form(...),
    action_class: str = Form(...),
    window_minutes: int = Form(30),
    principal_type: str = Form(""),
    principal_id: str = Form(""),
    server_id: str = Form(""),
    tool_pattern: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: call_approval_rule_service.add(
            actor.ctx, org_id=org_id, action_class=action_class, window_minutes=window_minutes,
            principal_type=principal_type.strip() or None,
            principal_id=principal_id.strip() or None,
            server_id=server_id.strip() or None,
            tool_pattern=tool_pattern.strip() or None,
        ),
        "rule_added", "/approvals?tab=rules",
        lambda **kw: approvals_page(request, actor, tab="rules", **kw),
    )


@router.post("/call-approval-rules/{rule_id}/disable")
def disable_call_approval_rule(
    rule_id: str,
    request: Request,
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: call_approval_rule_service.disable(
            actor.ctx, rule_id, expected_version=state_version
        ),
        "rule_disabled", "/approvals?tab=rules",
        lambda **kw: approvals_page(request, actor, tab="rules", **kw),
    )


@router.post("/call-approvals/bulk/{decision}")
def decide_calls(
    decision: str,
    request: Request,
    ids: list[str] = Form(default=[]),
    window_minutes: int = Form(DEFAULT_CALL_WINDOW),
    reason: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    """선택한 대기 요청을 한 번에 승인·거부한다. 항목 값은 ``<식별자>:<상태 버전>``이다.

    승인은 선택한 기간을 쓰되 1회만 되는 동작(쓰기 등)의 요청은 1회로 승인한다.
    """

    def action():
        if decision not in ("approve", "reject"):
            raise AdminError(AdminCode.NOT_FOUND, "알 수 없는 동작입니다.")
        if not ids:
            raise ControlError("선택한 요청이 없습니다.")
        one_shot = {
            str(r["id"]) for r in reads.call_approvals(actor.conn, actor.instance, status="pending")
            if r["action_type"] in ONE_SHOT_ACTIONS
        }
        failed = []
        for item in ids:
            call_id, _, version = item.rpartition(":")
            try:
                if decision == "approve":
                    call_approval_service.approve(
                        actor.ctx, call_id, None, expected_version=int(version),
                        window_minutes=None if call_id in one_shot else window_minutes or None,
                    )
                else:
                    call_approval_service.reject(
                        actor.ctx, call_id, expected_version=int(version), reason=reason
                    )
            except (ControlError, ValueError) as error:
                failed.append(str(error))
        if failed:
            actor.conn.commit()  # 처리된 항목은 남기고 실패한 항목만 알린다
            done = len(ids) - len(failed)
            raise ControlError(f"{done}건 처리, {len(failed)}건 실패: {failed[0]}")

    ok = {"approve": "call_approved", "reject": "call_rejected"}
    return act(actor, action, ok.get(decision, "call_approved"), "/approvals?tab=calls",
               lambda **kw: approvals_page(request, actor, tab="calls", **kw))


@router.post("/call-approvals/{call_id}/{decision}")
def decide_call(
    call_id: str,
    decision: str,
    request: Request,
    state_version: int = Form(...),
    second_approver_token: str = Form(""),
    window_minutes: int = Form(DEFAULT_CALL_WINDOW),
    reason: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        if decision == "approve":
            second = api.second_approver(actor, second_approver_token)
            call_approval_service.approve(
                actor.ctx, call_id, second, expected_version=state_version,
                window_minutes=window_minutes or None,
            )
        elif decision == "reject":
            call_approval_service.reject(
                actor.ctx, call_id, expected_version=state_version, reason=reason
            )
        elif decision == "cancel":
            call_approval_service.cancel(actor.ctx, call_id, expected_version=state_version)
        elif decision == "extend":
            call_approval_service.extend(actor.ctx, call_id, expected_version=state_version)
        else:
            raise AdminError(AdminCode.NOT_FOUND, "알 수 없는 동작입니다.")

    ok = {"approve": "call_approved", "reject": "call_rejected", "cancel": "call_cancelled",
          "extend": "call_extended"}
    back = "/approvals?tab=calls"
    if decision in ("approve", "reject"):  # 처리하면 다음 대기 요청을 이어서 연다
        later = [r for r in reads.call_approvals(actor.conn, actor.instance, status="pending")
                 if str(r["id"]) != call_id]
        back += f"&focus={later[0]['id']}" if later else ""
    return act(actor, action, ok.get(decision, "call_approved"), back,
               lambda **kw: approvals_page(request, actor, tab="calls", **kw))


@router.post("/allowlists")
def add_allowlist(
    request: Request,
    kind: str = Form(...),
    value: str = Form(...),
    valid_days: int = Form(90),
    note: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    now = datetime.now(UTC)
    return act(
        actor,
        lambda: allowlist_service.add(
            actor.ctx, kind, value, now, now + timedelta(days=valid_days), None, note or None
        ),
        "allowlist_added", "/access?tab=allowlists",
        lambda **kw: access_page(request, actor, tab="allowlists", **kw),
    )


@router.post("/allowlists/{allowlist_id}/lift")
def lift_allowlist(
    allowlist_id: str,
    request: Request,
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: allowlist_service.lift(actor.ctx, allowlist_id, expected_version=state_version),
        "lifted", "/access?tab=allowlists",
        lambda **kw: access_page(request, actor, tab="allowlists", **kw),
    )
