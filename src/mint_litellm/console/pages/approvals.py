"""승인·호출별 승인·거부·허용 목록 화면."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from mint_litellm.console import api
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act, lines, page_number, see_other
from mint_litellm.console.pages.endpoints_admin import admin_page
from mint_litellm.console.templating import render
from mint_litellm.control import dormant
from mint_litellm.control.approvals import DEFAULT_CALL_WINDOW
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import allowlists as allowlist_service
from mint_litellm.control.services import approval_metrics, reads
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


def approvals_page(request: Request, actor: Actor, error=None, status=200, form=None):
    focus = _focus(request)
    dormant_view = (
        request.query_params.get("filter") == "dormant"
        or request.query_params.get("tab") == "dormant"
    )
    if dormant_view:
        rows = dormant.find(actor.conn, actor.instance, actor.config.stage2.dormant_days)
        server = request.query_params.get("server")
        rows = [r for r in rows if not server or r["server_id"] == server]
    else:
        rows = reads.approvals(
            actor.conn, actor.instance, page=page_number(request), only_id=focus
        )
    ctx = {
        "queue": [] if focus or dormant_view else reads.queue(actor.conn, actor.instance),
        "rows": _with_recert(actor, rows),
        "dormant_view": dormant_view,
        "dormant_days": actor.config.stage2.dormant_days,
        "focus": focus,
        "form": form,
        "page": page_number(request),
        "error": error,
        "can_grant": actor.config.litellm_admin is not None,
        "renewal": renewal_service.candidates(actor.conn, actor.instance),
    }
    return render(request, "approvals.html", ctx, actor=actor, status=status)


@router.get("/approvals")
def approvals(request: Request, actor: Actor = Depends(page_actor)):
    query = request.query_params
    if query.get("tab") in ("calls", "rules"):
        return calls_page(request, actor)
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

    return act(actor, action, "approved", "/approvals", rebuild)


# --- 거부·철회 ------------------------------------------------------------------------------


def revocations_page(request: Request, actor: Actor, error=None, status=200):
    ctx = {
        "approvals": reads.approvals(actor.conn, actor.instance, status="active"),
        "denials": reads.denials(actor.conn, actor.instance),
        "error": error,
    }
    return render(request, "revocations.html", ctx, actor=actor, status=status)


@router.get("/access")
def access(request: Request, actor: Actor = Depends(page_actor)):
    if request.query_params.get("tab") == "dormant":
        return approvals_page(request, actor)
    return revocations_page(request, actor)


@router.post("/approvals/renew")
def renew_expiring(request: Request, actor: Actor = Depends(page_actor)):
    def action():
        _, failed = api.renew_approvals(actor)
        if failed:
            raise ControlError(f"갱신하지 못한 승인이 {len(failed)}건 있습니다. {failed[0]}")

    return act(
        actor, action, "renewed", "/approvals", lambda **kw: approvals_page(request, actor, **kw),
    )


def _dormant_action(request: Request, actor: Actor, ids: list[str], one) -> Response:
    """미사용 승인 일괄 처리. 항목 값은 ``<승인 식별자>:<상태 버전>``이고 관리자만 쓴다."""

    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "일괄 처리는 admin 역할만 할 수 있습니다.")
        for item in ids:
            approval_id, _, version = item.rpartition(":")
            one(approval_id, int(version))

    return act(actor, action, "dormant_done", "/approvals?filter=dormant",
               lambda **kw: approvals_page(request, actor, **kw))


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
        "recertified", "/approvals", lambda **kw: approvals_page(request, actor, **kw),
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
        "revoked_denied" if with_denial else "revoked", "/revocations",
        lambda **kw: revocations_page(request, actor, **kw),
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
        "denied", "/revocations", lambda **kw: revocations_page(request, actor, **kw),
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
        "lifted", "/revocations", lambda **kw: revocations_page(request, actor, **kw),
    )


# --- 호출별 승인 요청 -------------------------------------------------------------------------


def calls_page(request: Request, actor: Actor, error=None, status=200):
    focus = _focus(request)
    rows = reads.call_approvals(
        actor.conn, actor.instance, page=page_number(request), only_id=focus
    )
    rules = reads.call_approval_rules(actor.conn, actor.instance) if not focus else []
    chosen = request.query_params.get("range", "")
    stats = None if focus else approval_metrics.collect(
        actor.conn, actor.instance,
        chosen if chosen in approval_metrics.RANGES else approval_metrics.DEFAULT_RANGE,
        actor.config.time_zone,
    )
    prefill = {k: request.query_params.get(f"rule_{k}", "")
               for k in ("org", "server", "tool", "class")}
    return render(request, "call_approvals.html",
                  {"rows": rows, "rules": rules, "orgs": reads.orgs(actor.conn, actor.instance),
                   "stats": stats, "ranges": list(approval_metrics.RANGES), "prefill": prefill,
                   "error": error, "focus": focus, "one_shot": ONE_SHOT_ACTIONS},
                  actor=actor, status=status)


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
        "rule_added", "/call-approvals", lambda **kw: calls_page(request, actor, **kw),
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
        "rule_disabled", "/call-approvals", lambda **kw: calls_page(request, actor, **kw),
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
    return act(actor, action, ok.get(decision, "call_approved"), "/call-approvals",
               lambda **kw: calls_page(request, actor, **kw))


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
    return act(actor, action, ok.get(decision, "call_approved"), "/call-approvals",
               lambda **kw: calls_page(request, actor, **kw))


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
        "allowlist_added", "/admin", lambda **kw: admin_page(request, actor, **kw),
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
        "lifted", "/admin", lambda **kw: admin_page(request, actor, **kw),
    )
