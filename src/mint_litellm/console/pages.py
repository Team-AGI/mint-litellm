"""화면(서버 렌더링). 변경은 서비스 함수를 부르고, 실패하면 같은 화면에 오류를 보인다."""

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse, Response

from mint_litellm.console import alert_view, api, compare
from mint_litellm.console.core import STATUS, Actor, page_actor, require_csrf
from mint_litellm.console.templating import render
from mint_litellm.control import dormant, endpoint_kits, jobs, links, org_suggest
from mint_litellm.control import status as control_status
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import alerts as alert_service
from mint_litellm.control.services import allowlists as allowlist_service
from mint_litellm.control.services import approvals as approval_service
from mint_litellm.control.services import call_approvals as call_approval_service
from mint_litellm.control.services import contracts as contract_service
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import evidence as evidence_service
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.services import operators as operator_service
from mint_litellm.control.services import orgs as org_service
from mint_litellm.control.services import policy as policy_service
from mint_litellm.control.services import reads
from mint_litellm.control.services import recert as recert_service
from mint_litellm.control.services import renewals as renewal_service
from mint_litellm.control.services import servers as server_service
from mint_litellm.control.services import settings as settings_service
from mint_litellm.types.cli_commands import OperatorRole
from mint_litellm.types.settings import Mode

router = APIRouter(dependencies=[Depends(require_csrf)])

Rebuild = Callable[..., Response]


def page_number(request: Request) -> int:
    value = request.query_params.get("page", "1")
    return int(value) if value.isdigit() else 1


def lines(text: str) -> list[str]:
    return [part.strip() for part in text.replace(",", "\n").splitlines() if part.strip()]


def act(
    actor: Actor, action: Callable[[], Any], ok: str, back: str, rebuild: Rebuild
) -> Response:
    """서비스 호출 하나. 성공하면 알림과 함께 목록으로, 실패하면 같은 화면에 오류를 보인다."""
    try:
        action()
    except ControlError as error:
        actor.conn.rollback()
        status = STATUS[error.code] if isinstance(error, AdminError) else 400
        return rebuild(error=str(error), status=status)
    except ValueError:  # 선택 목록에 없는 값 등 잘못된 폼 값
        actor.conn.rollback()
        return rebuild(error="입력 값이 올바르지 않습니다.", status=400)
    return RedirectResponse(f"{back}{'&' if '?' in back else '?'}ok={ok}", status_code=303)


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


# --- 단말 설치 -------------------------------------------------------------------------------


@router.get("/endpoints")
def endpoints(request: Request, actor: Actor = Depends(page_actor)):
    rows = endpoint_kits.installs(actor.conn, actor.instance)
    return render(request, "endpoints.html", {"rows": rows}, actor=actor)


# --- MCP 서버 -------------------------------------------------------------------------------


@router.get("/endpoints/mcp")
def endpoint_mcp(request: Request, actor: Actor = Depends(page_actor)):
    rows = endpoint_kits.local_mcp_inventory(actor.conn, actor.instance)
    return render(request, "endpoint_mcp.html", {"rows": rows}, actor=actor)


@router.get("/servers")
def servers(request: Request, actor: Actor = Depends(page_actor)):
    return render(
        request, "servers.html", {"rows": reads.servers(actor.conn, actor.instance)}, actor=actor
    )


def server_page(request: Request, actor: Actor, server_id: str, error=None, status=200):
    row = reads.server(actor.conn, actor.instance, server_id)
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, f"서버 {server_id}을(를) 찾을 수 없습니다.")
    ctx = {"s": row, "error": error,
           "evidence": evidence_service.show(actor.ctx, "server", server_id)}
    return render(request, "server_detail.html", ctx, actor=actor, status=status)


@router.get("/servers/{server_id}")
def server_detail(server_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return server_page(request, actor, server_id)


def evidence_form(
    actor: Actor, subject_id: str, kind: str, summary: str, ref: str, valid_days: int | None,
    not_applicable: str, sha256: str = "",
) -> Callable[[], None]:
    def action():
        api.attach_evidence(actor, api.EvidenceBody(
            kind=kind, subject_id=subject_id, summary=summary, ref=ref.strip() or None,
            sha256=sha256.strip() or None, valid_days=valid_days,
            not_applicable=bool(not_applicable)))

    return action


@router.post("/servers/{server_id}/evidence")
def attach_server_evidence(
    server_id: str,
    request: Request,
    kind: str = Form(...),
    summary: str = Form(...),
    ref: str = Form(""),
    valid_days: int | None = Form(None),
    not_applicable: str = Form(""),
    sha256: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(actor, evidence_form(actor, server_id, kind, summary, ref, valid_days,
                                    not_applicable, sha256),
               "evidence_attached", f"/servers/{server_id}",
               lambda **kw: server_page(request, actor, server_id, **kw))


@router.post("/servers/{server_id}/suspend")
def suspend_server(
    server_id: str,
    request: Request,
    state_version: int = Form(...),
    confirm_name: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        api.confirm(server_id, confirm_name, "서버")
        server_service.suspend(actor.ctx, server_id, expected_version=state_version)

    return act(actor, action, "suspended", f"/servers/{server_id}",
               lambda **kw: server_page(request, actor, server_id, **kw))


@router.post("/servers/{server_id}/resume")
def resume_server(
    server_id: str,
    request: Request,
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: server_service.resume(actor.ctx, server_id, expected_version=state_version),
        "resumed", f"/servers/{server_id}",
        lambda **kw: server_page(request, actor, server_id, **kw),
    )


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
    dormant_view = request.query_params.get("filter") == "dormant"
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


@router.get("/approvals/new")
def approval_form(
    request: Request, relation_id: str = Query(...), actor: Actor = Depends(page_actor)
):
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


@router.get("/revocations")
def revocations(request: Request, actor: Actor = Depends(page_actor)):
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


@router.get("/link/{token}")
def open_link(token: str, actor: Actor = Depends(page_actor)):
    """알림의 서명 링크. 해당 화면에서 항목을 미리 고르기만 하고 아무것도 승인하지 않는다."""
    key = actor.config.stage2.webhook_hmac_key
    parsed = links.parse(key, token) if key else None
    target = None
    if parsed is not None:
        kind, ref = parsed
        target = {
            "call": f"/call-approvals?focus={quote(ref)}",
            "recert": f"/approvals?focus={quote(ref)}",
            "intake": f"/intakes/{quote(ref)}",
            "dormant": f"/approvals?filter=dormant&server={quote(ref)}",
        }.get(kind)
    if target is None:
        raise AdminError(AdminCode.NOT_FOUND, "링크가 만료되었거나 올바르지 않습니다.")
    return RedirectResponse(target, status_code=303)


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
    return render(request, "call_approvals.html",
                  {"rows": rows, "error": error, "focus": focus}, actor=actor, status=status)


@router.get("/call-approvals")
def call_approvals(request: Request, actor: Actor = Depends(page_actor)):
    return calls_page(request, actor)


@router.post("/call-approvals/{call_id}/{decision}")
def decide_call(
    call_id: str,
    decision: str,
    request: Request,
    state_version: int = Form(...),
    second_approver_token: str = Form(""),
    window_minutes: int = Form(0),
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
            call_approval_service.reject(actor.ctx, call_id, expected_version=state_version)
        elif decision == "cancel":
            call_approval_service.cancel(actor.ctx, call_id, expected_version=state_version)
        else:
            raise AdminError(AdminCode.NOT_FOUND, "알 수 없는 동작입니다.")

    ok = {"approve": "call_approved", "reject": "call_rejected", "cancel": "call_cancelled"}
    return act(actor, action, ok.get(decision, "call_approved"), "/call-approvals",
               lambda **kw: calls_page(request, actor, **kw))


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
    actor: Actor = Depends(page_actor),
):
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


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return alert_page(request, actor, alert_id)


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


# --- 운영자·조직·허용 목록 ---------------------------------------------------------------------


def admin_page(request: Request, actor: Actor, error=None, status=200):
    ctx = {
        "operators": [] if actor.role == "viewer" else reads.operators(actor.conn, actor.instance),
        "orgs": reads.orgs(actor.conn, actor.instance),
        "bindings": reads.bindings(actor.conn, actor.instance),
        "suggestions": org_service.list_suggestions(actor.ctx),
        "allowlists": reads.allowlists(actor.conn, actor.instance),
        "error": error,
    }
    return render(request, "admin.html", ctx, actor=actor, status=status)


@router.get("/admin")
def admin(request: Request, actor: Actor = Depends(page_actor)):
    return admin_page(request, actor)


@router.post("/operators/{name}/role")
def set_operator_role(
    name: str,
    request: Request,
    role: str = Form(...),
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: operator_service.set_role(
            actor.ctx, name, OperatorRole(role), expected_version=state_version
        ),
        "operator_role", "/admin", lambda **kw: admin_page(request, actor, **kw),
    )


@router.post("/operators/{name}/remove")
def remove_operator(
    name: str,
    request: Request,
    state_version: int = Form(...),
    confirm_name: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        api.confirm(name, confirm_name, "운영자")
        operator_service.remove(actor.ctx, name, expected_version=state_version)

    return act(actor, action, "operator_removed", "/admin",
               lambda **kw: admin_page(request, actor, **kw))


@router.post("/orgs")
def add_org(
    request: Request,
    org_id: str = Form(...),
    name: str = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(actor, lambda: org_service.add(actor.ctx, org_id, name), "org_added", "/admin",
               lambda **kw: admin_page(request, actor, **kw))


@router.post("/org-suggestions/rule")
def apply_org_suggestion_rule(
    request: Request, rule: str = Form(...), actor: Actor = Depends(page_actor)
):
    def action():
        if rule not in org_suggest.RULES:
            raise ValueError(rule)
        org_service.apply_rule(actor.ctx, rule)

    return act(actor, action, "org_suggestions_applied", "/admin",
               lambda **kw: admin_page(request, actor, **kw))


@router.post("/org-suggestions/{suggestion_id}/apply")
def apply_org_suggestion(
    suggestion_id: str, request: Request, actor: Actor = Depends(page_actor)
):
    return act(actor, lambda: org_service.apply_suggestion(actor.ctx, suggestion_id),
               "org_suggestion_applied", "/admin", lambda **kw: admin_page(request, actor, **kw))


@router.post("/org-suggestions/{suggestion_id}/ignore")
def ignore_org_suggestion(
    suggestion_id: str, request: Request, actor: Actor = Depends(page_actor)
):
    return act(actor, lambda: org_service.ignore_suggestion(actor.ctx, suggestion_id),
               "org_suggestion_ignored", "/admin", lambda **kw: admin_page(request, actor, **kw))


@router.post("/orgs/{org_id}/close")
def close_org(
    org_id: str,
    request: Request,
    state_version: int = Form(...),
    confirm_name: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        api.confirm(org_id, confirm_name, "조직")
        org_service.close(actor.ctx, org_id, expected_version=state_version)

    return act(actor, action, "org_closed", "/admin", lambda **kw: admin_page(request, actor, **kw))


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


# --- 신청·수용검증 ----------------------------------------------------------------------------


def intakes_page(request: Request, actor: Actor, error=None, status=200):
    wanted = request.query_params.get("status") or None
    rows = intake_service.list_intakes(actor.ctx, wanted)
    rows.sort(key=lambda r: (r["created_at"], str(r["id"])))  # 오래된 것 먼저
    ctx = {"rows": rows, "wanted": wanted or "", "error": error}
    return render(request, "intakes.html", ctx, actor=actor, status=status)


@router.get("/intakes")
def intakes(request: Request, actor: Actor = Depends(page_actor)):
    return intakes_page(request, actor)


def intake_page(request: Request, actor: Actor, intake_id: str, error=None, status=200):
    info = intake_service.show(actor.ctx, intake_id)
    now = datetime.now(UTC)
    checks = info["checks"]
    stale = any(
        c["check"] in ("connection", "definitions")
        and now - c["ran_at"] > intake_service.EVIDENCE_MAX_AGE
        for c in checks
    )
    expiries = [c["evidence_valid_until"] for c in checks if c["evidence_valid_until"]]
    strict = any(t["risk_grade"] in ("high", "critical") for t in info["tool_contracts"])
    ctx = {
        "i": info["intake"], "checks": checks, "tools": info["tool_contracts"], "stale": stale,
        "expires": min(expiries) if expiries else None,
        "days": api.STRICT_DAYS if strict else api.STANDARD_DAYS,
        "strict_days": api.STRICT_DAYS, "max_exception_days": api.EXCEPTION_MAX_DAYS,
        "can_assign": actor.config.litellm_admin is not None, "error": error,
        "evidence": evidence_service.show(actor.ctx, "intake", intake_id),
    }
    ctx["lacking"] = [
        e["label"] for e in ctx["evidence"]
        if e["gate"] == "approve" and e["state"] in ("missing", "expired")
    ]
    return render(request, "intake_detail.html", ctx, actor=actor, status=status)


INTAKE_FIELDS = ("server_id", "provider", "owner_user_id", "purpose")


def intake_new_page(request: Request, actor: Actor, form: dict, error=None, status=200):
    ctx = {"f": form, "grades": intake_service.DATA_GRADES, "error": error}
    return render(request, "intake_new.html", ctx, actor=actor, status=status)


@router.get("/intakes/new")
def intake_new(request: Request, actor: Actor = Depends(page_actor)):
    """단말 MCP 목록의 항목에서 신청을 시작한다. 쿼리 값으로 입력란을 미리 채운다."""
    query = request.query_params
    form = {key: query.get(key, "")[:256] for key in INTAKE_FIELDS}
    form["data_grade"] = "internal"
    return intake_new_page(request, actor, form)


@router.post("/intakes")
def create_intake(
    request: Request,
    server_id: str = Form(...),
    provider: str = Form(...),
    owner_user_id: str = Form(...),
    purpose: str = Form(...),
    data_grade: str = Form(...),
    allowed_resources: str = Form("[]"),
    credential_notice: str = Form(...),
    revocation_record: str = Form(...),
    audit_access_days: int = Form(...),
    data_return_terms: str = Form(...),
    actor: Actor = Depends(page_actor),
):
    form = {
        "server_id": server_id, "provider": provider, "owner_user_id": owner_user_id,
        "purpose": purpose, "data_grade": data_grade, "allowed_resources": allowed_resources,
        "credential_notice": credential_notice, "revocation_record": revocation_record,
        "audit_access_days": audit_access_days, "data_return_terms": data_return_terms,
    }

    def action():
        intake_service.create(
            actor.ctx, actor.litellm(), server_id.strip(), purpose=purpose, data_grade=data_grade,
            allowed_resources=json.loads(allowed_resources or "[]"), provider=provider,
            owner_user_id=owner_user_id,
            readiness={"credential_notice": credential_notice.strip(),
                       "revocation_record": revocation_record.strip(),
                       "audit_access_days": audit_access_days},
            data_return_terms=data_return_terms,
        )

    return act(
        actor, action, "intake_created", "/intakes",
        lambda **kw: intake_new_page(request, actor, form, **kw),
    )


@router.get("/intakes/{intake_id}")
def intake_detail(intake_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return intake_page(request, actor, intake_id)


@router.post("/intakes/{intake_id}/requester")
def assign_requester(
    intake_id: str,
    request: Request,
    user_id: str = Form(...),
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: intake_service.assign_requester(
            actor.ctx, actor.litellm(), intake_id, user_id, expected_version=state_version
        ),
        "requester_assigned", f"/intakes/{intake_id}",
        lambda **kw: intake_page(request, actor, intake_id, **kw),
    )


@router.post("/intakes/{intake_id}/evidence")
def attach_intake_evidence(
    intake_id: str,
    request: Request,
    kind: str = Form(...),
    summary: str = Form(...),
    ref: str = Form(""),
    valid_days: int | None = Form(None),
    not_applicable: str = Form(""),
    sha256: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(actor, evidence_form(actor, intake_id, kind, summary, ref, valid_days,
                                    not_applicable, sha256),
               "evidence_attached", f"/intakes/{intake_id}",
               lambda **kw: intake_page(request, actor, intake_id, **kw))


@router.post("/intakes/{intake_id}/recheck")
def recheck_intake(
    intake_id: str,
    request: Request,
    state_version: int = Form(...),
    url: str = Form(""),
    transport: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: intake_service.recheck(
            actor.ctx, intake_id, expected_version=state_version,
            url=url.strip() or None, transport=transport.strip() or None),
        "rechecked", f"/intakes/{intake_id}",
        lambda **kw: intake_page(request, actor, intake_id, **kw),
    )


@router.post("/intakes/{intake_id}/decision")
def decide_intake(
    intake_id: str,
    request: Request,
    decision: str = Form(...),
    state_version: int = Form(...),
    reason: str = Form(""),
    valid_days: int | None = Form(None),
    scope_type: str = Form("user"),
    scope_id: str = Form(""),
    second_approver_token: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        body = api.IntakeDecisionBody(
            state_version=state_version, decision=decision, reason=reason or None,
            valid_days=valid_days, scope_type=scope_type, scope_id=scope_id or None,
            second_approver_token=second_approver_token or None,
        )
        api.decide_intake(actor, intake_id, body)

    ok = "intake_rejected" if decision == "reject" else "intake_approved"
    return act(actor, action, ok, f"/intakes/{intake_id}",
               lambda **kw: intake_page(request, actor, intake_id, **kw))


# --- 계약 변경 비교·재승인 -------------------------------------------------------------------


@router.get("/contracts")
def contracts(request: Request, actor: Actor = Depends(page_actor)):
    rows = reads.drifted_servers(actor.conn, actor.instance)
    return render(request, "contracts.html", {"rows": rows}, actor=actor)


def contract_page(
    request: Request, actor: Actor, server_id: str, error=None, status=200
):
    info = contract_service.diff(actor.ctx, server_id)
    rows = compare.changes(info)
    wanted = (request.query_params.get("scope", ""), request.query_params.get("name", ""))
    chosen = next((r for r in rows if (r["scope"], r["name"]) == wanted), None)
    ctx = {
        "server_id": server_id,
        "server": info["server"],
        "rows": rows,
        "chosen": chosen,
        "sides": compare.side_by_side(chosen["approved"], chosen["observed"]) if chosen else None,
        "plan": reads.reapproval_plan(actor.conn, actor.instance, server_id),
        "cand": reads.candidates(actor.conn, actor.instance, server_id),
        "error": error,
    }
    return render(request, "contract_detail.html", ctx, actor=actor, status=status)


@router.get("/contracts/{server_id}")
def contract_detail(server_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return contract_page(request, actor, server_id)


@router.post("/contracts/{server_id}/reapprove")
def reapprove_contracts(
    server_id: str,
    request: Request,
    intake_id: str = Form(...),
    state_version: int = Form(...),
    tool_contract_ids: list[str] = Form([]),
    deployment_contract_id: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: contract_service.reapprove(
            actor.ctx, server_id, intake_id, tool_contract_ids,
            deployment_id=deployment_contract_id or None, expected_version=state_version,
        ),
        "reapproval_planned", f"/contracts/{server_id}",
        lambda **kw: contract_page(request, actor, server_id, **kw),
    )
