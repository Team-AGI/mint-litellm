"""MCP 서버·신청·계약 화면."""

import json
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console import api, compare
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.services import contracts as contract_service
from mint_litellm.control.services import evidence as evidence_service
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.services import reads
from mint_litellm.control.services import servers as server_service

router = APIRouter(dependencies=[Depends(require_csrf)])


@router.get("/servers")
def servers(request: Request, actor: Actor = Depends(page_actor)):
    if request.query_params.get("filter") == "changed":
        return contracts_page(request, actor)
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
    if request.query_params.get("tab") == "contract":
        return contract_page(request, actor, server_id)
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


def contracts_page(request: Request, actor: Actor):
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
