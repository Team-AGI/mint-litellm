"""HTTP API ``/api/v1/<자원>``. 상태 변경은 서비스 함수 하나를 부르고, 조회는 ``reads``를 부른다.

인증은 세션 쿠키(+``X-CSRF-Token``) 또는 운영자 토큰(``Authorization: Bearer``)이다.
변경 요청은 대상의
``state_version``을 보내야 하며 다르면 ``409 MINT-ADMIN-CONFLICT``이다. 오류 본문은
``{code, message, reference}``이다.
"""

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from mint_litellm.console import compare
from mint_litellm.console.core import Actor, api_actor, public, require_csrf
from mint_litellm.control import endpoint_kits, operators
from mint_litellm.control.approvals import build_conditions
from mint_litellm.control.context import Operator
from mint_litellm.control.errors import AdminCode, AdminError, AuthError, ControlError, forbidden
from mint_litellm.control.services import allowlists as allowlist_service
from mint_litellm.control.services import approval_metrics, metrics, reads
from mint_litellm.control.services import approvals as approval_service
from mint_litellm.control.services import call_approval_rules as call_approval_rule_service
from mint_litellm.control.services import call_approvals as call_approval_service
from mint_litellm.control.services import contracts as contract_service
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import evidence as evidence_service
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.services import operators as operator_service
from mint_litellm.control.services import orgs as org_service
from mint_litellm.control.services import relations as relation_service
from mint_litellm.control.services import renewals as renewal_service
from mint_litellm.control.services import servers as server_service
from mint_litellm.control.services import settings as settings_service
from mint_litellm.types.cli_commands import OperatorRole
from mint_litellm.types.identity import SubjectType
from mint_litellm.types.settings import Mode

router = APIRouter(dependencies=[Depends(require_csrf)])

STANDARD_DAYS = 90
STRICT_DAYS = 30  # 높음·심각 도구를 포함한 승인과 예외 승인의 기본 기간
EXCEPTION_MAX_DAYS = 90
CALL_APPROVAL_DEFAULT_HOURS = 24
CALL_APPROVAL_MAX_DAYS = 7


def approval_days(approval_class: str, tools: list[str], high_risk: list[str]) -> int:
    """승인 유효 기간 기본값(일): 일반 90, 높음·심각 도구를 포함하거나 예외이면 30."""
    if approval_class == "exception" or set(tools) & set(high_risk):
        return STRICT_DAYS
    return STANDARD_DAYS


def window(
    valid_days: int | None, approval_class: str, default_days: int
) -> tuple[datetime, datetime]:
    days = default_days if valid_days is None else valid_days
    if days < 1:
        raise ControlError("유효 기간은 1일 이상이어야 합니다.")
    if approval_class == "exception" and days > EXCEPTION_MAX_DAYS:
        raise ControlError(f"예외 승인의 유효 기간은 {EXCEPTION_MAX_DAYS}일을 넘을 수 없습니다.")
    now = datetime.now(UTC)
    return now, now + timedelta(days=days)


def second_approver(actor: Actor, token: str | None) -> Operator | None:
    if not token:
        return None
    try:
        return operators.authenticate(actor.conn, actor.instance, token)
    except AuthError as error:
        raise AdminError(AdminCode.SEPARATION_OF_DUTIES, str(error)) from None


def confirm(actual: str, typed: str, what: str) -> None:
    if typed != actual:
        raise ControlError(f"{what} 이름을 정확히 입력해야 합니다.")


def approval_conditions(body: "ApprovalBody", high_risk: list[str]) -> dict[str, Any]:
    """승인 조건. CLI·수용 승인과 같은 ``build_conditions``로 만들고, 경로는 세 값을 구분한다."""
    conditions = build_conditions(
        high_risk_tools=high_risk,
        business_hours_only=False,
        business_hours=None,
        require_consent=None,
        allowed_hosts=body.allowed_hosts,
        allowed_arg_keys=body.allowed_arg_keys,
    )
    if body.paths_mode == "listed":
        if not body.allowed_paths:
            raise ControlError("허용 경로를 하나 이상 입력하거나 다른 옵션을 선택하십시오.")
        conditions.update(build_conditions(
            high_risk_tools=None, business_hours_only=False, business_hours=None,
            require_consent=None, allowed_paths=body.allowed_paths))
    elif body.paths_mode == "unrestricted":
        conditions["allowed_paths_unrestricted"] = True
    for name in ("max_result_bytes", "max_result_items"):
        if getattr(body, name) is not None:
            conditions[name] = getattr(body, name)
    return conditions


def safe_cell(value: Any) -> str:
    """스프레드시트가 수식으로 읽는 칸(``=``·``+``·``-``·``@`` 등으로 시작)에 ``'``를 붙인다."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", chr(9), chr(13)) else text


def done(actor: Actor, **extra: Any) -> dict[str, Any]:
    return {"ok": True, **extra, "events": [e.source_key for e in actor.ctx.emitted]}


class Versioned(BaseModel):
    state_version: int


class RecheckBody(Versioned):
    url: str | None = None
    transport: str | None = None


class SuspendBody(Versioned):
    confirm_name: str


class RevokeBody(Versioned):
    reason: str
    deny: bool = False


class ApprovalBody(Versioned):
    """``state_version``은 이용 관계의 값이다."""

    relation_id: str
    scope_type: Literal["key", "user", "team"]
    scope_id: str
    tools: list[str] = Field(min_length=1)
    approval_class: Literal["standard", "exception"] = Field("standard", alias="class")
    basis: str
    requested_by: str
    valid_days: int | None = None
    allowlist_ids: list[str] = []
    second_approver_token: str | None = None
    allowed_hosts: list[str] = []
    allowed_arg_keys: list[str] = []
    # unset: 허용 경로 없음(절대 경로 모두 차단), listed: allowed_paths만 허용,
    # unrestricted: 제한 없음(명시 선택)
    paths_mode: Literal["unset", "listed", "unrestricted"] = "unset"
    allowed_paths: list[str] = []
    # 한 번의 호출 결과에서 허용하는 크기(바이트)와 항목 수. 비우면 상한 조건을 두지 않는다.
    max_result_bytes: int | None = Field(None, ge=1)
    max_result_items: int | None = Field(None, ge=1)

    model_config = {"populate_by_name": True}


class RejectCallBody(Versioned):
    reason: str | None = None


class ApproveCallBody(Versioned):
    second_approver_token: str | None = None
    window_minutes: int | None = None  # 없으면 30분(1회만 되는 동작은 1회), 0이면 1회


class DenialBody(BaseModel):
    scope_type: Literal["key", "user", "team", "org", "server"]
    scope_id: str
    server_id: str | None = None
    tools: list[str] | None = None
    reason: str
    org_id: str | None = None


class OrgBody(BaseModel):
    org_id: str
    name: str


class CloseOrgBody(Versioned):
    confirm_name: str


class BindingBody(BaseModel):
    subject_type: SubjectType
    subject_id: str


class RelationBody(BaseModel):
    org_id: str
    server_id: str
    purpose: str
    team_id: str | None = None


class CallApprovalRuleBody(BaseModel):
    org_id: str
    action_class: Literal["read", "write"]
    window_minutes: Literal[10, 30]
    principal_type: Literal["user", "team_key", "service_account"] | None = None
    principal_id: str | None = None
    server_id: str | None = None
    tool_pattern: str | None = None
    valid_until: datetime | None = None


class AllowlistBody(BaseModel):
    kind: Literal["provider", "auth_server", "egress_target", "registry_source"]
    value: str
    valid_until: datetime
    valid_from: datetime | None = None
    org_id: str | None = None
    note: str | None = None


class ModeBody(Versioned):
    mode: Mode


class DefaultOrgBody(Versioned):
    org_id: str | None


class OperatorBody(BaseModel):
    name: str
    role: OperatorRole
    user_id: str | None = None
    expires_in_days: int | None = None


class SetRoleBody(Versioned):
    role: OperatorRole


class RemoveOperatorBody(Versioned):
    confirm_name: str


class RegisterBody(BaseModel):
    server_id: str
    url: str | None = None


# --- 조회 -----------------------------------------------------------------------------------


@router.get("/overview")
def get_overview(actor: Actor = Depends(api_actor)):
    return public(reads.overview(actor.conn, actor.instance))


@router.get("/servers")
def list_servers(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.servers(actor.conn, actor.instance))}


@router.get("/endpoint/installs")
def list_endpoint_installs(actor: Actor = Depends(api_actor)):
    return {"items": public(endpoint_kits.installs(actor.conn, actor.instance))}


@router.get("/servers/{server_id}")
def get_server(server_id: str, actor: Actor = Depends(api_actor)):
    row = reads.server(actor.conn, actor.instance, server_id)
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, f"서버 {server_id}을(를) 찾을 수 없습니다.")
    return public(row)


@router.get("/relations")
def list_relations(server_id: str | None = None, actor: Actor = Depends(api_actor)):
    return {"items": public(reads.relations(actor.conn, actor.instance, server_id))}


@router.get("/approvals")
def list_approvals(
    status: str | None = None,
    server_id: str | None = None,
    page: int = 1,
    actor: Actor = Depends(api_actor),
):
    rows = reads.approvals(
        actor.conn, actor.instance, server_id=server_id, status=status, page=page
    )
    return {"items": public(rows)}


@router.get("/approvals/queue")
def approval_queue(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.queue(actor.conn, actor.instance))}


@router.get("/denials")
def list_denials(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.denials(actor.conn, actor.instance))}


@router.get("/call-approvals")
def list_call_approvals(
    status: str | None = None, page: int = 1, actor: Actor = Depends(api_actor)
):
    rows = reads.call_approvals(actor.conn, actor.instance, status=status, page=page)
    return {"items": public(rows)}


@router.get("/call-approval-rules")
def list_call_approval_rules(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.call_approval_rules(actor.conn, actor.instance))}


@router.get("/orgs")
def list_orgs(actor: Actor = Depends(api_actor)):
    return {
        "items": public(reads.orgs(actor.conn, actor.instance)),
        "bindings": public(reads.bindings(actor.conn, actor.instance)),
    }


@router.get("/operators")
def list_operators(actor: Actor = Depends(api_actor)):
    if actor.role == "viewer":
        raise AdminError(AdminCode.FORBIDDEN, "조회자는 운영자 목록을 볼 수 없습니다.")
    return {"items": public(reads.operators(actor.conn, actor.instance))}


@router.get("/allowlists")
def list_allowlists(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.allowlists(actor.conn, actor.instance))}


@router.get("/settings")
def get_settings(actor: Actor = Depends(api_actor)):
    return public(reads.settings(actor.conn, actor.instance))


@router.get("/policy/versions")
def list_policy_versions(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.policy_versions(actor.conn, actor.instance))}


@router.get("/metrics")
def get_metrics(actor: Actor = Depends(api_actor)):
    return Response(
        metrics.exposition(actor.conn, actor.instance),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/metrics/approvals")
def get_approval_metrics(
    range: str = approval_metrics.DEFAULT_RANGE, actor: Actor = Depends(api_actor)
):
    if range not in approval_metrics.RANGES:
        raise ControlError(f"range는 {', '.join(approval_metrics.RANGES)} 중 하나여야 합니다.")
    return approval_metrics.collect(actor.conn, actor.instance, range, actor.config.time_zone)


@router.get("/ledger")
def get_ledger(
    since: datetime | None = None,
    until: datetime | None = None,
    kind: str | None = None,
    actor_name: str | None = Query(None, alias="actor"),
    server_id: str | None = None,
    result: str | None = None,
    ref: str | None = None,
    page: int = 1,
    actor: Actor = Depends(api_actor),
):
    rows = reads.ledger(
        actor.conn, actor.instance, since=since, until=until, kind=kind, actor=actor_name,
        server_id=server_id, result=result, ref=ref, page=page,
    )
    return {"items": public(rows), "page": page}


@router.get("/ledger/export")
def export_ledger(
    format: Literal["csv", "json"] = "csv",
    since: datetime | None = None,
    until: datetime | None = None,
    kind: str | None = None,
    actor_name: str | None = Query(None, alias="actor"),
    server_id: str | None = None,
    result: str | None = None,
    ref: str | None = None,
    actor: Actor = Depends(api_actor),
):
    rows = reads.ledger(
        actor.conn, actor.instance, since=since, until=until, kind=kind, actor=actor_name,
        server_id=server_id, result=result, ref=ref, limit=reads.EXPORT_LIMIT,
    )
    if format == "json":
        return Response(
            json.dumps(public(rows), ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="ledger.json"'},
        )
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["event_id", "inserted_at", "kind", "actor", "server_id", "result", "source_key"]
    )
    for row in rows:
        writer.writerow([
            safe_cell(c) for c in (
                row["event_id"], row["inserted_at"].isoformat(), row["kind"], row["actor"] or "",
                row["server_id"] or "", row["result"] or "", row["source_key"],
            )
        ])
    return Response(
        "﻿" + out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="ledger.csv"'},
    )


# --- 변경 -----------------------------------------------------------------------------------


@router.post("/servers")
def register_server(body: RegisterBody, actor: Actor = Depends(api_actor)):
    server_service.register(actor.ctx, actor.litellm(), body.server_id, body.url)
    return done(actor, id=body.server_id)


@router.post("/servers/{server_id}/suspend")
def suspend_server(server_id: str, body: SuspendBody, actor: Actor = Depends(api_actor)):
    confirm(server_id, body.confirm_name, "서버")
    server_service.suspend(actor.ctx, server_id, expected_version=body.state_version)
    return done(actor, id=server_id)


@router.post("/servers/{server_id}/resume")
def resume_server(server_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    server_service.resume(actor.ctx, server_id, expected_version=body.state_version)
    return done(actor, id=server_id)


@router.post("/relations")
def add_relation(body: RelationBody, actor: Actor = Depends(api_actor)):
    rid = relation_service.add(actor.ctx, body.org_id, body.server_id, body.purpose, body.team_id)
    return done(actor, id=rid)


@router.post("/relations/{relation_id}/terminate")
def terminate_relation(relation_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    relation_service.terminate(actor.ctx, relation_id, expected_version=body.state_version)
    return done(actor, id=relation_id)


@router.post("/relations/{relation_id}/finish")
def finish_relation(relation_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    relation_service.finish(actor.ctx, relation_id, expected_version=body.state_version)
    return done(actor, id=relation_id)


# --- 증빙 ---------------------------------------------------------------------------------------


class EvidenceBody(BaseModel):
    kind: str
    subject_id: str
    summary: str
    ref: str | None = None
    sha256: str | None = None
    valid_days: int | None = Field(None, ge=1)
    not_applicable: bool = False


def attach_evidence(actor: Actor, body: EvidenceBody) -> str:
    valid_until = (
        None if body.valid_days is None else datetime.now(UTC) + timedelta(days=body.valid_days)
    )
    return evidence_service.attach(
        actor.ctx, body.kind, body.subject_id, summary=body.summary, ref=body.ref or None,
        sha256=body.sha256 or None, valid_until=valid_until, not_applicable=body.not_applicable,
    )


@router.get("/evidence")
def list_evidence(
    subject_kind: Literal["intake", "server", "relation"], subject_id: str,
    actor: Actor = Depends(api_actor),
):
    items = evidence_service.show(actor.ctx, subject_kind, subject_id)
    return {"items": public([
        {"kind": i["key"], "label": i["label"], "gate": i["gate"], "state": i["state"],
         "valid_until": i["row"]["valid_until"] if i["row"] else None}
        for i in items
    ])}


@router.post("/evidence")
def create_evidence(body: EvidenceBody, actor: Actor = Depends(api_actor)):
    return done(actor, id=attach_evidence(actor, body))


@router.post("/approvals")
def grant_approval(body: ApprovalBody, actor: Actor = Depends(api_actor)):
    relation = reads.relation(actor.conn, actor.instance, body.relation_id)
    if relation is None:
        raise AdminError(AdminCode.NOT_FOUND, f"이용 관계 {body.relation_id}이(가) 없습니다.")
    high = reads.high_risk_tools(actor.conn, actor.instance, relation["server_id"])
    valid_from, valid_until = window(
        body.valid_days, body.approval_class, approval_days(body.approval_class, body.tools, high)
    )
    approval_id, _ = approval_service.approve(
        actor.ctx,
        actor.litellm(),
        relation_id=body.relation_id,
        scope_type=body.scope_type,
        scope_id=body.scope_id,
        tools=body.tools,
        valid_from=valid_from,
        valid_until=valid_until,
        approval_class=body.approval_class,
        basis_text=body.basis,
        requested_by=body.requested_by,
        allowlist_ids=body.allowlist_ids,
        second=second_approver(actor, body.second_approver_token),
        conditions=approval_conditions(body, high),
        expected_version=body.state_version,
    )
    return done(actor, id=approval_id)


def renew_approvals(actor: Actor) -> tuple[int, list[str]]:
    """만료가 가까운데 계약·등급이 그대로인 승인을 같은 범위·도구·길이로 모두 갱신한다.

    승인마다 따로 확정하고, 갱신하지 못한 승인(분리 원칙 등)은 사유를 모아 돌려준다.
    """
    if actor.role != "admin":
        raise forbidden("승인 일괄 갱신은 admin만 할 수 있습니다.")
    renewed, failed = 0, []
    litellm = actor.litellm()
    for row in renewal_service.candidates(actor.conn, actor.instance)["unchanged"]:
        now = datetime.now(UTC)
        try:
            approval_service.approve(
                actor.ctx, litellm, relation_id=str(row["relation_id"]),
                scope_type=row["scope_type"], scope_id=row["scope_id"], tools=list(row["tools"]),
                valid_from=now, valid_until=now + (row["valid_until"] - row["valid_from"]),
                approval_class=row["class"], basis_text=f"기간 갱신(이전 승인 {row['id']})",
                requested_by=row["requested_by"], allowlist_ids=[], second=None,
                conditions=row["conditions"],
            )
            renewed += 1
        except ControlError as error:
            actor.conn.rollback()
            failed.append(f"{row['server_id']}: {error}")
    return renewed, failed


@router.post("/approvals/renew")
def renew_all(actor: Actor = Depends(api_actor)):
    renewed, failed = renew_approvals(actor)
    return done(actor, renewed=renewed, failed=failed)


@router.post("/approvals/{approval_id}/revoke")
def revoke_approval(approval_id: str, body: RevokeBody, actor: Actor = Depends(api_actor)):
    approval_service.revoke(
        actor.ctx, approval_id, body.reason, body.deny, expected_version=body.state_version
    )
    return done(actor, id=approval_id)


@router.post("/denials")
def create_denial(body: DenialBody, actor: Actor = Depends(api_actor)):
    did = denial_service.deny(
        actor.ctx, scope_type=body.scope_type, scope_id=body.scope_id, server_id=body.server_id,
        tools=body.tools, reason=body.reason, org_id=body.org_id,
    )
    return done(actor, id=did)


@router.post("/denials/{denial_id}/lift")
def lift_denial(denial_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    denial_service.lift(actor.ctx, denial_id, expected_version=body.state_version)
    return done(actor, id=denial_id)


@router.post("/call-approvals/{call_id}/approve")
def approve_call(call_id: str, body: ApproveCallBody, actor: Actor = Depends(api_actor)):
    call_approval_service.approve(
        actor.ctx, call_id, second_approver(actor, body.second_approver_token),
        expected_version=body.state_version, window_minutes=body.window_minutes or None,
        default_window=body.window_minutes is None,
    )
    return done(actor, id=call_id)


@router.post("/call-approvals/{call_id}/reject")
def reject_call(call_id: str, body: RejectCallBody, actor: Actor = Depends(api_actor)):
    call_approval_service.reject(
        actor.ctx, call_id, expected_version=body.state_version, reason=body.reason
    )
    return done(actor, id=call_id)


@router.post("/call-approvals/{call_id}/extend")
def extend_call(call_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    call_approval_service.extend(actor.ctx, call_id, expected_version=body.state_version)
    return done(actor, id=call_id)


@router.post("/call-approvals/{call_id}/cancel")
def cancel_call(call_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    call_approval_service.cancel(actor.ctx, call_id, expected_version=body.state_version)
    return done(actor, id=call_id)


@router.post("/orgs")
def add_org(body: OrgBody, actor: Actor = Depends(api_actor)):
    org_service.add(actor.ctx, body.org_id, body.name)
    return done(actor, id=body.org_id)


@router.post("/orgs/{org_id}/close")
def close_org(org_id: str, body: CloseOrgBody, actor: Actor = Depends(api_actor)):
    confirm(org_id, body.confirm_name, "조직")
    org_service.close(actor.ctx, org_id, expected_version=body.state_version)
    return done(actor, id=org_id)


@router.post("/orgs/{org_id}/bindings")
def bind_org(org_id: str, body: BindingBody, actor: Actor = Depends(api_actor)):
    org_service.bind(actor.ctx, org_id, body.subject_type, body.subject_id)
    return done(actor, id=org_id)


@router.post("/orgs/bindings/remove")
def unbind_org(body: BindingBody, actor: Actor = Depends(api_actor)):
    org_service.unbind(actor.ctx, body.subject_type, body.subject_id)
    return done(actor)


@router.post("/call-approval-rules")
def add_call_approval_rule(body: CallApprovalRuleBody, actor: Actor = Depends(api_actor)):
    rid = call_approval_rule_service.add(actor.ctx, **body.model_dump())
    return done(actor, id=rid)


@router.post("/call-approval-rules/{rule_id}/disable")
def disable_call_approval_rule(rule_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    call_approval_rule_service.disable(actor.ctx, rule_id, expected_version=body.state_version)
    return done(actor, id=rule_id)


@router.post("/allowlists")
def add_allowlist(body: AllowlistBody, actor: Actor = Depends(api_actor)):
    aid = allowlist_service.add(
        actor.ctx, body.kind, body.value, body.valid_from or datetime.now(UTC), body.valid_until,
        body.org_id, body.note,
    )
    return done(actor, id=aid)


@router.post("/allowlists/{allowlist_id}/lift")
def lift_allowlist(allowlist_id: str, body: Versioned, actor: Actor = Depends(api_actor)):
    allowlist_service.lift(actor.ctx, allowlist_id, expected_version=body.state_version)
    return done(actor, id=allowlist_id)


@router.post("/settings/mode")
def set_mode(body: ModeBody, actor: Actor = Depends(api_actor)):
    ceiling = actor.config.control.mode_ceiling
    settings_service.set_mode(actor.ctx, body.mode, ceiling, expected_version=body.state_version)
    return done(actor)


@router.post("/settings/default-org")
def set_default_org(body: DefaultOrgBody, actor: Actor = Depends(api_actor)):
    settings_service.set_default_org(actor.ctx, body.org_id, expected_version=body.state_version)
    return done(actor)


@router.post("/operators")
def add_operator(body: OperatorBody, actor: Actor = Depends(api_actor)):
    token = operator_service.add(
        actor.ctx, actor.litellm(), body.name, body.role, body.user_id, body.expires_in_days
    )
    return done(actor, id=body.name, token=token)


@router.post("/operators/{name}/role")
def set_operator_role(name: str, body: SetRoleBody, actor: Actor = Depends(api_actor)):
    operator_service.set_role(actor.ctx, name, body.role, expected_version=body.state_version)
    return done(actor, id=name)


@router.post("/operators/{name}/remove")
def remove_operator(name: str, body: RemoveOperatorBody, actor: Actor = Depends(api_actor)):
    confirm(name, body.confirm_name, "운영자")
    operator_service.remove(actor.ctx, name, expected_version=body.state_version)
    return done(actor, id=name)


# --- 신청·수용검증 ----------------------------------------------------------------------------


class RequesterBody(Versioned):
    user_id: str


class IntakeDecisionBody(Versioned):
    decision: Literal["approve", "except", "reject"]
    reason: str | None = None
    valid_days: int | None = None
    scope_type: Literal["key", "user", "team"] | None = None
    scope_id: str | None = None
    team_id: str | None = None
    second_approver_token: str | None = None


class ReapproveBody(Versioned):
    intake_id: str
    tool_contract_ids: list[str] = []
    deployment_contract_id: str | None = None


def intake_days(decision: str, valid_days: int | None, strict: bool) -> int:
    """신청 승인의 기본 기간(일): 일반 90, 높음·심각 도구를 포함하거나 예외이면 30."""
    days = valid_days or (STRICT_DAYS if decision == "except" or strict else STANDARD_DAYS)
    if days < 1:
        raise ControlError("유효 기간은 1일 이상이어야 합니다.")
    if decision == "except" and days > EXCEPTION_MAX_DAYS:
        raise ControlError(f"예외 승인의 유효 기간은 {EXCEPTION_MAX_DAYS}일을 넘을 수 없습니다.")
    return days


def decide_intake(actor: Actor, intake_id: str, body: IntakeDecisionBody) -> dict:
    valid_until = None
    if body.decision != "reject":
        info = intake_service.show(actor.ctx, intake_id)
        strict = any(t["risk_grade"] in ("high", "critical") for t in info["tool_contracts"])
        valid_until = datetime.now(UTC) + timedelta(
            days=intake_days(body.decision, body.valid_days, strict)
        )
    return intake_service.decide(
        actor.ctx, intake_id, body.decision, reason=body.reason, valid_until=valid_until,
        scope_type=body.scope_type, scope_id=body.scope_id, team_id=body.team_id,
        second=second_approver(actor, body.second_approver_token),
        expected_version=body.state_version,
        litellm=None if body.decision == "reject" else actor.litellm,
    )


@router.get("/intakes")
def list_intakes(status: str | None = None, actor: Actor = Depends(api_actor)):
    rows = intake_service.list_intakes(actor.ctx, status)
    return {"items": public(sorted(rows, key=lambda r: (r["created_at"], str(r["id"]))))}


@router.get("/intakes/{intake_id}")
def get_intake(intake_id: str, actor: Actor = Depends(api_actor)):
    return public(intake_service.show(actor.ctx, intake_id))


@router.post("/intakes/{intake_id}/requester")
def assign_requester(intake_id: str, body: RequesterBody, actor: Actor = Depends(api_actor)):
    intake_service.assign_requester(
        actor.ctx, actor.litellm(), intake_id, body.user_id, expected_version=body.state_version
    )
    return done(actor, id=intake_id)


@router.post("/intakes/{intake_id}/recheck")
def recheck_intake(intake_id: str, body: RecheckBody, actor: Actor = Depends(api_actor)):
    job = intake_service.recheck(
        actor.ctx, intake_id, expected_version=body.state_version,
        url=body.url or None, transport=body.transport or None,
    )
    return done(actor, id=intake_id, job_id=job)


@router.post("/intakes/{intake_id}/decision")
def decide_intake_route(
    intake_id: str, body: IntakeDecisionBody, actor: Actor = Depends(api_actor)
):
    decide_intake(actor, intake_id, body)
    return done(actor, id=intake_id)


# --- 계약 변경 비교와 재승인 ------------------------------------------------------------------


@router.get("/contracts")
def list_contract_changes(actor: Actor = Depends(api_actor)):
    return {"items": public(reads.drifted_servers(actor.conn, actor.instance))}


@router.get("/servers/{server_id}/contracts")
def get_contracts(server_id: str, actor: Actor = Depends(api_actor)):
    return public(contract_service.show(actor.ctx, server_id))


@router.get("/servers/{server_id}/contracts/diff")
def get_contract_diff(server_id: str, actor: Actor = Depends(api_actor)):
    info = contract_service.diff(actor.ctx, server_id)
    return {"changes": public(compare.changes(info)),
            "plan": public(reads.reapproval_plan(actor.conn, actor.instance, server_id))}


@router.post("/servers/{server_id}/contracts/reapprove")
def reapprove_contracts(server_id: str, body: ReapproveBody, actor: Actor = Depends(api_actor)):
    result = contract_service.reapprove(
        actor.ctx, server_id, body.intake_id, body.tool_contract_ids,
        deployment_id=body.deployment_contract_id, expected_version=body.state_version,
    )
    return done(actor, **result)
