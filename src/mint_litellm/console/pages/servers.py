"""MCP 서버·신청·계약 화면."""

import csv
import io
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from mint_litellm.console import api, compare, labels, pack_view
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages import intake_submission
from mint_litellm.console.pages.common import act, server_display
from mint_litellm.console.templating import local_time, render
from mint_litellm.control import intake_checks, source_scan, usage_reader
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import call_review as review_service
from mint_litellm.control.services import contracts as contract_service
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import evidence as evidence_service
from mint_litellm.control.services import exception_holds, local_intakes, reads
from mint_litellm.control.services import intake_inspections as inspection_service
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.services import relations as relation_service
from mint_litellm.control.services import servers as server_service
from mint_litellm.control.services.base import require_role
from mint_litellm.types.contracts import ACTION_DENIAL_PREFIX, DENIABLE_ACTIONS

router = APIRouter(dependencies=[Depends(require_csrf)])

# --- 서버 목록 ---------------------------------------------------------------------------------

ACTIVE_STATUSES = ("approved", "awaiting_approval", "suspended")
# (묶음, 표시, 결정색, 주소에 쓰는 값)
DONUT = (
    ("approved", "승인됨", "allow", "approved"),
    ("awaiting_approval", "승인 대기", "approve", "waiting"),
    ("changed", "변경됨", "block", ""),
    ("suspended", "중지됨", "observe", "stopped"),
    ("other", "그 밖", "observe", "other"),
)
FILTERS = {
    "changed": lambda r: r["contract"] in ("changed", "pending"),
    "provisional": lambda r: r["contract"] == "provisional",
    "vuln": lambda r: r["vulns"] > 0,
}
FILTER_NAMES = {"changed": "계약 변경", "provisional": "임시 계약", "vuln": "취약점 조치"}


def contract_state(row: dict, listed: bool) -> str | None:
    """서버 목록의 「계약」 열 값. 계약을 관리하지 않는 서버는 호출마다 추정한 임시 계약을 쓴다."""
    if row["contract_status"] != "managed":
        return None if row["status"] in ("rejected", "terminated") else "provisional"
    if row["deployment_drift"] or row["drifted"]:
        return "changed"
    return "pending" if listed else "ok"


def donut_bucket(row: dict) -> str:
    if row["contract"] == "changed":
        return "changed"
    return row["status"] if row["status"] in ACTIVE_STATUSES else "other"


@router.get("/servers")
def servers(request: Request, actor: Actor = Depends(page_actor)):
    rows = reads.servers(actor.conn, actor.instance)
    server_display(actor, rows)
    listed = {r["server_id"]: r for r in reads.drifted_servers(actor.conn, actor.instance)}
    vulns = reads.server_vuln_counts(actor.conn, actor.instance)
    for r in rows:
        r["contract"] = contract_state(r, r["server_id"] in listed)
        r["plan_status"] = (listed.get(r["server_id"]) or {}).get("plan_status")
        r["vulns"] = vulns.get(r["server_id"], 0)
    counts = {item[0]: 0 for item in DONUT}
    token = {item[3]: item[0] for item in DONUT}
    for r in rows:
        counts[donut_bucket(r)] += 1
    kind, status = request.query_params.get("filter", ""), request.query_params.get("status", "")
    shown = rows
    if kind in FILTERS:
        shown = [r for r in rows if FILTERS[kind](r)]
    elif status:
        shown = [r for r in rows if donut_bucket(r) == token.get(status)]
    numbers = {key: sum(1 for r in rows if test(r)) for key, test in FILTERS.items()}
    donut = {
        "items": [
            {
                "name": label,
                "value": counts[key],
                "decision": decision,
                "href": f"/servers?status={link}" if link else "/servers?filter=changed",
            }
            for key, label, decision, link in DONUT
            if counts[key]
        ]
    }
    ctx = {
        "rows": shown,
        "total": len(rows),
        "donut": donut,
        "numbers": numbers,
        "chips": [("", "전체", len(rows))]
        + [(f"?filter={key}", FILTER_NAMES[key], numbers[key]) for key in FILTERS],
        "kind": kind,
        "status": status,
    }
    return render(request, "servers.html", ctx, actor=actor)


REGISTRY_HEADER = ("MCP 서버", "제공자", "승인 상태", "승인 범위", "만료", "신청자")


@router.get("/servers/export")
def export_registry(actor: Actor = Depends(page_actor)):
    """MCP 서버 등록부(서버별 승인 내역)를 CSV로 내려받는다."""
    rows = reads.servers(actor.conn, actor.instance)
    server_display(actor, rows)
    intake = {
        r["server_id"]: r
        for r in fetchall(
            actor.conn,
            "SELECT DISTINCT ON (server_id) server_id, provider,"
            " coalesce(owner_user_id, requested_by) AS requester FROM mint.intakes"
            " WHERE instance_id = %s ORDER BY server_id, created_at DESC",
            (actor.instance,),
        )
    }
    approved: dict[str, list[dict]] = {}
    for a in fetchall(
        actor.conn,
        "SELECT server_id, scope_type, scope_id, tools, valid_until, status FROM mint.approvals"
        " WHERE instance_id = %s AND status IN ('pending', 'active')"
        " ORDER BY server_id, valid_until DESC, id",
        (actor.instance,),
    ):
        approved.setdefault(a["server_id"], []).append(a)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(REGISTRY_HEADER)
    for s in rows:
        info = intake.get(s["server_id"]) or {}
        base = (s["server_name"] or s["server_id"], info.get("provider") or "")
        who = info.get("requester") or s["registered_by"] or ""
        for a in approved.get(s["server_id"]) or [None]:
            if a is None:
                state, scope, until = labels.pick(labels.SERVER, s["status"]), "", ""
            else:
                state = labels.pick(labels.APPROVAL, a["status"])
                scope = f"{labels.pick(labels.SCOPE, a['scope_type'])} {a['scope_id']}"
                until = "" if a["valid_until"].year >= 2999 else local_time(a["valid_until"])
            writer.writerow([api.safe_cell(c) for c in (*base, state, scope, until, who)])
    return Response(
        "﻿" + out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="mcp-registry.csv"'},
    )


# --- 서버 상세 ---------------------------------------------------------------------------------

SERVER_TABS = (
    ("overview", "개요"),
    ("contract", "계약"),
    ("security", "보안"),
    ("usage", "이용"),
)
# 이전 주소의 탭 이름은 묶은 탭으로 열린다.
TAB_ALIAS = {"tools": "contract", "packages": "security", "vulns": "security", "evidence": "usage"}


def contract_context(request: Request, actor: Actor, server_id: str) -> dict:
    info = contract_service.diff(actor.ctx, server_id)
    rows = compare.changes(info)
    wanted = (request.query_params.get("scope", ""), request.query_params.get("name", ""))
    chosen = next((r for r in rows if (r["scope"], r["name"]) == wanted), None)
    return {
        "rows": rows,
        "chosen": chosen,
        "sides": compare.side_by_side(chosen["approved"], chosen["observed"]) if chosen else None,
        "plan": reads.reapproval_plan(actor.conn, actor.instance, server_id),
        "cand": reads.candidates(actor.conn, actor.instance, server_id),
        "provisional": reads.provisional_contracts(actor.conn, actor.instance, server_id),
    }


def server_page(
    request: Request, actor: Actor, server_id: str, error=None, status=200, tab: str | None = None
):
    row = reads.server(actor.conn, actor.instance, server_id)
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, f"서버 {server_id}을(를) 찾을 수 없습니다.")
    server_display(actor, [row])
    tab = tab or request.query_params.get("tab", "")
    tab = TAB_ALIAS.get(tab, tab)
    tab = tab if tab in dict(SERVER_TABS) else "overview"
    evidence = evidence_service.show(actor.ctx, "server", server_id)
    changed_tools = sum(1 for t in row["tools"] if t["drift"] != "none")
    counts = {
        "contract": changed_tools + bool(row["deployment_drift"]),
        "security": len(row["vulns"]),
        "usage": sum(
            1 for e in evidence if e["gate"] == "approve" and e["state"] in ("missing", "expired")
        ),
    }
    ctx = {
        "s": row,
        "error": error,
        "tab": tab,
        "evidence": evidence,
        "tabs": [(key, label, counts.get(key, 0)) for key, label in SERVER_TABS],
        "changed_tools": changed_tools,
        "critical": sum(1 for v in row["vulns"] if v["severity"] == "critical" or v["exploited"]),
        "active_approvals": sum(1 for a in row["approvals"] if a["status"] == "active"),
        "provisional": row["contract_status"] != "managed",
        "ctl": tool_controls(actor, server_id),
        "impact": relation_impacts(actor, row["relations"]) if tab == "usage" else {},
        "c": contract_context(request, actor, server_id) if tab == "contract" else None,
        "pack": pack_view.view(
            pack_view.read(actor.conn, actor.instance, server_id, approved=True), "decided"
        )
        if row["identity_kind"] == "stdio" and tab == "overview"
        else None,
    }
    return render(request, "server_detail.html", ctx, actor=actor, status=status)


def relation_impacts(actor: Actor, relations: list[dict]) -> dict[str, dict]:
    """이용 종료 전에 보이는 영향: 거둘 승인 수, 쓰던 사용자 수, 그 사용자들의 연결된 PC 수."""
    found = {}
    for r in relations:
        if r["status"] != "active":
            continue
        rows = fetchall(
            actor.conn,
            "SELECT scope_type, scope_id FROM mint.approvals WHERE instance_id = %s"
            " AND relation_id = %s AND status = 'active'",
            (actor.instance, str(r["id"])),
        )
        users = {a["scope_id"] for a in rows if a["scope_type"] == "user"}
        teams = [a["scope_id"] for a in rows if a["scope_type"] == "team"]
        if teams:
            users |= {
                p["user_id"]
                for p in fetchall(
                    actor.conn,
                    "SELECT user_id FROM mint.directory_users WHERE instance_id = %s"
                    " AND gone_at IS NULL AND team_ids ?| %s",
                    (actor.instance, teams),
                )
            }
        pcs = fetchone(
            actor.conn,
            "SELECT count(*) AS n FROM mint.endpoint_installs WHERE instance_id = %s"
            " AND revoked_at IS NULL AND user_id = ANY(%s)",
            (actor.instance, sorted(users)),
        )["n"] if users else 0
        found[str(r["id"])] = {"approvals": len(rows), "users": len(users), "pcs": pcs}
    return found


def tool_controls(actor: Actor, server_id: str) -> dict:
    """도구·행위별 차단(거부)과 호출별 검토 상태. 관리자에게만 조작 버튼이 보인다."""
    blocked: dict[str, dict] = {}
    actions: dict[str, dict] = {}
    whole = None
    for d in reads.denials(actor.conn, actor.instance, active_only=True):
        if d["scope_type"] != "server" or d["scope_id"] != server_id:
            continue
        if not d["tools"]:
            whole = whole or d
        for tool in d["tools"] or []:
            if tool.startswith(ACTION_DENIAL_PREFIX):
                actions.setdefault(tool[len(ACTION_DENIAL_PREFIX):], d)
            else:
                blocked.setdefault(tool, d)
    return {
        "blocked": blocked,
        "actions": actions,
        "action_choices": [a for a in labels.ACTION if a in DENIABLE_ACTIONS],
        "whole": whole,
        "reviewed": review_service.marked(actor.conn, actor.instance, server_id),
        "can": actor.role == "admin",
        "server_id": server_id,
    }


def safe_next(value: str, fallback: str) -> str:
    return value if value.startswith("/") and not value.startswith("//") else fallback


@router.post("/servers/{server_id}/tools/{operation}")
def tool_control(
    server_id: str,
    operation: str,
    request: Request,
    tool: str = Form(""),
    user: str = Form(""),
    action_type: str = Form(""),
    reason: str = Form(""),
    next: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    back = safe_next(next, f"/servers/{server_id}?tab=contract")

    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "관리자만 바꿀 수 있습니다.")
        if operation == "block":
            denial_service.deny(
                actor.ctx, scope_type="user" if user else "server",
                scope_id=user or server_id, server_id=server_id,
                tools=[tool] if tool else None, reason=reason.strip() or "관리자 차단",
                org_id=None, action_types=[action_type] if action_type else None,
            )
        elif operation == "unblock":
            for d in reads.denials(actor.conn, actor.instance, active_only=True):
                if (
                    d["scope_type"] == "server" and d["scope_id"] == server_id
                    and (
                        d["tools"] == [ACTION_DENIAL_PREFIX + action_type] if action_type
                        else d["tools"] == [tool] if tool else not d["tools"]
                    )
                ):
                    denial_service.lift(
                        actor.ctx, str(d["id"]), expected_version=d["state_version"]
                    )
        elif operation in ("review", "unreview"):
            review_service.set_tool(actor.ctx, server_id, tool, operation == "review")
        else:
            raise ValueError(operation)

    ok = {"block": "denied", "unblock": "lifted"}.get(operation, "review_changed")
    return act(
        actor, action, ok, back,
        lambda **kw: server_page(request, actor, server_id, tab="contract", **kw),
    )


@router.get("/servers/{server_id}")
def server_detail(server_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return server_page(request, actor, server_id)


def evidence_form(
    actor: Actor,
    subject_id: str,
    kind: str,
    summary: str,
    ref: str,
    valid_days: int | None,
    not_applicable: str,
    sha256: str = "",
) -> Callable[[], None]:
    def action():
        api.attach_evidence(
            actor,
            api.EvidenceBody(
                kind=kind,
                subject_id=subject_id,
                summary=summary,
                ref=ref.strip() or None,
                sha256=sha256.strip() or None,
                valid_days=valid_days,
                not_applicable=bool(not_applicable),
            ),
        )

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
    return act(
        actor,
        evidence_form(actor, server_id, kind, summary, ref, valid_days, not_applicable, sha256),
        "evidence_attached",
        f"/servers/{server_id}?tab=usage",
        lambda **kw: server_page(request, actor, server_id, tab="usage", **kw),
    )


def back_to(server_id: str, next: str) -> str:
    """중지·재개 뒤에 돌아갈 곳: 목록에서 눌렀으면 목록, 아니면 상세."""
    return next if next in ("/servers", "/approvals?tab=servers") else f"/servers/{server_id}"


@router.post("/servers/{server_id}/suspend")
def suspend_server(
    server_id: str,
    request: Request,
    state_version: int = Form(...),
    confirm_name: str = Form(""),
    next: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        api.confirm(server_id, confirm_name, "서버")
        server_service.suspend(actor.ctx, server_id, expected_version=state_version)

    return act(
        actor,
        action,
        "suspended",
        back_to(server_id, next),
        lambda **kw: server_page(request, actor, server_id, **kw),
    )


@router.post("/servers/{server_id}/resume")
def resume_server(
    server_id: str,
    request: Request,
    state_version: int = Form(...),
    next: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: server_service.resume(actor.ctx, server_id, expected_version=state_version),
        "resumed",
        back_to(server_id, next),
        lambda **kw: server_page(request, actor, server_id, **kw),
    )


def relation_action(server_id: str, relation_id: str, request: Request, actor: Actor, step: str,
                    state_version: int):
    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "관리자만 이용을 종료할 수 있습니다.")
        found = reads.relation(actor.conn, actor.instance, relation_id)
        if found is None or found["server_id"] != server_id:
            raise AdminError(AdminCode.NOT_FOUND, "이용 관계를 찾을 수 없습니다.")
        (relation_service.terminate if step == "terminate" else relation_service.finish)(
            actor.ctx, relation_id, expected_version=state_version
        )

    return act(
        actor, action, "relation_terminating" if step == "terminate" else "relation_finished",
        f"/servers/{server_id}?tab=usage",
        lambda **kw: server_page(request, actor, server_id, tab="usage", **kw),
    )


@router.post("/servers/{server_id}/relations/{relation_id}/terminate")
def terminate_relation(
    server_id: str, relation_id: str, request: Request, state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return relation_action(server_id, relation_id, request, actor, "terminate", state_version)


@router.post("/servers/{server_id}/relations/{relation_id}/finish")
def finish_relation(
    server_id: str, relation_id: str, request: Request, state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return relation_action(server_id, relation_id, request, actor, "finish", state_version)


# --- 신청·수용검증 ----------------------------------------------------------------------------

STAGES = {
    "received": ("received", "checking"),
    "passed": ("passed",),
    "indeterminate": ("indeterminate",),
    "decided": ("decided",),
    "failed": ("failed",),
}
OPEN_STATUSES = ("received", "checking", "passed", "indeterminate", "failed")
STALL = timedelta(hours=24)


def intakes_page(request: Request, actor: Actor, error=None, status=200):
    wanted = request.query_params.get("status") or ""
    source = request.query_params.get("source") or ""
    rows = intake_service.list_intakes(actor.ctx)
    source_counts = {k: sum(1 for r in rows if r["source"] == k) for k in labels.SOURCE}
    if source in labels.SOURCE:
        rows = [r for r in rows if r["source"] == source]
    else:
        source = ""
    server_display(actor, rows)
    rows.sort(key=lambda r: (r["created_at"], str(r["id"])))  # 오래된 것 먼저
    now = datetime.now(UTC)
    for r in rows:
        r["age"] = (now - r["created_at"]).total_seconds()
        r["stalled"] = r["status"] in OPEN_STATUSES and now - r["created_at"] > STALL
    counts = {key: sum(1 for r in rows if r["status"] in kinds) for key, kinds in STAGES.items()}
    stalled = sum(1 for r in rows if r["stalled"])
    if wanted == "stalled":
        shown = [r for r in rows if r["stalled"]]
    elif wanted:
        shown = [r for r in rows if r["status"] in STAGES.get(wanted, (wanted,))]
    else:
        shown = rows
    funnel = {
        "labels": [labels.INTAKE_STAGE[k] for k in STAGES],
        "values": [counts[k] for k in STAGES],
        "links": [f"/intakes?status={k}" for k in STAGES],
        "horizontal": True,
    }
    ctx = {
        "rows": shown,
        "wanted": wanted,
        "source": source,
        "sources": [(k, labels.SOURCE[k], n) for k, n in source_counts.items() if n],
        "error": error,
        "total": len(rows),
        "funnel": funnel,
        "waiting": sum(counts[k] for k in ("received", "passed", "indeterminate")),
        "stalled": stalled,
    }
    return render(request, "intakes.html", ctx, actor=actor, status=status)


@router.get("/intakes")
def intakes(request: Request, actor: Actor = Depends(page_actor)):
    return intakes_page(request, actor)


INTAKE_TABS = (("overview", "검사 결과"), ("info", "신청 내용"), ("evidence", "증빙"))
PACK_TAB = ("pack", "실행 묶음")


def shown_result(check: dict) -> str:
    """화면에 보이는 검사 결과. 코드 검사의 위험 발견은 「검토 필요」다(상태 계산은 원래 값)."""
    if check_na(check):
        return "n/a"
    inputs = check.get("inputs") if isinstance(check.get("inputs"), dict) else None
    if check.get("check") == "code_scan" and check["result"] == "pass" and (
            source_scan.review_needed(inputs)):
        return "review"
    return check["result"]


def check_na(check: dict) -> bool:
    """로컬(stdio·묶음) 신청의 원격 주소 검사: 옛 기록(지원하지 않음 실패)도 해당 없음이다."""
    return check.get("check") == "url_guard" and check.get("reason_code") in (
        "NOT_APPLICABLE", "UNSUPPORTED")


@router.get("/intakes/{intake_id}/sbom.json")
def intake_sbom(intake_id: str, actor: Actor = Depends(page_actor)):
    """신청 실행 묶음의 구성요소 목록(CycloneDX)."""
    from fastapi.responses import JSONResponse


    row = fetchone(
        actor.conn,
        "SELECT i.server_id, d.pack_manifest, d.pack_spec FROM mint.intakes i"
        " JOIN mint.deployment_contracts d ON d.instance_id = i.instance_id"
        " AND d.server_id = i.server_id WHERE i.instance_id = %s AND i.id::text = %s"
        " AND d.pack_manifest IS NOT NULL ORDER BY d.id DESC LIMIT 1",
        (actor.instance, intake_id),
    )
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, "구성요소 목록이 없습니다.")
    spec = row["pack_spec"] or {}
    doc = source_scan.sbom(row["pack_manifest"], row["server_id"], spec.get("version"))
    name = f"{row['server_id']}-sbom.cdx.json"
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _person(actor: Actor, user_id: str | None) -> str | None:
    """사용자 식별자의 사람 이름(이메일·아이디). 명부에 없으면 None."""
    if not user_id:
        return None
    row = fetchone(actor.conn, "SELECT email FROM mint.directory_users WHERE instance_id = %s"
                   " AND user_id = %s", (actor.instance, user_id))
    return row and row["email"]


def intake_progress(
    intake: dict, lacking: list[str], checks: list[dict] | None = None,
    hold: bool = False, cause: bool = False, seen: int = 0,
) -> list[tuple[str, str]]:
    """진행 표시 4단계(접수·검사·증빙·결정)를 (심각도, 이름)으로."""
    st = intake["status"]
    if intake.get("decision") == "withdrawn":
        return [("ok", "접수"), ("off", "검사 이력 보존"), ("off", "승인 심사 종료"),
                ("off", "신청 철회")]
    checks = [c for c in checks or [] if not check_na(c)] if checks is not None else None
    st = "passed" if st == "failed" and checks is not None and not any(
        c["result"] == "fail" for c in checks) and any(
        c["result"] != "fail" for c in checks) else st
    checked = {
        "failed": ("error", "검사 실패"),
        "received": ("wait", "검사 중"),
        "checking": ("wait", "검사 중"),
        "indeterminate": ("wait", "검사 판별 불가"),
    }.get(st, ("ok", "검사 통과"))
    if st == "decided":
        if any(c["result"] == "fail" for c in checks or []):
            checked = ("error", "검사 실패")
        elif not checks or any(c["result"] == "indeterminate" for c in checks):
            checked = ("wait", "검사 판별 불가")
    if seen and checked[0] == "wait":
        checked = ("ok", f"도구 {seen}개 확인")  # 검사는 못 읽었지만 실제 호출로 발견됐다
    if st in ("received", "checking", "failed") or checked[0] == "error" or cause:
        proof = ("off", "증빙")
    elif st == "decided" and intake.get("decision") in ("approved", "exception"):
        proof = ("off", "증빙 해당 없음")  # 승인된 뒤에는 부족 표시를 남기지 않는다
    else:
        # 승인 단계 증빙은 권고다(승인을 막지 않는다). 빨간 「부족」으로 보이면 검사 실패로 읽힌다.
        proof = ("wait", f"권장 증빙 {len(lacking)}건") if lacking else ("ok", "증빙 충족")
    if st == "decided":
        decision = ("ok", "결정 완료")
    elif hold:
        decision = ("wait", "두 번째 승인 대기")
    else:
        decision = (
            ("off", "결정") if st in ("received", "checking") else ("wait", "결정 대기")
        )
    return [("ok", "접수"), checked, proof, decision]


DELIVERY_STAGES = (
    ("approved", "승인"), ("registry_active", "LiteLLM 등록"), ("key_applied", "키 반영"),
    ("device_received", "PC 수신"), ("started", "시작"), ("discovered", "도구 발견"),
    ("first_response", "첫 응답"),
)


def delivery_progress(
    receipts: list[dict], *, local: bool = False, called: bool = False,
    failure: tuple[str, str] | None = None,
) -> list[tuple[str, str]]:
    """적용 7단계. 단조: 뒤 단계 증거(영수증·호출 기록)가 있으면 앞 단계는 완료.
    로컬 서버는 LiteLLM 등록을 건너뛰고, 실패 단계는 사유와 함께 오류로 보인다."""
    if not receipts and not called:
        return []
    latest = max((r["decision_version"] for r in receipts), default=0)
    done = {r["stage"] for r in receipts if r["decision_version"] == latest}
    if not failure and "start_failed" in done and not called and not done & {
        "started", "discovered", "first_response"
    }:  # 단말이 알린 시작 실패는 시작 단계의 실패로 보인다
        broken = next((r.get("reason") for r in receipts if r["decision_version"] == latest
                       and r["stage"] == "start_failed"), None)
        failure = ("started", broken or "사유 없음")
    order = [stage for stage, _ in DELIVERY_STAGES]
    reached = max((order.index(x) for x in done if x in order), default=-1)
    if called:
        reached = len(order) - 1  # 첫 성공 호출이 있으면 단말 보고가 없어도 거기까지 왔다
    if failure and failure[0] in order and failure[0] not in done and not called:
        reached = max(reached, order.index(failure[0]) - 1)  # 실패한 단계 앞은 지났다
    waiting = False
    out = []
    for i, (stage, text) in enumerate(DELIVERY_STAGES):
        if i <= reached and not (local and stage == "registry_active"):
            out.append(("ok", text))
        elif local and stage == "registry_active":
            out.append(("off", f"{text} 해당 없음"))
        elif failure and failure[0] == stage and not called and not waiting:
            waiting = True
            out.append(("error", f"{text} 실패 · {failure[1]}"))
        elif not waiting:
            waiting = True
            out.append(("wait", f"{text} 대기"))
        else:
            out.append(("off", text))
    return out


def minutes_left(inspection: dict, now: datetime) -> str:
    """검사용 승인의 남은 시간(분 단위, 1분 미만은 1분)."""
    return f"{max(1, int((inspection['expires_at'] - now).total_seconds() // 60))}분"


JOB_ERRORS = {
    "litellm_http_400": "LiteLLM이 MCP 서버 등록을 거절했습니다(주소나 이름 확인)",
    "litellm_http_401": "LiteLLM 인증에 실패했습니다",
    "litellm_http_403": "LiteLLM이 요청을 거부했습니다",
    "litellm_unreachable": "LiteLLM에 연결하지 못했습니다",
}


def intake_job_error(conn, instance: str, intake: dict) -> dict | None:
    """검사 작업이 실패해 다시 시도 중이거나 멈췄으면 사유와 횟수(「검사 중」에 가려지지 않게)."""
    if intake["status"] not in ("received", "checking"):
        return None
    row = fetchone(
        conn, "SELECT status, attempts, max_attempts, last_error_code, run_after FROM mint.jobs"
        " WHERE instance_id = %s AND kind = 'intake_run' AND target_ref = %s"
        " AND last_error_code IS NOT NULL ORDER BY created_at DESC LIMIT 1",
        (instance, str(intake["id"])),
    )
    if row is None:
        return None
    code = row["last_error_code"]
    return {"text": JOB_ERRORS.get(code, f"검사 작업이 실패했습니다({code})"),
            "n": row["attempts"], "limit": row["max_attempts"],
            "stopped": row["status"] == "failed", "next": row["run_after"]}


def intake_page(
    request: Request,
    actor: Actor,
    intake_id: str,
    error=None,
    status=200,
    tab: str | None = None,
    decision_form: dict | None = None,
):
    info = intake_service.show(actor.ctx, intake_id)
    now = datetime.now(UTC)
    intake, checks, tools = info["intake"], info["checks"], info["tool_contracts"]
    try:
        entry = actor.litellm().get_server(intake["server_id"]) or {}
    except ControlError:
        entry = {}
    candidate = intake_service.deployment_candidate(actor.conn, actor.instance, intake["server_id"])
    server_name = entry.get("server_name") or entry.get("alias") or intake["server_id"]
    local = intake["source"] == "endpoint"
    intake_tabs = INTAKE_TABS[:1] + (PACK_TAB,) + INTAKE_TABS[1:] if local else INTAKE_TABS
    pack = (
        pack_view.view(
            pack_view.read(actor.conn, actor.instance, intake["server_id"]), intake["status"]
        )
        if local
        else None
    )
    tab = tab or request.query_params.get("tab", "")
    tab = tab if tab in dict(intake_tabs) else "overview"
    stale = any(
        c["check"] in ("connection", "definitions", "inspection")
        and now - c["ran_at"] > intake_service.EVIDENCE_MAX_AGE
        for c in checks
    )
    expiries = [c["evidence_valid_until"] for c in checks if c["evidence_valid_until"]]
    strict = any(t["risk_grade"] in ("high", "critical") for t in tools)
    evidence = evidence_service.show(actor.ctx, "intake", intake_id)
    needed = [e for e in evidence if e["gate"] == "approve"]
    lacking = [e["label"] for e in needed if e["state"] in ("missing", "expired")]
    risk = {
        g: sum(1 for t in tools if t["risk_grade"] == g)
        for g in ("low", "medium", "high", "critical")
    }
    status_now = intake["status"]
    if actor.role == "viewer":
        next_step = None
    elif status_now == "received" and not intake["requested_by"] and actor.role == "admin":
        next_step = "신청자 지정"
    elif status_now in ("passed", "indeterminate", "failed"):
        next_step = "결정"
    else:
        next_step = None
    hold = next(iter(exception_holds.pending(actor.conn, actor.instance, intake_id)), None)
    if hold and next_step == "결정":
        next_step = "다른 승인자의 확인"
    approved = intake["status"] == "decided" and intake["decision"] in ("approved", "exception")
    receipts = intake_service.delivery_receipts(actor.ctx, intake_id) if approved else []
    seen = (
        usage_reader.read_tools(actor.conn, actor.instance, intake["server_id"]) if approved else []
    )
    # 검사로 도구 목록을 못 받았으면 설명 검사·위험 등급은 파생 결과다.
    bad = next((c for c in checks if c["check"] == "inspection" and c["result"] != "pass"), None)
    why = labels.pick(labels.CHECK_REASON, bad["reason_code"]) if bad else ""
    lost = bad and not tools and not seen
    cause = f"검사로 도구 목록을 받지 못했습니다 · {why}" if lost else None
    answered = approved and usage_reader.has_response(  # 성공 응답이 돌아온 호출만
        actor.conn, actor.instance, intake["server_id"])
    refused = next((t for t in seen if t["blocked"]), None)
    failure = ("discovered", why) if lost else None
    if refused and not answered and not lost:
        failure = ("first_response", labels.outcome_reason(refused.get("reason")))
    delivery = delivery_progress(
        receipts, local=intake["source"] == "endpoint", called=answered, failure=failure,
    )
    inspections = (
        inspection_service.for_intake(actor.conn, actor.instance, intake["id"]) if local else []
    )
    open_inspection = next((x for x in inspections if x["status"] in inspection_service.OPEN), None)
    counted = [c for c in checks if not check_na(c)]
    ctx = {
        "delivery": delivery,
        "seen": seen,
        "i": intake,
        "inspect": {
            "open": open_inspection,
            "left": None if open_inspection is None else minutes_left(open_inspection, now),
            "latest": inspections[0] if inspections else None,
            "history": inspections,
            "can": local and status_now == "indeterminate" and open_inspection is None
            and bool(pack and pack["ready"]),
            "source": "단말 검사" if any(
                c["method"] == "endpoint:tools_list" and c["reason_code"] == "ENDPOINT_INSPECTED"
                for c in checks) else "검사 컨테이너",
        },
        "server_name": server_name,
        "ctl": tool_controls(actor, intake["server_id"]),
        "server_url": candidate["url"] if candidate else entry.get("url"),
        "checks": [{**c, "shown": shown_result(c)} for c in checks],
        "tools": tools,
        "stale": stale,
        "expires": min(expiries) if expiries else None,
        "days": api.STRICT_DAYS if strict else api.STANDARD_DAYS,
        "strict_days": api.STRICT_DAYS,
        "max_exception_days": api.EXCEPTION_MAX_DAYS,
        "can_assign": actor.config.litellm_admin is not None,
        "error": error,
        "evidence": evidence,
        "lacking": lacking,
        "tab": tab,
        "next_step": next_step,
        "tabs": [
            (key, label, len(lacking) if key == "evidence" else 0) for key, label in intake_tabs
        ],
        "pack": pack,
        "requester_name": _person(actor, intake.get("requested_by") or intake.get("owner_user_id")),
        "progress": intake_progress(intake, lacking, checks, hold is not None, cause is not None,
                                 len(seen)),
        "cause": cause,
        "retry": intake_service.retry_state(actor.conn, actor.instance, intake),
        "job_error": intake_job_error(actor.conn, actor.instance, intake),
        "decision_form": decision_form or {},
        "hold": hold,
        "provider_blocked": intake_checks.provider_limit_enabled()
        and any(c["reason_code"] == "PROVIDER_NOT_ALLOWED" for c in checks),
        "passed": sum(1 for c in counted if c["result"] == "pass"),
        "failed": sum(1 for c in counted if c["result"] == "fail"),
        "checks_total": len(counted),
        "risk": risk,
        "high_risk": risk["high"] + risk["critical"],
        "proof": (sum(1 for e in needed if e["state"] not in ("missing", "expired")), len(needed)),
    }
    return render(request, "intake_detail.html", ctx, actor=actor, status=status)


def intake_new_page(request: Request, actor: Actor, form: dict, error=None, status=200):
    return render(request, "intake_new.html", {"f": form, "error": error},
                  actor=actor, status=status)


KEEP = ("owner_user_id", "local", "found")


def discovered_name(value: str) -> str:
    """단말에서 발견한 이름을 신청 이름 규칙(영문·숫자·밑줄)에 맞춘다."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_")[:128]
    return name if name[:1].isalnum() else ""


@router.get("/intakes/new")
def intake_new(request: Request, actor: Actor = Depends(page_actor)):
    query = request.query_params
    form = {"server_url": query.get("server_url", "")[:2048],
            "purpose": query.get("purpose", "")[:256],
            "owner_user_id": query.get("owner_user_id", "")[:256]}
    if query.get("kind") == "stdio":
        form["local"] = "1"
        form["name"] = discovered_name(query.get("server_id", ""))
        form["found"] = " ".join(
            p for p in (query.get("provider", ""), query.get("package", "")) if p)[:256]
        if query.get("provider") in ("uvx", "npx") and not form["server_url"]:
            form["server_url"] = form["found"]  # 발견한 패키지를 신청 주소칸에 채운다
    elif not form["server_url"] and query.get("server_id"):
        candidate = intake_service.deployment_candidate(
            actor.conn, actor.instance, query["server_id"])
        if candidate:
            form["server_url"] = candidate["url"]
        else:
            try:
                entry = actor.litellm().get_server(query["server_id"]) or {}
                form["server_url"] = entry.get("url") or ""
            except ControlError:
                pass
    return intake_new_page(request, actor, form)


@router.post("/intakes")
def create_intake(
    request: Request,
    server_url: str = Form(""),
    purpose: str = Form(...),
    step: str = Form(""),
    name: str = Form(""),
    commit: str = Form(""),
    command: str = Form(""),
    owner_user_id: str = Form(""),
    local: str = Form(""),
    found: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    form = {"server_url": server_url, "purpose": purpose, "owner_user_id": owner_user_id,
            "local": local, "found": found, "name": name}
    target = {}
    if local_intakes.is_local(server_url):
        return repo_intake(request, actor, {**form, "url": server_url, "step": step, "name": name,
                                            "commit": commit, "command": command})

    def action():
        if local:
            raise ControlError("로컬 실행 MCP는 소스 저장소 주소로 신청합니다.")
        target["id"], target["existing"] = intake_submission.submit(
            actor, server_url, purpose, owner_user_id.strip() or None)

    response = act(actor, action, "intake_created", "/intakes",
                   lambda **kw: intake_new_page(request, actor, form, **kw))
    if response.status_code == 303:
        notice = "intake_existing" if target["existing"] else "intake_created"
        response.headers["location"] = f"/intakes/{target['id']}?ok={notice}"
    return response


def repo_intake(request: Request, actor: Actor, form: dict):
    """소스 저장소 주소: 확인 단계는 미리보기를 보이고, 제출 단계는 로컬 신청을 만든다."""
    if form["step"] != "submit":
        try:
            found = local_intakes.resolve(form["url"])
            form = {**form, **found, "step": "submit", "name": form.get("name") or found["name"],
                    "server_url": found.get("url") or form["server_url"]}
        except ControlError as error:
            return intake_new_page(request, actor, form, error=str(error), status=422)
        return intake_new_page(request, actor, form)
    target = {}

    def action():
        require_role(actor.ctx, "intake create")
        user = actor.ctx.operator.user_id
        if not user:
            raise ControlError("로그인한 사용자를 확인할 수 없습니다.")
        owner = intake_submission.known_owner(actor, (form.get("owner_user_id") or "").strip())
        target["id"], target["existing"] = local_intakes.submit_operator(
            actor.ctx, user, form, owner=owner)

    response = act(actor, action, "intake_created", "/intakes",
                   lambda **kw: intake_new_page(request, actor, form, **kw))
    if response.status_code == 303:
        notice = "intake_existing" if target["existing"] else "intake_created"
        response.headers["location"] = f"/intakes/{target['id']}?ok={notice}"
    return response


@router.post("/intakes/{intake_id}/withdraw")
def withdraw_intake(intake_id: str, request: Request, state_version: int = Form(...),
                    reason: str = Form(...), confirm: str = Form(""),
                    actor: Actor = Depends(page_actor)):
    from mint_litellm.control.services import intake_withdrawals

    def action():
        if confirm != "yes":
            raise ControlError("철회 확인란을 선택하십시오.")
        return intake_withdrawals.withdraw(actor.ctx, intake_id, state_version, reason)

    return act(actor, action, "intake_withdrawn", "/intakes/" + intake_id,
               lambda **kw: intake_page(request, actor, intake_id, **kw))


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
        "requester_assigned",
        f"/intakes/{intake_id}",
        lambda **kw: intake_page(request, actor, intake_id, **kw),
    )


@router.post("/intakes/{intake_id}/inspect")
def inspect_intake(intake_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return act(actor, lambda: inspection_service.issue(actor.ctx, intake_id),
               "inspection_issued", f"/intakes/{intake_id}",
               lambda **kw: intake_page(request, actor, intake_id, **kw))


@router.post("/intakes/{intake_id}/inspect-revoke")
def revoke_inspection(intake_id: str, request: Request, inspection_id: str = Form(...),
                      actor: Actor = Depends(page_actor)):
    return act(actor, lambda: inspection_service.revoke(actor.ctx, inspection_id),
               "inspection_revoked", f"/intakes/{intake_id}",
               lambda **kw: intake_page(request, actor, intake_id, **kw))


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
    return act(
        actor,
        evidence_form(actor, intake_id, kind, summary, ref, valid_days, not_applicable, sha256),
        "evidence_attached",
        f"/intakes/{intake_id}?tab=evidence",
        lambda **kw: intake_page(request, actor, intake_id, tab="evidence", **kw),
    )


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
            actor.ctx,
            intake_id,
            expected_version=state_version,
            url=url.strip() or None,
            transport=transport.strip() or None,
        ),
        "rechecked",
        f"/intakes/{intake_id}",
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
    narrow_network: str = Form(""),
    narrow_files: str = Form(""),
    narrow_file_access: list[str] = Form([]),
    actor: Actor = Depends(page_actor),
):
    def action():
        body = api.IntakeDecisionBody(
            narrow_network="none" if narrow_network == "none" else None,
            narrow_file_access=narrow_file_access if narrow_files else None,
            state_version=state_version,
            decision=decision,
            reason=reason or ("관리자 거부" if decision == "reject" else None),
            valid_days=valid_days,
            scope_type=scope_type,
            scope_id=scope_id or None,
        )
        (api.hold_exception if decision == "except" else api.decide_intake)(
            actor, intake_id, body)

    ok = {"reject": "intake_rejected", "except": "exception_requested"}.get(
        decision, "intake_approved")
    return act(
        actor,
        action,
        ok,
        f"/intakes/{intake_id}",
        lambda **kw: intake_page(
            request,
            actor,
            intake_id,
            decision_form={
                "reason": reason,
                "valid_days": valid_days,
                "scope_type": scope_type,
                "scope_id": scope_id,
            },
            **kw,
        ),
    )


# --- 계약 재승인 -----------------------------------------------------------------------------


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
            actor.ctx,
            server_id,
            intake_id,
            tool_contract_ids,
            deployment_id=deployment_contract_id or None,
            expected_version=state_version,
        ),
        "reapproval_planned",
        f"/servers/{server_id}?tab=contract",
        lambda **kw: server_page(request, actor, server_id, tab="contract", **kw),
    )


@router.post("/contracts/{server_id}/approve-provisional")
def approve_provisional_contracts(
    server_id: str,
    request: Request,
    state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: contract_service.approve_provisional(
            actor.ctx, server_id, expected_version=state_version
        ),
        "provisional_approved",
        f"/servers/{server_id}?tab=contract",
        lambda **kw: server_page(request, actor, server_id, tab="contract", **kw),
    )
