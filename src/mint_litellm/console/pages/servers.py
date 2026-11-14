"""MCP 서버·신청·계약 화면."""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console import api, compare, labels
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


# --- 서버 상세 ---------------------------------------------------------------------------------

SERVER_TABS = (
    ("overview", "개요"),
    ("contract", "계약 변경"),
    ("tools", "도구"),
    ("packages", "패키지"),
    ("vulns", "취약점"),
    ("usage", "이용"),
    ("evidence", "증빙"),
)


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
    }


def server_page(
    request: Request, actor: Actor, server_id: str, error=None, status=200, tab: str | None = None
):
    row = reads.server(actor.conn, actor.instance, server_id)
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, f"서버 {server_id}을(를) 찾을 수 없습니다.")
    tab = tab or request.query_params.get("tab", "")
    tab = tab if tab in dict(SERVER_TABS) else "overview"
    evidence = evidence_service.show(actor.ctx, "server", server_id)
    changed_tools = sum(1 for t in row["tools"] if t["drift"] != "none")
    counts = {
        "contract": changed_tools + bool(row["deployment_drift"]),
        "tools": len(row["tools"]),
        "packages": len(row["packages"]),
        "vulns": len(row["vulns"]),
        "usage": len(row["approvals"]),
        "evidence": sum(
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
        "c": contract_context(request, actor, server_id) if tab == "contract" else None,
    }
    return render(request, "server_detail.html", ctx, actor=actor, status=status)


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
        f"/servers/{server_id}?tab=evidence",
        lambda **kw: server_page(request, actor, server_id, tab="evidence", **kw),
    )


def back_to(server_id: str, next: str) -> str:
    """중지·재개 뒤에 돌아갈 곳: 목록에서 눌렀으면 목록, 아니면 상세."""
    return "/servers" if next == "/servers" else f"/servers/{server_id}"


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


# --- 신청·수용검증 ----------------------------------------------------------------------------

STAGES = {
    "received": ("received", "checking"),
    "passed": ("passed",),
    "indeterminate": ("indeterminate",),
    "decided": ("decided",),
    "failed": ("failed",),
}
OPEN_STATUSES = ("received", "checking", "passed", "indeterminate")
STALL = timedelta(hours=24)


def intakes_page(request: Request, actor: Actor, error=None, status=200):
    wanted = request.query_params.get("status") or ""
    rows = intake_service.list_intakes(actor.ctx)
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


def intake_progress(intake: dict, lacking: list[str]) -> list[tuple[str, str]]:
    """진행 표시 4단계(접수·검사·증빙·결정)를 (심각도, 이름)으로."""
    st = intake["status"]
    checked = {
        "failed": ("error", "검사 실패"),
        "received": ("wait", "검사 중"),
        "checking": ("wait", "검사 중"),
        "indeterminate": ("wait", "검사 판별 불가"),
    }.get(st, ("ok", "검사 통과"))
    if st in ("received", "checking", "failed"):
        proof = ("off", "증빙")
    else:
        proof = ("error", f"증빙 {len(lacking)}건 부족") if lacking else ("ok", "증빙 충족")
    if st == "decided":
        decision = ("ok", "결정 완료")
    else:
        decision = (
            ("off", "결정") if st in ("received", "checking", "failed") else ("wait", "결정 대기")
        )
    return [("ok", "접수"), checked, proof, decision]


def intake_page(
    request: Request, actor: Actor, intake_id: str, error=None, status=200, tab: str | None = None
):
    info = intake_service.show(actor.ctx, intake_id)
    now = datetime.now(UTC)
    intake, checks, tools = info["intake"], info["checks"], info["tool_contracts"]
    tab = tab or request.query_params.get("tab", "")
    tab = tab if tab in dict(INTAKE_TABS) else "overview"
    stale = any(
        c["check"] in ("connection", "definitions")
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
    elif stale and status_now in ("passed", "indeterminate"):
        next_step = "재검사"
    elif status_now == "received" and not intake["requested_by"] and actor.role == "admin":
        next_step = "신청자 지정"
    elif status_now in ("passed", "indeterminate"):
        next_step = "증빙 첨부" if lacking else "결정"
    else:
        next_step = None
    ctx = {
        "i": intake,
        "checks": checks,
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
            (key, label, len(lacking) if key == "evidence" else 0) for key, label in INTAKE_TABS
        ],
        "progress": intake_progress(intake, lacking),
        "passed": sum(1 for c in checks if c["result"] == "pass"),
        "failed": sum(1 for c in checks if c["result"] == "fail"),
        "risk": risk,
        "high_risk": risk["high"] + risk["critical"],
        "proof": (sum(1 for e in needed if e["state"] not in ("missing", "expired")), len(needed)),
    }
    return render(request, "intake_detail.html", ctx, actor=actor, status=status)


INTAKE_FIELDS = ("server_id", "provider", "owner_user_id", "purpose")
NEW_STEPS = ("대상", "데이터", "종료 준비")
NEW_DEFAULTS = {"data_grade": "internal", "audit_access_days": "90"}


def intake_new_page(
    request: Request,
    actor: Actor,
    form: dict,
    error=None,
    status=200,
    step: int = 1,
    resources: list[str] | None = None,
):
    rows = list(resources or [])
    ctx = {
        "f": {**NEW_DEFAULTS, **{k: v for k, v in form.items() if v not in (None, "")}},
        "grades": intake_service.DATA_GRADES,
        "error": error,
        "step": step,
        "steps": NEW_STEPS,
        "rows": rows or [""],
    }
    return render(request, "intake_new.html", ctx, actor=actor, status=status)


@router.get("/intakes/new")
def intake_new(request: Request, actor: Actor = Depends(page_actor)):
    """단말 MCP 목록의 항목에서 신청을 시작한다. 쿼리 값으로 입력란을 미리 채운다."""
    query = request.query_params
    return intake_new_page(request, actor, {key: query.get(key, "")[:256] for key in INTAKE_FIELDS})


@router.post("/intakes/new")
def intake_new_step(
    request: Request,
    step: int = Form(1),
    go: str = Form(""),
    resource: list[str] = Form([]),
    server_id: str = Form(""),
    provider: str = Form(""),
    owner_user_id: str = Form(""),
    purpose: str = Form(""),
    data_grade: str = Form(""),
    audit_access_days: str = Form(""),
    credential_notice: str = Form(""),
    revocation_record: str = Form(""),
    data_return_terms: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    """신청 등록의 단계 이동·자원 행 추가. 값은 숨은 입력으로 이어 받고 아무것도 저장하지 않는다."""
    form = {
        "server_id": server_id,
        "provider": provider,
        "owner_user_id": owner_user_id,
        "purpose": purpose,
        "data_grade": data_grade,
        "audit_access_days": audit_access_days,
        "credential_notice": credential_notice,
        "revocation_record": revocation_record,
        "data_return_terms": data_return_terms,
    }
    step = min(max(step + {"next": 1, "prev": -1}.get(go, 0), 1), len(NEW_STEPS))
    rows = resource + [""] if go == "add" else resource
    return intake_new_page(request, actor, form, step=step, resources=rows)


@router.post("/intakes")
def create_intake(
    request: Request,
    server_id: str = Form(...),
    provider: str = Form(...),
    owner_user_id: str = Form(...),
    purpose: str = Form(...),
    data_grade: str = Form(...),
    allowed_resources: str = Form("[]"),
    resource: list[str] = Form([]),
    credential_notice: str = Form(...),
    revocation_record: str = Form(...),
    audit_access_days: int = Form(...),
    data_return_terms: str = Form(...),
    actor: Actor = Depends(page_actor),
):
    form = {
        "server_id": server_id,
        "provider": provider,
        "owner_user_id": owner_user_id,
        "purpose": purpose,
        "data_grade": data_grade,
        "credential_notice": credential_notice,
        "revocation_record": revocation_record,
        "audit_access_days": audit_access_days,
        "data_return_terms": data_return_terms,
    }

    def action():
        resources = (
            [r.strip() for r in resource if r.strip()]
            if resource
            else json.loads(allowed_resources or "[]")
        )
        intake_service.create(
            actor.ctx,
            actor.litellm(),
            server_id.strip(),
            purpose=purpose,
            data_grade=data_grade,
            allowed_resources=resources,
            provider=provider,
            owner_user_id=owner_user_id,
            readiness={
                "credential_notice": credential_notice.strip(),
                "revocation_record": revocation_record.strip(),
                "audit_access_days": audit_access_days,
            },
            data_return_terms=data_return_terms,
        )

    return act(
        actor,
        action,
        "intake_created",
        "/intakes",
        lambda **kw: intake_new_page(
            request, actor, form, step=len(NEW_STEPS), resources=resource, **kw
        ),
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
        "requester_assigned",
        f"/intakes/{intake_id}",
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
    second_approver_token: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        body = api.IntakeDecisionBody(
            state_version=state_version,
            decision=decision,
            reason=reason or None,
            valid_days=valid_days,
            scope_type=scope_type,
            scope_id=scope_id or None,
            second_approver_token=second_approver_token or None,
        )
        api.decide_intake(actor, intake_id, body)

    ok = "intake_rejected" if decision == "reject" else "intake_approved"
    return act(
        actor,
        action,
        ok,
        f"/intakes/{intake_id}",
        lambda **kw: intake_page(request, actor, intake_id, **kw),
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
