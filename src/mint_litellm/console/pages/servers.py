"""MCP 서버·신청·계약 화면."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console import api, compare, labels, pack_view
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages import intake_submission
from mint_litellm.console.pages.common import act, server_display
from mint_litellm.console.templating import render
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import call_review as review_service
from mint_litellm.control.services import contracts as contract_service
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import evidence as evidence_service
from mint_litellm.control.services import exception_holds, reads
from mint_litellm.control.services import intake_inspections as inspection_service
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.services import servers as server_service
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
        "c": contract_context(request, actor, server_id) if tab == "contract" else None,
        "pack": pack_view.view(
            pack_view.read(actor.conn, actor.instance, server_id, approved=True), "decided"
        )
        if row["identity_kind"] == "stdio" and tab == "overview"
        else None,
    }
    return render(request, "server_detail.html", ctx, actor=actor, status=status)


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


def intake_progress(
    intake: dict, lacking: list[str], checks: list[dict] | None = None,
    hold: bool = False, cause: bool = False,
) -> list[tuple[str, str]]:
    """진행 표시 4단계(접수·검사·증빙·결정)를 (심각도, 이름)으로."""
    st = intake["status"]
    if intake.get("decision") == "withdrawn":
        return [("ok", "접수"), ("off", "검사 이력 보존"), ("off", "승인 심사 종료"),
                ("off", "신청 철회")]
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
    if st in ("received", "checking", "failed") or checked[0] == "error" or cause:
        proof = ("off", "증빙")
    else:
        proof = ("error", f"증빙 {len(lacking)}건 부족") if lacking else ("ok", "증빙 충족")
    if st == "decided":
        decision = ("ok", "결정 완료")
    elif hold:
        decision = ("wait", "두 번째 승인 대기")
    else:
        decision = (
            ("off", "결정") if st in ("received", "checking") else ("wait", "결정 대기")
        )
    return [("ok", "접수"), checked, proof, decision]


def minutes_left(inspection: dict, now: datetime) -> str:
    """검사용 승인의 남은 시간(분 단위, 1분 미만은 1분)."""
    return f"{max(1, int((inspection['expires_at'] - now).total_seconds() // 60))}분"


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
    # 검사로 도구 목록을 못 받았으면 설명 검사·위험 등급은 파생 결과다.
    bad = next((c for c in checks if c["check"] == "inspection" and c["result"] != "pass"), None)
    why = labels.pick(labels.CHECK_REASON, bad["reason_code"]) if bad else ""
    cause = f"검사로 도구 목록을 받지 못했습니다 · {why}" if bad and not tools else None
    inspections = (
        inspection_service.for_intake(actor.conn, actor.instance, intake["id"]) if local else []
    )
    open_inspection = next((x for x in inspections if x["status"] in inspection_service.OPEN), None)
    ctx = {
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
            (key, label, len(lacking) if key == "evidence" else 0) for key, label in intake_tabs
        ],
        "pack": pack,
        "progress": intake_progress(intake, lacking, checks, hold is not None, cause is not None),
        "cause": cause,
        "decision_form": decision_form or {},
        "hold": hold,
        "provider_blocked": any(c["reason_code"] == "PROVIDER_NOT_ALLOWED" for c in checks),
        "passed": sum(1 for c in checks if c["result"] == "pass"),
        "failed": sum(1 for c in checks if c["result"] == "fail"),
        "risk": risk,
        "high_risk": risk["high"] + risk["critical"],
        "proof": (sum(1 for e in needed if e["state"] not in ("missing", "expired")), len(needed)),
    }
    return render(request, "intake_detail.html", ctx, actor=actor, status=status)


def intake_new_page(request: Request, actor: Actor, form: dict, error=None, status=200):
    return render(request, "intake_new.html", {"f": form, "error": error},
                  actor=actor, status=status)


@router.get("/intakes/new")
def intake_new(request: Request, actor: Actor = Depends(page_actor)):
    query = request.query_params
    form = {"server_url": query.get("server_url", "")[:2048],
            "purpose": query.get("purpose", "")[:256]}
    if not form["server_url"] and query.get("server_id"):
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
    actor: Actor = Depends(page_actor),
):
    form = {"server_url": server_url, "purpose": purpose}
    target = {}

    def action():
        target["id"], target["existing"] = intake_submission.submit(actor, server_url, purpose)

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
