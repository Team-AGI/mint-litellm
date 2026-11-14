"""엔드포인트·운영자·조직 화면."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console import api
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control import endpoint_kits, org_suggest, siem
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.services import operators as operator_service
from mint_litellm.control.services import orgs as org_service
from mint_litellm.control.services import reads
from mint_litellm.types.cli_commands import OperatorRole

router = APIRouter(dependencies=[Depends(require_csrf)])


# --- 엔드포인트 -------------------------------------------------------------------------------

STALE = timedelta(hours=24)
STATES = {"applied": "적용", "unapplied": "미적용", "stale": "보고 끊김", "violation": "격리 위반"}
DECISION = {"applied": "allow", "unapplied": "block", "stale": "approve"}
VIOLATIONS = (
    ("sandbox", "격리 없음"), ("egress", "호스트 제한 미집행"), ("outside", "실행기 밖 실행"),
)


def violations(row: dict) -> set[str]:
    """단말이 보고한 격리 위반의 종류."""
    found = set()
    for p in row.get("processes") or []:
        if p.get("sandbox") in ("none", "unsupported"):
            found.add("sandbox")
        if p.get("egress_unfiltered"):
            found.add("egress")
    if row.get("outside_processes"):
        found.add("outside")
    return found


def classify(row: dict, now: datetime) -> str | None:
    """적용·미적용·보고 끊김. 해제·제거된 단말은 집계에서 뺀다."""
    if row["state"] in ("revoked", "removed"):
        return None
    if row["state"] == "user":
        return "unapplied"
    reported = row["reported_at"]
    return "stale" if reported is None or now - reported > STALE else "applied"


def endpoint_view(rows: list[dict], mcp: list[dict], now: datetime) -> dict:
    live = []
    for r in rows:
        r["group"] = classify(r, now)
        r["violations"] = violations(r) if r["group"] else set()
        r["ref"] = f"{r['user_id']}|{r['issued_at']}"
        if r["group"]:
            live.append(r)
    count = {k: sum(r["group"] == k for r in live) for k in DECISION}
    count["violation"] = sum(bool(r["violations"]) for r in live)
    link = "/endpoints?tab=installs&state="
    donut = {"items": [
        {"name": STATES[k], "value": count[k], "decision": DECISION[k], "href": link + k}
        for k in DECISION
    ]}
    kinds = {k: sum(k in r["violations"] for r in live) for k, _ in VIOLATIONS}
    bars = {
        "labels": [label for _, label in VIOLATIONS], "values": list(kinds.values()),
        "horizontal": True, "links": [f"{link}violation&kind={k}" for k, _ in VIOLATIONS],
    }
    return {"rows": rows, "count": count, "mcp": mcp, "donut": donut, "bars": bars}


@router.get("/endpoints")
def endpoints(request: Request, actor: Actor = Depends(page_actor)):
    view = endpoint_view(
        endpoint_kits.installs(actor.conn, actor.instance),
        endpoint_kits.local_mcp_inventory(actor.conn, actor.instance),
        datetime.now(UTC),
    )
    tab = "local-mcp" if request.query_params.get("tab") == "local-mcp" else "installs"
    state = request.query_params.get("state", "")
    if state in STATES:
        view["rows"] = [
            r for r in view["rows"]
            if (bool(r["violations"]) if state == "violation" else r["group"] == state)
        ]
    kind = request.query_params.get("kind", "")
    if state == "violation" and kind in dict(VIOLATIONS):
        view["rows"] = [r for r in view["rows"] if kind in r["violations"]]
    else:
        kind = ""
    opened = request.query_params.get("open")
    selected = next((r for r in view["rows"] if r["ref"] == opened), None) if opened else None
    ctx = {**view, "tab": tab, "state": state if state in STATES else "", "STATES": STATES,
           "VIOLATIONS": VIOLATIONS, "selected": selected, "kind": kind}
    return render(request, "endpoints.html", ctx, actor=actor)


# --- 운영자·조직 -------------------------------------------------------------------------------


def admin_tab(tab: str | None, role: str) -> str:
    """운영자·조직 화면의 탭. 전달 대상은 백업·이전과 한 탭이고, 조회자는 운영자 탭이 없다."""
    tab = "transfer" if tab == "siem" else tab
    if tab == "transfer" and role != "admin":
        tab = None
    if tab in ("orgs", "suggestions", "transfer") or (tab == "operators" and role != "viewer"):
        return tab
    return "orgs" if role == "viewer" else "operators"


def admin_page(request: Request, actor: Actor, error=None, status=200, tab=None):
    tab = tab or request.query_params.get("tab")
    operators = [] if actor.role == "viewer" else reads.operators(actor.conn, actor.instance)
    soon = datetime.now(UTC) + timedelta(days=7)
    ctx = {
        "operators": operators,
        "expiring": sum(1 for o in operators if o["expires_at"] and o["expires_at"] < soon),
        "orgs": reads.orgs(actor.conn, actor.instance),
        "bindings": reads.bindings(actor.conn, actor.instance),
        "suggestions": org_service.list_suggestions(actor.ctx),
        "transfers": reads.transfers(actor.conn, actor.instance) if actor.role == "admin" else [],
        "siem": siem.listing(actor.conn, actor.instance) if actor.role == "admin" else [],
        "tab": admin_tab(tab, actor.role),
        "error": error,
    }
    return render(request, "admin.html", ctx, actor=actor, status=status)


def tabbed(request: Request, actor: Actor, tab: str):
    return lambda **kw: admin_page(request, actor, tab=tab, **kw)


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
        "operator_role", "/admin?tab=operators",
        tabbed(request, actor, "operators"),
    )


@router.post("/operators/{name}/chat-bind")
def bind_operator_chat(
    name: str,
    request: Request,
    slack_user: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: operator_service.chat_bind(actor.ctx, name, slack_user.strip() or None),
        "operator_chat_bound", "/admin?tab=operators",
        tabbed(request, actor, "operators"),
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

    return act(actor, action, "operator_removed", "/admin?tab=operators",
               tabbed(request, actor, "operators"))


@router.post("/admin/siem/{name}/test")
def siem_test(name: str, request: Request, actor: Actor = Depends(page_actor)):
    """시험 전송 요청. 비밀은 작업 실행기만 읽으므로 요청만 남기고 실행기가 보낸다."""

    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "관리자만 시험 전송을 할 수 있습니다.")
        if not siem.request_test(actor.conn, actor.instance, name):
            raise AdminError(AdminCode.NOT_FOUND, "SIEM 대상이 없습니다.")

    return act(actor, action, "siem_test_requested", "/admin?tab=siem",
               tabbed(request, actor, "siem"))


@router.post("/orgs")
def add_org(
    request: Request,
    org_id: str = Form(...),
    name: str = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(actor, lambda: org_service.add(actor.ctx, org_id, name), "org_added",
               "/admin?tab=orgs", tabbed(request, actor, "orgs"))


@router.post("/org-suggestions/rule")
def apply_org_suggestion_rule(
    request: Request, rule: str = Form(...), actor: Actor = Depends(page_actor)
):
    def action():
        if rule not in org_suggest.RULES:
            raise ValueError(rule)
        org_service.apply_rule(actor.ctx, rule)

    return act(actor, action, "org_suggestions_applied", "/admin?tab=suggestions",
               tabbed(request, actor, "suggestions"))


@router.post("/org-suggestions/{suggestion_id}/apply")
def apply_org_suggestion(
    suggestion_id: str, request: Request, actor: Actor = Depends(page_actor)
):
    return act(actor, lambda: org_service.apply_suggestion(actor.ctx, suggestion_id),
               "org_suggestion_applied", "/admin?tab=suggestions",
               tabbed(request, actor, "suggestions"))


@router.post("/org-suggestions/{suggestion_id}/ignore")
def ignore_org_suggestion(
    suggestion_id: str, request: Request, actor: Actor = Depends(page_actor)
):
    return act(actor, lambda: org_service.ignore_suggestion(actor.ctx, suggestion_id),
               "org_suggestion_ignored", "/admin?tab=suggestions",
               tabbed(request, actor, "suggestions"))


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

    return act(actor, action, "org_closed", "/admin?tab=orgs",
               tabbed(request, actor, "orgs"))
