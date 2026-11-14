"""단말 설치·운영자·조직 화면."""


from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console import api
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control import endpoint_kits, org_suggest
from mint_litellm.control.services import operators as operator_service
from mint_litellm.control.services import orgs as org_service
from mint_litellm.control.services import reads
from mint_litellm.types.cli_commands import OperatorRole

router = APIRouter(dependencies=[Depends(require_csrf)])


# --- 단말 설치 -------------------------------------------------------------------------------


@router.get("/endpoints")
def endpoints(request: Request, actor: Actor = Depends(page_actor)):
    if request.query_params.get("tab") == "local-mcp":
        rows = endpoint_kits.local_mcp_inventory(actor.conn, actor.instance)
        return render(request, "endpoint_mcp.html", {"rows": rows}, actor=actor)
    rows = endpoint_kits.installs(actor.conn, actor.instance)
    return render(request, "endpoints.html", {"rows": rows}, actor=actor)


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
