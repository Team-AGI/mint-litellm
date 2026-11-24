"""사람 화면: LiteLLM 사용자 사본(명부)에서 MCP 차단·운영자 지정을 한다."""

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.pages.endpoints_admin import designate_operator
from mint_litellm.console.templating import render
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import reads

router = APIRouter(dependencies=[Depends(require_csrf)])

LIMIT = 500


def directory_people(actor: Actor) -> list[dict]:
    """로그인한 적 있는 LiteLLM 사용자(이름 순). 선택 목록과 사람 화면이 함께 쓴다."""
    return fetchall(
        actor.conn,
        "SELECT d.user_id, d.email, d.litellm_role, d.team_ids,"
        " (SELECT max(c.last_login_at) FROM mint.directory_credentials c"
        "  WHERE c.instance_id = d.instance_id AND c.user_id = d.user_id AND c.gone_at IS NULL)"
        "  AS last_login,"
        " (SELECT o.role FROM mint.operators o WHERE o.instance_id = d.instance_id"
        "  AND o.user_id = d.user_id AND (o.expires_at IS NULL OR o.expires_at > now())"
        "  ORDER BY o.name LIMIT 1) AS operator_role"
        " FROM mint.directory_users d WHERE d.instance_id = %s AND d.gone_at IS NULL"
        " ORDER BY coalesce(d.email, d.user_id) LIMIT %s",
        (actor.instance, LIMIT),
    )


def user_denials(actor: Actor) -> dict[str, dict]:
    """사용자별 유효한 거부: 전체 차단(서버·도구 지정 없음) 목록과 그 밖의 일부 차단 수."""
    found: dict[str, dict] = {}
    for d in reads.denials(actor.conn, actor.instance, active_only=True):
        if d["scope_type"] != "user":
            continue
        item = found.setdefault(d["scope_id"], {"whole": [], "partial": 0})
        if d["server_id"] is None and not d["tools"]:
            item["whole"].append(d)
        else:
            item["partial"] += 1
    return found


def people_page(request: Request, actor: Actor, error=None, status=200):
    wanted = request.query_params.get("q", "").strip().lower()
    blocked = user_denials(actor)
    rows = directory_people(actor)
    for r in rows:
        r["block"] = blocked.get(r["user_id"]) or {"whole": [], "partial": 0}
    if wanted:
        rows = [r for r in rows if wanted in f"{r['email'] or ''} {r['user_id']}".lower()]
    ctx = {
        "rows": rows, "q": wanted, "error": error,
        "total": len(rows), "blocked": sum(1 for r in rows if r["block"]["whole"]),
        "can_manage": actor.role == "admin",
    }
    return render(request, "people.html", ctx, actor=actor, status=status)


@router.get("/people")
def people(request: Request, actor: Actor = Depends(page_actor)):
    return people_page(request, actor)


def _known(actor: Actor, user_id: str) -> None:
    if fetchone(
        actor.conn,
        "SELECT 1 AS x FROM mint.directory_users WHERE instance_id = %s AND user_id = %s",
        (actor.instance, user_id),
    ) is None:
        raise AdminError(AdminCode.NOT_FOUND, "사람 목록에 없는 사용자입니다.")


@router.post("/people/block")
def block_person(
    request: Request, user_id: str = Form(...), reason: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def action():
        _known(actor, user_id)
        denial_service.deny(
            actor.ctx, scope_type="user", scope_id=user_id, server_id=None, tools=None,
            reason=reason.strip()[:500] or "관리자 차단", org_id=None,
        )

    return act(actor, action, "person_blocked", "/people",
               lambda **kw: people_page(request, actor, **kw))


@router.post("/people/unblock")
def unblock_person(
    request: Request, user_id: str = Form(...), actor: Actor = Depends(page_actor)
):
    def action():
        for d in user_denials(actor).get(user_id, {}).get("whole", []):
            denial_service.lift(actor.ctx, str(d["id"]), expected_version=d["state_version"])

    return act(actor, action, "person_unblocked", "/people",
               lambda **kw: people_page(request, actor, **kw))


@router.post("/people/operator")
def make_operator(
    request: Request, user_id: str = Form(...), role: str = Form("approver"),
    actor: Actor = Depends(page_actor),
):
    return act(actor, lambda: designate_operator(actor, user_id, role), "operator_added",
               "/people", lambda **kw: people_page(request, actor, **kw))
