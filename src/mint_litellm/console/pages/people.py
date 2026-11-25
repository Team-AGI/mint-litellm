"""사람 화면: LiteLLM 사용자 사본(명부)에서 MCP 차단·운영자 지정을 한다."""

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.labels import Status
from mint_litellm.console.pages.common import act
from mint_litellm.console.pages.endpoints_admin import designate_operator
from mint_litellm.console.templating import is_root, render
from mint_litellm.control import endpoint_apps, endpoint_kits
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.services import denials as denial_service
from mint_litellm.control.services import reads
from mint_litellm.control.services import root_controls as root

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
    """사용자별 유효한 거부. lock 전체 차단, whole MCP 차단(서버·도구 없음), partial 그 밖"""
    found: dict[str, dict] = {}
    for d in reads.denials(actor.conn, actor.instance, active_only=True):
        if d["scope_type"] != "user":
            continue
        item = found.setdefault(
            d["scope_id"], {"lock": [], "whole": [], "partial": 0, "all": []})
        item["all"].append(d)
        if d["server_id"] is not None or d["tools"]:
            item["partial"] += 1
        elif (d["reason"] or "").startswith(root.LOCKOUT_REASON_PREFIX):
            item["lock"].append(d)
        else:
            item["whole"].append(d)
    return found


def status_of(block: dict) -> Status:
    if block["lock"]:
        return Status("전체 차단", "block")
    if block["whole"] or block["partial"]:
        return Status("일부 차단", "wait")
    return Status("정상", "ok")


LIVE_PC = "revoked_at IS NULL AND coalesce(install_mode, '') <> 'removed'"
LIVE_SESSION = "revoked_at IS NULL AND idle_expiry > now() AND absolute_expiry > now()"


def pc_counts(actor: Actor) -> dict[str, int]:
    rows = fetchall(
        actor.conn,
        f"SELECT user_id, count(*) AS n FROM mint.endpoint_installs WHERE instance_id = %s"
        f" AND {LIVE_PC} GROUP BY user_id",
        (actor.instance,),
    )
    return {r["user_id"]: r["n"] for r in rows}


def person_detail(actor: Actor, person: dict, block: dict) -> dict:
    """서랍: 권한·차단 목록, PC·앱, 키·세션, 조치 가능 여부와 영향 수."""
    uid = person["user_id"]
    operators = [o for o in reads.operators(actor.conn, actor.instance) if o["user_id"] == uid]
    names = root.root_names(actor.conn, actor.instance)
    for o in operators:
        o["root"] = o["name"] == "root" or o["name"] in names
    pcs = [r for r in endpoint_kits.installs(actor.conn, actor.instance, uid)
           if not r["revoked_at"] and r["install_mode"] != "removed"]
    apps = [a for a in endpoint_apps.list_apps(actor.conn, actor.instance, uid)
            if a["state"] == "active"]
    sessions = fetchall(
        actor.conn,
        f"SELECT subject, count(*) AS n FROM mint.console_sessions WHERE instance_id = %s"
        f" AND user_id = %s AND {LIVE_SESSION} GROUP BY subject",
        (actor.instance, uid),
    )
    by_subject = {r["subject"]: r["n"] for r in sessions}
    reported = [r["reported_at"] for r in pcs if r["reported_at"]]
    me = uid == actor.ctx.operator.user_id
    target_root = any(o["root"] for o in operators)
    why = None
    if me:
        why = "본인은 차단할 수 없습니다."
    elif target_root and not is_root(actor):
        why = "Root는 Root만 차단할 수 있습니다."
    return {
        **person, "operators": operators, "block": block, "pcs": pcs, "apps": apps,
        "last_report": max(reported) if reported else None,
        "sessions": {"admin": by_subject.get("admin", 0), "staff": by_subject.get("staff", 0)},
        "impact": {"pcs": len(pcs), "apps": len(apps), "sessions": sum(by_subject.values())},
        "lock_blocked_reason": why,
        "end_blocked_reason": None if sum(by_subject.values()) else "끝낼 활성 세션이 없습니다.",
    }


def people_page(request: Request, actor: Actor, error=None, status=200):
    wanted = request.query_params.get("q", "").strip().lower()
    blocked = user_denials(actor)
    counts = pc_counts(actor)
    everyone = directory_people(actor)
    rows = everyone
    for r in rows:
        r["block"] = blocked.get(r["user_id"]) or {"lock": [], "whole": [], "partial": 0, "all": []}
        r["state"] = status_of(r["block"])
        r["pcs"] = counts.get(r["user_id"], 0)
    if wanted:
        rows = [r for r in rows if wanted in f"{r['email'] or ''} {r['user_id']}".lower()]
    opened = request.query_params.get("open")
    selected = None
    if opened:
        person = next((r for r in everyone if r["user_id"] == opened), None)
        if person is None:
            raise AdminError(AdminCode.NOT_FOUND, "사람 목록에 없는 사용자입니다.")
        selected = person_detail(actor, person, person["block"])
    ctx = {
        "rows": rows, "q": wanted, "error": error, "selected": selected,
        "total": len(rows), "blocked": sum(1 for r in rows if r["block"]["lock"]),
        "can_manage": actor.role == "admin",
    }
    return render(request, "people.html", ctx, actor=actor, status=status)


@router.get("/people")
def people(request: Request, actor: Actor = Depends(page_actor)):
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 사람 화면을 볼 수 있습니다.")
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
