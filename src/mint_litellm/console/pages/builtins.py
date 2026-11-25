"""하네스 기본 기능(Claude Code·Codex 내장 셸·파일 편집·웹) 화면: 도구별 호출 수와 차단·허용."""

from fastapi import APIRouter, Depends, Form, Request

from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import denials as denial_service
from mint_litellm.types.decision import BUILTIN_PREFIX

router = APIRouter(dependencies=[Depends(require_csrf)])

# (하네스, 표시 이름, ((도구, 하는 일), ...)) — 단말 훅이 판정하는 내장 도구 이름 그대로다.
HARNESSES = (
    ("claude", "Claude Code", (
        ("Bash", "셸 명령 실행"), ("PowerShell", "PowerShell 명령 실행"),
        ("Edit", "파일 고치기"), ("MultiEdit", "파일 여러 곳 고치기"), ("Write", "파일 쓰기"),
        ("NotebookEdit", "노트북 고치기"), ("WebFetch", "웹 페이지 가져오기"),
        ("WebSearch", "웹 검색"),
    )),
    ("codex", "Codex", (
        ("Bash", "셸 명령 실행"), ("apply_patch", "파일 고치기(패치)"),
    )),
)
KNOWN = {(h, t) for h, _, tools in HARNESSES for t, _ in tools}


def builtin_page(request: Request, actor: Actor, error=None, status=200):
    counts = {
        (r["server"], r["tool"]): r for r in fetchall(
            actor.conn,
            "SELECT payload->>'resolved_server_id' AS server, payload->>'tool' AS tool,"
            " count(*) AS calls,"
            " count(*) FILTER (WHERE payload->>'enforced_action' <> 'allow') AS blocked"
            " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
            " AND inserted_at > now() - interval '7 days'"
            " AND payload->>'resolved_server_id' LIKE 'builtin:%%' GROUP BY 1, 2",
            (actor.instance,),
        )
    }
    denials = {}
    for d in fetchall(
        actor.conn,
        "SELECT id, server_id, tools, state_version FROM mint.denials WHERE instance_id = %s"
        " AND lifted_at IS NULL AND scope_type = 'server' AND server_id LIKE 'builtin:%%'",
        (actor.instance,),
    ):
        for tool in d["tools"] or ["*"]:
            denials.setdefault((d["server_id"], tool), d)
    groups = []
    for harness, name, tools in HARNESSES:
        server = BUILTIN_PREFIX + harness
        whole = denials.get((server, "*"))
        rows = []
        for tool, what in tools:
            seen = counts.get((server, tool)) or {}
            rows.append({
                "tool": tool, "what": what, "calls": seen.get("calls", 0),
                "blocked": seen.get("blocked", 0), "denial": denials.get((server, tool)) or whole,
            })
        groups.append({"harness": harness, "name": name, "rows": rows})
    return render(request, "builtin_tools.html", {
        "groups": groups, "error": error, "can_manage": actor.role == "admin",
    }, actor=actor, status=status)


@router.get("/builtin-tools")
def builtin_tools(request: Request, actor: Actor = Depends(page_actor)):
    return builtin_page(request, actor)


@router.post("/builtin-tools/block")
def block_builtin(
    request: Request, harness: str = Form(...), tool: str = Form(...),
    actor: Actor = Depends(page_actor),
):
    def action():
        if (harness, tool) not in KNOWN:
            raise ControlError("알 수 없는 기본 기능입니다.")
        server = BUILTIN_PREFIX + harness
        denial_service.deny(
            actor.ctx, scope_type="server", scope_id=server, server_id=server, tools=[tool],
            reason="기본 기능 차단", org_id=None,
        )

    return act(actor, action, "denied", "/builtin-tools",
               lambda **kw: builtin_page(request, actor, **kw))


@router.post("/builtin-tools/allow")
def allow_builtin(
    request: Request, denial_id: str = Form(...), state_version: int = Form(...),
    actor: Actor = Depends(page_actor),
):
    return act(
        actor,
        lambda: denial_service.lift(actor.ctx, denial_id, expected_version=state_version),
        "lifted", "/builtin-tools", lambda **kw: builtin_page(request, actor, **kw),
    )
