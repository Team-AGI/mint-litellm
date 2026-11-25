"""Root 화면: 긴급 통제(전역 정지)와 강제 조치 기록, 신청·서버·사람 강제 조치 경로.

판정은 모두 ``control.services.root_controls``가 한다. 여기는 Root 확인·입력·결과 화면만 맡는다.
"""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import root_controls as root

router = APIRouter(dependencies=[Depends(require_csrf)])

ACTION_LABEL = {
    "halt": "전역 정지", "halt_lift": "정지 해제", "intake_reject": "강제 반려",
    "server_suspend": "서버 중지", "server_resume": "서버 재개", "server_terminate": "서버 폐기",
    "person_lockout": "사람 전체 차단", "person_unlock": "전체 차단 해제",
    "sessions_end": "세션 종료", "root_set": "Root 지정", "root_unset": "Root 해제",
    "intake_except": "검사 생략 승인", "run_cancel": "진행 중 실행 취소",
}
DONE = {
    "halt": "전역 정지를 걸었습니다.", "halt_lift": "정지를 해제했습니다.",
    "intake_reject": "반려했습니다. 남은 검사를 멈췄습니다.",
    "server_suspend": "서버를 중지했습니다.", "server_resume": "서버를 다시 열었습니다.",
    "server_terminate": "폐기를 시작했습니다.", "person_lockout": "차단했습니다.",
    "person_unlock": "해제했습니다. PC는 다시 설치해야 합니다.",
    "sessions_end": "세션을 끝냈습니다.",
    "intake_except": "검사를 생략하고 예외 승인했습니다(30일).",
    "run_cancel": "대기 중인 호출 승인을 취소했습니다. 이미 보낸 호출은 끝까지 실행됩니다.",
}
SERVER_ACTIONS = {
    "server_suspend": "suspend", "server_resume": "resume", "server_terminate": "terminate",
}
PROPAGATION_LINE = "전파 상태: MINT 판정 즉시 · LiteLLM 키 최대 60초 · PC 다음 보고"
MARK = {"반영": "✓", "대기": "◷"}


def _need_root(actor: Actor) -> None:
    if not root.is_root(actor.ctx):
        raise AdminError(AdminCode.FORBIDDEN, "이 화면은 Root만 쓸 수 있습니다.")


def _mark(point: dict) -> str:
    state = point["state"]
    if state in MARK:
        return MARK[state]
    if state == "확인되지 않음":
        return "▲"
    done, _, total = state.rstrip("대").partition("/")
    return "✓" if done == total else "◷"


def _view(row: dict) -> dict:
    points = [{**p, "mark": _mark(p)} for p in row["points"]]
    summary = " · ".join(f"{m} {n}" for m in "✓◷▲" if (n := sum(p["mark"] == m for p in points)))
    return {
        **row, "label": ACTION_LABEL.get(row["action"], row["action"]), "points": points,
        "summary": summary,
    }


def root_page(request: Request, actor: Actor, error=None, status=200):
    _need_root(actor)
    cnt = fetchone(
        actor.conn,
        "SELECT count(*) AS n FROM mint.events WHERE instance_id = %s"
        " AND kind = 'decision_evaluated' AND inserted_at > now() - interval '1 hour'",
        (actor.instance,),
    )
    impact = {**root._halt_impact(actor.ctx, "all"), "calls": cnt["n"]}
    return render(request, "root.html", {
        "halt": root.halt_state(actor.conn, actor.instance), "scopes": root.HALT_SCOPES,
        "impact": impact, "error": error,
        "recent": [_view(r) for r in root.recent(actor.conn, actor.instance, 5)],
    }, actor=actor, status=status)


def actions_page(request: Request, actor: Actor, error=None, status=200):
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 강제 조치 기록을 볼 수 있습니다.")
    q = request.query_params
    rows = [_view(r) for r in root.recent(actor.conn, actor.instance, 200)]
    everyone = sorted({r["actor"] for r in rows})
    rows = [r for r in rows
            if (not q.get("action") or r["action"] == q["action"])
            and (not q.get("actor") or r["actor"] == q["actor"])]
    by_id = {str(r["id"]): r for r in rows}
    done = by_id.get(q.get("done", ""))
    return render(request, "root_actions.html", {
        "rows": rows, "labels": ACTION_LABEL, "actors": everyone, "q": q, "error": error,
        "open": by_id.get(q.get("open", "")),
        "done": done and {"text": DONE.get(done["action"], "처리했습니다."), "id": done["id"],
                          "line": PROPAGATION_LINE},
    }, actor=actor, status=status)


def _run(actor: Actor, fn, rebuild):
    """서비스 한 번. 성공하면 결과 줄이 있는 기록 화면으로, 실패하면 같은 화면에 오류를 보인다."""
    box: list[str] = []
    response = act(actor, lambda: box.append(fn()), "done", "/root/actions", rebuild)
    return RedirectResponse(f"/root/actions?done={box[0]}", status_code=303) if box else response


@router.get("/root")
def root_home(request: Request, actor: Actor = Depends(page_actor)):
    return root_page(request, actor)


@router.post("/root/halt")
def halt(
    request: Request, scope: str = Form(""), reason: str = Form(""),
    confirm_name: str = Form(""), actor: Actor = Depends(page_actor),
):
    def action():
        if confirm_name.strip() != "정지":
            raise ControlError("확인 칸에 「정지」를 입력하십시오.")
        return root.set_halt(actor.ctx, scope, reason)

    return _run(actor, action, lambda **kw: root_page(request, actor, **kw))


@router.post("/root/halt/lift")
def halt_lift(
    request: Request, reason: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _run(actor, lambda: root.lift_halt(actor.ctx, reason),
                lambda **kw: root_page(request, actor, **kw))


@router.get("/root/actions")
def root_actions(request: Request, actor: Actor = Depends(page_actor)):
    return actions_page(request, actor)


@router.post("/root/actions")
def force(
    request: Request, action: str = Form(...), target: str = Form(...), reason: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    def run():
        if action == "intake_reject":
            return root.force_reject(actor.ctx, target, reason)
        if action == "intake_except":
            return root.force_except(actor.ctx, target, reason)
        if action in ("server_run_cancel", "person_run_cancel"):
            return root.cancel_runs(actor.ctx, action.split("_")[0], target, reason)
        if action in SERVER_ACTIONS:
            return root.server_action(actor.ctx, target, SERVER_ACTIONS[action], reason)
        raise ValueError(action)

    return _run(actor, run, lambda **kw: actions_page(request, actor, **kw))


@router.post("/root/actions/{action_id}/verify")
def verify(action_id: str, request: Request, actor: Actor = Depends(page_actor)):
    return act(actor, lambda: root.verify(actor.ctx, action_id), "done",
               f"/root/actions?open={action_id}", lambda **kw: actions_page(request, actor, **kw))


@router.post("/people/{user_id}/lockout")
def lockout(
    user_id: str, request: Request, reason: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _run(actor, lambda: root.lockout(actor.ctx, actor.config.kit_issuer, user_id, reason),
                lambda **kw: actions_page(request, actor, **kw))


@router.post("/people/{user_id}/unlock")
def unlock(
    user_id: str, request: Request, reason: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _run(actor, lambda: root.unlock(actor.ctx, user_id, reason),
                lambda **kw: actions_page(request, actor, **kw))


@router.post("/people/{user_id}/sessions/end")
def end_sessions(
    user_id: str, request: Request, reason: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _run(actor, lambda: root.end_sessions(actor.ctx, user_id, reason),
                lambda **kw: actions_page(request, actor, **kw))
