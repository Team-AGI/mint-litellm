"""엔드포인트·운영자·조직 화면."""

import logging
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import FileResponse, JSONResponse

from mint_litellm.console import api, setup_state
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.pages.common import act
from mint_litellm.console.templating import render
from mint_litellm.control import (
    config_transfer,
    directory,
    endpoint_apps,
    endpoint_coverage,
    endpoint_kits,
    org_suggest,
    siem,
)
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.operators import SERVICE_ACCOUNTS
from mint_litellm.control.services import operators as operator_service
from mint_litellm.control.services import orgs as org_service
from mint_litellm.control.services import reads
from mint_litellm.control.services.base import transact
from mint_litellm.types.cli_commands import OperatorRole
from mint_litellm.types.events import EventKind

log = logging.getLogger(__name__)
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


TABS = ("installs", "local-mcp", "ai-tools")


@router.get("/endpoints")
def endpoints(request: Request, actor: Actor = Depends(page_actor)):
    return endpoints_page(request, actor)


def endpoints_page(request: Request, actor: Actor, error=None, status=200):
    view = endpoint_view(
        endpoint_kits.installs(actor.conn, actor.instance),
        endpoint_kits.local_mcp_inventory(actor.conn, actor.instance),
        datetime.now(UTC),
    )
    people = {r["user_id"]: r["email"] for r in fetchall(  # 목록에 UUID 대신 사람 이름
        actor.conn, "SELECT user_id, email FROM mint.directory_users WHERE instance_id = %s",
        (actor.instance,))}
    for r in [*view["rows"], *view.get("mcp", [])]:
        if isinstance(r, dict):
            r["person"] = people.get(r.get("user_id")) or r.get("user_id")
    asked = request.query_params.get("tab")
    tab = asked if asked in TABS else "installs"
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
    ai = endpoint_coverage.coverage_view(view["rows"], view["mcp"])
    chosen = request.query_params.get("client", "")
    client = next((c for c in ai["clients"] if c["client"] == chosen), None)
    if selected is not None:
        selected["pause_view"] = pause_view(actor, selected)
        selected["apps"] = endpoint_apps.list_apps(actor.conn, actor.instance, selected["user_id"])
    ctx = {**view, "tab": tab, "state": state if state in STATES else "", "STATES": STATES,
           "VIOLATIONS": VIOLATIONS, "selected": selected, "kind": kind, "ai": ai,
           "client": client, "error": error}
    return render(request, "endpoints.html", ctx, actor=actor, status=status)


def pause_view(actor: Actor, row: dict) -> dict:
    """연결 중지의 네 상태: 서버 차단 · 단말 수신 · 실행기 정지 · 관리 밖 경로."""
    paused = row.get("paused_at")
    runner = None
    if paused:
        runner = endpoint_coverage.paused_runner_at(
            actor.conn, actor.instance, row["key_alias"], paused)
    return {
        "paused": bool(paused), "blocked_at": paused,
        "received": row.get("paused_ack") == row.get("pause_gen") and row.get("paused_ack_at"),
        "runner_at": runner,
    }


def _back(client: str) -> str:
    return "/endpoints?tab=ai-tools" + (f"&client={client}" if client else "")


def _device_action(
    request: Request, actor: Actor, alias: str, client: str, work, ok: str, back: str | None = None
):
    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "관리자만 할 수 있습니다.")
        work()

    return act(
        actor, action, ok, back or _back(client),
        lambda **kw: endpoints_page(request, actor, **kw))


@router.post("/endpoints/{alias}/pause")
def pause_endpoint(
    alias: str, request: Request, client: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _device_action(request, actor, alias, client,
                          lambda: endpoint_coverage.pause(actor.ctx, alias), "endpoint_paused")


@router.post("/endpoints/{alias}/resume")
def resume_endpoint(
    alias: str, request: Request, client: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _device_action(request, actor, alias, client,
                          lambda: endpoint_coverage.resume(actor.ctx, alias), "endpoint_resumed")


@router.post("/endpoints/{alias}/reconnect")
def reconnect_endpoint(
    alias: str, request: Request, client: str = Form(""), actor: Actor = Depends(page_actor)
):
    return _device_action(
        request, actor, alias, client,
        lambda: endpoint_coverage.request_reconnect(actor.conn, actor.instance, alias),
        "endpoint_reconnect")


@router.post("/endpoints/apps/{app_id}/revoke")
def revoke_app(
    app_id: str, request: Request, ref: str = Form(""), actor: Actor = Depends(page_actor)
):
    """사람이 만든 앱의 자격을 회수한다(관리자만)."""

    def work():
        issuer = actor.config.kit_issuer
        if issuer is None:
            raise AdminError(AdminCode.CONFLICT, "앱 자격을 회수할 수 없습니다.")
        try:
            endpoint_apps.revoke_app(
                actor.conn, issuer, actor.instance, app_id, actor=actor.ctx.operator.name)
        except LiteLLMError:
            raise AdminError(AdminCode.CONFLICT, "앱 자격을 회수하지 못했습니다.") from None

    back = "/endpoints?tab=installs" + (f"&open={quote(ref, safe='')}" if ref else "")
    return _device_action(request, actor, "", "", work, "app_revoked", back)


@router.post("/endpoints/{key_alias}/revoke")
def revoke_device(
    key_alias: str, request: Request, reason: str = Form(""), actor: Actor = Depends(page_actor)
):
    """PC 한 대의 연결만 해제한다(분실). 같은 사람의 다른 PC는 그대로다."""
    issuer = actor.config.kit_issuer

    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "관리자만 단말 연결을 해제할 수 있습니다.")
        if issuer is None:
            raise ControlError("단말 연결을 해제할 수 없습니다.")
        with transact(actor.ctx):
            try:
                user_id = endpoint_kits.revoke_install(
                    actor.conn, issuer, actor.instance, key_alias, actor.ctx.operator.name)
            except LiteLLMError:
                log.exception("단말 설치 묶음 키 해제 실패")
                raise ControlError("단말 연결을 해제하지 못했습니다.") from None
            actor.ctx.emit(
                EventKind.ENDPOINT_REVOKED, user_id, int(datetime.now(UTC).timestamp()),
                {"user_id": user_id, "installs": 1, "key_alias": key_alias,
                 "reason": reason.strip()[:500]},
            )

    return act(actor, action, "endpoint_revoked", "/endpoints?tab=installs",
               lambda **kw: endpoints_page(request, actor, **kw))


@router.post("/endpoints/revoke")
def revoke_endpoint(
    request: Request, user_id: str = Form(...), reason: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    """사용자의 단말 연결을 해제한다(분실·퇴사). 직원 본인의 해제와 같은 키 폐기를 쓴다."""
    issuer = actor.config.kit_issuer

    def action():
        if actor.role != "admin":
            raise AdminError(AdminCode.FORBIDDEN, "관리자만 단말 연결을 해제할 수 있습니다.")
        if issuer is None:
            raise ControlError("단말 연결을 해제할 수 없습니다.")
        with transact(actor.ctx):
            try:
                count = endpoint_kits.revoke_keys(actor.conn, issuer, actor.instance, user_id)
            except LiteLLMError:
                log.exception("단말 설치 묶음 키 해제 실패")
                raise ControlError("단말 연결을 해제하지 못했습니다.") from None
            actor.ctx.emit(
                EventKind.ENDPOINT_REVOKED, user_id, int(datetime.now(UTC).timestamp()),
                {"user_id": user_id, "installs": count, "reason": reason.strip()[:500]},
            )

    return act(actor, action, "endpoint_revoked", "/endpoints?tab=installs",
               lambda **kw: endpoints_page(request, actor, **kw))


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
    listed = [] if actor.role == "viewer" else reads.operators(actor.conn, actor.instance)
    operators = [o for o in listed if o["name"] not in SERVICE_ACCOUNTS]
    system_accounts = [o for o in listed if o["name"] in SERVICE_ACCOUNTS]
    soon = datetime.now(UTC) + timedelta(days=7)
    ctx = {
        "operators": operators,
        "system_accounts": system_accounts,
        "expiring": sum(1 for o in operators if o["expires_at"] and o["expires_at"] < soon),
        "orgs": reads.orgs(actor.conn, actor.instance),
        "bindings": reads.bindings(actor.conn, actor.instance),
        "suggestions": org_service.list_suggestions(actor.ctx),
        "transfers": reads.transfers(actor.conn, actor.instance) if actor.role == "admin" else [],
        "siem": siem.listing(actor.conn, actor.instance) if actor.role == "admin" else [],
        "people": _people(actor) if actor.role == "admin" else [],
        "backups": backup_folders() if actor.role == "admin" else [],
        "backup_requested": (
            setup_state.mark_time(actor, BACKUP_MARK) if actor.role == "admin" else None
        ),
        "siem_kinds": siem.KINDS,
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


def _admin_only(actor: Actor) -> None:
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 할 수 있습니다.")


def _people(actor: Actor) -> list[dict]:
    """운영자로 지정할 수 있는 사람: 로그인한 적 있는 LiteLLM 사용자 중 아직 운영자가 아닌 사람."""
    return fetchall(
        actor.conn,
        "SELECT d.user_id, d.email FROM mint.directory_users d WHERE d.instance_id = %s"
        " AND d.gone_at IS NULL AND NOT EXISTS (SELECT 1 FROM mint.operators o"
        " WHERE o.instance_id = d.instance_id AND o.user_id = d.user_id"
        " AND (o.expires_at IS NULL OR o.expires_at > now()))"
        " ORDER BY coalesce(d.email, d.user_id)",
        (actor.instance,),
    )


def designate_operator(actor: Actor, user_id: str, role: str) -> None:
    """명부의 사람을 운영자로 지정한다(운영자 화면과 사람 화면이 함께 쓴다)."""
    _admin_only(actor)
    user = fetchone(
        actor.conn,
        "SELECT email FROM mint.directory_users WHERE instance_id = %s AND user_id = %s"
        " AND gone_at IS NULL",
        (actor.instance, user_id),
    )
    if user is None:
        raise AdminError(AdminCode.NOT_FOUND, "사람 목록에 없는 사용자입니다.")
    name = directory._operator_name(actor.conn, actor.instance, user_id, user["email"])
    operator_service.add(actor.ctx, actor.litellm(), name, OperatorRole(role), user_id, None)


@router.post("/admin/operators")
def add_operator(
    request: Request,
    user_id: str = Form(...),
    role: str = Form(...),
    actor: Actor = Depends(page_actor),
):
    """명부의 사람을 운영자로 지정한다. 지정된 사람은 자기 LiteLLM 계정으로 /login에 들어온다."""
    return act(actor, lambda: designate_operator(actor, user_id, role), "operator_added",
               "/admin?tab=operators", tabbed(request, actor, "operators"))


@router.post("/admin/siem")
def siem_add(
    request: Request,
    name: str = Form(...),
    kind: str = Form(...),
    endpoint: str = Form(...),
    token: str = Form(""),
    secret: str = Form(""),
    index: str = Form(""),
    from_start: str = Form(""),
    actor: Actor = Depends(page_actor),
):
    """전달 대상 추가. 토큰은 값을 적어 봉인해 두거나 읽을 곳(환경 변수·파일)을 적는다."""

    def action():
        _admin_only(actor)
        if kind not in siem.KINDS:
            raise ValueError(kind)
        target, where = name.strip(), token.strip()
        ref = (f"file:{where}" if where.startswith("/") else f"env:{where}") if where else None
        source = "sealed" if secret.strip() else ref.partition(":")[0] if ref else None
        siem.add(
            actor.conn, actor.instance, name=target, kind=kind, endpoint=endpoint.strip(),
            secret_ref=ref, options={"index": index.strip()} if index.strip() else {},
            from_start=bool(from_start), created_by=actor.ctx.operator.name,
            token=secret.strip() or None,
        )
        actor.ctx.emit(
            EventKind.SIEM_TARGET_ADDED, f"{target}-{_stamp()}", 1,
            {"name": target, "kind": kind, "secret_source": source},
        )

    return act(actor, action, "siem_added", "/admin?tab=siem", tabbed(request, actor, "siem"))


@router.post("/admin/siem/{name}/remove")
def siem_remove(
    name: str, request: Request, confirm_name: str = Form(""), actor: Actor = Depends(page_actor)
):
    def action():
        _admin_only(actor)
        api.confirm(name, confirm_name, "SIEM 대상")
        done = actor.conn.execute(
            "DELETE FROM mint.siem_targets WHERE instance_id = %s AND name = %s",
            (actor.instance, name),
        ).rowcount
        if not done:
            raise AdminError(AdminCode.NOT_FOUND, "SIEM 대상이 없습니다.")
        actor.ctx.emit(EventKind.SIEM_TARGET_REMOVED, f"{name}-{_stamp()}", 1, {"name": name})

    return act(actor, action, "siem_removed", "/admin?tab=siem", tabbed(request, actor, "siem"))


# --- 백업 ---------------------------------------------------------------------------------------
# 예약 백업 컨테이너가 하루 한 번, 그리고 요청 표시가 새로 생기면 1분 안에 두 데이터베이스를
# backups/<시각>/에 덤프한다. 콘솔은 그 폴더를 읽기 전용으로 보고 요청 표시만 남긴다.

BACKUP_MARK = "backup_requested"
BACKUP_FOLDER = re.compile(r"\d{8}T\d{6}Z")
BACKUP_FILES = ("mint.sql", "litellm.sql")


def backup_root() -> Path:
    return Path(os.environ.get("MINT_BACKUP_DIR", "/var/lib/mint/backups"))


def backup_folders() -> list[dict]:
    root = backup_root()
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir(), reverse=True):
        if d.is_dir() and BACKUP_FOLDER.fullmatch(d.name):
            files = [{"name": f.name, "size": f.stat().st_size}
                     for f in (d / n for n in BACKUP_FILES) if f.is_file()]
            at = datetime.strptime(d.name, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
            out.append({"name": d.name, "files": files, "at": at})
    return out


@router.post("/admin/backups")
def backup_now(request: Request, actor: Actor = Depends(page_actor)):
    def action():
        _admin_only(actor)
        setup_state.mark(actor.conn, actor.instance, BACKUP_MARK, actor.ctx.operator.name)

    return act(actor, action, "backup_requested", "/admin?tab=transfer",
               tabbed(request, actor, "transfer"))


@router.get("/admin/backups/{folder}/{file}")
def backup_download(folder: str, file: str, actor: Actor = Depends(page_actor)):
    _admin_only(actor)
    path = backup_root() / folder / file
    if not BACKUP_FOLDER.fullmatch(folder) or file not in BACKUP_FILES or not path.is_file():
        raise AdminError(AdminCode.NOT_FOUND, "백업 파일이 없습니다.")
    return FileResponse(path, media_type="application/sql", filename=f"{folder}-{file}")


@router.get("/admin/config/export")
def config_export(actor: Actor = Depends(page_actor)):
    """설정 내보내기(비밀·토큰 없음). 다른 환경의 가져오기에 쓴다."""
    _admin_only(actor)
    doc = config_transfer.export_doc(actor.conn, actor.instance)
    counts = {k: len(v) for k, v in doc.items() if isinstance(v, list) and k != "refill"}
    stamp = _stamp()
    actor.ctx.emit(EventKind.CONFIG_EXPORTED, stamp, 1, {"file": "console", "counts": counts})
    actor.conn.commit()
    name = f"mint-config-{stamp[:15]}.json"
    return JSONResponse(doc, headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")


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
