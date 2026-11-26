"""직원 화면(서버 렌더링): 내 서버(동의 포함), 내 요청, 내 단말.

로그인은 관리자와 같은 본인 키 확인이지만 운영자 행이 필요 없고 세션 쿠키가 따로다. 모든 쓰기는
``control.services.staff``의 서비스 함수(데이터베이스의 ``mint.staff_*`` 함수)만 부르며, 직원
연결(``mint_staff_app``)로 한 트랜잭션에서 한다.
"""

import logging
import secrets
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from mint_litellm.console import labels, login, pack_view
from mint_litellm.console.cookies import DEFAULT_PASSWORD, delete_cookie, set_cookie
from mint_litellm.console.core import (
    COOKIE,
    STAFF_COOKIE,
    STATUS,
    ConsoleConfig,
    Unauthenticated,
    config_of,
    db,
    read_cookie,
    require_csrf,
    require_origin,
    too_many_attempts,
)
from mint_litellm.console.oidc import login_context
from mint_litellm.console.pages.common import see_other, server_names
from mint_litellm.console.templating import render
from mint_litellm.control import (
    alerts,
    directory,
    endpoint_apps,
    endpoint_coverage,
    endpoint_kits,
    kit_codes,
    kit_key_sync,
    links,
    ui_sessions,
)
from mint_litellm.control.db.connection import connect, fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.services import (
    access_requests,
    console_sessions,
    local_intakes,
    reads,
    staff,
    staff_intakes,
)
from mint_litellm.control.services import intakes as intakes_service
from mint_litellm.endpoint.kit_build import HARNESSES, build_kit, kit_version
from mint_litellm.plugin.snapshot import WINDOW_MAX_USES
from mint_litellm.types.events import AlertKind
from mint_litellm.types.ids import new_uuid7

router = APIRouter(dependencies=[Depends(require_csrf)])
# 로그인은 세션이 없을 때(또는 만료된 쿠키가 남았을 때)도 받으므로 CSRF 토큰 대신 출처만 본다.
public = APIRouter()

RECENT_RECORDS = 50
EXPIRING = timedelta(days=7)
REQUESTS = "/staff/confirmations"
log = logging.getLogger(__name__)


class StaffUnauthenticated(Unauthenticated):
    pass


@dataclass
class StaffActor:
    sctx: staff.StaffContext
    id_hash: str
    session_id: str
    config: ConsoleConfig
    request_id: str

    @property
    def user_id(self) -> str:
        return self.sctx.user_id

    @property
    def key_token(self) -> str:
        return self.sctx.key_token

    @property
    def csrf(self) -> str:
        return console_sessions.csrf_token(self.session_id)

    @property
    def label(self) -> str:
        """화면 상단에 보이는 이름: 이메일, 없으면 사용자 ID."""
        row = fetchall(
            self.sctx.control,
            "SELECT email FROM mint.directory_users WHERE instance_id = %s AND user_id = %s",
            (self.config.instance_id, self.user_id),
        )
        return (row[0]["email"] if row else None) or self.user_id


def staff_connection(request: Request) -> Iterator[psycopg.Connection]:
    url = config_of(request).staff_database_url
    if not url:
        raise AdminError(AdminCode.NOT_FOUND, "직원 화면이 설정되어 있지 않습니다.")
    with connect(url) as conn:
        yield conn


def staff_actor(
    request: Request,
    control: psycopg.Connection = Depends(db),
    staff_conn: psycopg.Connection = Depends(staff_connection),
) -> StaffActor:
    config = config_of(request)
    session_id = read_cookie(request, STAFF_COOKIE)
    if not session_id:
        raise StaffUnauthenticated()
    id_hash = console_sessions.hash_id(session_id)
    row = staff.find_session(
        control, config.instance_id, id_hash, config.stage2.session_verify_window_seconds)
    if row is not None and ui_sessions.litellm_logged_out(
        control, config.instance_id, config.litellm_url, config.stage2.export_hmac_key, id_hash
    ):
        console_sessions.revoke(
            control, config.instance_id, id_hash, actor=row["user_id"], reason="litellm_logout"
        )
        control.commit()  # 아래 인증 오류가 이 폐기를 되돌리지 않게 한다
        row = None
    if row is None:
        raise StaffUnauthenticated()
    sctx = staff.StaffContext(
        staff_conn, control, config.instance_id, row["user_id"],
        consent_max_days=config.stage2.staff_consent_max_days,
        verify_window_seconds=config.stage2.session_verify_window_seconds,
        team_ids=tuple(row["team_ids"]), key_token=row["key_token"],
    )
    staff.touch_session(
        sctx, id_hash,
        datetime.now(UTC) + timedelta(seconds=config.stage2.session_idle_seconds),
    )
    return StaffActor(sctx, id_hash, session_id, config, request.state.request_id)


def act(
    actor: StaffActor, action: Callable[[], Any], ok: str, back: str,
    rebuild: Callable[..., Response],
) -> Response:
    """서비스 호출 하나. 성공하면 알림과 함께 목록으로, 실패하면 같은 화면에 오류를 보인다."""
    try:
        action()
    except ControlError as error:
        status = STATUS[error.code] if isinstance(error, AdminError) else 400
        return rebuild(error=str(error), status=status)
    except psycopg.errors.InsufficientPrivilege:
        return rebuild(
            error="이 요청을 처리할 수 있는 상태가 아닙니다. 화면을 새로 고치십시오.", status=403
        )
    except psycopg.errors.CheckViolation:
        return rebuild(error="이미 처리되었거나 만료된 요청입니다.", status=409)
    return RedirectResponse(f"{back}{'&' if '?' in back else '?'}ok={ok}", status_code=303)


def staff_render(
    request: Request, name: str, ctx: dict, actor: StaffActor, status: int = 200
) -> Response:
    """직원 화면. 메뉴의 「내 요청」 배지에 확인을 기다리는 요청 수를 싣는다."""
    now = datetime.now(UTC)
    waiting = sum(
        c["status"] == "pending" and c["expires_at"] > now
        for c in staff.list_confirmations(actor.sctx)
    )
    return render(
        request, name, {**ctx, "badges": {"staff_requests": waiting}}, actor=actor, status=status
    )


# --- 서버 도입 신청 --------------------------------------------------------------------------


@router.get("/staff/intakes")
def intake_list(request: Request, actor: StaffActor = Depends(staff_actor)):
    rows = application_rows(actor)
    return staff_render(request, "staff_intakes.html", {"rows": rows}, actor)


def name_intakes(actor: StaffActor, rows: list[dict]) -> None:
    """신청 행에 서버 별칭과 신청한 주소를 붙인다(별칭이 없으면 식별자)."""
    if not rows:
        return
    names = server_names(actor.config.litellm_admin)
    urls = {
        r["server_id"]: r["url"] for r in fetchall(
            actor.sctx.control,
            "SELECT DISTINCT ON (server_id) server_id, url FROM mint.deployment_contracts"
            " WHERE instance_id = %s AND server_id = ANY(%s)"
            " AND status IN ('candidate', 'approved')"
            " ORDER BY server_id, (status = 'candidate') DESC, id DESC",
            (actor.sctx.instance_id, [r["server_id"] for r in rows]),
        )
    }
    for row in rows:
        row["server_name"] = names.get(row["server_id"]) or row["server_id"]
        row["server_url"] = urls.get(row["server_id"])


def application_rows(actor: StaffActor) -> list[dict]:
    rows = staff_intakes.listing(actor.sctx)
    name_intakes(actor, rows)
    if rows:
        details = fetchall(
            actor.sctx.control,
            "SELECT id, source, state_version, endpoint_key_token IS NOT NULL AS via_pc"
            " FROM mint.intakes WHERE instance_id = %s AND requested_by = %s AND id = ANY(%s)",
            (actor.sctx.instance_id, actor.user_id, [r["id"] for r in rows]),
        )
        by_id = {r["id"]: r for r in details}
        live = {r["server_id"] for r in fetchall(  # 승인이 하나라도 살아 있는 서버
            actor.sctx.control,
            "SELECT DISTINCT server_id FROM mint.approvals WHERE instance_id = %s"
            " AND server_id = ANY(%s) AND status IN ('active', 'pending') AND valid_until > now()",
            (actor.sctx.instance_id, [r["server_id"] for r in rows]))}
        for row in rows:
            row.update(by_id.get(row["id"], {}))
            row["ended"] = (row.get("decision") in ("approved", "exception")
                            and row.get("server_id") not in live)
    return rows


def source_of(actor: StaffActor, ids: list) -> dict:
    """신청별 출처. 단말 신청에만 배지를 단다."""
    if not ids:
        return {}
    rows = fetchall(actor.sctx.control,
                    "SELECT id, source FROM mint.intakes WHERE instance_id=%s AND id = ANY(%s)",
                    (actor.sctx.instance_id, ids))
    return {r["id"]: r["source"] for r in rows}


def from_pc(actor: StaffActor, ids: list) -> set:
    """PC(mint add)에서 낸 신청. 나머지 로컬 신청은 웹 화면에서 냈다."""
    if not ids:
        return set()
    return {r["id"] for r in fetchall(
        actor.sctx.control, "SELECT id FROM mint.intakes WHERE instance_id=%s AND id = ANY(%s)"
        " AND endpoint_key_token IS NOT NULL", (actor.sctx.instance_id, ids))}


def intake_form(request: Request, actor: StaffActor, form=None, error=None, status=200):
    values = {"request_id": str(new_uuid7()), **(form or {})}
    ports = ", ".join(map(str, actor.config.stage2.intake_allowed_ports))
    return staff_render(request, "staff_intake_new.html",
                        {"f": values, "error": error, "ports": ports}, actor, status)


@router.post("/staff/intakes/probe")
def intake_probe(
    request: Request, request_id: str = Form(""), url: str = Form(""), purpose: str = Form(""),
    actor: StaffActor = Depends(staff_actor),
):
    """제출 전 주소 확인. 실패해도 제출은 막지 않는다."""
    form = dict(request_id=request_id or str(new_uuid7()), url=url, purpose=purpose)
    if local_intakes.is_local(url):  # 저장소·패키지: 판본·실행 명령을 풀어 미리보기를 보인다
        return repo_intake(request, actor, {**form, "step": ""})
    ports = actor.config.stage2.intake_allowed_ports
    try:
        found = staff_intakes.probe(
            url.strip(), ports, fetchall(
                actor.sctx.control,
                "SELECT id, kind, value FROM mint.allowlists WHERE instance_id = %s"
                " AND status = 'active' AND valid_from <= now() AND valid_until > now()"
                " AND org_id IS NULL", (actor.sctx.instance_id,)),
            actor.config.control.litellm_control())
    except ControlError as error:
        return intake_form(request, actor, form, error=str(error), status=422)
    text = labels.PROBE[found["state"]].format(
        tools=found["tools"], reason=labels.pick(labels.CHECK_REASON, found.get("reason")))
    return intake_form(request, actor, {**form, "probe": text, "probe_ok": found["state"] == "ok"})


# 폐기·반려된 서버의 옛 신청은 「이미 신청한 서버」로 돌려보내지 않는다(다시 신청할 수 있어야 한다).
LIVE_SERVER = (" AND NOT EXISTS (SELECT 1 FROM mint.servers s WHERE s.instance_id = i.instance_id"
               " AND s.server_id = i.server_id"
               " AND s.status IN ('terminating', 'terminated', 'rejected'))")


@router.get("/staff/intakes/new")
def intake_new(request: Request, actor: StaffActor = Depends(staff_actor)):
    return intake_form(request, actor)


@router.post("/staff/intakes")
def intake_submit(
    request: Request, request_id: str = Form(...), url: str = Form(...),
    purpose: str = Form(...), step: str = Form(""), name: str = Form(""),
    commit: str = Form(""), command: str = Form(""), actor: StaffActor = Depends(staff_actor),
):
    form = dict(request_id=request_id, url=url, purpose=purpose)
    ports = actor.config.stage2.intake_allowed_ports
    if local_intakes.is_local(url):
        return repo_intake(request, actor, {**form, "step": step, "name": name,
                                            "commit": commit, "command": command})
    target = {}

    def action():
        payload, _ = staff_intakes.validate(form, ports)
        prior = fetchone(
            actor.sctx.control,
            "SELECT i.id FROM mint.intakes i WHERE i.instance_id = %s AND i.requested_by = %s"
            " AND i.source IN ('staff', 'endpoint')"
            " AND (i.status <> 'decided' OR i.decision IN ('approved', 'exception'))"
            + LIVE_SERVER +
            " AND EXISTS (SELECT 1 FROM mint.deployment_contracts d WHERE d.instance_id ="
            " i.instance_id AND d.server_id = i.server_id AND d.url = %s)"
            " ORDER BY i.created_at DESC LIMIT 1",
            (actor.sctx.instance_id, actor.user_id, payload["url"]),
        )
        if prior and str(prior["id"]) != request_id:
            target.update(id=str(prior["id"]), existing=True)
        else:
            identifier = staff_intakes.submit(actor.sctx, actor.id_hash, request_id, form, ports)
            target.update(id=identifier, existing=False)

    response = act(actor, action, "intake_created", "/staff/intakes/" + request_id,
                   lambda **kw: intake_form(request, actor, form, **kw))
    if response.status_code == 303:
        notice = "intake_existing" if target["existing"] else "intake_created"
        response.headers["location"] = f"/staff/intakes/{target['id']}?ok={notice}"
    return response


def repo_intake(request: Request, actor: StaffActor, form: dict):
    """소스 저장소 주소: 확인 단계는 미리보기를 보이고, 제출 단계는 로컬 신청을 만든다."""
    if form["step"] != "submit":
        try:
            form = {**form, **local_intakes.resolve(form["url"]), "step": "submit"}
        except ControlError as error:
            return intake_form(request, actor, form, error=str(error), status=422)
        return intake_form(request, actor, form)
    target = {"existing": False}

    def action():
        prior = my_prior_local_intake(actor, form)
        if prior:  # 같은 서버를 다시 신청하면 오류 대신 기존 신청으로 보낸다(원격 신청과 같다)
            target.update(id=prior, existing=True)
        else:
            target["id"] = local_intakes.submit_staff(
                actor.sctx, actor.id_hash, form["request_id"], form)

    response = act(actor, action, "intake_created", "/staff/intakes/" + form["request_id"],
                   lambda **kw: intake_form(request, actor, form, **kw))
    if response.status_code == 303:
        notice = "intake_existing" if target["existing"] else "intake_created"
        response.headers["location"] = f"/staff/intakes/{target['id']}?ok={notice}"
    return response


def my_prior_local_intake(actor: StaffActor, form: dict) -> str | None:
    """같은 직원이 같은 이름·판본으로 낸 진행 중이거나 승인된 로컬 신청의 번호(없으면 None)."""
    payload = local_intakes.build_payload(form)
    version = (payload["spec"] or {}).get("version")
    row = fetchone(
        actor.sctx.control,
        "SELECT i.id, d.pack_spec ->> 'version' AS version FROM mint.intakes i"
        " LEFT JOIN mint.deployment_contracts d ON d.instance_id = i.instance_id AND d.id = i.id"
        " WHERE i.instance_id = %s AND i.requested_by = %s AND i.server_id = %s"
        " AND i.source = 'endpoint' AND (i.status <> 'decided' OR i.decision IN"
        " ('approved', 'exception'))" + LIVE_SERVER + " ORDER BY i.created_at DESC LIMIT 1",
        (actor.sctx.instance_id, actor.user_id, payload["server_id"]),
    )
    if row and (row["version"] is None or version is None or row["version"] == version):
        return str(row["id"])
    return None


def _intake_job_error(actor: StaffActor, row: dict):
    from mint_litellm.console.pages.servers import intake_job_error  # 순환 참조를 피한다

    return intake_job_error(actor.sctx.control, actor.sctx.instance_id, row)


@router.get("/staff/intakes/{intake_id}")
def intake_detail(intake_id: str, request: Request, actor: StaffActor = Depends(staff_actor)):
    row = staff_intakes.detail(actor.sctx, intake_id)
    name_intakes(actor, [row])
    reason = row["decision_reason"] or ""
    if reason.startswith("check_failed:"):
        _, check, code = reason.split(":", 2)
        reason = labels.pick(labels.CHECK, check) + ": " + labels.pick(labels.CHECK_REASON, code)
    source = source_of(actor, [row["id"]]).get(row["id"], "staff")
    via_pc = row["id"] in from_pc(actor, [row["id"]])
    # 검사에서 걸린 것(가장 최근 시도). 판별 불가·실패에서 직원이 다음을 알 수 있게 사유를 보인다.
    issues = [
        f"{labels.pick(labels.CHECK, c['check'])}: {labels.check_reason(c)}"
        for c in fetchall(
            actor.sctx.control,
            "SELECT \"check\", result, reason_code, inputs FROM mint.intake_checks c"
            " WHERE c.instance_id = %s AND c.intake_id = %s AND c.result <> 'pass'"
            " AND c.attempt = (SELECT max(attempt) FROM mint.intake_checks d"
            " WHERE d.instance_id = c.instance_id AND d.intake_id = c.intake_id)",
            (actor.sctx.instance_id, row["id"]))
    ] if row["status"] in ("indeterminate", "failed", "passed") else []
    stages = None
    if source == "endpoint":
        pack = pack_view.read(actor.sctx.control, actor.sctx.instance_id, row["server_id"])
        stages = pack_view.stages(row["status"], bool(pack and pack.get("pack_sha256")))
    delivery = []
    if row["status"] == "decided" and row["decision"] in ("approved", "exception"):
        from mint_litellm.console.pages.servers import delivery_progress
        from mint_litellm.control import usage_reader

        seen = usage_reader.read_tools(actor.sctx.control, actor.sctx.instance_id, row["server_id"])
        delivery = delivery_progress(fetchall(
            actor.sctx.control,
            "SELECT decision_version, stage, target, reason FROM mint.delivery_receipts"
            " WHERE instance_id = %s AND intake_id = %s",
            (actor.sctx.instance_id, row["id"])),
            local=source == "endpoint", called=any(t["calls"] for t in seen))
    return staff_render(request, "staff_intake_detail.html",
                        {"i": row, "decision_reason": reason, "source": source,
                         "issues": issues, "via_pc": via_pc,
                         "stages": stages, "delivery": delivery,
                         "job_error": _intake_job_error(actor, row),
                         "retry": intakes_service.retry_state(
                             actor.sctx.control, actor.sctx.instance_id,
                             {**row, "source": source})}, actor)


# --- 로그인·로그아웃 --------------------------------------------------------------------------

@router.post("/staff/intakes/{intake_id}/withdraw")
def intake_withdraw(intake_id: str, request: Request, state_version: int = Form(...),
                    reason: str = Form(...), confirm: str = Form(""),
                    actor: StaffActor = Depends(staff_actor)):
    from mint_litellm.control.services import intake_withdrawals

    def action():
        if confirm != "yes":
            raise ControlError("철회 확인란을 선택하십시오.")
        return intake_withdrawals.staff_withdraw(actor.sctx, actor.id_hash,
                                                 intake_id, state_version, reason)

    def rebuild(error=None, status=400):
        row = staff_intakes.detail(actor.sctx, intake_id)
        name_intakes(actor, [row])
        return staff_render(request, "staff_intake_detail.html",
                            {"i": row, "decision_reason": row["decision_reason"] or "",
                             "error": error}, actor, status)

    return act(actor, action, "intake_withdrawn", "/staff/intakes/" + intake_id, rebuild)


def start_staff_session(
    config: ConsoleConfig, control: psycopg.Connection, staff_conn: psycopg.Connection,
    user_id: str, key_token: str, team_ids: tuple[str, ...],
) -> str:
    """직원 세션을 만들고 쿠키에 담을 세션 식별자(평문)를 돌려준다."""
    session_id = secrets.token_urlsafe(32)
    id_hash = console_sessions.hash_id(session_id)
    sctx = staff.StaffContext(
        staff_conn, control, config.instance_id, user_id,
        consent_max_days=config.stage2.staff_consent_max_days,
        verify_window_seconds=config.stage2.session_verify_window_seconds,
        team_ids=team_ids, key_token=key_token,
    )
    now = datetime.now(UTC)
    staff.start_session(
        sctx, id_hash, key_token,
        now + timedelta(seconds=config.stage2.session_idle_seconds),
        now + timedelta(seconds=config.stage2.session_absolute_seconds),
    )
    return session_id


@public.get("/staff/login")
def login_form() -> Response:
    return RedirectResponse("/login", status_code=303)


@public.post("/staff/login", dependencies=[Depends(require_origin)])
def login_submit(
    request: Request,
    key: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    control: psycopg.Connection = Depends(db),
    staff_conn: psycopg.Connection = Depends(staff_connection),
) -> Response:
    config = config_of(request)
    if not key:
        from mint_litellm.console.password_login import sign_in  # 순환 참조를 피한다

        return sign_in(request, control, "auto", username, password)
    if not config.key_login:
        return render(
            request, "login.html", login_context(request, "키 로그인은 사용하지 않습니다."),
            status=403,
        )
    if too_many_attempts(request):
        return render(
            request, "login.html",
            login_context(request, "로그인 시도가 너무 많습니다. 잠시 뒤 다시 시도하십시오."),
            status=429,
        )
    try:
        identity = login.verify(config.litellm_url, key)
    except login.LoginRefused as refused:
        return render(request, "login.html", login_context(request, str(refused)), status=401)
    finally:
        key = ""  # 평문 키는 여기서 버린다
    directory.record_login(
        control, config.instance_id, identity.user_id, identity.key_token, identity.user,
        identity.team_ids,
    )
    session_id = start_staff_session(
        config, control, staff_conn, identity.user_id, identity.key_token, identity.team_ids)
    response = RedirectResponse("/staff", status_code=303)
    set_cookie(response, request, STAFF_COOKIE, session_id)
    return response


def password_page(request: Request, actor: StaffActor, error=None, status=200):
    from mint_litellm.console import password_login  # 순환 참조를 피한다

    ctx = {"error": error, "has_password": password_login.has_password(actor.key_token)}
    return staff_render(request, "staff_password.html", ctx, actor, status)


@router.get("/staff/account/password")
def password_form(request: Request, actor: StaffActor = Depends(staff_actor)):
    return password_page(request, actor)


@router.post("/staff/account/password")
def password_submit(
    request: Request, current_password: str = Form(""), new_password: str = Form(""),
    confirm_password: str = Form(""), actor: StaffActor = Depends(staff_actor),
):
    from mint_litellm.console import password_login  # 순환 참조를 피한다

    error, status = password_login.submit(
        request, actor.user_id, actor.key_token,
        current_password, new_password, confirm_password,
    )
    if error:
        return password_page(request, actor, error, status)
    response = RedirectResponse("/staff/account/password?ok=password_changed", status_code=303)
    delete_cookie(response, request, DEFAULT_PASSWORD)
    return response


@router.post("/staff/logout")
def logout(request: Request, actor: StaffActor = Depends(staff_actor)) -> Response:
    staff.end_session(actor.sctx, actor.id_hash)
    ui_sessions.end_session(
        actor.sctx.control, actor.config.instance_id, actor.config.litellm_url,
        actor.config.stage2.export_hmac_key, actor.id_hash,
    )
    target = "/login"
    oidc_client = request.app.state.oidc
    if oidc_client is not None and console_sessions.is_oidc_session(actor.sctx.key_token):
        target = oidc_client.logout_url(request, target) or target
    response = RedirectResponse(target, status_code=303)
    delete_cookie(response, request, STAFF_COOKIE)
    delete_cookie(response, request, COOKIE)  # 한 번 로그인으로 함께 열린 관리자 화면도 닫는다
    delete_cookie(response, request, DEFAULT_PASSWORD)
    return response


# --- 11 내 서버(동의 포함) --------------------------------------------------------------------


def name_servers(actor: StaffActor, *groups: list[dict]) -> None:
    """행의 ``server_name``(LiteLLM 별칭, 없으면 식별자)과 ``server_url``을 채운다."""
    for rows in groups:
        name_intakes(actor, rows)


def event_label(row: dict) -> str:
    payload = row.get("payload") or {}
    if payload.get("kind") == "confirmation" and row["kind"] in labels.CONFIRMATION_EVENT:
        return labels.CONFIRMATION_EVENT[row["kind"]]
    if payload.get("subject") == "staff" and row["kind"] in labels.STAFF_SESSION_EVENT:
        return labels.STAFF_SESSION_EVENT[row["kind"]]
    return labels.EVENT_KIND.get(row["kind"], "기록")


START_FAILED = ("SERVER_START_FAILED", "SERVER_DEPS_MISMATCH")


def start_failures(actor: StaffActor, server_ids: list[str]) -> dict[str, str]:
    """시작하지 못한 서버와 사유: 가장 최근 도구 목록 검사, 그리고 내 PC가 알린 시작 실패(그 PC에서
    도구를 받은 적이 없을 때). 사유를 모르면 빈 문자열."""
    if not server_ids:
        return {}
    pcs = fetchall(
        actor.sctx.control,
        "SELECT DISTINCT ON (i.server_id) i.server_id, r.reason FROM mint.delivery_receipts r"
        " JOIN mint.intakes i ON i.instance_id = r.instance_id AND i.id = r.intake_id"
        " JOIN mint.endpoint_installs k ON k.instance_id = r.instance_id AND k.key_token = r.target"
        " AND k.user_id = %s AND k.revoked_at IS NULL"
        " WHERE r.instance_id = %s AND i.server_id = ANY(%s) AND r.stage = 'start_failed'"
        " AND NOT EXISTS (SELECT 1 FROM mint.delivery_receipts d"
        " WHERE d.instance_id = r.instance_id AND d.intake_id = r.intake_id"
        " AND d.target = r.target AND d.stage = 'discovered'"
        " AND d.decision_version = r.decision_version)"
        " ORDER BY i.server_id, r.recorded_at DESC",
        (actor.user_id, actor.sctx.instance_id, server_ids),
    )
    found = fetchall(
        actor.sctx.control,
        "SELECT DISTINCT ON (i.server_id) i.server_id, c.reason_code FROM mint.intake_checks c"
        " JOIN mint.intakes i ON i.instance_id = c.instance_id AND i.id = c.intake_id"
        " WHERE c.instance_id = %s AND i.server_id = ANY(%s) AND c.\"check\" = 'inspection'"
        " ORDER BY i.server_id, c.ran_at DESC",
        (actor.sctx.instance_id, server_ids),
    )
    out = {r["server_id"]: "" for r in found if r["reason_code"] in START_FAILED}
    out.update({r["server_id"]: r["reason"] or "" for r in pcs})
    return out


CALL_BUCKET = {"allowed": "allow", "observed": "observe", "pending_approval": "approve"}


def my_calls(actor: StaffActor) -> list[dict]:
    """내 호출 판정 목록. 읽기는 직원 역할의 본인 범위 함수가 맡아 다른 사람 호출은 오지 않는다."""
    rows = []
    for e in staff.list_events(actor.sctx, 1000):
        if e["kind"] != "decision_evaluated":
            continue
        p = e["payload"] or {}
        outcome = p.get("outcome") or ("allowed" if p.get("enforced_action") == "allow" else "")
        bucket = CALL_BUCKET.get(outcome, "block")
        code = ((p.get("stop") or {}).get("reason_code")
                or ((p.get("findings") or [{}])[0] or {}).get("reason_code"))
        rows.append({
            "at": e["inserted_at"], "server_id": p.get("resolved_server_id") or p.get("server_id"),
            "tool": p.get("tool"), "bucket": bucket,
            "reason": labels.outcome_reason(code) if bucket == "block" else None,
            "code": code if bucket == "block" else None,
        })
        if len(rows) == RECENT_RECORDS:
            break
    name_servers(actor, rows)
    return rows


def server_guide(actor: StaffActor, row: dict) -> dict:
    """서랍의 「이용 방법」과 동의 미리 채움: 승인된 신청의 목적·자료 범위, 로컬이면 출처."""
    control, iid = actor.sctx.control, actor.sctx.instance_id
    intake = fetchone(
        control,
        "SELECT purpose, data_grade, allowed_resources FROM mint.intakes WHERE instance_id = %s"
        " AND server_id = %s AND decision IN ('approved', 'exception')"
        " ORDER BY decided_at DESC LIMIT 1", (iid, row["server_id"])) or {}
    resources = intake.get("allowed_resources")
    scope = ", ".join(str(r) for r in resources)[:200] if isinstance(resources, list) else ""
    if not scope and intake:
        scope = f"{labels.pick(labels.DATA_GRADE, intake['data_grade'])} 자료"
    out = {"purpose": (intake.get("purpose") or "")[:128], "scope": scope, "repo": None,
           "commit": None}
    if row["local"]:
        spec = (fetchone(
            control,
            "SELECT pack_spec FROM mint.deployment_contracts WHERE instance_id = %s"
            " AND server_id = %s AND status = 'approved'", (iid, row["server_id"])) or {}
                ).get("pack_spec") or {}
        out.update(repo=spec.get("git"), commit=(spec.get("version") or "")[:12] or None)
    return out


def pc_stages(actor: StaffActor, server_ids: list[str]) -> dict[str, set[str]]:
    """내 PC(해제되지 않은 것)가 서버별로 받거나 시작한 단계(device_received·started·discovered)."""
    if not server_ids:
        return {}
    out: dict[str, set[str]] = {}
    for r in fetchall(
        actor.sctx.control,
        "SELECT DISTINCT i.server_id, r.stage FROM mint.delivery_receipts r"
        " JOIN mint.intakes i ON i.instance_id = r.instance_id AND i.id = r.intake_id"
        " JOIN mint.endpoint_installs k ON k.instance_id = r.instance_id AND k.key_token ="
        " r.target AND k.user_id = %s AND k.revoked_at IS NULL"
        " WHERE r.instance_id = %s AND i.server_id = ANY(%s)"
        " AND r.stage IN ('device_received', 'started', 'discovered')",
        (actor.user_id, actor.sctx.instance_id, server_ids),
    ):
        out.setdefault(r["server_id"], set()).add(r["stage"])
    return out


def card_phase(row: dict, stages: set[str], pcs: int) -> tuple[str, str]:
    """카드 상태. PC가 받고 시작하고 도구를 발견하기 전에는 사용 가능으로 보이지 않는다.

    원격 서버는 게이트웨이로 가므로 승인되고 도구가 있으면 사용 가능이다. 로컬(stdio) 서버는 내 PC가
    도구 목록을 보고해야 사용 가능이고, 그 전에는 준비 중(수신 대기·시작 중)이다.
    시작 실패는 사유와 함께 보인다.
    """
    if row["stopped"]:
        return "stopped", "내가 사용을 그만둔 서버입니다"
    if row["seen"]:
        return "ready", ""
    if row["start_failed"]:
        return "failed", "시작 실패" + (f" · {row['start_reason']}" if row["start_reason"] else "")
    if row["preparing"]:
        return "preparing", "승인됐고 도구를 확인하는 중입니다"
    if not row["local"]:
        return "ready", ""
    if not pcs:
        return "preparing", "연결된 PC가 없습니다. 내 PC에서 설치 명령을 실행하십시오"
    if stages & {"device_received", "started"}:
        return "preparing", "내 PC가 받았습니다. 시작하고 도구를 확인하는 중입니다"
    return "preparing", "승인됐고 내 PC가 아직 받지 않았습니다"


def my_open_requests(actor: StaffActor) -> dict[tuple[str, str], dict]:
    """내 대기 권한 요청: (서버, 도구)별. 도구를 비운 요청(서버 전체)은 도구가 빈 문자열이다."""
    return {(r["server_id"], r["tool"] or ""): r for r in access_requests.mine(actor.sctx)
            if r["status"] == "open"}


def tool_table(actor: StaffActor, row: dict, calls: list[dict]) -> list[dict]:
    """서랍의 도구 표. 승인된 도구 계약·검사 후보·내 PC가 실제로 본 도구를 합쳐 도구별 상태를 낸다.

    상태: 사용 가능 / 관리자 차단 / 승인 범위 밖 / 호출마다 승인. ``source``는 근거(내 PC가 확인 ·
    승인된 도구 · 검사 후보), ``code``는 막힌 사유 코드(권한 요청 양식에 그대로 실린다).
    """
    sctx, sid = actor.sctx, row["server_id"]
    status: dict[str, str] = {}
    for c in fetchall(sctx.control, "SELECT tool, status FROM mint.tool_contracts"
                      " WHERE instance_id = %s AND server_id = %s AND status IN ('candidate',"
                      " 'approved')", (sctx.instance_id, sid)):
        if status.get(c["tool"]) != "approved":
            status[c["tool"]] = c["status"]
    seen = {
        t.get("name") for r in fetchall(
            sctx.control,
            "SELECT t.tools FROM mint.endpoint_tool_lists t JOIN mint.endpoint_installs i ON"
            " i.instance_id = t.instance_id AND i.key_token = t.key_token WHERE"
            " t.instance_id = %s AND t.server_id = %s AND i.user_id = %s AND i.revoked_at IS NULL",
            (sctx.instance_id, sid, actor.user_id))
        for t in r["tools"] if isinstance(t, dict) and t.get("name")
    }
    names = sorted(set(status) | seen | {t for t in row["tools"] if t != "*"})
    denied = fetchall(
        sctx.control,
        "SELECT tools FROM mint.denials WHERE instance_id = %(iid)s AND lifted_at IS NULL"
        " AND server_id = %(sid)s AND ((scope_type = 'user' AND scope_id = %(user)s)"
        " OR (scope_type = 'team' AND scope_id = ANY(%(teams)s))"
        " OR (scope_type = 'key' AND scope_id = %(key)s) OR scope_type = 'server')"
        " AND NOT (scope_type = 'user' AND created_by = %(user)s AND tools IS NULL)",
        {"iid": sctx.instance_id, "sid": sid, "user": actor.user_id,
         "teams": list(sctx.team_ids), "key": sctx.key_token},
    )
    denied_all = any(d["tools"] is None for d in denied)
    denied_tools = {t for d in denied for t in d["tools"] or ()}
    last: dict[str, dict] = {}
    for c in calls:  # 최근 순
        if c["server_id"] == sid and c["tool"] and c["tool"] not in last:
            last[c["tool"]] = c
    out = []
    for name in names:
        if denied_all or name in denied_tools:
            state, text, code = "block", "관리자 차단", "DENIED"
        elif "*" not in row["tools"] and name not in row["tools"]:
            state, text, code = "block", "승인 범위 밖", "TOOL_NOT_IN_APPROVAL"
        elif last.get(name, {}).get("bucket") == "approve":
            state, text, code = "wait", "호출마다 승인", None
        else:
            state, text, code = "ok", "사용 가능", None
        source = ("내 PC가 확인" if name in seen
                  else "검사 후보" if status.get(name) == "candidate" else "승인된 도구")
        out.append({"name": name, "state": state, "text": text, "code": code,
                    "source": source, "last": last.get(name, {}).get("at")})
    return out


def org_servers(actor: StaffActor, available: list[dict], shown: set, blocked: dict,
                lapsed: set[str]) -> list[dict]:
    """조직에 승인돼 있지만 내 권한이 없는 서버: 이름과 목적만 보인다(도구 목록은 보이지 않는다)."""
    rows = [
        {**r, "ref": f"{r['org_id']}|{r['server_id']}",
         "reason_code": "APPROVAL_EXPIRED" if r["server_id"] in lapsed else "APPROVAL_ABSENT"}
        for r in available
        if (r["org_id"], r["server_id"]) not in shown and r["server_id"] not in blocked
    ]
    if rows:
        purposes = {
            p["server_id"]: p["purpose"] for p in fetchall(
                actor.sctx.control,
                "SELECT DISTINCT ON (server_id) server_id, purpose FROM mint.intakes"
                " WHERE instance_id = %s AND server_id = ANY(%s) AND decision IN ('approved',"
                " 'exception') ORDER BY server_id, decided_at DESC",
                (actor.sctx.instance_id, [r["server_id"] for r in rows]))
        }
        for r in rows:
            r["purpose"] = (purposes.get(r["server_id"]) or "")[:128]
    name_servers(actor, rows)
    return rows


def request_preset(request: Request, rows: list[dict], orgs: list[dict], tools_of) -> dict | None:
    """거부 응답의 해결 링크 ``/staff?request=서버&tool=도구&reason=사유``를 읽는다.

    내가 볼 수 있는 서버·도구일 때만 그 서랍과 요청 양식을 열고, 아니면 None(그냥 목록)이다.
    """
    want = request.query_params.get("request")
    if not want:
        return None
    tool = request.query_params.get("tool", "").strip()
    code = request.query_params.get("reason", "").strip().upper()
    code = code if code in access_requests.SUGGESTED else "APPROVAL_ABSENT"
    match = next((r for r in rows if r["server_id"] == want), None)
    if match and (not tool or tool in {t["name"] for t in tools_of(match)}):
        return {"server_id": want, "tool": tool, "reason_code": code, "ref": match["ref"]}
    other = next((r for r in orgs if r["server_id"] == want), None)
    if other and not tool:
        return {"server_id": want, "tool": "", "reason_code": code, "ref": other["ref"]}
    return None


def servers_page(request: Request, actor: StaffActor, error=None, status=200, form=None):
    now = datetime.now(UTC)
    by_server: dict[tuple, list[dict]] = {}
    for row in staff.list_consents(actor.sctx):
        row["view"] = "revoked" if row["revoked_at"] else (
            "expired" if row["valid_until"] <= now else "active")
        by_server.setdefault((row["org_id"], row["server_id"]), []).append(row)
    available = staff.list_available(actor.sctx)
    can_consent = {(t["org_id"], t["server_id"]) for t in available}
    blocked = staff.blocked_servers(actor.sctx)
    lapsed = staff.lapsed_servers(actor.sctx)
    progress = {}  # 내 신청의 진행 화면. 최근 신청부터 보므로 서버마다 가장 최근 것이 남는다
    for intake in reversed(staff_intakes.listing(actor.sctx)):
        if intake["decision"] not in ("withdrawn", "rejected"):
            progress[intake["server_id"]] = f"/staff/intakes/{intake['id']}"
    rows = []
    for r in available:
        sid = r["server_id"]
        stopped = blocked.get(sid) is True  # 내가 그만둔 서버(관리자가 막은 서버는 보이지 않는다)
        # 내가 신청해 승인됐지만 도구가 아직 없다(남이 신청한 서버는 승인 전까지 숨긴다).
        # 승인이 만료·철회돼 없어진 서버는 준비 중이 아니다.
        preparing = (not r["tools"] and sid not in blocked and sid in progress
                     and sid not in lapsed)
        if r["tools"] or stopped or preparing:
            rows.append({**r, "stopped": stopped, "preparing": preparing})
    shown = {(r["org_id"], r["server_id"]) for r in rows}
    rows += [  # 도구가 없어진 서버의 기존 동의도 철회할 수 있게 남긴다
        {"org_id": o, "server_id": sid, "org_name": o, "transport": None, "auth_type": None,
         "tools": [], "valid_until": None, "stopped": False, "preparing": False}
        for (o, sid) in by_server if (o, sid) not in shown
    ]
    seen = staff_intakes.observed(actor.sctx)
    for row in rows:
        key = (row["org_id"], row["server_id"])
        row["ref"] = f"{key[0]}|{key[1]}"
        row["consents"] = by_server.get(key, [])
        active = [c for c in row["consents"] if c["view"] == "active"]
        required = row.get("consent_required", True)
        row["state"] = "active" if active else ("none" if required else "free")
        row["consent_until"] = max((c["valid_until"] for c in active), default=None)
        row["expiring"] = bool(active) and row["consent_until"] < now + EXPIRING
        row["can_consent"] = key in can_consent and not row["preparing"]
        row["seen"] = seen.get(row["server_id"])
        row["progress"] = progress.get(row["server_id"])
        row["local"] = row.get("transport") == "stdio"
    failed = start_failures(actor, [r["server_id"] for r in rows if not r["seen"]])
    stages = pc_stages(actor, [r["server_id"] for r in rows if r["local"]])
    pcs = sum(i["state"] in ("managed", "user") for i in endpoint_kits.installs(
        actor.sctx.control, actor.sctx.instance_id, actor.user_id))
    for row in rows:
        row["start_failed"] = row["server_id"] in failed
        row["start_reason"] = failed.get(row["server_id"], "")
        row["phase"], row["phase_note"] = card_phase(
            row, stages.get(row["server_id"], set()), pcs)
    name_servers(actor, rows)
    orgs = org_servers(actor, available, shown, blocked, lapsed)
    open_requests = my_open_requests(actor)
    tab = request.query_params.get("tab", "servers")
    tab = tab if tab in ("servers", "applications", "records", "calls") else "servers"
    search = request.query_params.get("q", "").strip()[:256]
    def found(r: dict) -> bool:  # 식별자·이름·주소·조직 어디든 부분 일치(대소문자 무시)
        text = f"{r['server_id']} {r['server_name']} {r.get('server_url') or ''} {r['org_name']}"
        return search.casefold() in text.casefold()

    catalog = [r for r in rows if found(r)]
    org_found = [r for r in orgs if found(r)]
    records = [
        {"at": e["inserted_at"], "label": event_label(e)}
        for e in staff.list_events(actor.sctx, RECENT_RECORDS)
    ] if tab == "records" else []
    form = form or {}
    params = request.query_params
    wants_calls = tab == "calls" or params.get("open") or params.get("request") or form
    recent_calls = my_calls(actor) if wants_calls else []
    preset = request_preset(request, rows, orgs, lambda r: tool_table(actor, r, recent_calls))
    opened = form.get("target") or request.query_params.get("open") or (preset or {}).get("ref")
    selected = next((r for r in rows if r["ref"] == opened), None) if opened else None
    selected_org = next((r for r in orgs if r["ref"] == opened), None) if opened else None
    ctx = {
        "rows": rows,
        "catalog": catalog,
        "search": search,
        "applications": application_rows(actor) if tab == "applications" else [],
        "tab": tab,
        "records": records,
        "calls": [{**c, "requested": open_requests.get((c["server_id"], c["tool"] or ""))}
                  for c in recent_calls] if tab == "calls" else [],
        "pending_calls": sum(r["view"] == "pending" for r in my_approvals(actor))
        if not rows
        else 0,
        "need": sum(r["state"] == "none" and not r["stopped"] and not r["preparing"] for r in rows),
        "pcs": pcs,
        "expiring": sum(r["expiring"] for r in rows),
        "selected": selected,
        "selected_org": selected_org,
        "org_servers": org_found,
        "open_requests": {f"{k[0]}|{k[1]}": v for k, v in open_requests.items()},
        "tools_table": tool_table(actor, selected, recent_calls) if selected else [],
        "preset": preset,
        "ready": sum(r["phase"] == "ready" for r in rows),
        "waiting": sum(r["phase"] in ("preparing", "failed") for r in rows),
        "guide": server_guide(actor, selected) if selected else None,
        "max_days": actor.config.stage2.staff_consent_max_days,
        "text_version": labels.CONSENT_TEXT_VERSION,
        "text": labels.CONSENT_TEXT[labels.CONSENT_TEXT_VERSION],
        "form": form,
        "error": error,
    }
    return staff_render(request, "staff_servers.html", ctx, actor, status)


@router.get("/staff")
def servers(request: Request, actor: StaffActor = Depends(staff_actor)):
    return servers_page(request, actor)


@router.get("/staff/consents", include_in_schema=False)
def consents():
    return RedirectResponse("/staff", status_code=303)


@router.post("/staff/consents")
def give_consent(
    request: Request,
    target: str = Form(...),
    purpose: str = Form(...),
    data_scope: str = Form(...),
    text_version: str = Form(...),
    valid_days: int = Form(...),
    actor: StaffActor = Depends(staff_actor),
):
    org_id, _, server_id = target.partition("|")
    max_days = actor.config.stage2.staff_consent_max_days

    def action():
        if text_version not in labels.CONSENT_TEXT:
            raise ControlError("동의 문구를 확인할 수 없습니다. 화면을 새로 고치십시오.")
        if not 1 <= valid_days <= max_days:
            raise ControlError(f"유효 기간은 1일에서 {max_days}일 사이여야 합니다.")
        staff.grant_consent(
            actor.sctx, actor.id_hash, org_id=org_id, server_id=server_id, purpose=purpose,
            data_scope=data_scope, text_version=text_version,
            valid_until=datetime.now(UTC) + timedelta(days=valid_days),
            team_ids=actor.sctx.team_ids,
        )

    form = {"target": target, "purpose": purpose, "data_scope": data_scope, "days": valid_days}
    return act(actor, action, "consent_given", "/staff",
               lambda **kw: servers_page(request, actor, form=form, **kw))


@router.post("/staff/servers/{action}")
def stop_or_resume(
    action: str, request: Request, target: str = Form(...),
    actor: StaffActor = Depends(staff_actor),
):
    """내 사용 권한만 해제하거나(그만두기) 되돌린다. 서버 승인은 그대로다."""
    if action not in ("stop", "resume"):
        raise AdminError(AdminCode.NOT_FOUND, "알 수 없는 동작입니다.")
    org_id, _, server_id = target.partition("|")
    function = staff.stop_using if action == "stop" else staff.resume_using
    return act(
        actor, lambda: function(actor.sctx, actor.id_hash, org_id, server_id),
        "server_stopped" if action == "stop" else "server_resumed", "/staff",
        lambda **kw: servers_page(request, actor, **kw),
    )


@router.post("/staff/consents/{consent_id}/revoke")
def withdraw_consent(
    consent_id: str, request: Request, actor: StaffActor = Depends(staff_actor)
):
    uuid.UUID(consent_id)
    return act(
        actor, lambda: staff.revoke_consent(actor.sctx, actor.id_hash, consent_id),
        "consent_withdrawn", "/staff", lambda **kw: servers_page(request, actor, **kw),
    )


@router.post("/staff/access-requests")
def access_request_open(
    request: Request, server_id: str = Form(..., max_length=128),
    tool: str = Form("", max_length=256), reason_code: str = Form("APPROVAL_ABSENT"),
    note: str = Form("", max_length=500),
    actor: StaffActor = Depends(staff_actor),
):
    """막힌 도구·서버의 권한 요청. 같은 대상의 대기 요청이 있으면 그 요청으로 안내한다."""
    result: dict = {}

    def action():
        calls = my_calls(actor)
        visible = {r["server_id"] for r in staff.list_available(actor.sctx)}
        visible |= {c["server_id"] for c in calls if c["server_id"]}
        if server_id not in visible:
            raise ControlError("이 서버는 권한을 요청할 수 없습니다. 관리자에게 문의하십시오.")
        result["existing"] = (server_id, tool.strip()) in my_open_requests(actor)
        access_requests.staff_open(
            actor.sctx, actor.id_hash, server_id=server_id, tool=tool.strip() or None,
            reason_code=reason_code, note=note.strip())

    response = act(actor, action, "access_requested", f"{REQUESTS}?tab=access",
                   lambda **kw: servers_page(request, actor, **kw))
    if response.status_code == 303 and result["existing"]:
        response.headers["location"] = f"{REQUESTS}?tab=access&ok=access_existing"
    return response


@router.post("/staff/access-requests/{request_id}/cancel")
def access_request_cancel(
    request_id: str, request: Request, actor: StaffActor = Depends(staff_actor)
):
    def action():
        if not access_requests.staff_cancel(actor.sctx, actor.id_hash, request_id):
            raise ControlError("이미 처리되었거나 취소된 요청입니다.")

    return act(actor, action, "access_cancelled", f"{REQUESTS}?tab=access",
               lambda **kw: requests_page(request, actor, tab="access", **kw))


# --- 12 내 요청(확인할 요청 · 내 승인 요청) ----------------------------------------------------


def confirmation_rows(actor: StaffActor) -> list[dict]:
    rows = staff.list_confirmations(actor.sctx)
    separate = staff.requires_separate_key(actor.sctx)
    now = datetime.now(UTC)
    for row in rows:
        pending_expired = row["status"] == "pending" and row["expires_at"] <= now
        row["view"] = "expired" if pending_expired else row["status"]
        row["same_key"] = separate and row["requested_by_key_token"] == actor.sctx.key_token
    return rows


def requests_page(request: Request, actor: StaffActor, error=None, status=200, tab=None):
    tab = tab or request.query_params.get("tab")
    rows = confirmation_rows(actor)
    waiting = [r for r in rows if r["view"] in ("pending", "confirmed")]
    history = [r for r in rows if r["view"] not in ("pending", "confirmed")][:RECENT_RECORDS]
    mine = my_approvals(actor)
    name_servers(actor, waiting, history, mine)
    now = datetime.now(UTC)
    pending = [r for r in waiting if r["view"] == "pending"]
    opened = request.query_params.get("open")
    asked = access_requests.mine(actor.sctx)
    name_servers(actor, asked)
    for r in asked:
        r["reason_text"] = labels.outcome_reason(r["reason_code"])
    ctx = {
        "tab": tab if tab in ("mine", "access") else "pending",
        "asked": asked, "access_waiting": sum(r["status"] == "open" for r in asked),
        "waiting": waiting, "history": history, "mine": mine, "error": error,
        "pending_count": len(pending),
        "soonest": min(
            (int((r["expires_at"] - now).total_seconds()) for r in pending), default=None),
        "mine_waiting": sum(r["view"] == "pending" for r in mine),
        "selected": next((r for r in mine if str(r["id"]) == opened), None) if opened else None,
    }
    return staff_render(request, "staff_requests.html", ctx, actor, status)


@router.get(REQUESTS)
def requests(request: Request, actor: StaffActor = Depends(staff_actor)):
    return requests_page(request, actor)


@router.get("/staff/requests", include_in_schema=False)
def legacy_requests(request: Request):
    return see_other(request, REQUESTS, tab=request.query_params.get("tab", "mine"))


@router.get("/staff/link/{token}")
def open_link(token: str, actor: StaffActor = Depends(staff_actor)):
    """본인 확인 링크. 로그인한 직원에게 확인 화면만 열고 아무것도 확인하지 않는다."""
    key = actor.config.stage2.webhook_hmac_key
    parsed = links.parse(key, token) if key else None
    if parsed is None or parsed[0] != "confirm":
        raise AdminError(AdminCode.NOT_FOUND, "링크가 만료되었거나 올바르지 않습니다.")
    return RedirectResponse(f"{REQUESTS}?tab=pending", status_code=303)


@router.post("/staff/confirmations/{confirmation_id}/{decision}")
def decide(
    confirmation_id: str,
    decision: str,
    request: Request,
    actor: StaffActor = Depends(staff_actor),
):
    uuid.UUID(confirmation_id)
    operations = {
        "confirm": (staff.confirm, "staff_confirmed"),
        "reject": (staff.reject, "staff_rejected"),
        "cancel": (staff.cancel, "staff_cancelled"),
    }
    if decision not in operations:
        raise AdminError(AdminCode.NOT_FOUND, "알 수 없는 동작입니다.")
    function, ok = operations[decision]
    return act(
        actor, lambda: function(actor.sctx, actor.id_hash, confirmation_id), ok,
        f"{REQUESTS}?tab=pending",
        lambda **kw: requests_page(request, actor, tab="pending", **kw),
    )


# --- 승인 요청 현황 -----------------------------------------------------------------------------


def my_approvals(actor: StaffActor) -> list[dict]:
    """본인의 호출별 승인 요청과 기간 승인. 화면 상태(``view``)는 만료·사용 횟수를 반영한다."""
    rows = reads.my_call_approvals(actor.sctx.control, actor.sctx.instance_id, actor.user_id)
    now = datetime.now(UTC)
    for row in rows:
        windowed = row["valid_until"] is not None
        end = row["valid_until"] or row["expires_at"]
        view = row["status"]
        if view in ("pending", "approved") and end <= now:
            view = "expired"
        elif view == "approved" and windowed and row["uses"] >= WINDOW_MAX_USES:
            view = "consumed"
        row["view"] = view
        row["remaining_seconds"] = (
            int((end - now).total_seconds()) if view == "approved" and windowed else None
        )
        row["uses_left"] = max(WINDOW_MAX_USES - row["uses"], 0) if windowed else None
        by = row["approved_by"]
        row["decider"] = "자동 규칙" if by and by.startswith("rule:") else by
    return rows


@router.get("/api/v1/me/call-approvals")
def my_approvals_api(actor: StaffActor = Depends(staff_actor)):
    keep = ("id", "server_id", "tool", "action", "display", "view", "decider", "decision_reason",
            "requested_at", "decided_at", "remaining_seconds", "uses_left", "hold_timed_out_at")
    return {"items": reads.jsonable([{k: r[k] for k in keep} for r in my_approvals(actor)])}


@router.get("/staff/usage")
def usage(request: Request, period: str = "", actor: StaffActor = Depends(staff_actor)):
    from mint_litellm.console.pages.reports import usage_view

    ctx = usage_view(actor.config.litellm_admin, actor.sctx.control, actor.sctx.instance_id,
                     period, "/staff/usage", actor.user_id)
    return staff_render(request, "staff_usage.html", ctx, actor)


# --- 14 단말 설치 -----------------------------------------------------------------------------


def own_endpoint_tools(actor: StaffActor, rows: list[dict]) -> dict:
    """내 단말의 AI 도구 보장, 이 PC에서 쓰던 서버, 보관이 필요한 키."""
    live = [r for r in rows if r["state"] in ("managed", "user")]
    tools = [{**c, "install": r} for r in live for c in r.get("ai_clients") or []]
    keys = [k for r in live for k in r.get("plaintext_keys") or []]
    sctx = actor.sctx
    ignored = endpoint_coverage.ignored_names(sctx.control, sctx.instance_id, actor.user_id)
    asked = endpoint_coverage.intake_requests(sctx.control, sctx.instance_id, actor.user_id)
    found: dict[str, dict] = {}
    for m in endpoint_kits.local_mcp_inventory(sctx.control, sctx.instance_id):
        if m["user_id"] == actor.user_id and m["name"] not in found:
            found[m["name"]] = {**m, "excluded": m["name"] in ignored, "ask": asked.get(m["name"])}
    return {"tools": tools, "keys": keys, "servers": list(found.values())}


def endpoint_page(request: Request, actor: StaffActor, error=None, status=200, commands=None):
    rows = endpoint_kits.installs(actor.sctx.control, actor.sctx.instance_id, actor.user_id)
    # 받는 사람의 브라우저가 Windows면 Windows 묶음을 미리 고른다.
    windows = "windows" in request.headers.get("user-agent", "").lower()
    ctx = {
        **own_endpoint_tools(actor, rows),
        "rows": rows, "active": any(r["state"] != "revoked" for r in rows), "error": error,
        "apps": endpoint_apps.list_apps(actor.sctx.control, actor.sctx.instance_id, actor.user_id),
        "platform": "windows" if windows else "linux", "commands": commands,
        # 고정 공개 키가 없는 옛 설치(자동 갱신 불가)만 한 번 다시 설치해야 한다. 판본이 다르기만
        # 한 단말은 다음 보고에 스스로 갱신된다.
        "behind": any(r["state"] in ("managed", "user") and r.get("update_error") == "needed"
                      and r["kit_version"] != kit_version() for r in rows),
    }
    return staff_render(request, "staff_endpoint.html", ctx, actor, status)


@router.get("/staff/endpoint")
def endpoint(request: Request, actor: StaffActor = Depends(staff_actor)):
    return endpoint_page(request, actor)


class KitRefused(Exception):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


NOT_READY = "관리자가 준비 중입니다. 준비가 끝나면 다시 시도할 수 있습니다."


def note_kit_gap(control: psycopg.Connection, config: ConsoleConfig) -> str:
    """빠진 설정이 있으면 관리자 경보를 남기고(없으면 닫고) 그 내용을 돌려준다."""
    gap = config.kit_gap
    with control.transaction():
        if gap:
            alerts.raise_alert(
                control, config.instance_id, kind=AlertKind.ENDPOINT_KIT_NOT_READY.value,
                severity="medium", dedup_key=AlertKind.ENDPOINT_KIT_NOT_READY.value,
                subject={"missing": gap},
            )
        else:
            alerts.resolve(control, config.instance_id, AlertKind.ENDPOINT_KIT_NOT_READY.value)
    return gap


def issue_kit(
    config: ConsoleConfig, control: psycopg.Connection, user_id: str, team_id: str | None,
    platform: str, harness: str,
) -> bytes:
    """본인 키를 새로 발급해 담은 설치 묶음을 만든다(다른 PC의 키는 그대로다)."""
    if platform not in labels.KIT_PLATFORM or harness not in labels.KIT_HARNESS:
        raise KitRefused("설치 묶음의 종류가 올바르지 않습니다.", 400)
    if config.kit_gap:
        raise KitRefused(NOT_READY, 503)
    # 승인된 로컬 서버가 없어도 게이트웨이 항목과 키만으로 의미가 있어 묶음을 낸다.
    # 묶음에는 이 직원에게 승인된 로컬 서버만 넣는다(다른 직원의 서버 계약이 새지 않게).
    mine = kit_key_sync.local_servers_for(control, config.instance_id, user_id, team_id)
    every = endpoint_kits.approved_contracts(control, config.instance_id)
    contracts = {name: contract for name, contract in every.items() if name in mine}
    try:
        key = endpoint_kits.issue_key(
            control, config.kit_issuer, config.instance_id, user_id=user_id,
            team_id=team_id, issued_by=user_id, ttl_days=config.stage2.endpoint_key_days,
        )
        gateway_key = endpoint_kits.issue_gateway_key(
            control, config.kit_issuer, config.instance_id, user_id=user_id,
            team_id=team_id, kit_key=key,
        )
    except LiteLLMError:
        log.exception("단말 설치 묶음 키 발급 실패")
        raise KitRefused("설치 묶음을 발급하지 못했습니다.", 503) from None
    return build_kit(
        contracts, decide_url=config.endpoint_url or config.litellm_url, key=key,
        ca_pem=config.endpoint_ca_pem, platform=platform,
        harnesses=tuple(HARNESSES) if harness == "all" else (harness,),
        allow_unsandboxed=config.endpoint_allow_unsandboxed, gateway_key=gateway_key,
    )


@router.post("/staff/endpoint/kit")
def endpoint_kit(
    request: Request,
    actor: StaffActor = Depends(staff_actor),
    platform: str = Form("linux"),
    harness: str = Form("claude"),
):
    """설치 묶음 파일을 내려준다."""
    sctx = actor.sctx
    team_id = sctx.team_ids[0] if sctx.team_ids else None
    try:
        kit = issue_kit(actor.config, sctx.control, actor.user_id, team_id, platform, harness)
    except KitRefused as refused:
        return endpoint_page(request, actor, str(refused), refused.status)
    media, name = (
        ("application/zip", "mint-kit.zip") if platform == "windows"
        else ("application/gzip", "mint-kit.tar.gz")
    )  # fmt: skip
    return Response(
        kit, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'}
    )


@router.post("/staff/endpoint/code")
def endpoint_code(request: Request, actor: StaffActor = Depends(staff_actor)):
    """한 줄 설치 명령을 만든다. 코드는 한 번만 쓰이고 곧 만료된다."""
    sctx = actor.sctx
    if note_kit_gap(sctx.control, actor.config):
        return endpoint_page(request, actor, NOT_READY, 503)
    team_id = sctx.team_ids[0] if sctx.team_ids else None
    code = kit_codes.create(sctx.control, actor.config.instance_id, actor.user_id, team_id)
    base = f"{str(request.base_url).rstrip('/')}/kit/{code}"
    return endpoint_page(request, actor, commands={
        "linux": f"curl -fsSL {base}/install.sh | sh",
        "windows": f"irm {base}/install.ps1 | iex",
    })


@public.get("/kit/{code}/{name}")
def kit_redeem(
    code: str, name: str, request: Request, control: psycopg.Connection = Depends(db)
) -> Response:
    """한 줄 설치 명령이 부르는 주소. 코드를 한 번 쓰고 키를 새로 발급해 설치 스크립트를 준다."""
    config = config_of(request)
    if name not in kit_codes.NAMES:
        return PlainTextResponse("코드가 없거나 이미 쓰였거나 만료되었습니다.\n", status_code=404)
    # 스크립트를 받는 쪽(curl -f)은 오류 본문을 숨기므로, 실패는 사람이 읽을 한 줄을 출력하는
    # 스크립트 본문(200)으로 돌려준다.
    if config.kit_gap:  # 코드를 쓰기 전에 거절해 한 번 쓰는 코드가 소진되지 않게 한다
        note_kit_gap(control, config)
        return kit_codes.refusal(name, NOT_READY)
    who = kit_codes.redeem(control, config.instance_id, code)
    if who is None:
        return kit_codes.refusal(
            name, "설치 코드가 없거나 이미 쓰였거나 만료되었습니다. 내 단말에서 새로 만드십시오.",
            404)
    try:
        kit = issue_kit(
            config, control, who["user_id"], who["team_id"],
            "windows" if name in ("install.ps1", "kit.zip") else "linux", "all",
        )
    except KitRefused as refused:
        return kit_codes.refusal(name, str(refused), refused.status)
    return PlainTextResponse(
        kit_codes.script(name, kit), headers={"Cache-Control": "no-store"})


@router.post("/staff/endpoint/reconnect")
def endpoint_reconnect(
    request: Request, alias: str = Form(...), actor: StaffActor = Depends(staff_actor)
):
    sctx = actor.sctx
    return act(
        actor,
        lambda: endpoint_coverage.request_reconnect(
            sctx.control, sctx.instance_id, alias, actor.user_id),
        "endpoint_reconnect", "/staff/endpoint",
        lambda **kw: endpoint_page(request, actor, **kw))


@router.post("/staff/endpoint/ignore")
def endpoint_ignore(
    request: Request, name: str = Form(..., max_length=128),
    actor: StaffActor = Depends(staff_actor),
):
    sctx = actor.sctx
    return act(
        actor,
        lambda: endpoint_coverage.ignore_server(
            sctx.control, sctx.instance_id, actor.user_id, name),
        "server_ignored", "/staff/endpoint",
        lambda **kw: endpoint_page(request, actor, **kw))


@router.post("/staff/endpoint/request")
def endpoint_request(
    request: Request, name: str = Form(..., max_length=128),
    purpose: str = Form("", max_length=256), actor: StaffActor = Depends(staff_actor),
):
    sctx = actor.sctx
    return act(
        actor,
        lambda: endpoint_coverage.request_intake(
            sctx.control, sctx.instance_id, actor.user_id, name, purpose),
        "server_requested", "/staff/endpoint",
        lambda **kw: endpoint_page(request, actor, **kw))


@router.post("/staff/endpoint/apps/{app_id}/revoke")
def endpoint_app_revoke(
    app_id: str, request: Request, actor: StaffActor = Depends(staff_actor)
):
    """본인이 만든 앱의 자격을 회수한다."""
    issuer = actor.config.kit_issuer
    sctx = actor.sctx

    def action():
        if issuer is None:
            raise ControlError("앱 자격을 회수할 수 없습니다.")
        try:
            endpoint_apps.revoke_app(
                sctx.control, issuer, sctx.instance_id, app_id, actor=actor.user_id,
                user_id=actor.user_id)
        except LiteLLMError:
            log.exception("앱 자격 회수 실패")
            raise ControlError("앱 자격을 회수하지 못했습니다.") from None

    return act(actor, action, "app_revoked", "/staff/endpoint",
               lambda **kw: endpoint_page(request, actor, **kw))


@router.post("/staff/endpoint/revoke")
def endpoint_revoke(
    request: Request, key_alias: str = Form("", max_length=256),
    actor: StaffActor = Depends(staff_actor),
):
    """내 PC의 연결을 해제한다. ``key_alias``가 있으면 그 PC 하나(본인 PC만), 없으면 내 모든 PC."""
    issuer = actor.config.kit_issuer
    sctx = actor.sctx

    def action():
        if issuer is None:
            raise ControlError("단말 연결을 해제할 수 없습니다.")
        try:
            if key_alias:
                mine = {r["key_alias"] for r in endpoint_kits.installs(
                    sctx.control, sctx.instance_id, actor.user_id) if r["state"] != "revoked"}
                if key_alias not in mine:
                    raise ControlError("해제할 단말 연결이 없습니다.")
                endpoint_kits.revoke_install(
                    sctx.control, issuer, sctx.instance_id, key_alias, actor.user_id)
            else:
                endpoint_kits.revoke_keys(
                    sctx.control, issuer, sctx.instance_id, actor.user_id, actor.user_id)
        except LiteLLMError:
            log.exception("단말 설치 묶음 키 해제 실패")
            raise ControlError("단말 연결을 해제하지 못했습니다.") from None

    return act(actor, action, "kit_revoked_one" if key_alias else "kit_revoked",
               "/staff/endpoint", lambda **kw: endpoint_page(request, actor, **kw))
