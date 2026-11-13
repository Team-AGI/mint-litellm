"""직원 화면(서버 렌더링): 사용 가능한 서버·도구, 본인 확인 요청, 동의 관리와 내 기록.

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
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from mint_litellm.console import labels, login
from mint_litellm.console.core import (
    COOKIE_OPTIONS,
    STAFF_COOKIE,
    STATUS,
    ConsoleConfig,
    Unauthenticated,
    config_of,
    db,
    require_csrf,
    require_origin,
    too_many_attempts,
)
from mint_litellm.console.templating import render
from mint_litellm.control import endpoint_kits
from mint_litellm.control.db.connection import connect
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.services import console_sessions, staff
from mint_litellm.endpoint.kit_build import build_kit

router = APIRouter(dependencies=[Depends(require_csrf)])
# 로그인은 세션이 없을 때(또는 만료된 쿠키가 남았을 때)도 받으므로 CSRF 토큰 대신 출처만 본다.
public = APIRouter()

RECENT_RECORDS = 50
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
    def csrf(self) -> str:
        return console_sessions.csrf_token(self.session_id)


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
    session_id = request.cookies.get(STAFF_COOKIE)
    if not session_id:
        raise StaffUnauthenticated()
    id_hash = console_sessions.hash_id(session_id)
    row = staff.find_session(
        control, config.instance_id, id_hash, config.stage2.session_verify_window_seconds)
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
    return RedirectResponse(f"{back}?ok={ok}", status_code=303)


# --- 로그인·로그아웃 --------------------------------------------------------------------------


@public.get("/staff/login", response_class=HTMLResponse)
def login_form(request: Request) -> Response:
    return render(request, "staff_login.html", {"error": None})


@public.post("/staff/login", dependencies=[Depends(require_origin)])
def login_submit(
    request: Request,
    key: str = Form(""),
    control: psycopg.Connection = Depends(db),
    staff_conn: psycopg.Connection = Depends(staff_connection),
) -> Response:
    config = config_of(request)
    if too_many_attempts(request):
        return render(
            request, "staff_login.html",
            {"error": "로그인 시도가 너무 많습니다. 잠시 뒤 다시 시도하십시오."}, status=429,
        )
    try:
        identity = login.verify(config.litellm_url, key)
    except login.LoginRefused as refused:
        return render(request, "staff_login.html", {"error": str(refused)}, status=401)
    finally:
        key = ""  # 평문 키는 여기서 버린다
    session_id = secrets.token_urlsafe(32)
    id_hash = console_sessions.hash_id(session_id)
    sctx = staff.StaffContext(
        staff_conn, control, config.instance_id, identity.user_id,
        consent_max_days=config.stage2.staff_consent_max_days,
        verify_window_seconds=config.stage2.session_verify_window_seconds,
        team_ids=identity.team_ids, key_token=identity.key_token,
    )
    now = datetime.now(UTC)
    staff.start_session(
        sctx, id_hash, identity.key_token,
        now + timedelta(seconds=config.stage2.session_idle_seconds),
        now + timedelta(seconds=config.stage2.session_absolute_seconds),
    )
    response = RedirectResponse("/staff", status_code=303)
    response.set_cookie(STAFF_COOKIE, session_id, **COOKIE_OPTIONS)
    return response


@router.post("/staff/logout")
def logout(actor: StaffActor = Depends(staff_actor)) -> Response:
    staff.end_session(actor.sctx, actor.id_hash)
    response = RedirectResponse("/staff/login", status_code=303)
    response.delete_cookie(STAFF_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return response


# --- 11 사용 가능한 서버·도구 -------------------------------------------------------------------


@router.get("/staff")
def servers(request: Request, actor: StaffActor = Depends(staff_actor)):
    rows = [r for r in staff.list_available(actor.sctx) if r["tools"]]
    return render(request, "staff_servers.html", {"rows": rows}, actor=actor)


# --- 12 본인 확인 요청 ------------------------------------------------------------------------


def confirmations_page(request: Request, actor: StaffActor, error=None, status=200):
    rows = staff.list_confirmations(actor.sctx)
    separate = staff.requires_separate_key(actor.sctx)
    now = datetime.now(UTC)
    for row in rows:
        pending_expired = row["status"] == "pending" and row["expires_at"] <= now
        row["view"] = "expired" if pending_expired else row["status"]
        row["same_key"] = separate and row["requested_by_key_token"] == actor.sctx.key_token
    waiting = [r for r in rows if r["view"] in ("pending", "confirmed")]
    history = [r for r in rows if r["view"] not in ("pending", "confirmed")][:RECENT_RECORDS]
    return render(
        request, "staff_confirmations.html",
        {"waiting": waiting, "history": history, "error": error}, actor=actor, status=status,
    )


@router.get("/staff/confirmations")
def confirmations(request: Request, actor: StaffActor = Depends(staff_actor)):
    return confirmations_page(request, actor)


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
        "/staff/confirmations", lambda **kw: confirmations_page(request, actor, **kw),
    )


# --- 13 동의 관리와 내 기록 -------------------------------------------------------------------


def event_label(row: dict) -> str:
    payload = row.get("payload") or {}
    if payload.get("kind") == "confirmation" and row["kind"] in labels.CONFIRMATION_EVENT:
        return labels.CONFIRMATION_EVENT[row["kind"]]
    if payload.get("subject") == "staff" and row["kind"] in labels.STAFF_SESSION_EVENT:
        return labels.STAFF_SESSION_EVENT[row["kind"]]
    return labels.EVENT_KIND.get(row["kind"], "기록")


def consents_page(request: Request, actor: StaffActor, error=None, status=200, form=None):
    now = datetime.now(UTC)
    consents = staff.list_consents(actor.sctx)
    for row in consents:
        row["view"] = "revoked" if row["revoked_at"] else (
            "expired" if row["valid_until"] <= now else "active")
    records = [
        {"at": e["inserted_at"], "label": event_label(e)}
        for e in staff.list_events(actor.sctx, RECENT_RECORDS)
    ]
    ctx = {
        "consents": consents,
        "records": records,
        "targets": staff.list_available(actor.sctx),
        "max_days": actor.config.stage2.staff_consent_max_days,
        "text_version": labels.CONSENT_TEXT_VERSION,
        "text": labels.CONSENT_TEXT[labels.CONSENT_TEXT_VERSION],
        "form": form or {},
        "error": error,
    }
    return render(request, "staff_consents.html", ctx, actor=actor, status=status)


@router.get("/staff/consents")
def consents(request: Request, actor: StaffActor = Depends(staff_actor)):
    return consents_page(request, actor)


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
    return act(actor, action, "consent_given", "/staff/consents",
               lambda **kw: consents_page(request, actor, form=form, **kw))


@router.post("/staff/consents/{consent_id}/revoke")
def withdraw_consent(
    consent_id: str, request: Request, actor: StaffActor = Depends(staff_actor)
):
    uuid.UUID(consent_id)
    return act(
        actor, lambda: staff.revoke_consent(actor.sctx, actor.id_hash, consent_id),
        "consent_withdrawn", "/staff/consents",
        lambda **kw: consents_page(request, actor, **kw),
    )


# --- 14 단말 설치 -----------------------------------------------------------------------------


def endpoint_page(request: Request, actor: StaffActor, error=None, status=200):
    rows = endpoint_kits.installs(actor.sctx.control, actor.sctx.instance_id, actor.user_id)
    # 받는 사람의 브라우저가 Windows면 Windows 묶음을 미리 고른다.
    windows = "windows" in request.headers.get("user-agent", "").lower()
    ctx = {
        "rows": rows, "active": any(r["state"] != "revoked" for r in rows), "error": error,
        "platform": "windows" if windows else "linux",
    }
    return render(request, "staff_endpoint.html", ctx, actor=actor, status=status)


@router.get("/staff/endpoint")
def endpoint(request: Request, actor: StaffActor = Depends(staff_actor)):
    return endpoint_page(request, actor)


@router.post("/staff/endpoint/kit")
def endpoint_kit(
    request: Request,
    actor: StaffActor = Depends(staff_actor),
    platform: str = Form("linux"),
    harness: str = Form("claude"),
):
    """본인 키를 새로 발급해 담은 설치 묶음을 내려준다(이전 묶음의 키는 지워진다)."""
    config, sctx = actor.config, actor.sctx
    if platform not in labels.KIT_PLATFORM or harness not in labels.KIT_HARNESS:
        return endpoint_page(request, actor, "설치 묶음의 종류가 올바르지 않습니다.", 400)
    if config.kit_issuer is None:
        return endpoint_page(request, actor, "단말 설치 묶음을 발급할 수 없습니다.", 503)
    contracts = endpoint_kits.approved_contracts(sctx.control, sctx.instance_id)
    if not contracts:
        return endpoint_page(request, actor, "승인된 로컬 서버가 없습니다.", 409)
    try:
        key = endpoint_kits.issue_key(
            sctx.control, config.kit_issuer, sctx.instance_id, user_id=actor.user_id,
            team_id=sctx.team_ids[0] if sctx.team_ids else None, issued_by=actor.user_id,
            ttl_days=config.stage2.endpoint_key_days,
        )
    except LiteLLMError:
        log.exception("단말 설치 묶음 키 발급 실패")
        return endpoint_page(request, actor, "설치 묶음을 발급하지 못했습니다.", 503)
    kit = build_kit(
        contracts, decide_url=config.endpoint_url or config.litellm_url, key=key,
        ca_pem=config.endpoint_ca_pem, platform=platform,
        harnesses=("claude", "codex") if harness == "all" else (harness,),
    )
    media, name = (
        ("application/zip", "mint-kit.zip") if platform == "windows"
        else ("application/gzip", "mint-kit.tar.gz")
    )  # fmt: skip
    return Response(
        kit, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'}
    )


@router.post("/staff/endpoint/revoke")
def endpoint_revoke(request: Request, actor: StaffActor = Depends(staff_actor)):
    issuer = actor.config.kit_issuer
    sctx = actor.sctx

    def action():
        if issuer is None:
            raise ControlError("단말 연결을 해제할 수 없습니다.")
        try:
            endpoint_kits.revoke_keys(sctx.control, issuer, sctx.instance_id, actor.user_id)
        except LiteLLMError:
            log.exception("단말 설치 묶음 키 해제 실패")
            raise ControlError("단말 연결을 해제하지 못했습니다.") from None

    return act(actor, action, "kit_revoked", "/staff/endpoint",
               lambda **kw: endpoint_page(request, actor, **kw))
