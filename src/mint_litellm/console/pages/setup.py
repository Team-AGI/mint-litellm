"""시작하기 화면: 점검표와 알림 시험 전송."""

import os
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mint_litellm.console import password_login, setup_state
from mint_litellm.console.cookies import DEFAULT_PASSWORD, delete_cookie, read_cookie
from mint_litellm.console.core import Actor, page_actor, require_csrf, screen_message
from mint_litellm.console.templating import render
from mint_litellm.control import webhook, webhook_store
from mint_litellm.control.errors import AdminCode, AdminError, ControlError

router = APIRouter(dependencies=[Depends(require_csrf)])


def send_test(settings) -> bool:
    """설정된 알림 주소 모두에 시험 메시지를 보낸다. 모두 성공해야 참이다."""
    now = datetime.now(UTC)
    row = {
        "kind": "webhook_test",
        "severity": "low",
        "subject": {},
        "count": 1,
        "first_at": now,
        "last_at": now,
    }
    hosts = [urlsplit(u).hostname for u in settings.webhook_urls]
    with webhook.client() as http:
        for url in settings.webhook_urls:
            webhook.check_url(url, hosts)
            body = webhook.build_body(row, settings.console_url, settings.webhook_format(url))
            sent, _ = webhook.post(http, url, settings.webhook_hmac_key, str(uuid.uuid4()), body)
            if not sent:
                return False
    return True


def setup_page(request: Request, actor: Actor, error=None, status=200):
    items = setup_state.steps(actor, read_cookie(request, DEFAULT_PASSWORD) is not None)
    ctx = {
        "items": items,
        "pending": setup_state.pending(items),
        "error": error,
        "litellm_ui_url": os.getenv("MINT_LITELLM_UI_URL", ""),
    }
    return render(request, "setup.html", ctx, actor=actor, status=status)


@router.get("/setup")
def setup(request: Request, actor: Actor = Depends(page_actor)):
    return setup_page(request, actor)


@router.post("/setup/webhook")
def webhook_save(
    request: Request,
    url: str = Form(""),
    fmt: str = Form("slack"),
    actor: Actor = Depends(page_actor),
):
    """알림 주소 저장(관리자). 설치 설정에 주소가 있으면 그쪽이 우선이라 화면에서 바꾸지 않는다."""
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 알림 주소를 정할 수 있습니다.")
    if actor.config.stage2.webhook_urls:
        return setup_page(request, actor, "알림 주소는 설치 설정에서 정해져 있습니다.", 409)
    try:
        webhook_store.save(actor.conn, actor.instance, url, fmt, actor.ctx.operator.name)
    except ControlError as error:
        actor.conn.rollback()
        return setup_page(request, actor, screen_message(str(error)), 400)
    return RedirectResponse("/setup?ok=webhook_saved#step-approval", status_code=303)


@router.post("/setup/webhook-test")
def webhook_test(request: Request, actor: Actor = Depends(page_actor)):
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 시험 전송을 할 수 있습니다.")
    settings = webhook_store.effective(actor.config.stage2, actor.conn, actor.instance)
    if not settings.webhook_urls:
        return setup_page(request, actor, "알림 주소가 설정되어 있지 않습니다.", 409)
    try:
        sent = send_test(settings)
    except Exception:  # 주소 검사 실패·전송 오류 모두 같은 안내로 보인다
        sent = False
    if not sent:
        return setup_page(
            request, actor, "시험 메시지를 보내지 못했습니다. 알림 주소를 확인하십시오.", 502
        )
    setup_state.mark(actor.conn, actor.instance, "webhook_test", actor.ctx.operator.name)
    return RedirectResponse("/setup?ok=webhook_tested", status_code=303)


def password_page(request: Request, actor: Actor, error=None, status=200):
    ctx = {"error": error, "has_password": password_login.has_password(actor.session.key_token)}
    return render(request, "password.html", ctx, actor=actor, status=status)


@router.get("/account/password")
def password_form(request: Request, actor: Actor = Depends(page_actor)):
    return password_page(request, actor)


@router.post("/account/password")
def password_submit(
    request: Request, current_password: str = Form(""), new_password: str = Form(""),
    confirm_password: str = Form(""), actor: Actor = Depends(page_actor),
):
    error, status = password_login.submit(
        request, actor.session.user_id, actor.session.key_token,
        current_password, new_password, confirm_password,
    )
    if error:
        return password_page(request, actor, error, status)
    response = RedirectResponse("/account/password?ok=password_changed", status_code=303)
    delete_cookie(response, request, DEFAULT_PASSWORD)
    return response
