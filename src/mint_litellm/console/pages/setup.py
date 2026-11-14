"""시작하기 화면: 점검표와 알림 시험 전송."""

import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from mint_litellm.console import setup_state
from mint_litellm.console.core import Actor, page_actor, require_csrf
from mint_litellm.console.templating import render
from mint_litellm.control import webhook
from mint_litellm.control.errors import AdminCode, AdminError

router = APIRouter(dependencies=[Depends(require_csrf)])


def send_test(config) -> bool:
    """설정된 알림 주소 모두에 시험 메시지를 보낸다. 모두 성공해야 참이다."""
    settings = config.stage2
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
    items = setup_state.steps(actor)
    ctx = {"items": items, "pending": setup_state.pending(items), "error": error}
    return render(request, "setup.html", ctx, actor=actor, status=status)


@router.get("/setup")
def setup(request: Request, actor: Actor = Depends(page_actor)):
    return setup_page(request, actor)


@router.post("/setup/webhook-test")
def webhook_test(request: Request, actor: Actor = Depends(page_actor)):
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 시험 전송을 할 수 있습니다.")
    if not actor.config.stage2.webhook_urls:
        return setup_page(request, actor, "알림 주소가 설정되어 있지 않습니다.", 409)
    try:
        sent = send_test(actor.config)
    except Exception:  # 주소 검사 실패·전송 오류 모두 같은 안내로 보인다
        sent = False
    if not sent:
        return setup_page(
            request, actor, "시험 메시지를 보내지 못했습니다. 알림 주소를 확인하십시오.", 502
        )
    setup_state.mark(actor.conn, actor.instance, "webhook_test", actor.ctx.operator.name)
    return RedirectResponse("/setup?ok=webhook_tested", status_code=303)
