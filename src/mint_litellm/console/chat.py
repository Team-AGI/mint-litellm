"""채팅 승인 수신 지점. Slack이 단추·입력창 제출을 보내는 주소이다.

로그인 세션이 없는 요청이므로 인증은 전부 요청 서명이다. 서명 비밀(``MINT_SLACK_SIGNING_SECRET``)이
없으면 이 주소는 없는 것처럼 404로 답한다.
"""

import logging

import httpx
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from mint_litellm.console.core import config_of
from mint_litellm.control import chat_approval as chat
from mint_litellm.control.db.connection import connect

log = logging.getLogger("mint_litellm.chat")
router = APIRouter()
TIMEOUT_SECONDS = 2.5
VIEWS_OPEN = "https://slack.com/api/views.open"


def post_response(url: str, message: dict) -> None:
    """``response_url``로 메시지를 바꾼다. 실패해도 처리 결과에는 영향이 없다."""
    try:
        httpx.post(url, json=message, timeout=TIMEOUT_SECONDS, follow_redirects=False)
    except httpx.HTTPError as error:
        log.warning("채팅 메시지 갱신 실패: %s", type(error).__name__)


def open_modal(token: str, view: dict) -> bool:
    try:
        reply = httpx.post(
            VIEWS_OPEN,
            json=view,
            timeout=TIMEOUT_SECONDS,
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )
        return bool(reply.json().get("ok"))
    except (httpx.HTTPError, ValueError):
        return False


def _handle(request: Request, body: bytes) -> tuple[Response, tuple[str, dict] | None]:
    """서명을 확인하고 요청을 처리한다. (HTTP 응답, 갱신할 (response_url, 메시지))."""
    config = config_of(request)
    settings = config.stage2
    secret = settings.slack_signing_secret
    if not secret:
        return Response(status_code=404), None
    signature = request.headers.get("x-slack-signature", "")
    if not chat.verify_signature(
        secret, request.headers.get("x-slack-request-timestamp", ""), signature, body
    ):
        return Response(status_code=401), None
    payload = chat.parse_payload(body)
    parsed = chat.interpret(payload) if payload else None
    with connect(config.database_url) as conn:
        if not chat.first_use(conn, config.instance_id, signature):
            return Response(status_code=401), None
        if parsed is None:
            return Response(status_code=200), None
        kind, value = parsed
        url = value.get("response_url")
        reply_to = url if chat.response_url_ok(url) else None
        if kind == "decide" and value["decision"] == "reject" and settings.slack_bot_token:
            if chat.operator_of(conn, config.instance_id, value["user"]) is not None and (
                reply_to
                and value.get("trigger_id")
                and open_modal(
                    settings.slack_bot_token,
                    chat.reject_modal(value["trigger_id"], value["call_id"], reply_to),
                )
            ):
                return Response(status_code=200), None
        message = chat.decide(
            conn,
            config.instance_id,
            value["user"],
            value["call_id"],
            value["decision"],
            value.get("reason"),
        )
    update = (reply_to, message) if reply_to else None
    if kind == "submit":
        return JSONResponse({"response_action": "clear"}), update
    return Response(status_code=200), update


@router.post("/chat/slack/actions", include_in_schema=False)
async def slack_actions(request: Request, background: BackgroundTasks) -> Response:
    body = await request.body()
    response, update = await run_in_threadpool(_handle, request, body)
    if update:
        background.add_task(post_response, *update)
    response.background = background
    return response
