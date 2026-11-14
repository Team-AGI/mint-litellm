"""채팅(Slack) 단추로 호출별 승인을 처리한다.

요청 서명(``X-Slack-Signature`` v0)·시각 차이·재전송을 먼저 확인하고, 결속된 운영자의 이름으로
콘솔과 같은 서비스(``call_approvals``)를 부른다. 그래서 역할 확인, 요청자 본인 승인 금지, 1회만
되는 동작의 1회 강제, 사건 기록은 콘솔과 같고 사건에 채널(slack)만 더해진다.
"""

import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import psycopg

from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import call_approvals as service
from mint_litellm.control.webhook import SLACK_APPROVE_30, SLACK_APPROVE_ONCE, SLACK_REJECT

CHANNEL = "slack"
TOLERANCE_SECONDS = 300
REASON_WHEN_UNASKED = "chat"
MODAL_ID = "mint_call_reject"
REASON_BLOCK, REASON_ACTION = "reason", "reason_input"
RESPONSE_HOST = "hooks.slack.com"
_DECISIONS = {
    SLACK_APPROVE_30: "approve_30",
    SLACK_APPROVE_ONCE: "approve_once",
    SLACK_REJECT: "reject",
}


def verify_signature(
    secret: str, timestamp: str, signature: str, body: bytes, *, now: int | None = None
) -> bool:
    """``v0=`` + HMAC-SHA256(``v0:<시각>:<본문>``). 시각 차이가 5분을 넘으면 거짓이다."""
    try:
        stamp = int(timestamp)
    except ValueError:
        return False
    if abs((int(time.time()) if now is None else now) - stamp) > TOLERANCE_SECONDS:
        return False
    mac = hmac.new(secret.encode(), f"v0:{timestamp}:".encode() + body, hashlib.sha256)
    return hmac.compare_digest("v0=" + mac.hexdigest(), signature)


def first_use(conn: psycopg.Connection, instance_id: str, signature: str) -> bool:
    """같은 서명의 요청은 한 번만 받는다(재전송 방지). 처음이면 참."""
    conn.execute(
        "DELETE FROM mint.chat_requests_seen WHERE instance_id = %s"
        " AND seen_at < clock_timestamp() - make_interval(secs => %s)",
        (instance_id, 2 * TOLERANCE_SECONDS),
    )
    row = conn.execute(
        "INSERT INTO mint.chat_requests_seen (instance_id, digest) VALUES (%s, %s)"
        " ON CONFLICT DO NOTHING RETURNING 1",
        (instance_id, hashlib.sha256(signature.encode()).hexdigest()),
    ).fetchone()
    return row is not None


def parse_payload(body: bytes) -> dict[str, Any] | None:
    values = parse_qs(body.decode("utf-8", "replace")).get("payload")
    try:
        parsed = json.loads(values[0]) if values else None
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def response_url_ok(url: Any) -> bool:
    parts = urlsplit(url) if isinstance(url, str) else None
    return bool(parts and parts.scheme == "https" and parts.hostname == RESPONSE_HOST)


def _message(text: str, *, replace: bool) -> dict:
    """채팅 메시지 본문. ``replace``이면 원래 메시지를 바꾸고, 아니면 누른 사람에게만 보인다."""
    if replace:
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
        return {"replace_original": True, "text": text, "blocks": blocks}
    return {"response_type": "ephemeral", "replace_original": False, "text": text}


def operator_of(conn: psycopg.Connection, instance_id: str, slack_user: str) -> Operator | None:
    row = fetchone(
        conn,
        "SELECT o.name, o.role, o.user_id FROM mint.operator_chat_bindings b"
        " JOIN mint.operators o ON o.instance_id = b.instance_id AND o.name = b.operator_name"
        " WHERE b.instance_id = %s AND b.channel = %s AND b.external_id = %s"
        " AND (o.expires_at IS NULL OR o.expires_at > now())",
        (instance_id, CHANNEL, slack_user),
    )
    return Operator(row["name"], row["role"], row["user_id"]) if row else None


_STATUS_TEXT = {
    "approved": "이미 승인되었습니다.",
    "rejected": "이미 거부되었습니다.",
    "cancelled": "요청자가 취소했습니다.",
    "expired": "만료되었습니다.",
}


def decide(
    conn: psycopg.Connection,
    instance_id: str,
    slack_user: str,
    call_id: str,
    decision: str,
    reason: str | None = None,
) -> dict:
    """승인·거부를 처리하고 채팅에 돌려줄 메시지를 만든다. 서비스 오류는 메시지로 바꾼다."""
    operator = operator_of(conn, instance_id, slack_user)
    if operator is None:
        return _message(
            "이 Slack 계정은 MINT 운영자에 결속되어 있지 않아 처리할 수 없습니다. "
            "관리자에게 결속을 요청하십시오.",
            replace=False,
        )
    ctx = Context(conn, instance_id, operator, channel=CHANNEL)
    try:
        row = fetchone(
            conn,
            "SELECT status, server_id, tool, approved_by,"
            " (coalesce(valid_until, expires_at) <= clock_timestamp()) AS lapsed"
            " FROM mint.call_approvals WHERE instance_id = %s AND id::text = %s",
            (instance_id, call_id),
        )
    except psycopg.errors.DataError:
        row = None
    if row is None:
        return _message("요청을 찾을 수 없습니다.", replace=False)
    where = f"`{row['server_id']}` / `{row['tool']}`"
    if row["status"] != "pending" or row["lapsed"]:
        state = "expired" if row["status"] == "pending" else row["status"]
        who = f" ({row['approved_by']})" if row["approved_by"] else ""
        return _message(f"{where}: {_STATUS_TEXT.get(state, state)}{who}", replace=True)
    try:
        if decision == "reject":
            service.reject(ctx, call_id, reason=reason or REASON_WHEN_UNASKED)
        else:
            service.approve(
                ctx, call_id, None, window_minutes=None, default_window=decision == "approve_30"
            )
    except AdminError as error:
        if error.code in (AdminCode.FORBIDDEN, AdminCode.SEPARATION_OF_DUTIES):
            return _message(f"처리할 권한이 없습니다: {error}", replace=False)
        return _message(f"{where}: 이미 처리되었거나 만료되었습니다.", replace=True)
    except ControlError as error:
        return _message(f"처리하지 못했습니다: {error}", replace=False)
    if decision == "reject":
        return _message(
            f"{where}: {operator.name} 님이 거부했습니다. 사유: {reason or REASON_WHEN_UNASKED}",
            replace=True,
        )
    done = fetchone(
        conn,
        "SELECT window_minutes FROM mint.call_approvals WHERE instance_id = %s AND id::text = %s",
        (instance_id, call_id),
    )
    span = f"{done['window_minutes']}분" if done and done["window_minutes"] else "1회"
    return _message(f"{where}: {operator.name} 님이 {span} 승인했습니다.", replace=True)


def reject_modal(trigger_id: str, call_id: str, response_url: str) -> dict:
    """``views.open`` 본문. 사유는 필수 입력이다."""
    return {
        "trigger_id": trigger_id,
        "view": {
            "type": "modal",
            "callback_id": MODAL_ID,
            "private_metadata": json.dumps([call_id, response_url]),
            "title": {"type": "plain_text", "text": "호출 거부"},
            "submit": {"type": "plain_text", "text": "거부"},
            "close": {"type": "plain_text", "text": "취소"},
            "blocks": [
                {
                    "type": "input",
                    "block_id": REASON_BLOCK,
                    "label": {"type": "plain_text", "text": "거부 사유"},
                    "element": {
                        "type": "plain_text_input",
                        "action_id": REASON_ACTION,
                        "multiline": True,
                        "max_length": 500,
                    },
                }
            ],
        },
    }


def interpret(payload: dict) -> tuple[str, dict] | None:
    """채팅 요청을 (종류, 값)으로 바꾼다. 알 수 없으면 None.

    종류는 ``decide``(단추), ``submit``(사유 입력창 제출). 단추의 거부는 ``decision``이 reject이다.
    """
    user = (payload.get("user") or {}).get("id")
    if not isinstance(user, str):
        return None
    kind = payload.get("type")
    if kind == "block_actions":
        actions = payload.get("actions") or []
        action = actions[0] if actions and isinstance(actions[0], dict) else {}
        decision = _DECISIONS.get(action.get("action_id"))
        call_id = action.get("value")
        if not decision or not isinstance(call_id, str):
            return None
        return "decide", {
            "user": user,
            "call_id": call_id,
            "decision": decision,
            "response_url": payload.get("response_url"),
            "trigger_id": payload.get("trigger_id"),
        }
    if kind == "view_submission":
        view = payload.get("view") or {}
        if view.get("callback_id") != MODAL_ID:
            return None
        try:
            call_id, response_url = json.loads(view.get("private_metadata") or "")
            text = view["state"]["values"][REASON_BLOCK][REASON_ACTION]["value"]
        except (ValueError, KeyError, TypeError):
            return None
        return "submit", {
            "user": user,
            "call_id": call_id,
            "decision": "reject",
            "response_url": response_url,
            "reason": (text or "").strip() or None,
        }
    return None
