"""Slack 승인 단추 메시지와 요청 서명·해석. DB 없이 돈다."""

import hashlib
import hmac
import json
from datetime import UTC, datetime

from mint_litellm.control import chat_approval as chat
from mint_litellm.control import webhook

LINK = "https://console.example.com/link/abc"
ROW = {
    "kind": "call_approval_requested",
    "severity": "medium",
    "subject": {"id": "c-1", "server_id": "files", "tool": "read"},
    "count": 1,
    "first_at": datetime(2030, 1, 1, tzinfo=UTC),
    "last_at": datetime(2030, 1, 1, tzinfo=UTC),
}
SECRET = "slack-signing-secret"
BODY = b"payload=%7B%7D"


def signed(body: bytes, stamp: int) -> str:
    mac = hmac.new(SECRET.encode(), f"v0:{stamp}:".encode() + body, hashlib.sha256)
    return "v0=" + mac.hexdigest()


def test_signature_accepts_a_fresh_valid_request_only():
    assert chat.verify_signature(SECRET, "1000", signed(BODY, 1000), BODY, now=1100)
    assert not chat.verify_signature(SECRET, "1000", signed(BODY, 1000), BODY + b"x", now=1100)
    assert not chat.verify_signature("other", "1000", signed(BODY, 1000), BODY, now=1100)
    assert not chat.verify_signature(SECRET, "1000", signed(BODY, 1000), BODY, now=1301)
    assert not chat.verify_signature(SECRET, "1000", signed(BODY, 1000), BODY, now=699)
    assert not chat.verify_signature(SECRET, "soon", signed(BODY, 1000), BODY, now=1000)


def test_buttons_are_added_only_when_enabled_and_only_for_call_requests():
    plain = json.loads(webhook.build_body(ROW, None, "slack", LINK))
    assert not any(b.get("block_id") == "mint_call_decide" for b in plain["blocks"])
    body = json.loads(
        webhook.build_body(
            {**ROW, "subject": {**ROW["subject"], "id": "c-1"}}, None, "slack", LINK, buttons=True
        )
    )
    decide = next(b for b in body["blocks"] if b.get("block_id") == "mint_call_decide")
    assert decide == {
        "type": "actions",
        "block_id": "mint_call_decide",
        "elements": [
            {
                "type": "button",
                "action_id": "mint_call_approve_30",
                "value": "c-1",
                "text": {"type": "plain_text", "text": "30분 승인"},
                "style": "primary",
            },
            {
                "type": "button",
                "action_id": "mint_call_approve_once",
                "value": "c-1",
                "text": {"type": "plain_text", "text": "1회 승인"},
            },
            {
                "type": "button",
                "action_id": "mint_call_reject",
                "value": "c-1",
                "text": {"type": "plain_text", "text": "거부"},
                "style": "danger",
            },
        ],
    }
    other = {**ROW, "kind": "job_failed", "subject": {"id": "x"}}
    assert (
        "mint_call_decide"
        not in webhook.build_body(other, None, "slack", None, buttons=True).decode()
    )
    assert (
        "mint_call_decide"
        not in webhook.build_body(ROW, None, "teams", LINK, buttons=True).decode()
    )


def test_actions_and_modal_submissions_are_interpreted_and_junk_is_ignored():
    click = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "trigger_id": "t",
        "response_url": "https://hooks.slack.com/x",
        "actions": [{"action_id": "mint_call_approve_once", "value": "c-1"}],
    }
    assert chat.interpret(click) == (
        "decide",
        {
            "user": "U1",
            "call_id": "c-1",
            "decision": "approve_once",
            "response_url": "https://hooks.slack.com/x",
            "trigger_id": "t",
        },
    )
    modal = chat.reject_modal("t", "c-1", "https://hooks.slack.com/x")
    assert (
        modal["view"]["blocks"][0]["type"] == "input"
        and "optional" not in modal["view"]["blocks"][0]
    )
    submit = {
        "type": "view_submission",
        "user": {"id": "U1"},
        "view": {
            "callback_id": "mint_call_reject",
            "private_metadata": modal["view"]["private_metadata"],
            "state": {"values": {"reason": {"reason_input": {"value": " 범위 밖 "}}}},
        },
    }
    assert chat.interpret(submit)[1]["reason"] == "범위 밖"
    assert (
        chat.interpret(
            {
                "type": "block_actions",
                "user": {"id": "U1"},
                "actions": [{"action_id": "other", "value": "c"}],
            }
        )
        is None
    )
    assert chat.interpret({"type": "shortcut"}) is None
    assert chat.response_url_ok("https://hooks.slack.com/a")
    assert not chat.response_url_ok("https://evil.example.com/a")
    assert not chat.response_url_ok("http://hooks.slack.com/a")
