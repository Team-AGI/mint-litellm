"""채팅 웹훅 형식(Slack·Teams), 콘솔 바로가기 서명 링크, 미사용 승인 집계. DB 없이 돈다."""

import json
from datetime import UTC, datetime

import pytest

from mint_litellm.control import dormant, links, webhook
from mint_litellm.control.errors import ControlError
from mint_litellm.control.stage2_config import Stage2Settings

KEY = b"k" * 32
LINK = "https://console.example.com/link/abc"
ROW = {
    "kind": "call_approval_requested",
    "severity": "medium",
    "subject": {"id": "c-1", "server_id": "files", "tool": "read"},
    "count": 1,
    "first_at": datetime(2030, 1, 1, tzinfo=UTC),
    "last_at": datetime(2030, 1, 1, tzinfo=UTC),
}
SUMMARY, ACTION = webhook.GUIDE["call_approval_requested"]


def test_generic_json_is_unchanged_without_a_link_and_gains_one_url_with_it():
    plain = json.loads(webhook.build_body(ROW, None))
    assert "action_url" not in plain
    linked = json.loads(webhook.build_body(ROW, None, "json", LINK))
    assert linked.pop("action_url") == LINK
    assert linked == plain


def test_slack_blocks_match_the_golden_message():
    body = json.loads(webhook.build_body(ROW, "https://console.example.com", "slack", LINK))
    assert body == {
        "text": f"MINT 경보(보통): {SUMMARY}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "MINT 경보"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": SUMMARY}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": "*심각도*\n보통"},
                    {"type": "mrkdwn", "text": "*서버*\nfiles"},
                    {"type": "mrkdwn", "text": "*도구*\nread"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*조치*\n{ACTION}"}},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "콘솔에서 열기"},
                        "url": LINK,
                    }
                ],
            },
        ],
    }


def test_slack_escapes_markup_in_server_names_and_falls_back_to_the_console_address():
    row = {**ROW, "kind": "job_failed", "subject": {"server_id": "a<b>&c"}}
    body = json.loads(webhook.build_body(row, "https://console.example.com", "slack"))
    assert "a&lt;b&gt;&amp;c" in body["blocks"][2]["fields"][1]["text"]
    assert body["blocks"][-1]["elements"][0]["url"] == "https://console.example.com"
    assert not any(
        b["type"] == "actions" for b in json.loads(webhook.build_body(row, None, "slack"))["blocks"]
    )


def test_teams_adaptive_card_matches_the_golden_message():
    body = json.loads(webhook.build_body(ROW, None, "teams", LINK))
    assert body == {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": "MINT 경보", "weight": "Bolder",
                         "size": "Medium"},
                        {"type": "TextBlock", "text": SUMMARY, "wrap": True},
                        {"type": "FactSet", "facts": [
                            {"title": "심각도", "value": "보통"},
                            {"title": "서버", "value": "files"},
                            {"title": "도구", "value": "read"},
                        ]},
                        {"type": "TextBlock", "text": f"조치: {ACTION}", "wrap": True},
                    ],
                    "actions": [
                        {"type": "Action.OpenUrl", "title": "콘솔에서 열기", "url": LINK}
                    ],
                },
            }
        ],
    }


def test_every_new_alert_kind_has_a_guide_and_a_link_target():
    for kind in ("call_approval_requested", "intake_pending", "approval_dormant"):
        assert all(webhook.GUIDE[kind])
        assert kind in links.ALERT_LINKS


# --- 형식 설정 ----------------------------------------------------------------

ENV = {
    "MINT_EXPORT_DIR": "/tmp/mint-export",
    "MINT_EXPORT_HMAC_KEY": "A" * 43,
    "MINT_WEBHOOK_URLS": "https://a.example.com/x,https://b.example.com/y",
    "MINT_WEBHOOK_HMAC_KEY": "B" * 43,
}


def test_the_format_is_chosen_per_url_and_defaults_to_json():
    default = Stage2Settings.from_env(ENV)
    assert [default.webhook_format(u) for u in default.webhook_urls] == ["json", "json"]
    chosen = Stage2Settings.from_env({**ENV, "MINT_WEBHOOK_FORMATS": "Slack, teams"})
    assert [chosen.webhook_format(u) for u in chosen.webhook_urls] == ["slack", "teams"]
    assert (chosen.link_ttl_seconds, chosen.dormant_days) == (86400, 30)


@pytest.mark.parametrize("value", ["slack", "slack,json,json", "slack,discord"])
def test_a_format_list_that_does_not_match_the_urls_is_refused(value):
    with pytest.raises(ControlError):
        Stage2Settings.from_env({**ENV, "MINT_WEBHOOK_FORMATS": value})


# --- 서명 링크 ----------------------------------------------------------------


def test_a_link_token_round_trips_until_it_expires():
    token = links.make(KEY, "call", "c-1", ttl=60, now=1000)
    assert links.parse(KEY, token, now=1060) == ("call", "c-1")
    assert links.parse(KEY, token, now=1061) is None


def test_a_forged_or_foreign_token_is_refused():
    token = links.make(KEY, "call", "c-1", now=1000)
    payload, _, mac = token.partition(".")
    other = links.make(KEY, "recert", "c-1", now=1000).partition(".")[0]
    for bad in (
        "", "x", payload, f"{other}.{mac}", f"{payload}.{'0' * 32}", token + "0", "!!!.zz",
    ):
        assert links.parse(KEY, bad, now=1000) is None
    assert links.parse(b"z" * 32, token, now=1000) is None


def test_the_link_for_an_alert_points_at_the_console_and_needs_an_address_and_key():
    link = links.for_alert(ROW, "https://console.example.com/", KEY, 3600)
    assert link.startswith("https://console.example.com/link/")
    token = link.rsplit("/", 1)[1]
    assert links.parse(KEY, token) == ("call", "c-1")
    assert links.for_alert(ROW, None, KEY, 3600) is None
    assert links.for_alert(ROW, "https://c.example.com", None, 3600) is None
    assert links.for_alert({**ROW, "kind": "job_failed"}, "https://c.example.com", KEY, 1) is None


# --- 미사용 승인 -----------------------------------------------------------------


def test_dormant_approvals_are_counted_per_server():
    rows = [{"server_id": "a"}, {"server_id": "b"}, {"server_id": "a"}]
    assert dormant.by_server(rows) == {"a": 2, "b": 1}
    assert dormant.key_for("a") == "approval_dormant:a"


def test_chat_messages_carry_the_tool_action_and_preview_of_an_approval_request():
    row = {**ROW, "subject": {**ROW["subject"], "action": "write", "preview": "path=/tmp/a"}}
    slack = json.loads(webhook.build_body(row, None, "slack", LINK))
    texts = [f["text"] for f in slack["blocks"][2]["fields"]]
    assert "*도구*\nread" in texts and "*동작*\nwrite" in texts and "*인자*\npath=/tmp/a" in texts
    teams = json.loads(webhook.build_body(row, None, "teams", LINK))
    facts = teams["attachments"][0]["content"]["body"][2]["facts"]
    assert {"title": "인자", "value": "path=/tmp/a"} in facts
    assert {"title": "도구", "value": "read"} in facts
