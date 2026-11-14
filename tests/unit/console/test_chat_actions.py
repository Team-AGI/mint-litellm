"""Slack 단추로 호출별 승인 처리: 서명 확인, 결속, 직무 분리, 1회 강제, 멱등, 메시지 갱신."""

import hashlib
import hmac
import json
import uuid
from urllib.parse import urlencode

import psycopg
import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.console import chat as chat_route
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import operators as operator_service

SECRET = "slack-signing-secret"
HOOK = "https://hooks.slack.com/actions/T/1/x"
USERS = {"approver": "U0APPROVER", "admin": "U0ADMIN"}


@pytest.fixture
def slack(world, monkeypatch):
    updates = []
    monkeypatch.setattr(chat_route, "post_response", lambda url, message: updates.append(message))
    world.updates = updates
    world.slack = world.client_with(slack_signing_secret=SECRET)
    world.clock = [1_900_000_000]
    monkeypatch.setattr("time.time", lambda: world.clock[0])
    return world


def conn_ctx(conn, name, user_id):
    return Context(conn, INSTANCE, Operator(name, "admin", user_id))


def bind(world, name, user):
    with psycopg.connect(world.url) as conn:
        operator_service.chat_bind(conn_ctx(conn, "admin", "human-1"), name, user)


def pending(world, requester="someone", principal="human-7", action=None):
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s) ON CONFLICT DO NOTHING",
        INSTANCE,
        "ab" * 32,
        "ab" * 32,
    )
    contract = None
    if action:
        contract = str(uuid.uuid4())
        world.query(
            "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
            " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
            " VALUES (%s, %s, 'srv-ok', 'server', 'echo', '{}', repeat('a', 64), repeat('b', 64),"
            " 'low', %s, 'intake', 'candidate')",
            contract,
            INSTANCE,
            action,
        )
        world.query("UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s", contract)
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at, contract_id) VALUES (%s, %s, 'acme', 'user', %s, 'srv-ok', 'echo', %s, 1,"
        " 'v1', 'pending', %s, now() + interval '1 hour', %s)",
        call_id,
        INSTANCE,
        principal,
        "ab" * 32,
        requester,
        contract,
    )
    return call_id


def post(world, payload, *, stamp=None, secret=SECRET):
    body = urlencode({"payload": json.dumps(payload)}).encode()
    if stamp is None:
        world.clock[0] += 1
        stamp = world.clock[0]
    mac = hmac.new(secret.encode(), f"v0:{stamp}:".encode() + body, hashlib.sha256).hexdigest()
    return world.slack.post(
        "/chat/slack/actions",
        content=body,
        headers={
            "X-Slack-Request-Timestamp": str(stamp),
            "X-Slack-Signature": "v0=" + mac,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )


def click(world, user, call_id, action="mint_call_approve_30", *, stamp=None):
    return post(
        world,
        {
            "type": "block_actions",
            "user": {"id": user},
            "trigger_id": "trig",
            "response_url": HOOK,
            "actions": [{"action_id": action, "value": call_id}],
        },
        stamp=stamp,
    )


def row(world):
    return world.query(
        "SELECT status, approved_by, window_minutes, decision_reason FROM mint.call_approvals"
    )[0]


def test_a_bound_approver_approves_for_thirty_minutes_and_the_message_is_replaced(slack):
    bind(slack, "approver", USERS["approver"])
    call_id = pending(slack)
    assert click(slack, USERS["approver"], call_id).status_code == 200
    assert row(slack) == ("approved", "approver", 30, None)
    text = "`srv-ok` / `echo`: approver 님이 30분 승인했습니다."
    assert slack.updates == [
        {
            "replace_original": True,
            "text": text,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
        }
    ]
    event = slack.query(
        "SELECT actor, payload FROM mint.events WHERE kind = 'call_approval_approved'"
    )[0]
    assert event[0] == "approver" and event[1]["channel"] == "slack"


def test_an_unbound_slack_account_is_refused_and_nothing_changes(slack):
    call_id = pending(slack)
    assert click(slack, "U0STRANGER", call_id).status_code == 200
    assert row(slack)[0] == "pending"
    assert slack.updates[0]["response_type"] == "ephemeral"
    assert "결속되어 있지 않아" in slack.updates[0]["text"]


def test_the_requesters_own_operator_cannot_approve(slack):
    bind(slack, "admin", USERS["admin"])  # 운영자 admin의 사용자는 human-1
    call_id = pending(slack, principal="human-1")
    click(slack, USERS["admin"], call_id)
    assert row(slack)[0] == "pending"
    assert slack.updates[0]["response_type"] == "ephemeral"
    assert "권한이 없습니다" in slack.updates[0]["text"]


def test_a_viewer_cannot_be_bound_and_a_taken_slack_user_cannot_be_reused(slack):
    for name, user in (("viewer", "U0VIEWER"), ("admin", "bad id")):
        with psycopg.connect(slack.url) as conn, pytest.raises(ControlError):
            operator_service.chat_bind(conn_ctx(conn, "admin", "human-1"), name, user)
    bind(slack, "approver", "U0SHARED")
    with psycopg.connect(slack.url) as conn, pytest.raises(ControlError):
        operator_service.chat_bind(conn_ctx(conn, "admin", "human-1"), "admin", "U0SHARED")
    with psycopg.connect(slack.url) as conn:
        operator_service.chat_bind(conn_ctx(conn, "admin", "human-1"), "approver", None)
    assert slack.query("SELECT count(*) FROM mint.operator_chat_bindings")[0][0] == 0
    assert (
        slack.query("SELECT count(*) FROM mint.events WHERE kind = 'operator_chat_bound'")[0][0]
        == 2
    )


def test_one_shot_actions_are_forced_to_a_single_use_even_on_the_thirty_minute_button(slack):
    bind(slack, "approver", USERS["approver"])
    click(slack, USERS["approver"], pending(slack, action="delete"))
    assert row(slack) == ("approved", "approver", None, None)
    assert "1회 승인했습니다" in slack.updates[0]["text"]


def test_the_once_button_approves_a_single_use(slack):
    bind(slack, "approver", USERS["approver"])
    click(slack, USERS["approver"], pending(slack), "mint_call_approve_once")
    assert row(slack) == ("approved", "approver", None, None)


def test_a_second_click_reports_the_existing_decision_and_changes_nothing(slack):
    bind(slack, "approver", USERS["approver"])
    bind(slack, "admin", USERS["admin"])
    call_id = pending(slack)
    click(slack, USERS["approver"], call_id)
    click(slack, USERS["admin"], call_id, "mint_call_reject")
    assert row(slack) == ("approved", "approver", 30, None)
    assert slack.updates[1]["text"] == "`srv-ok` / `echo`: 이미 승인되었습니다. (approver)"
    assert (
        slack.query(
            "SELECT count(*) FROM mint.events WHERE kind IN"
            " ('call_approval_approved', 'call_approval_rejected')"
        )[0][0]
        == 1
    )


def test_rejecting_without_a_bot_token_records_chat_as_the_reason(slack):
    bind(slack, "approver", USERS["approver"])
    click(slack, USERS["approver"], pending(slack), "mint_call_reject")
    assert row(slack)[0] == "rejected" and row(slack)[3] == "chat"
    assert "거부했습니다. 사유: chat" in slack.updates[0]["text"]


def test_rejecting_with_a_bot_token_opens_a_modal_and_the_submitted_reason_is_stored(
    slack, monkeypatch
):
    opened = []
    monkeypatch.setattr(chat_route, "open_modal", lambda token, view: opened.append(view) or True)
    slack.slack = slack.client_with(slack_signing_secret=SECRET, slack_bot_token="xoxb-test")
    bind(slack, "approver", USERS["approver"])
    click(slack, USERS["approver"], pending(slack), "mint_call_reject")
    assert row(slack)[0] == "pending" and slack.updates == []
    view = opened[0]["view"]
    submit = {
        "type": "view_submission",
        "user": {"id": USERS["approver"]},
        "view": {
            "callback_id": view["callback_id"],
            "private_metadata": view["private_metadata"],
            "state": {"values": {"reason": {"reason_input": {"value": "범위 밖 요청"}}}},
        },
    }
    assert post(slack, submit).json() == {"response_action": "clear"}
    assert row(slack)[0] == "rejected" and row(slack)[3] == "범위 밖 요청"
    assert "사유: 범위 밖 요청" in slack.updates[0]["text"]


def test_bad_stale_and_replayed_requests_are_refused_before_anything_runs(slack):
    bind(slack, "approver", USERS["approver"])
    call_id = pending(slack)
    assert click(slack, USERS["approver"], call_id, stamp=slack.clock[0] - 301).status_code == 401
    assert post(slack, {"type": "x"}, secret="wrong").status_code == 401
    forged = slack.slack.post(
        "/chat/slack/actions",
        content=b"payload=%7B%7D",
        headers={"X-Slack-Request-Timestamp": str(slack.clock[0]), "X-Slack-Signature": "v0=00"},
    )
    assert forged.status_code == 401
    assert row(slack)[0] == "pending"
    stamp = slack.clock[0] + 1
    assert click(slack, USERS["approver"], call_id, stamp=stamp).status_code == 200
    assert click(slack, USERS["approver"], call_id, stamp=stamp).status_code == 401
    assert len(slack.updates) == 1


def test_without_a_signing_secret_the_endpoint_does_not_exist(world):
    response = world.client.post("/chat/slack/actions", content=b"payload=%7B%7D")
    assert response.status_code == 404
