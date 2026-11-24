"""사용량 읽기: 호출·차단 집계, 직원 범위, 중복 없음, 판정 지연."""

import json
from datetime import UTC, datetime, timedelta

from ctl_fixtures import INSTANCE

from mint_litellm.control import usage_reader
from mint_litellm.types.ids import new_uuid7


def test_calls_and_blocks_are_summed_without_cost():
    ledger = [
        {"team_id": "t1", "user_id": "u1", "server_id": "a", "calls": 2, "blocked": 2},
        {"team_id": "t1", "user_id": "u1", "server_id": "b", "calls": 5, "blocked": 0},
        {"team_id": "t2", "user_id": "u2", "server_id": "b", "calls": 1, "blocked": 0},
    ]
    out = usage_reader.combine(ledger, [], {"b": "B"}, scoped=False)
    assert "cost" not in out and all("cost" not in r for r in out["teams"])
    servers = {r["name"]: r for r in out["servers"]}
    assert servers["B"]["calls"] == 6 and servers["a"]["blocked"] == 2
    assert out["calls"] == 8 and out["blocked"] == 2


def event(conn, kind, inv, attempt, payload):
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (new_uuid7(), INSTANCE, kind, f"t:{new_uuid7()}", inv, attempt, json.dumps(payload)),
    )


def test_ledger_counts_a_retried_call_once_and_limits_to_one_user(conn):
    me = {"user_id": "me", "team_id": "t", "resolved_server_id": "s", "enforced_action": "allow"}
    blocked = {**me, "enforced_action": "block", "outcome": "blocked"}
    one, two = new_uuid7(), new_uuid7()
    event(conn, "decision_evaluated", one, 1, me)
    event(conn, "decision_evaluated", one, 2, me)  # 같은 호출의 재시도
    event(conn, "decision_evaluated", two, 1, blocked)
    event(conn, "decision_evaluated", new_uuid7(), 1, {**me, "user_id": "other"})
    event(conn, "call_response_received", one, 2, {})
    start = datetime.now(UTC) - timedelta(days=1)
    end = datetime.now(UTC) + timedelta(days=1)
    rows = usage_reader.read_ledger(conn, INSTANCE, start, end, "me")
    assert [(r["user_id"], r["calls"], r["blocked"]) for r in rows] == [("me", 2, 1)]
    everyone = usage_reader.read_ledger(conn, INSTANCE, start, end, None)
    assert sum(r["calls"] for r in everyone) == 3
    first = usage_reader.read_first_success(conn, INSTANCE, "me")
    assert [(f["user_id"], f["server_id"]) for f in first] == [("me", "s")]


def test_ledger_reads_the_user_from_the_principal(conn):
    mine = {"principal": {"principal_type": "user", "principal_id": "me", "team_id": "t"},
            "resolved_server_id": "s", "enforced_action": "allow"}
    key = {"principal": {"principal_type": "team_key", "principal_id": "k1", "team_id": "t"},
           "resolved_server_id": "s", "enforced_action": "allow"}
    event(conn, "decision_evaluated", new_uuid7(), 1, mine)
    event(conn, "decision_evaluated", new_uuid7(), 1, key)
    start = datetime.now(UTC) - timedelta(days=1)
    end = datetime.now(UTC) + timedelta(days=1)
    rows = usage_reader.read_ledger(conn, INSTANCE, start, end, "me")
    assert [(r["user_id"], r["team_id"], r["calls"]) for r in rows] == [("me", "t", 1)]
    everyone = usage_reader.read_ledger(conn, INSTANCE, start, end, None)
    assert {r["user_id"] for r in everyone} == {"me", ""}
    assert usage_reader.read_tools(conn, INSTANCE, "s") == []


def test_decision_latency_reports_median_and_p95_in_ms(conn):
    start = datetime.now(UTC) - timedelta(days=1)
    end = datetime.now(UTC) + timedelta(days=1)
    assert usage_reader.decision_latency(conn, INSTANCE, start, end) == {
        "p50": None, "p95": None, "count": 0}
    for us in (1000, 2000, 3000, 4000, 100000):
        event(conn, "decision_evaluated", new_uuid7(), 1, {"decision_us": us, "user_id": "me"})
    event(conn, "decision_evaluated", new_uuid7(), 1, {"user_id": "me"})  # 시간 기록 없음
    got = usage_reader.decision_latency(conn, INSTANCE, start, end, "me")
    assert got["count"] == 5 and got["p50"] == 3.0 and 4.0 < got["p95"] <= 100.0


def test_read_only_client_exposes_daily_activity():
    from mint_litellm.console.core import ReadOnlyLiteLLM
    from mint_litellm.control.litellm_admin import LiteLLMAdmin

    assert ReadOnlyLiteLLM(LiteLLMAdmin("http://x", "k")).daily_activity
