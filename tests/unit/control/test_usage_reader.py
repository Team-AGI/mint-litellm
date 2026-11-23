"""사용량 읽기: LiteLLM 일별 활동 합산, 직원 범위, 중복 없음, 못 읽으면 「미수집」."""

import json
from datetime import UTC, datetime, timedelta

from ctl_fixtures import INSTANCE

from mint_litellm.control import usage_reader
from mint_litellm.control.errors import ControlError
from mint_litellm.types.ids import new_uuid7


def day(spend, calls, entities=None, servers=None):
    def item(v):
        return {"metrics": {"spend": v[0], "api_requests": v[1]}}

    return {"metrics": {"spend": spend, "api_requests": calls},
            "breakdown": {"entities": {k: item(v) for k, v in (entities or {}).items()},
                          "mcp_servers": {k: item(v) for k, v in (servers or {}).items()}}}


class FakeAdmin:
    def __init__(self, by_path, fail=()):
        self.by_path, self.fail, self.calls = by_path, set(fail), []

    def daily_activity(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if path in self.fail:
            raise ControlError("x")
        rows = self.by_path[path] if not isinstance(self.by_path[path], dict) else \
            self.by_path[path][(params or {}).get("user_id")]
        return {"results": rows, "metadata": {"total_pages": 1}}


def fresh():
    usage_reader._cache.clear()


def test_spend_is_summed_per_team_and_server_over_days():
    fresh()
    admin = FakeAdmin({"/team/daily/activity": [
        day(1.5, 3, {"t1": (1.0, 2)}, {"srv": (0.5, 1)}),
        day(2.0, 4, {"t1": (1.5, 3), "t2": (0.5, 1)}, {"srv": (0.0, 1)})],
        "/user/daily/activity": {"u1": [day(0.25, 1)]}})
    start, end = usage_reader.window("7d")
    teams, servers, people = usage_reader.read_spend(admin, start, end, ["u1"], None)
    assert teams == {"t1": (2.5, 5), "t2": (0.5, 1)}
    assert servers == {"srv": (0.5, 2)}
    assert people == {"u1": (0.25, 1)}


def test_a_repeated_read_does_not_double_the_totals():
    fresh()
    admin = FakeAdmin({"/team/daily/activity": [day(1.0, 1, {"t": (1.0, 1)})]})
    start, end = usage_reader.window("today")
    a = usage_reader.read_spend(admin, start, end, [], None)
    b = usage_reader.read_spend(admin, start, end, [], None)
    assert a[0] == b[0] == {"t": (1.0, 1)}


def test_staff_reads_only_their_own_user():
    fresh()
    admin = FakeAdmin({"/user/daily/activity": {"me": [day(2.0, 2, servers={"srv": (2.0, 2)})]}})
    start, end = usage_reader.window("7d")
    teams, servers, people = usage_reader.read_spend(admin, start, end, ["other"], "me")
    assert teams is None and people == {"me": (2.0, 2)} and servers == {"srv": (2.0, 2)}
    assert {p for p, _ in admin.calls} == {"/user/daily/activity"}
    assert all(q["user_id"] == "me" for _, q in admin.calls)


def test_unreadable_spend_is_shown_as_not_collected_not_zero():
    fresh()
    admin = FakeAdmin({"/team/daily/activity": [], "/user/daily/activity": {}},
                      fail={"/team/daily/activity", "/user/daily/activity"})
    start, end = usage_reader.window("7d")
    spend = usage_reader.read_spend(admin, start, end, ["u1"], None)
    assert spend == (None, None, None)
    ledger = [{"team_id": "t1", "user_id": "u1", "server_id": "s", "calls": 3, "blocked": 1}]
    out = usage_reader.combine(ledger, [], spend, {}, scoped=False)
    assert out["cost"]["text"] == "미수집" and out["calls"] == 3
    assert out["teams"][0]["cost"]["state"] == "missing"


def test_pre_blocked_unlisted_and_real_zero_are_distinct():
    ledger = [
        {"team_id": "t1", "user_id": "u1", "server_id": "a", "calls": 2, "blocked": 2},
        {"team_id": "t1", "user_id": "u1", "server_id": "b", "calls": 5, "blocked": 0},
        {"team_id": "t2", "user_id": "u2", "server_id": "b", "calls": 1, "blocked": 0},
    ]
    spend = ({"t1": (0.0, 7)}, {"B": (1.234, 5)}, {"u1": (0.0, 7)})
    out = usage_reader.combine(ledger, [], spend, {"b": "B"}, scoped=False)
    teams = {r["name"]: r for r in out["teams"]}
    assert teams["t1"]["cost"]["text"] == "$0.00" and teams["t1"]["cost"]["state"] == "ok"
    assert teams["t2"]["cost"]["state"] == "none"
    servers = {r["name"]: r for r in out["servers"]}
    assert servers["B"]["cost"]["text"] == "$1.23" and servers["B"]["calls"] == 6
    assert servers["a"]["blocked"] == 2 and servers["a"]["cost"]["state"] == "none"
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


def test_ledger_reads_the_user_from_the_principal_and_cost_is_never_half_known(conn):
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
    # 팀별 지출을 못 읽었으면 사람별이 비어 있어도 상단 비용은 미수집이다.
    out = usage_reader.combine(everyone, [], (None, None, {}), {}, scoped=False)
    assert out["cost"]["text"] == "미수집"
    assert usage_reader.read_tools(conn, INSTANCE, "s") == []


def test_total_without_model_spend_is_not_applicable():
    assert usage_reader.total_cost(0.0)["text"] == "해당 없음(모델 지출 없음)"
    assert usage_reader.total_cost(1.5)["text"] == "$1.50"
    assert usage_reader.total_cost(None)["text"] == "미수집"


def test_mcp_server_keys_are_grouped_by_server():
    days = [day(0.0, 2, None, {"srv/a": (0.5, 1), "srv/b": (0.25, 1)})]
    assert usage_reader._sum(days, "mcp_servers") == {"srv": (0.75, 2)}


def test_read_only_client_exposes_daily_activity():
    from mint_litellm.console.core import ReadOnlyLiteLLM
    from mint_litellm.control.litellm_admin import LiteLLMAdmin

    assert ReadOnlyLiteLLM(LiteLLMAdmin("http://x", "k")).daily_activity
