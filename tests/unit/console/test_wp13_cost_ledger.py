"""사용량 비용(LiteLLM 지출 기록)과 호출 기록의 「오류」 결과 필터."""

import json
import re
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from console_pages_support import INSTANCE
from psycopg.rows import dict_row

from mint_litellm.control import usage_reader
from mint_litellm.control.litellm_admin import LiteLLMAdmin, LiteLLMError
from mint_litellm.control.services import reads

from .test_dashboard import shown


def day(*users):
    return {"breakdown": {"entities": {u: {"metrics": {"spend": s}} for u, s in users}}}


def test_user_spend_sums_pages_and_keeps_zero_apart_from_missing(monkeypatch):
    pages = [
        {"results": [day(("a", 0.5), ("b", 0))], "metadata": {"has_more": True}},
        {"results": [day(("a", 0.25))], "metadata": {"has_more": False}},
    ]
    seen = []
    admin = LiteLLMAdmin("http://x", "k")
    monkeypatch.setattr(admin, "daily_activity",
                        lambda path, params: seen.append((path, params["page"])) or pages.pop(0))
    got = admin.user_spend("s", "e")
    assert got == {"total": 0.75, "by_user": {"a": 0.75, "b": 0.0}}
    assert seen == [("/user/daily/activity", 1), ("/user/daily/activity", 2)]


def test_user_spend_gives_up_when_the_record_never_ends(monkeypatch):
    admin = LiteLLMAdmin("http://x", "k")
    monkeypatch.setattr(admin, "daily_activity",
                        lambda p, q: {"results": [], "metadata": {"has_more": True}})
    with pytest.raises(LiteLLMError):
        admin.user_spend("s", "e")


class Spend:
    def __init__(self, result):
        self.result = result

    def user_spend(self, start, end, user=None):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_attach_spend_separates_cost_zero_and_unrecorded():
    now = datetime.now(UTC)
    report = {"users": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}
    usage_reader.attach_spend(
        report, Spend({"total": 1.5, "by_user": {"a": 1.5, "b": 0.0}}), now, now, None)
    assert report["spend"] == 1.5
    assert [r["spend"] for r in report["users"]] == [1.5, 0.0, None]
    for admin in (Spend(LiteLLMError("막힘")), Spend(TimeoutError()), None):
        usage_reader.attach_spend(report, admin, now, now, None)
        assert report["spend"] is None and all(r["spend"] is None for r in report["users"])


def decision_row(world, user, server="srv-ok"):
    event = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.events(event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES(%s,%s,'decision_evaluated',%s,%s,1,%s::jsonb)",
        event, INSTANCE, f"c:{event}", event,
        json.dumps({"user_id": user, "resolved_server_id": server, "enforced_action": "allow"}))


def test_usage_screen_shows_cost_zero_and_unrecorded(world, admin):
    for user in ("u-paid", "u-zero", "u-none"):
        decision_row(world, user)
    fake = Spend({"total": 0.0123, "by_user": {"u-paid": 0.0123, "u-zero": 0.0}})
    fake.list_servers = lambda: []
    object.__setattr__(world.config, "litellm_admin", fake)
    html = admin.get("/reports/usage").text
    text = shown(html)
    assert "비용(LiteLLM 기록)" in text and "$0.0123" in text
    cells = {}
    for user in ("u-paid", "u-zero", "u-none"):
        tr = re.search(rf"<tr><td>{user}</td>.*?</tr>", html).group(0)
        cells[user] = re.findall(r"<td[^>]*>(.*?)</td>", tr)[3]
    assert cells == {"u-paid": "$0.0123", "u-zero": "0", "u-none": "미집계"}


def test_usage_screen_survives_an_unreadable_spend_record(world, admin):
    decision_row(world, "u-paid")
    fake = Spend(LiteLLMError("막힘"))
    fake.list_servers = lambda: []
    object.__setattr__(world.config, "litellm_admin", fake)
    page = admin.get("/reports/usage")
    assert page.status_code == 200
    assert "미집계" in shown(page.text) and "LiteLLM 지출 기록을 읽지 못했습니다" in page.text


def event(world, kind, payload):
    eid = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.events(event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES(%s,%s,%s,%s,%s,1,%s::jsonb)",
        eid, INSTANCE, kind, f"e:{eid}", eid, json.dumps(payload))
    return eid


def test_error_filter_selects_tool_errors_and_unknown_results_only(world, admin):
    err = event(world, "call_response_received", {"outcome": "tool_error"})
    old = event(world, "call_response_received", {"is_error": "true"})  # outcome 이전 행
    unk = event(world, "call_outcome_unknown", {"reason": "no_report"})
    event(world, "call_response_received", {"outcome": "success"})
    deny = event(world, "decision_evaluated", {"enforced_action": "deny"})
    with psycopg.connect(world.admin_url, row_factory=dict_row) as conn:
        ids = {str(r["event_id"]) for r in reads.ledger(conn, INSTANCE, result="error")}
        assert ids == {err, old, unk}
        assert {str(r["event_id"]) for r in reads.ledger(conn, INSTANCE, result="deny")} == {deny}
    html = admin.get("/ledger?result=error").text
    assert "result=error" in html and "오류" in shown(html)
    assert admin.get("/ledger?result=deny").status_code == 200
