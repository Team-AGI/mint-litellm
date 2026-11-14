"""승인 운영 지표: 기간별 집계 값, API, 화면 렌더링."""

import json
import uuid

from console_fixtures import HEX, TOKENS

INSTANCE = "inst1"


def bearer(role: str = "viewer") -> dict:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def seed(world, *, status="pending", approved_by=None, tool="echo", server="srv-ok",
         age="1 hour", decided="10 minutes", window=None, uses=0, contract=None, org="acme"):
    """요청 시각이 ``age`` 전이고, 결정이 ``decided`` 뒤에 난 호출별 승인 한 행."""
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s) ON CONFLICT DO NOTHING", INSTANCE, HEX, HEX)
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at, requested_at, contract_id)"
        " VALUES (%s, %s, %s, 'user', 'human-7', %s, %s, %s, 1, 'v1', 'pending', 'human-7',"
        " now() + interval '1 day', now() - %s::interval, %s)",
        call_id, INSTANCE, org, server, tool, HEX, age, contract)
    if status == "pending":
        pass
    elif status in ("rejected", "expired"):
        world.query("UPDATE mint.call_approvals SET status = %s, decided_at = now() - %s::interval"
                    " + %s::interval WHERE id = %s", status, age, decided, call_id)
    else:
        world.query(
            "UPDATE mint.call_approvals SET status = 'approved', approved_by = %s,"
            " decided_at = now() - %s::interval + %s::interval, window_minutes = %s,"
            " valid_until = CASE WHEN %s::int IS NULL THEN NULL ELSE now() + interval '1 day' END"
            " WHERE id = %s", approved_by, age, decided, window, window, call_id)
        if status == "consumed":
            world.query("UPDATE mint.call_approvals SET status = 'consumed',"
                        " consumed_invocation_id = gen_random_uuid() WHERE id = %s", call_id)
    for _ in range(uses):
        world.query(
            "INSERT INTO mint.call_approval_uses (instance_id, call_approval_id, invocation_id)"
            " VALUES (%s, %s, gen_random_uuid())", INSTANCE, call_id)
    return call_id


def contract(world, tool="echo", action="write", server="srv-ok") -> str:
    cid = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (%s, %s, %s, 'server', %s, '{}', repeat('a', 64), repeat('b', 64), 'low', %s,"
        " 'intake', 'candidate')", cid, INSTANCE, server, tool, action)
    world.query("UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s", cid)
    return cid


def stats(world, range_name="7d") -> dict:
    response = world.client.get(f"/api/v1/metrics/approvals?range={range_name}",
                                headers=bearer())
    assert response.status_code == 200, response.text
    return response.json()


def test_counts_split_by_who_decided_and_the_range(world):
    seed(world, status="approved", approved_by="human-2", decided="2 minutes")
    seed(world, status="approved", approved_by="rule:" + str(uuid.uuid4()), window=30)
    seed(world, status="rejected", decided="8 minutes")
    seed(world, status="expired", decided="0 minutes")
    seed(world, status="pending")
    seed(world, status="approved", approved_by="human-2", age="3 days", decided="1 minute")
    seed(world, status="rejected", age="20 days")
    day = stats(world, "24h")
    assert (day["opened"], day["approved_by_person"], day["approved_by_rule"]) == (5, 1, 1)
    assert (day["denied"], day["expired_unused"], day["pending"]["count"]) == (1, 1, 1)
    week = stats(world, "7d")
    assert (week["opened"], week["approved_by_person"], week["denied"]) == (6, 2, 1)
    assert stats(world, "30d")["opened"] == 7


def test_decision_time_uses_people_only_and_reports_the_pending_age(world):
    for minutes in (1, 2, 3, 4, 10):
        seed(world, status="approved", approved_by="human-2", decided=f"{minutes} minutes")
    seed(world, status="approved", approved_by="rule:" + str(uuid.uuid4()), window=30,
         decided="0 minutes")
    seed(world, status="pending", age="2 hours")
    data = stats(world)
    assert data["median_seconds"] == 180
    assert data["p90_seconds"] == 456
    assert 7100 <= data["pending"]["oldest_seconds"] <= 7300


def test_period_reuse_share_counts_uses_against_one_shot_calls(world):
    seed(world, status="approved", approved_by="human-2", window=30, uses=3)
    seed(world, status="consumed", approved_by="human-2")
    data = stats(world)
    assert (data["period_uses"], data["one_shot_uses"], data["period_share"]) == (3, 1, 0.75)
    assert stats(world, "24h")["period_share"] == 0.75


def test_a_hold_that_ended_in_approval_is_counted_from_the_decision_event(world):
    for hold in ("approved", "approved", "denied", None):
        payload = {"enforced_action": "allow"} | ({"approval_hold": hold} if hold else {})
        world.query(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
            " attempt_id, payload) VALUES (%s, %s, 'decision_evaluated', %s, %s, 1, %s)",
            uuid.uuid4(), INSTANCE, f"call:{uuid.uuid4()}:1:decision_evaluated", uuid.uuid4(),
            json.dumps(payload))
    assert stats(world)["held_completed"] == 2


def test_top_tools_series_and_an_empty_range(world):
    assert stats(world)["opened"] == 0 and stats(world)["period_share"] is None
    for _ in range(3):
        seed(world, tool="send")
    seed(world, tool="echo")
    data = stats(world, "24h")
    assert data["top"][0] == {"server_id": "srv-ok", "tool": "send", "n": 3}
    assert len(data["series"]["labels"]) == 24 and sum(data["series"]["values"]) == 4
    assert len(stats(world, "30d")["series"]["labels"]) == 30


def test_a_suggestion_appears_only_for_five_repeated_manual_approvals(world):
    cid = contract(world)
    for _ in range(4):
        seed(world, status="approved", approved_by="human-2", contract=cid)
    assert stats(world)["suggestion"] is None
    seed(world, status="approved", approved_by="human-2", contract=cid)
    suggestion = stats(world)["suggestion"]
    assert (suggestion["tool"], suggestion["action_type"], suggestion["n"]) == ("echo", "write", 5)


def test_a_bad_range_is_refused(world):
    assert world.client.get("/api/v1/metrics/approvals?range=1y",
                            headers=bearer()).status_code == 400


def test_the_screen_shows_the_cards_the_chart_and_the_prefilled_rule_link(world):
    cid = contract(world)
    for _ in range(5):
        seed(world, status="approved", approved_by="human-2", contract=cid)
    page = world.session_client("admin")
    html = page.get("/call-approvals?range=30d").text
    assert "사람이 승인" in html and "결정 중앙값" in html and "data-bars=" in html
    assert "상시 승인 규칙 만들기" in html and "rule_tool=echo" in html
    form = page.get("/call-approvals?rule_server=srv-ok&rule_tool=echo&rule_class=write").text
    assert 'name="tool_pattern" value="echo"' in form and 'value="write" selected' in form
    assert "상시 승인 규칙 만들기" not in world.session_client("viewer").get("/call-approvals").text
