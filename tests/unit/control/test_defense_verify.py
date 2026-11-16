"""방어 검증기: 인자 선택, 판정 대조, 안전장치, 사건·경보 기록."""

import json

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.control import defense_verify as dv
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.defense_profile import CASES, host_is_safe, payload_is_safe
from mint_litellm.control.errors import ControlError
from mint_litellm.types.ids import new_uuid7

SCHEMA = {"type": "object", "required": ["path", "mode"], "properties": {
    "zeta": {"type": "string"}, "path": {"type": "string"}, "url": {"type": "string"},
    "mode": {"type": "string", "enum": ["fast", "slow"]}, "n": {"type": "integer"}}}


def tool(name, action="read", schema=SCHEMA):
    return {"tool": name, "action_type": action,
            "canonical_text": json.dumps({"description": "", "input_schema": schema})}


def test_arg_choice_is_deterministic_and_skips_enums():
    assert dv.pick_arg(SCHEMA, "path") == "path"
    assert dv.pick_arg(SCHEMA, "url") == "url"
    assert dv.pick_arg(SCHEMA, "text") == "path"  # 이름이 맞는 칸이 없으면 이름 순 첫 문자열
    assert dv.pick_arg({"properties": {"m": {"type": "string", "enum": ["a"]}}}, "text") is None
    assert dv.build_arguments(SCHEMA, "url", "v") == {"url": "v", "path": "MINT-VERIFY",
                                                      "mode": "fast"}
    assert dv.build_arguments({"required": ["x"], "properties": {}}, "q", "v") is None


def test_only_read_tools_are_called_and_the_plan_repeats():
    tools = [tool("write_all", "write"), tool("b_read"), tool("a_read")]
    one = dv.make_plan(tools, "MINT-VERIFY-x")
    two = dv.make_plan(list(reversed(tools)), "MINT-VERIFY-x")
    assert {c.tool for c in one.calls} == {"a_read"}
    assert [(c.id, c.tool, c.arg) for c in one.calls] == [(c.id, c.tool, c.arg) for c in two.calls]
    assert dv.make_plan([tool("w", "write"), tool("d", "delete")], "m").calls == []


def test_payloads_carry_the_marker_and_never_leave_safe_destinations():
    plan = dv.make_plan([tool("a")], "MINT-VERIFY-abc", allowed_host="docs.example.invalid")
    assert plan.calls and all("MINT-VERIFY-abc" in json.dumps(c.arguments) for c in plan.calls)
    for case in CASES:
        assert payload_is_safe(case.payload("MINT-VERIFY-abc", "docs.example.invalid"),
                               "docs.example.invalid"), case.id
    assert not payload_is_safe("see https://evil.example.com/x")
    assert not host_is_safe("example.com") and host_is_safe("a.invalid")
    assert any(s["id"] == "addr-6" for s in dv.make_plan([tool("a")], "m").skipped)


def test_result_cases_need_the_declared_test_server():
    leak = tool("leak", schema={"properties": {"kind": {"type": "string"}}})
    assert not [c for c in dv.make_plan([leak], "m").calls if c.result_side]
    on = dv.make_plan([leak], "m", test_server=True)
    assert len([c for c in on.calls if c.result_side]) == 6


def test_call_cap_is_enforced():
    plan = dv.make_plan([tool("a")], "m", max_calls=3)
    assert len(plan.calls) == 3 and len(plan.skipped) >= 20


def call(expect, policies=("POL-E-05",), result_side=False):
    return dv.Call("c", "g", "d", "t", "a", {}, expect, policies, result_side)


BLOCK = {"status": 400, "text": "blocked MINT-POLICY", "blocked": True, "reference": None}
OPEN = {"status": 200, "text": "ok", "blocked": False, "reference": None}


def test_judge_compares_client_ledger_and_expectation():
    deny = {"enforced_action": "block", "policy_ids": ["POL-E-05"]}
    allow = {"enforced_action": "allow"}
    assert dv.judge(call("blocked"), BLOCK, deny, None)[0] == "pass"
    assert dv.judge(call("blocked"), OPEN, allow, None)[0] == "fail"
    assert dv.judge(call("blocked"), OPEN, deny, None)[0] == "fail"
    assert dv.judge(call("blocked"), BLOCK, None, None)[0] == "fail"
    assert dv.judge(call("blocked", ("POL-E-07",)), BLOCK, deny, None)[0] == "warn"
    assert dv.judge(call("allowed", ()), OPEN, allow, None)[0] == "pass"
    assert dv.judge(call("allowed", ()), BLOCK, deny, None)[0] == "fail"


def test_judge_result_side():
    allow = {"enforced_action": "allow"}
    masked = {"status": 200, "text": "a [MASKED:email]", "blocked": False}
    assert dv.judge(call("masked", result_side=True), masked, allow,
                    {"sensitive_findings": {"email": 1}})[0] == "pass"
    assert dv.judge(call("masked", result_side=True), OPEN, allow, {})[0] == "fail"
    out = {"status": 200, "text": "MINT-OUTPUT-BLOCKED", "blocked": True}
    assert dv.judge(call("blocked", ("POL-E-04",), True), out, allow,
                    {"output_findings": ["POL-E-04"]})[0] == "pass"


def test_correlation_prefers_the_reference_then_order():
    rows = [{"invocation_id": "i1", "attempt_id": 1, "payload": {"tool": "t"}},
            {"invocation_id": "i2", "attempt_id": 1, "payload": {"tool": "pre-t"}}]
    calls = [call("allowed"), call("allowed")]
    got = dv.correlate(calls, [{"reference": "i2:1"}, {"reference": None}], rows)
    assert [r["invocation_id"] for r in got] == ["i2", "i1"]


def seed(conn, tools):
    conn.execute(
        "INSERT INTO mint.servers(id,instance_id,server_id,status,url_sha256,transport,"
        "auth_type,registered_by) VALUES (%s,%s,'srv','pending',repeat('a',64),'http','none','x')",
        (new_uuid7(), INSTANCE),
    )
    seed_tools(conn, tools)


def seed_tools(conn, tools):
    for t in tools:
        conn.execute(
            "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
            " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
            " VALUES (%s, %s, 'srv', 'server', %s, %s, repeat('a', 64), repeat('b', 64), 'low',"
            " %s, 'intake', 'candidate')",
            (new_uuid7(), INSTANCE, t["tool"], t["canonical_text"], t["action_type"]),
        )
    conn.execute("UPDATE mint.tool_contracts SET status = 'approved'")


DENY_WORDS = ("etc/", "AKIA", "BEGIN", "169.", "127.", "10.0", "file:", "invalid/", "900101",
              "4111", "5500", "SAM", "ssh", "ghp_", "Bearer", "eyJ", "/proc")


def ledger_caller(conn, key, wrong=()):
    """게이트웨이 대신 원장에 판정 사건을 직접 남긴다(문서대로 막고 대조군은 허용)."""

    def caller(gateway, k, server_id, name, arguments):
        deny = any(s in json.dumps(arguments) for s in DENY_WORDS)
        if name in wrong:
            deny = not deny
        payload = {
            "principal": {"principal_type": "user", "key_id": dv.key_id_of(key)},
            "tool": name, "enforced_action": "block" if deny else "allow",
            "policy_ids": ["POL-E-05", "POL-E-09", "POL-E-14", "POL-E-07"] if deny else [],
        }
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key,"
            " invocation_id, attempt_id, payload) VALUES (%s, %s, clock_timestamp(),"
            " 'decision_evaluated', %s, %s, 1, %s)",
            (new_uuid7(), INSTANCE, f"t:{new_uuid7()}", new_uuid7(), json.dumps(payload)),
        )
        return {"status": 400 if deny else 200, "text": "MINT-x" if deny else "ok",
                "blocked": deny, "reference": None}

    return caller


def run(ctx, **kw):
    return dv.run_verify(ctx, server_id="srv", key="sk-verify", gateway="http://gw.invalid",
                         wait=0, commit=lambda: None, namer=lambda *a: {"p-a": "p-a"},
                         sleep=lambda s: None, **kw)


def test_run_records_the_event_and_opens_then_resolves_the_alert(conn, ctx):
    seed(conn, [tool("a"), tool("w", "write")])
    good = ledger_caller(conn, "sk-verify")
    result = run(ctx, caller=good)
    assert result["counts"]["fail"] == 0 and result["counts"]["pass"] == 24
    assert result["counts"]["skipped"] == 7 and "MINT-VERIFY-" in result["marker"]
    (event,) = fetchall(conn, "SELECT payload FROM mint.events WHERE kind = 'defense_verify_run'")
    assert event["payload"]["profile_version"] == dv.PROFILE_VERSION
    assert event["payload"]["counts"]["pass"] == 24 and "sk-verify" not in json.dumps(event)
    assert not fetchall(conn, "SELECT 1 FROM mint.alerts WHERE kind = 'defense_verify_failed'")
    failing = run(ctx, caller=ledger_caller(conn, "sk-verify", wrong=("p-a",)))
    assert failing["counts"]["fail"] > 0
    (alert,) = fetchall(conn, "SELECT severity, subject FROM mint.alerts"
                        " WHERE kind = 'defense_verify_failed'")
    assert alert["severity"] == "high" and alert["subject"]["failed"] == failing["counts"]["fail"]
    run(ctx, caller=good)
    (closed,) = fetchall(conn, "SELECT status FROM mint.alerts"
                         " WHERE kind = 'defense_verify_failed'")
    assert closed["status"] == "resolved"


def test_missing_ledger_event_fails_and_no_read_tool_is_refused(conn, ctx):
    seed(conn, [tool("a")])

    def silent(*a):
        return {"status": 200, "text": "ok", "blocked": False, "reference": None}

    result = run(ctx, caller=silent)
    assert result["counts"]["pass"] == 0 and result["counts"]["fail"] == 24
    conn.execute("DELETE FROM mint.tool_contracts")
    seed_tools(conn, [tool("w", "write")])
    with pytest.raises(ControlError):
        run(ctx, caller=silent)
