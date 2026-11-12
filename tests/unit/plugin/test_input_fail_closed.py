"""허용 인자 키를 알 수 없으면 막고(닫힌 쪽), 도구로 보내는 인자의 비밀을 막는다(POL-E-05)."""

import asyncio
from dataclasses import replace

from plugin_helpers import NOW, approval, evaluator, harness, request, server_row, snapshot

from mint_litellm.control.approvals import ALLOWABLE_INPUT_SECRETS, build_conditions
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.policy.sensitive_scan import INPUT_SECRET_KINDS, SCAN_LIMIT, scan_arguments
from mint_litellm.plugin.snapshot import SettingsRow, ToolContractRow
from mint_litellm.types.settings import Mode

# 저장소 비밀 검사에 걸리지 않게 나눠 쓴다.
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def decide(tmp_path, *, input_keys, conditions=None, arguments=None, managed=True, observe=False):
    contract = ToolContractRow("c1", "server", "search", "none", 1, input_keys=input_keys)
    extra = {"settings": SettingsRow(mode=Mode.OBSERVE)} if observe else {}
    snap = snapshot(
        server=server_row(contract_status="managed" if managed else "none", last_observed_at=NOW),
        tool_contracts=(contract,),
        approvals=(approval(conditions=conditions or {}),),
        **extra,
    )
    h = harness(tmp_path, snap, evaluate=evaluator())
    if observe:
        h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    return asyncio.run(evaluate_request(request(arguments=arguments or {"q": "x"}), h.deps))


def codes(outcome):
    return [f.reason_code for f in outcome.snapshot.findings]


def test_unknown_input_keys_without_an_explicit_list_block_the_call(tmp_path):
    out = decide(tmp_path, input_keys=None)
    assert not out.allowed
    assert "CONTRACT_DRIFT_input_keys_unknown" in codes(out)
    assert out.error.code == "MINT-CONTRACT-DRIFT-input-keys-unknown"


def test_the_block_is_not_converted_in_observe_mode(tmp_path):
    assert not decide(tmp_path, input_keys=None, observe=True).allowed


def test_known_input_keys_keep_the_current_behavior(tmp_path):
    assert decide(tmp_path, input_keys=("q",)).allowed
    assert decide(tmp_path, input_keys=()).allowed


def test_an_explicit_key_list_in_the_approval_covers_unknown_input_keys(tmp_path):
    assert decide(tmp_path, input_keys=None, conditions={"allowed_arg_keys": ["q"]}).allowed


def test_a_secret_in_the_arguments_blocks_and_the_value_is_never_recorded(tmp_path):
    out = decide(tmp_path, input_keys=("q",), arguments={"q": f"key {AWS_KEY}"})
    assert not out.allowed
    assert codes(out) == ["POLICY_DETECT_POL-E-05"]
    assert out.error.code == "MINT-POLICY-DETECT-POL-E-05"
    assert out.snapshot.findings[0].detail == "input cloud_access_key=1"
    assert AWS_KEY not in repr(out.snapshot)


def test_nested_values_and_keys_are_scanned(tmp_path):
    out = decide(tmp_path, input_keys=("q",), arguments={"q": [{"a": ("x", AWS_KEY)}]})
    assert codes(out) == ["POLICY_DETECT_POL-E-05"]


def test_the_approval_can_allow_a_kind_for_its_tools(tmp_path):
    allow = {"allow_input_secrets": ["cloud_access_key"]}
    assert decide(tmp_path, input_keys=("q",), conditions=allow, arguments={"q": AWS_KEY}).allowed
    other = {"allow_input_secrets": ["jwt"]}
    blocked = decide(tmp_path, input_keys=("q",), conditions=other, arguments={"q": AWS_KEY})
    assert not blocked.allowed


def test_the_secret_block_is_not_converted_in_observe_mode(tmp_path):
    out = decide(tmp_path, input_keys=("q",), arguments={"q": AWS_KEY}, observe=True)
    assert not out.allowed


def test_ordinary_personal_data_and_unmanaged_servers_are_not_blocked(tmp_path):
    assert decide(tmp_path, input_keys=("q",), arguments={"q": "kim@corp.test.kr"}).allowed
    assert decide(tmp_path, input_keys=("q",), arguments={"q": AWS_KEY}, managed=False).allowed


def test_scan_arguments_counts_kinds_and_stops_at_the_depth_limit():
    assert scan_arguments({"a": [AWS_KEY, AWS_KEY]}) == {"cloud_access_key": 2}
    assert scan_arguments({"n": 4111111111111111}) == {"card_number": 1}
    deep: object = AWS_KEY
    for _ in range(30):
        deep = [deep]
    assert scan_arguments(deep) == {SCAN_LIMIT: 1}


def test_the_approval_condition_accepts_only_known_kinds():
    assert ALLOWABLE_INPUT_SECRETS == (INPUT_SECRET_KINDS - {SCAN_LIMIT}) | {"custom_marker"}
    kwargs = dict(
        high_risk_tools=None, business_hours_only=False, business_hours=None, require_consent=None
    )
    got = build_conditions(**kwargs, allow_input_secrets=["jwt", "jwt"])
    assert got == {"allow_input_secrets": ["jwt"]}
    try:
        build_conditions(**kwargs, allow_input_secrets=["email"])
    except Exception as exc:
        assert "allow-input-secret" in str(exc)
    else:
        raise AssertionError("unknown kind accepted")
