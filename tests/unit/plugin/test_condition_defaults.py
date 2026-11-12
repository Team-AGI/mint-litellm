"""승인에 적히지 않은 집행 조건을 MINT가 정책 입력에 채우는지 본다."""

import asyncio

from plugin_helpers import NOW, approval, evaluator, harness, request, server_row, snapshot

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.policy.defaults import (
    CONFIRM_PURPOSE,
    CONSENT_FALLBACK,
    effective_conditions,
)
from mint_litellm.plugin.snapshot import RelationRow, ToolContractRow

SERVER = server_row(contract_status="managed", last_observed_at=NOW)


def sent(tmp_path, *, contract, conditions=None, **extra):
    calls = []
    snap = snapshot(
        server=SERVER,
        tool_contracts=(contract,),
        approvals=(approval(conditions=conditions or {}),),
        **extra,
    )
    h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
    asyncio.run(evaluate_request(request(arguments={"q": "x"}), h.deps))
    return calls[0]


def contract(**kw):
    return ToolContractRow("c1", "server", "search", "none", 1, **kw)


def test_the_allowed_keys_default_to_the_contract_input_definition(tmp_path):
    doc = sent(tmp_path, contract=contract(input_keys=("q", "limit")))
    assert doc["approval"]["conditions"]["allowed_arg_keys"] == ["limit", "q"]
    assert doc["tool"].get("action_type") is None


def test_an_empty_input_definition_allows_no_key(tmp_path):
    doc = sent(tmp_path, contract=contract(input_keys=()))
    assert doc["approval"]["conditions"]["allowed_arg_keys"] == []


def test_an_unknown_input_definition_adds_no_default(tmp_path):
    doc = sent(tmp_path, contract=contract())
    assert "allowed_arg_keys" not in doc["approval"]["conditions"]


def test_allowed_keys_written_in_the_approval_are_kept(tmp_path):
    doc = sent(
        tmp_path, contract=contract(input_keys=("q", "limit")),
        conditions={"allowed_arg_keys": ["q"]},
    )
    assert doc["approval"]["conditions"]["allowed_arg_keys"] == ["q"]


def test_a_delete_tool_always_needs_the_user_to_confirm(tmp_path):
    doc = sent(tmp_path, contract=contract(action_type="delete"))
    assert doc["tool"]["action_type"] == "delete"
    assert doc["approval"]["conditions"]["require_user_confirmation"] == {
        "tools": ["search"], "purpose": CONFIRM_PURPOSE, "display_fields": [],
    }


def test_a_read_tool_needs_no_confirmation(tmp_path):
    doc = sent(tmp_path, contract=contract(action_type="read"))
    assert "require_user_confirmation" not in doc["approval"]["conditions"]


def test_a_confidential_server_requires_consent_for_its_use_purpose(tmp_path):
    relation = RelationRow(id="r1", status="active", purpose="환자 상담 정리")
    doc = sent(tmp_path, contract=contract(), data_grade="confidential", relations={"r1": relation})
    assert doc["approval"]["conditions"]["require_consent"] == "환자 상담 정리"
    assert doc["consent"]["status"] == "absent"


def test_a_public_server_needs_no_consent(tmp_path):
    doc = sent(tmp_path, contract=contract(), data_grade="public")
    assert "require_consent" not in doc["approval"]["conditions"]
    assert doc["consent"]["status"] == "not_applicable"


def test_the_pure_function_never_changes_what_the_approval_wrote():
    base = {"require_consent": "내 목적", "require_user_confirmation": {
        "tools": ["other"], "purpose": "직접", "display_fields": ["to"]}}
    result = effective_conditions(
        base, tool="send", action_type="external_send", input_keys=None,
        data_grade="restricted", purpose="무시됨",
    )
    assert result["require_consent"] == "내 목적"
    assert result["require_user_confirmation"] == {
        "tools": ["other", "send"], "purpose": "직접", "display_fields": ["to"]}
    assert base["require_user_confirmation"]["tools"] == ["other"]


def test_a_long_or_missing_purpose_still_gives_a_valid_consent_purpose():
    long = effective_conditions({}, tool="t", action_type=None, input_keys=None,
                                data_grade="restricted", purpose="가" * 300)
    assert len(long["require_consent"]) == 128
    none = effective_conditions({}, tool="t", action_type=None, input_keys=None,
                                data_grade="restricted", purpose=None)
    assert none["require_consent"] == CONSENT_FALLBACK
