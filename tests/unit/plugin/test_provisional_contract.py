"""승인된 계약이 없는 서버의 임시 계약(추정 행위 유형·위험 등급)을 본다."""

import asyncio

import pytest
from plugin_helpers import approval, evaluator, harness, request, server_row, snapshot

from mint_litellm.plugin.pipeline import current_contract, evaluate_request
from mint_litellm.plugin.policy.provisional import infer


@pytest.mark.parametrize(
    ("name", "kind", "grade"),
    [
        ("decompile_function", "read", "low"),
        ("list_functions", "read", "low"),
        ("get_current_address", "read", "low"),
        ("rename_function", "write", "medium"),
        ("set_decompiler_comment", "write", "medium"),
        ("deleteFile", "delete", "high"),
        ("remove_label", "delete", "high"),
        ("drop_table", "delete", "high"),
        ("send_email", "external_send", "high"),
        ("upload_report", "external_send", "high"),
        ("post_webhook", "external_send", "high"),
        ("run_script", "exec", "high"),
        ("eval_expression", "exec", "high"),
        ("get_api_token", "credential_access", "critical"),
        ("frobnicate", "write", "medium"),
    ],
)
def test_name_table(name, kind, grade):
    assert tuple(infer(name)) == (kind, grade)


def test_a_command_argument_makes_an_innocent_name_exec():
    assert infer("query", keys=["command"]).action_type == "exec"
    assert infer("query", keys=["sql"]).action_type == "read"


def test_the_description_is_used_only_when_the_name_says_nothing():
    assert infer("x", "Removes the file. Does more.").action_type == "delete"
    assert infer("list_x", "Deletes everything").action_type == "read"


def sent(tmp_path, tool, arguments, conditions=None, server=None):
    calls = []
    snap = snapshot(
        server=server or server_row(),
        approvals=(approval(conditions=conditions or {}, tools=(tool,)),),
    )
    h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
    asyncio.run(evaluate_request(request(tool_name=tool, arguments=arguments), h.deps))
    return calls[0], snap


def test_an_unmanaged_server_sends_the_provisional_contract(tmp_path):
    doc, _ = sent(tmp_path, "delete_file", {"path": "a"})
    assert doc["server"]["contract_status"] == "provisional"
    assert doc["tool"] == {"name": "delete_file", "risk_grade": "high", "action_type": "delete"}
    assert "patterns" in doc["arguments"]


def test_a_provisional_delete_tool_needs_the_user_to_confirm(tmp_path):
    doc, _ = sent(tmp_path, "delete_file", {"path": "a"})
    assert doc["approval"]["conditions"]["require_user_confirmation"]["tools"] == ["delete_file"]


def test_a_provisional_read_tool_needs_no_confirmation(tmp_path):
    doc, _ = sent(tmp_path, "decompile_function", {"name": "main"})
    assert "require_user_confirmation" not in doc["approval"]["conditions"]


def test_a_provisional_contract_never_matches_approval_rules(tmp_path):
    _, snap = sent(tmp_path, "decompile_function", {"name": "main"})
    assert current_contract(snap, "decompile_function") is None


def test_a_managed_server_without_a_tool_contract_gets_no_guess(tmp_path):
    doc, _ = sent(tmp_path, "delete_file", {}, server=server_row(contract_status="managed"))
    assert doc["server"]["contract_status"] == "managed"
    assert "action_type" not in doc["tool"]
