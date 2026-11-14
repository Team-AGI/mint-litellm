"""관측한 도구 목록의 임시 계약·승인본이 호출별 추정보다 먼저 쓰이는 순서를 본다."""

import asyncio

from plugin_helpers import approval, evaluator, harness, request, server_row, snapshot

from mint_litellm.plugin.pipeline import evaluate_request, tool_traits
from mint_litellm.plugin.snapshot import ProvisionalRow, ToolContractRow

LOCAL = {"identity_kind": "stdio", "contract_status": "none"}


def row(**kw):
    return ToolContractRow("c1", "server", "query", "none", 1, "low", "read", ("sql",), **kw)


def traits(**snap):
    return tool_traits(snapshot(server=server_row(**LOCAL), **snap), "query", {"command": "x"})


def test_without_observation_the_call_is_inferred():
    assert traits() == ("exec", "high", True)


def test_the_stored_provisional_contract_beats_inference():
    prov = ProvisionalRow("read", "low", ("sql",))
    assert traits(provisional=prov) == ("read", "low", True)


def test_an_approved_observed_contract_beats_the_provisional_one_but_stays_provisional():
    prov = ProvisionalRow("write", "medium")
    assert traits(provisional=prov, tool_contracts=(row(),)) == ("read", "low", True)


def test_a_drifted_approved_contract_is_not_used():
    drifted = ToolContractRow("c1", "server", "query", "input_schema", 1, "low", "read")
    prov = ProvisionalRow("write", "medium")
    assert traits(provisional=prov, tool_contracts=(drifted,)) == ("write", "medium", True)


def test_schema_keys_become_the_default_allowed_arguments(tmp_path):
    calls = []
    snap = snapshot(
        approvals=(approval(tools=("query",)),),
        provisional=ProvisionalRow("read", "low", ("sql",)),
    )
    h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
    asyncio.run(evaluate_request(request(tool_name="query", arguments={"sql": "x"}), h.deps))
    assert calls[0]["approval"]["conditions"]["allowed_arg_keys"] == ["sql"]
    assert calls[0]["server"]["contract_status"] == "provisional"
