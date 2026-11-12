"""서버 식별 방식(identity_kind)과 실행 계약 필드가 URL 칸과 따로 흐르는지 확인한다."""

import asyncio

import pytest
from plugin_helpers import evaluator, harness, request, resolved_server, server_row, snapshot
from pydantic import ValidationError

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.policy.input import has_only_policy_fields
from mint_litellm.types.decision import ResolvedServer

EXEC = "e" * 64


def stdio_resolved(**override):
    args = {
        "server_id": "srv-1",
        "identity_kind": "stdio",
        "exec_contract_sha256": EXEC,
        "exec_contract_version": 1,
        "transport": "stdio",
        "auth_type": "none",
        "candidates_with_same_name": 1,
    }
    return ResolvedServer(**(args | override))


def stdio_row(**override):
    args = {
        "identity_kind": "stdio",
        "url_sha256": None,
        "exec_contract_sha256": EXEC,
        "exec_contract_version": 1,
        "transport": "stdio",
    }
    return server_row(**(args | override))


def decide(h, **kw):
    return asyncio.run(evaluate_request(request(**kw), h.deps))


def test_a_remote_server_has_no_execution_contract_and_a_stdio_server_has_no_url_hash():
    assert resolved_server().identity_kind == "remote"
    assert stdio_resolved().url_sha256 is None
    for bad in (
        {"identity_kind": "stdio", "url_sha256": "a" * 64},
        {"identity_kind": "stdio", "exec_contract_sha256": None},
        {"identity_kind": "stdio", "exec_contract_version": None},
        {"identity_kind": "ftp"},
    ):
        with pytest.raises(ValidationError):
            stdio_resolved(**bad)
    with pytest.raises(ValidationError):
        ResolvedServer(
            server_id="s", url_sha256="a" * 64, exec_contract_sha256=EXEC,
            exec_contract_version=1, transport="http", auth_type="none",
            candidates_with_same_name=1,
        )
    with pytest.raises(ValidationError):
        ResolvedServer(
            server_id="s", transport="http", auth_type="none", candidates_with_same_name=1
        )


@pytest.mark.parametrize(
    "field,value",
    [("exec_contract_sha256", "f" * 64), ("exec_contract_version", 2),
     ("identity_kind", "remote"), ("transport", "http")],
)
def test_the_execution_contract_hash_and_version_both_decide_the_match(field, value):
    same = {
        "identity_kind": "stdio", "exec_contract_sha256": EXEC, "exec_contract_version": 1,
        "transport": "stdio", "auth_type": "none",
    }
    resolved = stdio_resolved()
    assert resolved.matches_contract(**same)
    assert not resolved.matches_contract(**(same | {field: value}))


def test_a_remote_server_never_matches_a_stdio_contract_and_the_reverse(tmp_path):
    remote_vs_stdio_row = snapshot(server=stdio_row())
    assert decide(harness(tmp_path, remote_vs_stdio_row)).error.code == (
        "MINT-SERVER-IDENTITY-MISMATCH"
    )
    stdio_vs_remote_row = snapshot(server=server_row())
    assert decide(harness(tmp_path, stdio_vs_remote_row), resolved=stdio_resolved()).error.code == (
        "MINT-SERVER-IDENTITY-MISMATCH"
    )
    changed = snapshot(server=stdio_row(exec_contract_sha256="f" * 64))
    assert decide(harness(tmp_path, changed), resolved=stdio_resolved()).error.code == (
        "MINT-SERVER-IDENTITY-MISMATCH"
    )


def test_a_stdio_call_carries_the_contract_to_the_policy_input_and_the_event(tmp_path):
    calls = []
    h = harness(tmp_path, snapshot(server=stdio_row()), evaluate=evaluator(calls=calls))
    outcome = decide(h, resolved=stdio_resolved())
    assert outcome.allowed, outcome.error
    server = calls[0]["server"]
    assert server["identity_kind"] == "stdio"
    assert (server["exec_contract_sha256"], server["exec_contract_version"]) == (EXEC, 1)
    assert "url_sha256" not in server
    assert has_only_policy_fields(calls[0])

    event = outcome.snapshot
    assert (event.resolved_identity_kind, event.resolved_exec_contract_sha256) == ("stdio", EXEC)
    assert event.resolved_exec_contract_version == 1
    # URL 해시는 자리 값이 아니라 비어 있고, 이유가 적힌다.
    assert event.resolved_url_sha256 is None
    assert event.missing_reasons["resolved_url_sha256"] == "not_applicable"


def test_a_remote_call_keeps_its_url_hash_and_sends_no_execution_contract(tmp_path):
    calls = []
    outcome = decide(harness(tmp_path, evaluate=evaluator(calls=calls)))
    assert outcome.allowed
    assert calls[0]["server"]["identity_kind"] == "remote"
    assert not {"exec_contract_sha256", "exec_contract_version"} & set(calls[0]["server"])
    event = outcome.snapshot
    assert event.resolved_url_sha256 == resolved_server().url_sha256
    assert event.resolved_identity_kind == "remote"
    assert event.resolved_exec_contract_sha256 is None
    assert "resolved_url_sha256" not in event.missing_reasons


def test_an_unresolved_server_still_reports_the_url_hash_as_unresolved(tmp_path):
    outcome = decide(harness(tmp_path), resolved=None)
    assert outcome.snapshot.missing_reasons["resolved_url_sha256"] == "server_unresolved"
    assert outcome.snapshot.resolved_identity_kind is None

