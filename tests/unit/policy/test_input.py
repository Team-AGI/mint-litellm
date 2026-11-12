from datetime import UTC, datetime, timedelta, timezone

import pytest

from mint_litellm.plugin.policy.input import policy_input
from mint_litellm.types.identity import Principal, PrincipalType, Provenance


def make_input(**overrides):
    principal = Principal(
        instance_id="i", principal_type=PrincipalType.USER, principal_id="u", key_id="k",
        org_id="o", org_source="user", provenance={"org_id": Provenance.DERIVED},
    )
    values = {
        "principal": principal,
        "server": {"id": "s", "credentials": "secret"},
        "tool": {"name": "read", "raw_arguments": "secret"},
        "argument_keys": ["message"],
        "argument_sizes": {"message": 6},
        "approval": {"present": False, "conditions": {"private": "secret"}},
        "consent": {"status": "not_applicable", "source": None},
        "now": datetime(1970, 1, 1, 9, tzinfo=timezone(timedelta(hours=9))),
        "high_risk_tools": ["write"],
        "mode": "enforce",
        "operation": "tool_call",
    }
    return policy_input(**(values | overrides))


def test_input_uses_summary_and_omits_unlisted_values():
    result = make_input()
    assert "secret" not in str(result)
    assert result["arguments"] == {"keys": ["message"], "sizes": {"message": 6}}
    assert result["approval"] == {"present": False}
    assert result["time"]["ns"] == 0


def test_input_keeps_selected_approval_conditions_and_consent():
    approval = {"present": True, "conditions": {"require_consent": "purpose"}}
    consent = {"status": "revoked", "source": "self_service"}
    result = make_input(approval=approval, consent=consent, now=datetime.now(UTC))
    assert result["approval"] == approval
    assert result["consent"] == consent


def test_input_rejects_naive_time_and_invalid_sizes():
    with pytest.raises(ValueError):
        make_input(now=datetime(1970, 1, 1))
    with pytest.raises(ValueError):
        make_input(argument_sizes={"x": -1})


def test_input_keeps_the_contract_grade_of_the_tool_and_the_engine_client_accepts_it():
    from mint_litellm.plugin.policy.input import has_only_policy_fields

    result = make_input(tool={"name": "read", "risk_grade": "high", "raw_arguments": "secret"})
    assert result["tool"] == {"name": "read", "risk_grade": "high"}
    assert has_only_policy_fields(result)


def test_input_keeps_the_identity_kind_and_execution_contract_of_the_server():
    from mint_litellm.plugin.policy.input import has_only_policy_fields

    server = {
        "id": "s", "identity_kind": "stdio", "exec_contract_sha256": "e" * 64,
        "exec_contract_version": 1, "url_sha256": "a" * 64, "credentials": "secret",
    }
    result = make_input(server=server)
    assert result["server"] == {
        "id": "s", "identity_kind": "stdio", "exec_contract_sha256": "e" * 64,
        "exec_contract_version": 1,
    }
    assert has_only_policy_fields(result)
