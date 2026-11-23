import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest
from plugin_helpers import (
    KEY,
    NOW,
    approval,
    evaluator,
    harness,
    request,
    server_row,
    snapshot,
    user_principal,
)

from mint_litellm.plugin.pipeline import contract_result, evaluate_request
from mint_litellm.plugin.snapshot import RelationRow, SettingsRow, ToolContractRow
from mint_litellm.types.decision import OperationType, SkippedStage, Stage
from mint_litellm.types.identity import Principal, PrincipalType
from mint_litellm.types.settings import Mode


def managed(**overrides):
    values = dict(
        server=server_row(contract_status="managed", last_observed_at=NOW),
        tool_contracts=(ToolContractRow("c1", "server", "search", "none", 1, input_keys=()),),
    )
    values.update(overrides)
    return snapshot(**values)


@pytest.mark.parametrize(
    "change,reason",
    [
        (
            {"tool_contracts": (ToolContractRow("c", "server", "search", "input_schema", 1),)},
            "input_schema",
        ),
        (  # 승인 뒤 설명·annotations 변경(러그 풀)도 재승인 전까지 막는다
            {"tool_contracts": (ToolContractRow("c", "server", "search", "description", 1),)},
            "description",
        ),
        (
            {
                "server": server_row(
                    contract_status="managed", deployment_drift=True, last_observed_at=NOW
                )
            },
            "deployment",
        ),
        ({"server": server_row(contract_status="managed")}, "unobserved"),
        (
            {
                "server": server_row(
                    contract_status="managed", last_observed_at=NOW - timedelta(seconds=121)
                )
            },
            "unobserved",
        ),
    ],
)
def test_contract_blocks_each_drift(tmp_path, change, reason):
    h = harness(tmp_path, managed(**change))
    h.deps.config = replace(h.deps.config, observe_seconds=60)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert not result.allowed
    assert f"CONTRACT_DRIFT_{reason}" in [f.reason_code for f in result.snapshot.findings]


def test_a_new_tool_on_an_approved_server_is_allowed(tmp_path):
    h = harness(tmp_path, managed(tool_contracts=()))
    h.deps.config = replace(h.deps.config, observe_seconds=60)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert "CONTRACT_DRIFT_unapproved_tool" not in [
        f.reason_code for f in result.snapshot.findings]
    assert contract_result(managed(tool_contracts=()), "search", 60).reason_code is None


def test_observation_deadline_boundary_and_legacy():
    snap = managed(
        server=server_row(contract_status="managed", last_observed_at=NOW - timedelta(seconds=120))
    )
    assert contract_result(snap, "search", 60).reason_code is None
    assert isinstance(contract_result(snapshot(), "search", 60), SkippedStage)


@pytest.mark.parametrize("auth", ["oauth_delegate", "true_passthrough"])
def test_scope_does_not_fall_back(auth):
    snap = managed(
        server=server_row(contract_status="managed", auth_type=auth, last_observed_at=NOW)
    )
    # 다른 자격 범위의 계약은 이 서버의 계약으로 보지 않는다(그 계약의 드리프트도 옮겨 오지 않는다)
    stray = (ToolContractRow("c", "server", "search", "description", 2),)
    other = replace(snap, tool_contracts=stray)
    assert contract_result(other, "search", 60).reason_code is None
    snap = replace(snap, tool_contracts=(ToolContractRow("c", "per_user", "search", "none", 2),))
    assert contract_result(snap, "search", 60).reason_code is None


def test_oauth2_uses_the_server_scope():
    from mint_litellm.types.canonical import credential_scope

    assert credential_scope("oauth2") == "server"
    assert credential_scope("oauth_delegate") == "per_user"


def test_contract_findings_convert_as_family(tmp_path):
    drifted = (ToolContractRow("c", "server", "search", "description", 1, input_keys=()),)
    h = harness(tmp_path, managed(tool_contracts=drifted, settings=SettingsRow(mode=Mode.OBSERVE)))
    h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.allowed
    assert result.snapshot.findings[0].reason_code == "CONTRACT_DRIFT_description"


def test_output_change_is_alert_only(tmp_path):
    for drift in ("none", "output_schema"):
        contract = ToolContractRow("c", "server", "search", drift, 1, input_keys=())
        h = harness(tmp_path, managed(tool_contracts=(contract,)))
        assert asyncio.run(evaluate_request(request(), h.deps)).allowed


def test_control_first_activation_lists_without_events(tmp_path):
    h = harness(
        tmp_path,
        managed(
            server=server_row(contract_status="managed", status="awaiting_approval"),
            approvals=(),
            tool_contracts=(),
            settings=SettingsRow(control_key_token=KEY),
        ),
        evaluate=evaluator("Block"),
    )
    result = asyncio.run(
        evaluate_request(request(operation=OperationType.RUNTIME_DISCOVERY), h.deps)
    )
    assert result.allowed
    assert not h.store.events


@pytest.mark.parametrize("status", ["rejected", "suspended", "terminating", "terminated"])
def test_control_negative_server_still_hides(tmp_path, status):
    h = harness(
        tmp_path,
        managed(
            server=server_row(status=status, contract_status="managed"),
            settings=SettingsRow(control_key_token=KEY),
        ),
    )
    assert not asyncio.run(
        evaluate_request(request(operation=OperationType.RUNTIME_DISCOVERY), h.deps)
    ).allowed


@pytest.mark.parametrize(
    "change",
    [
        {"relations": {"r1": RelationRow("r1", "terminating")}},
        {"negative_relation": True},
    ],
)
def test_control_negative_relationship(tmp_path, change):
    h = harness(tmp_path, managed(settings=SettingsRow(control_key_token=KEY), **change))
    assert not asyncio.run(
        evaluate_request(request(operation=OperationType.RUNTIME_DISCOVERY), h.deps)
    ).allowed


def test_control_call_never_exempt(tmp_path):
    h = harness(tmp_path, managed(settings=SettingsRow(control_key_token=KEY)))
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert not result.allowed
    assert result.snapshot.stop.reason_code == "ENFORCEMENT_UNVERIFIED"
    assert result.snapshot.stop.detail == "control_key_call"
    assert next(iter(h.store.events.values())).payload["cause"] == "control_key_call"


@pytest.mark.parametrize("token", [None, KEY + "x"])
def test_control_both_tokens_must_match(tmp_path, token):
    h = harness(tmp_path, managed(approvals=(), settings=SettingsRow(control_key_token=token)))
    assert not asyncio.run(
        evaluate_request(request(operation=OperationType.RUNTIME_DISCOVERY), h.deps)
    ).allowed


def test_control_anonymous_and_master_are_never_exempt(tmp_path):
    for principal in (
        Principal(instance_id="inst", principal_type=PrincipalType.ANONYMOUS),
        Principal(
            instance_id="inst",
            principal_type=PrincipalType.MASTER_KEY,
            principal_id=KEY,
            key_id=KEY,
        ),
    ):
        h = harness(tmp_path, managed(settings=SettingsRow(control_key_token=KEY)))
        result = asyncio.run(
            evaluate_request(request(principal, operation=OperationType.RUNTIME_DISCOVERY), h.deps)
        )
        assert not result.allowed


def test_legacy_tool_call_and_discovery_are_unchanged(tmp_path):
    h = harness(tmp_path, snapshot(approvals=(approval(),)))
    result = asyncio.run(evaluate_request(request(user_principal()), h.deps))
    assert result.allowed
    contract = next(s for s in result.snapshot.stages if s.stage == Stage.CONTRACT)
    assert contract.missing_reason == "unsupported_stage"


@pytest.mark.parametrize(
    "server_changes,contracts,reason",
    [
        ({"pin_blocked": True, "deployment_drift": True}, None, "pin"),
        ({"pin_blocked": True}, (), "pin"),  # 도구 계약이 없어도 고정 사유가 우선이다
        ({"approved_contracts": 0}, (), "no_contract"),
    ],
)
def test_pin_safety_blocks_cannot_be_relaxed_by_observe_mode(
    tmp_path, server_changes, contracts, reason
):
    """고정 불일치·해제 미완료·승인 계약 0개는 CONTRACT_DRIFT를 관측으로 설정해도 막는다."""
    values = {"settings": SettingsRow(mode=Mode.OBSERVE)}
    if contracts is not None:
        values["tool_contracts"] = contracts
    snap = managed(
        server=server_row(contract_status="managed", last_observed_at=NOW, **server_changes),
        **values,
    )
    h = harness(tmp_path, snap)
    h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert not result.allowed
    assert f"CONTRACT_DRIFT_{reason}" in [f.reason_code for f in result.snapshot.findings]


def test_other_drift_kinds_still_convert_in_observe_mode(tmp_path):
    """고정 사유가 아닌 계약 사유(배포 변경 등)는 지금처럼 관측 모드에서 허용으로 전환된다."""
    snap = managed(
        server=server_row(
            contract_status="managed", last_observed_at=NOW, deployment_drift=True,
            approved_contracts=1,
        ),
        settings=SettingsRow(mode=Mode.OBSERVE),
    )
    h = harness(tmp_path, snap)
    h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    assert asyncio.run(evaluate_request(request(), h.deps)).allowed
