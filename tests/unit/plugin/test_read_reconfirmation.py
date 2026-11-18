"""Exact read reuse never substitutes for ordinary policy, scope or result checks."""

import asyncio
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from plugin_helpers import (
    FP_KEY,
    KEY,
    NOW,
    approval,
    call_approval,
    evaluator,
    harness,
    request,
    server_row,
    snapshot,
)
from test_plugin_confirmations import confirmation

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.snapshot import ToolContractRow
from mint_litellm.types.fingerprint import argument_fingerprint
from mint_litellm.types.reason_codes import Reason

ARGS = {"url": "https://docs.example/normal"}
FP = argument_fingerprint(ARGS, FP_KEY)
CONTRACT = str(uuid4())


def world(**changes):
    parent = approval(
        scope_type="user",
        scope_id="u1",
        conditions={"reuse_read_confirmations": True, "allowed_hosts": ["docs.example"]},
    )
    contract = ToolContractRow(
        CONTRACT,
        "server",
        "search",
        "none",
        1,
        risk_grade="low",
        action_type="read",
        input_keys=("url",),
    )
    return snapshot(
        server=server_row(contract_status="managed", approved_contracts=1, last_observed_at=NOW),
        approvals=(parent,),
        tool_contracts=(contract,),
        **changes,
    )


def proof(**changes):
    return {
        "event_id": str(uuid4()),
        "call_id": str(uuid4()),
        "confirmation_id": str(uuid4()),
        "approval_id": approval().id,
        "key_id": KEY,
        "org_id": "org1",
        "principal_id": "u1",
        "server_id": "srv-1",
        "tool": "search",
        "args_fp": FP,
        "fp_key_version": 1,
        "policy_version_id": "pv1",
        "contract_id": CONTRACT,
        "expires_at": (NOW + timedelta(days=1)).isoformat(),
        **changes,
    }


def run(tmp_path, snap, *, evaluate=None, arguments=None):
    h = harness(tmp_path, snap, evaluate=evaluate or evaluator())
    h.snapshots.calls = []
    h.snapshots.confirmations = []

    async def call(params):
        h.snapshots.calls.append(params)
        return str(params["id"])

    async def confirm(params):
        h.snapshots.confirmations.append(params)

    h.snapshots.request_call_approval = call
    h.snapshots.request_confirmation = confirm
    result = asyncio.run(evaluate_request(request(arguments=arguments or ARGS), h.deps))
    return h, result


def test_first_use_requires_admin_then_user_even_if_normal_policy_allows(tmp_path):
    h, result = run(tmp_path, world())
    assert not result.allowed and result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    assert len(h.snapshots.calls) == 1 and not h.snapshots.confirmations
    assert "재확인 재사용" in h.snapshots.calls[0]["display"]
    ca = call_approval(args_fp=FP, contract_id=CONTRACT)
    h, result = run(tmp_path / "second", world(call_approvals=(ca,)))
    assert not result.allowed and result.snapshot.stop.reason_code == Reason.CONFIRMATION_REQUIRED
    assert "재확인 재사용" in h.snapshots.confirmations[0]["display"]


def test_dual_checks_are_consumed_and_seed_scope_is_audited(tmp_path):
    ca = call_approval(args_fp=FP, contract_id=CONTRACT)
    sc = confirmation(args_fp=FP, contract_id=CONTRACT)
    h, result = run(tmp_path, world(call_approvals=(ca,), self_confirmations=(sc,)))
    assert result.allowed
    assert h.store.consumed[0].call_approval_id == ca.id
    assert h.store.consumed[0].confirmation.id == sc.id
    assert result.snapshot.read_reconfirmation_scope == approval().id
    assert result.snapshot.read_reconfirmation_proof_event_id is None


def test_exact_repeat_reuses_proof_but_still_requires_durable_audit(tmp_path):
    previous = proof()
    h, result = run(tmp_path, world(read_reconfirmations=(previous,)))
    assert result.allowed and not h.snapshots.calls and not h.snapshots.confirmations
    consume = h.store.consumed[0]
    assert consume.call_approval_id is None and consume.confirmation is None
    assert consume.read_reconfirmation.event_id == previous["event_id"]
    assert result.snapshot.read_reconfirmation_proof_event_id == previous["event_id"]
    assert len(h.store.events) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"approval_id": "different"},
        {"key_id": "other-key"},
        {"org_id": "other"},
        {"principal_id": "other"},
        {"server_id": "other"},
        {"tool": "other"},
        {"args_fp": "0" * 64},
        {"fp_key_version": 2},
        {"policy_version_id": "pv2"},
        {"contract_id": str(uuid4())},
        {"expires_at": NOW.isoformat()},
        {"expires_at": "invalid"},
    ],
)
def test_changed_or_expired_evidence_requires_new_checks(tmp_path, change):
    _, result = run(tmp_path, world(read_reconfirmations=(proof(**change),)))
    assert not result.allowed and result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED


@pytest.mark.parametrize(
    ("action", "grade"),
    [
        ("write", "low"),
        ("delete", "low"),
        ("external_send", "low"),
        ("credential_access", "low"),
        ("read", "medium"),
        ("read", "high"),
        ("read", "critical"),
    ],
)
def test_no_risk_or_action_downgrade(tmp_path, action, grade):
    snap = world(read_reconfirmations=(proof(),))
    snap = replace(
        snap,
        tool_contracts=(replace(snap.tool_contracts[0], action_type=action, risk_grade=grade),),
    )
    policy = evaluator("RequireApproval", policy_ids=("R2",))
    _, result = run(tmp_path, snap, evaluate=policy)
    assert not result.allowed and result.snapshot.read_reconfirmation_scope is None


def test_disabled_scope_does_not_activate_old_evidence(tmp_path):
    snap = world(read_reconfirmations=(proof(),))
    snap = replace(snap, approvals=(replace(snap.approvals[0], conditions={}),))
    _, result = run(tmp_path, snap, evaluate=evaluator("RequireApproval", policy_ids=("R2",)))
    assert not result.allowed and result.snapshot.read_reconfirmation_scope is None


def test_explicit_policy_block_is_not_bypassed_by_a_proof(tmp_path):
    h, result = run(
        tmp_path,
        world(read_reconfirmations=(proof(),)),
        evaluate=evaluator("Block", policy_ids=("POL-E-07",)),
    )
    assert not result.allowed and not h.store.consumed


def test_other_destination_and_path_cannot_reuse_evidence(tmp_path):
    for i, url in enumerate(("https://other.example/normal", "https://docs.example/other")):
        _, result = run(
            tmp_path / str(i),
            world(read_reconfirmations=(proof(),)),
            evaluate=evaluator("RequireApproval", policy_ids=("R2",)),
            arguments={"url": url},
        )
        assert not result.allowed


def test_consent_is_still_required_after_a_read_proof(tmp_path):
    _, result = run(
        tmp_path,
        world(read_reconfirmations=(proof(),)),
        evaluate=evaluator(obligations=({"type": "require_consent", "purpose": "business"},)),
    )
    assert not result.allowed and result.snapshot.stop.reason_code == Reason.CONSENT_REQUIRED


@pytest.mark.parametrize("lost", [False, True])
def test_reuse_never_allows_when_durable_proof_or_audit_write_fails(tmp_path, lost):
    h = harness(tmp_path, world(read_reconfirmations=(proof(),)), evaluate=evaluator())
    if lost:
        h.store.lose_consumption = True
    else:
        h.store.fail = RuntimeError("database unavailable")
    result = asyncio.run(evaluate_request(request(arguments=ARGS), h.deps))
    assert not result.allowed
    assert all(event.payload.get("enforced_action") != "allow"
               for event in h.store.events.values())
