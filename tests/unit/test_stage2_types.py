"""2단계 타입 계약: 1단계 값은 그대로이고 추가분만 늘었는지 확인한다."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from mint_litellm.plugin.obligations import (
    SUPPORTED_OBLIGATIONS,
    RequireUserConfirmation,
    compose_obligations,
)
from mint_litellm.types.contracts import (
    ActionType,
    DataGrade,
    RiskGrade,
    risk_grade,
)
from mint_litellm.types.decision import ObligationType
from mint_litellm.types.errors import DispatchState, error_for_reason
from mint_litellm.types.events import (
    CALL_KINDS,
    CONTROL_ENTITY,
    SYSTEM_KINDS,
    Event,
    EventKind,
    control_source_key,
)
from mint_litellm.types.jobs import (
    alert_deliver_job_key,
    export_negative_job_key,
    intake_run_job_key,
    scheduled_job_key,
)
from mint_litellm.types.reason_codes import (
    NON_CONVERTIBLE_REASONS,
    OBSERVATION_CANDIDATES,
    ContractDriftKind,
    Reason,
    contract_drift_code,
    is_observation_candidate,
    parse_reason_code,
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)

STAGE_ONE_EVENTS = {
    "decision_evaluated", "discovery_evaluated", "call_response_received", "call_outcome_unknown",
    "enforcement_unverified", "enforcement_verified", "server_identity_mismatch_observed",
    "buffer_overflow", "buffer_replayed",
    "server_registered", "server_approved", "server_suspended", "server_resumed",
    "relation_created", "relation_terminating", "approval_granted", "approval_revoked",
    "denial_created", "denial_lifted", "call_approval_requested", "call_approval_approved",
    "call_approval_rejected", "call_approval_cancelled", "consent_granted", "consent_revoked",
    "allowlist_added", "allowlist_lifted", "org_created", "org_closed", "org_binding_created",
    "org_binding_removed", "policy_activated", "settings_changed", "operator_added",
}  # fmt: skip

STAGE_TWO_EVENTS = {
    "relation_terminated", "evidence_attached", "server_terminating", "server_terminated",
    "operator_removed", "operator_role_changed",
    "intake_received", "intake_requester_assigned", "intake_checked", "intake_decided",
    "contract_approved", "contract_drift_detected", "contract_superseded", "reapproval_requested",
    "sync_applied", "sync_held", "export_written", "export_failed", "restore_blocked",
    "restore_attested", "restore_stale_accepted", "alert_opened", "alert_acknowledged",
    "alert_resolved", "console_session_started", "console_session_ended",
    "deployment_contract_approved", "deployment_drift_detected",
    "deployment_contract_superseded",
    "approval_recert_requested", "approval_held", "approval_recert_confirmed",
    "policy_shadow_set", "policy_shadow_cleared",
    "event_partition_exported", "event_partition_dropped",
    "endpoint_remediated",
}  # fmt: skip

STAGE_ONE_REASONS = {
    "SERVER_UNREGISTERED", "SERVER_NOT_APPROVED", "APPROVAL_ABSENT", "TOOL_NOT_IN_APPROVAL",
    "POLICY_DETECT", "CONTRACT_DRIFT", "OUTPUT_SCAN", "SERVER_REJECTED", "SERVER_SUSPENDED",
    "SERVER_TERMINATED", "RELATION_TERMINATED", "DENIED", "APPROVAL_REVOKED", "APPROVAL_EXPIRED",
    "CALL_APPROVAL_REQUIRED", "CALL_APPROVAL_STALE", "CONSENT_REQUIRED", "CONSENT_EXPIRED",
    "CONSENT_REVOKED", "ALLOWLIST_EXPIRED", "SERVER_IDENTITY_MISMATCH",
    "SERVER_IDENTITY_AMBIGUOUS", "SERVER_UNRESOLVED", "MASTER_KEY_FORBIDDEN", "UNSUPPORTED",
    "SCHEMA_ERROR", "POLICY_VERSION_MISMATCH", "DEPENDENCY_FAILURE", "AUDIT_FAILURE",
    "ORG_BOUNDARY", "ANONYMOUS", "ENFORCEMENT_UNVERIFIED", "CANCELLED",
}  # fmt: skip


def test_event_kinds_are_the_stage_one_set_plus_exactly_the_stage_two_additions():
    assert len(STAGE_ONE_EVENTS) == 34 and len(STAGE_TWO_EVENTS) == 37
    assert {k.value for k in EventKind} == STAGE_ONE_EVENTS | STAGE_TWO_EVENTS
    assert {k.value for k in CALL_KINDS} | {k.value for k in SYSTEM_KINDS} <= STAGE_ONE_EVENTS


def test_every_event_kind_has_a_key_entity_and_the_new_entities_are_the_declared_ones():
    for kind in EventKind:
        if kind not in CALL_KINDS:
            assert kind in CONTROL_ENTITY, kind
    new = {CONTROL_ENTITY[EventKind(k)] for k in STAGE_TWO_EVENTS}
    assert new == {
        "intake", "intake_check", "tool_contract", "deployment_contract", "litellm_grant",
        "export", "restore", "alert", "console_session", "operator", "evidence", "relation",
        "approval", "server", "policy_shadow", "event_partition", "endpoint",
    }  # fmt: skip


@pytest.mark.parametrize("kind", sorted(STAGE_TWO_EVENTS))
def test_stage_two_events_pass_the_unchanged_event_validation(kind):
    event_kind = EventKind(kind)
    key = control_source_key(event_kind, "0192f7a0-7c1e-7a10-8000-0123456789ab", 3)
    assert key.endswith(f":3:{kind}")
    event = Event(
        instance_id="i", inserted_at=NOW, kind=event_kind, source_key=key, actor="alice", payload={}
    )
    assert Event.from_json_line(event.to_json_line()) == event


def test_a_key_of_another_entity_is_rejected_and_the_given_forms_are_built():
    with pytest.raises(ValidationError):
        Event(
            instance_id="i", inserted_at=NOW, kind=EventKind.EXPORT_WRITTEN,
            source_key=control_source_key(EventKind.ALERT_OPENED, "a1", 1),
            actor="alice", payload={},
        )  # fmt: skip
    assert control_source_key(EventKind.RESTORE_BLOCKED, "42", 1) == "restore:42:1:restore_blocked"
    assert (
        control_source_key(EventKind.INTAKE_CHECKED, "chk-1", 2)
        == "intake_check:chk-1:2:intake_checked"
    )


def test_server_identity_mismatch_keeps_the_selfcheck_key():
    key = control_source_key(EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED, "run1", 2)
    assert key == "selfcheck:run1:2:server_identity_mismatch_observed"


def test_reasons_are_the_stage_one_set_plus_the_later_additions():
    assert {r.value for r in Reason} == STAGE_ONE_REASONS | {
        "CONFIRMATION_REQUIRED",
        "CONFIRMATION_STALE",
        "EXTERNAL_MCP_FORBIDDEN",
        "REALTIME_FORBIDDEN",
        "CODE_EXECUTION_FORBIDDEN",
        "TOKEN_FORWARD_FORBIDDEN",
        "APPROVAL_RECERT_REQUIRED",
    }
    later = ("CONFIRMATION_REQUIRED", "CONFIRMATION_STALE", "EXTERNAL_MCP_FORBIDDEN")
    for code in (*later, "REALTIME_FORBIDDEN", "CODE_EXECUTION_FORBIDDEN"):
        assert Reason(code) in NON_CONVERTIBLE_REASONS
        assert not is_observation_candidate(code)
        error = error_for_reason(code, "ref-1")
        assert error.code == "MINT-" + code.replace("_", "-")
        assert error.dispatch_state is DispatchState.NOT_DISPATCHED
        assert error.retry_safe is False
    assert {r.value for r in OBSERVATION_CANDIDATES} <= STAGE_ONE_REASONS


@pytest.mark.parametrize("kind", ["input_schema", "deployment", "unobserved", "unapproved_tool"])
def test_contract_drift_codes_stay_in_the_observation_family(kind):
    code = contract_drift_code(ContractDriftKind(kind))
    assert code == f"CONTRACT_DRIFT_{kind}"
    assert parse_reason_code(code) == (Reason.CONTRACT_DRIFT, kind)
    assert is_observation_candidate(code)


def test_the_fourth_obligation_is_accepted_by_the_pipeline():
    assert ObligationType.REQUIRE_USER_CONFIRMATION.value == "require_user_confirmation"
    assert ObligationType.REQUIRE_USER_CONFIRMATION in SUPPORTED_OBLIGATIONS
    item = RequireUserConfirmation(purpose="transfer", display_fields=("amount", "to"))
    assert item.display_fields == ("amount", "to")
    with pytest.raises(ValidationError):
        RequireUserConfirmation(purpose=" ")
    out = compose_obligations([{"type": "require_user_confirmation", "purpose": "p"}])
    assert out.failure is None and out.obligations == (RequireUserConfirmation(purpose="p"),)


@pytest.mark.parametrize(
    ("data", "action", "irreversible", "expected"),
    [
        (DataGrade.PUBLIC, ActionType.READ, False, RiskGrade.LOW),
        (DataGrade.INTERNAL, ActionType.READ, False, RiskGrade.MEDIUM),
        (DataGrade.PUBLIC, ActionType.WRITE, False, RiskGrade.MEDIUM),
        (DataGrade.PUBLIC, ActionType.DELETE, False, RiskGrade.HIGH),
        (DataGrade.CONFIDENTIAL, ActionType.EXTERNAL_SEND, False, RiskGrade.HIGH),
        (DataGrade.PUBLIC, ActionType.READ, True, RiskGrade.MEDIUM),
        (DataGrade.PUBLIC, ActionType.CREDENTIAL_ACCESS, False, RiskGrade.CRITICAL),
        (DataGrade.RESTRICTED, ActionType.READ, False, RiskGrade.CRITICAL),
        (DataGrade.RESTRICTED, ActionType.CREDENTIAL_ACCESS, True, RiskGrade.CRITICAL),
        (DataGrade.INTERNAL, ActionType.WRITE, True, RiskGrade.HIGH),
    ],
)
def test_risk_grade_table(data, action, irreversible, expected):
    assert risk_grade(data, action, irreversible=irreversible) is expected


def test_risk_values_match_the_column_checks():
    assert {g.value for g in RiskGrade} == {"low", "medium", "high", "critical"}
    assert {a.value for a in ActionType} == {
        "read", "write", "delete", "external_send", "credential_access",
    }  # fmt: skip
    assert {d.value for d in DataGrade} == {"public", "internal", "confidential", "restricted"}


def test_job_key_formats():
    start = datetime(2030, 1, 2, 3, 4, 0, tzinfo=timezone(timedelta(hours=9)))
    assert scheduled_job_key("seal", start) == "seal:2030-01-01T18:04:00Z"
    assert export_negative_job_key(7) == "export_negative:7"
    delivery = UUID("0192f7a0-7c1e-7a10-8000-0123456789ab")
    assert alert_deliver_job_key(delivery) == f"alert_deliver:{delivery}"
    assert intake_run_job_key(delivery, 2) == f"intake_run:{delivery}:2"
    for bad in (
        lambda: scheduled_job_key("Seal", NOW),
        lambda: scheduled_job_key("seal", datetime(2030, 1, 1)),
        lambda: export_negative_job_key(-1),
        lambda: intake_run_job_key(delivery, 0),
    ):
        with pytest.raises(ValueError):
            bad()
