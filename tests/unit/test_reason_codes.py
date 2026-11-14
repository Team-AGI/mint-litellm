import pytest

from mint_litellm.types.reason_codes import (
    NON_CONVERTIBLE_REASONS,
    OBSERVATION_CANDIDATES,
    PARAMETERIZED_REASONS,
    Reason,
    is_observation_candidate,
    make_reason_code,
    parse_reason_code,
)

CONVERTIBLE = {
    "SERVER_UNREGISTERED",
    "SERVER_NOT_APPROVED",
    "APPROVAL_ABSENT",
    "TOOL_NOT_IN_APPROVAL",
    "POLICY_DETECT",
    "CONTRACT_DRIFT",
    "OUTPUT_SCAN",
}

NOT_CONVERTIBLE = {
    "SERVER_REJECTED",
    "SERVER_SUSPENDED",
    "SERVER_TERMINATED",
    "RELATION_TERMINATED",
    "DENIED",
    "APPROVAL_REVOKED",
    "APPROVAL_EXPIRED",
    "APPROVAL_RECERT_REQUIRED",
    "CALL_APPROVAL_REQUIRED",
    "CALL_APPROVAL_STALE",
    "CONSENT_REQUIRED",
    "CONSENT_EXPIRED",
    "CONSENT_REVOKED",
    "ALLOWLIST_EXPIRED",
    "SERVER_IDENTITY_MISMATCH",
    "SERVER_IDENTITY_AMBIGUOUS",
    "SERVER_UNRESOLVED",
    "MASTER_KEY_FORBIDDEN",
    "EXTERNAL_MCP_FORBIDDEN",
    "REALTIME_FORBIDDEN",
    "CODE_EXECUTION_FORBIDDEN",
    "TOKEN_FORWARD_FORBIDDEN",
    "RESOLVED_ADDRESS_FORBIDDEN",
    "TOKEN_AUDIENCE_MISMATCH",
    "UNSUPPORTED",
    "SCHEMA_ERROR",
    "POLICY_VERSION_MISMATCH",
    "DEPENDENCY_FAILURE",
    "AUDIT_FAILURE",
    "ORG_BOUNDARY",
    "ANONYMOUS",
    "ENFORCEMENT_UNVERIFIED",
    "CANCELLED",
    "CONFIRMATION_REQUIRED",
    "CONFIRMATION_STALE",
}


def test_classification_matches_the_published_split():
    assert {r.value for r in OBSERVATION_CANDIDATES} == CONVERTIBLE
    assert {r.value for r in NON_CONVERTIBLE_REASONS} == NOT_CONVERTIBLE
    assert CONVERTIBLE.isdisjoint(NOT_CONVERTIBLE)
    assert {r.value for r in Reason} == CONVERTIBLE | NOT_CONVERTIBLE


def test_only_candidate_families_take_a_qualifier():
    assert {r.value for r in PARAMETERIZED_REASONS} == {
        "POLICY_DETECT",
        "CONTRACT_DRIFT",
        "OUTPUT_SCAN",
    }
    assert PARAMETERIZED_REASONS <= OBSERVATION_CANDIDATES


@pytest.mark.parametrize(
    ("reason", "qualifier", "code"),
    [
        (Reason.POLICY_DETECT, "POL-E-07", "POLICY_DETECT_POL-E-07"),
        (Reason.CONTRACT_DRIFT, "schema", "CONTRACT_DRIFT_schema"),
        (Reason.OUTPUT_SCAN, "secret", "OUTPUT_SCAN_secret"),
        (Reason.DENIED, None, "DENIED"),
    ],
)
def test_make_and_parse_round_trip(reason, qualifier, code):
    assert make_reason_code(reason, qualifier) == code
    assert parse_reason_code(code) == (reason, qualifier)


@pytest.mark.parametrize(
    "call",
    [
        lambda: make_reason_code(Reason.POLICY_DETECT),
        lambda: make_reason_code(Reason.POLICY_DETECT, "has space"),
        lambda: make_reason_code(Reason.POLICY_DETECT, "x" * 65),
        lambda: make_reason_code(Reason.DENIED, "extra"),
        lambda: parse_reason_code("POLICY_DETECT"),
        lambda: parse_reason_code("POLICY_DETECT_"),
        lambda: parse_reason_code("POLICY_DETECT_a b"),
        lambda: parse_reason_code("NO_SUCH_REASON"),
        lambda: parse_reason_code("DENIED_extra"),
    ],
)
def test_invalid_codes_are_rejected(call):
    with pytest.raises(ValueError):
        call()


def test_observation_candidate_follows_the_family():
    assert is_observation_candidate("POLICY_DETECT_POL-R-01")
    assert is_observation_candidate("APPROVAL_ABSENT")
    assert not is_observation_candidate("APPROVAL_REVOKED")
    assert not is_observation_candidate("SERVER_IDENTITY_AMBIGUOUS")


@pytest.mark.parametrize("code", ["POLICY_DETECT_POL-E-07\n", "POLICY_DETECT_POL-E-07\r\n"])
def test_trailing_line_breaks_are_not_part_of_a_qualifier(code):
    with pytest.raises(ValueError):
        parse_reason_code(code)
    with pytest.raises(ValueError):
        make_reason_code(Reason.POLICY_DETECT, "POL-E-07\n")
