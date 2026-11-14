import json
import re

import pytest
from pydantic import ValidationError

from mint_litellm.types.errors import (
    BLOCK_STATUS_CODE,
    Dependency,
    DispatchState,
    MintError,
    cancelled_error,
    error_code,
    error_for_reason,
    output_blocked_error,
    record_failed_error,
)
from mint_litellm.types.reason_codes import PARAMETERIZED_REASONS, Reason

REF = "0192f7a0-7c1e-7a10-8000-0123456789ab"


@pytest.mark.parametrize(
    ("reason_code", "code"),
    [
        ("SERVER_NOT_APPROVED", "MINT-SERVER-NOT-APPROVED"),
        ("APPROVAL_REVOKED", "MINT-APPROVAL-REVOKED"),
        ("CALL_APPROVAL_STALE", "MINT-CALL-APPROVAL-STALE"),
        ("CONSENT_REQUIRED", "MINT-CONSENT-REQUIRED"),
        ("UNSUPPORTED", "MINT-UNSUPPORTED"),
        ("POLICY_DETECT_POL-E-07", "MINT-POLICY-DETECT-POL-E-07"),
        ("SERVER_IDENTITY_AMBIGUOUS", "MINT-SERVER-IDENTITY-AMBIGUOUS"),
    ],
)
def test_error_code_is_the_hyphenated_reason(reason_code, code):
    assert error_code(reason_code) == code


def test_error_code_rejects_unknown_reasons():
    with pytest.raises(ValueError):
        error_code("NOT_A_REASON")


def test_every_reason_maps_to_a_pre_dispatch_error():
    for reason in Reason:
        if reason is Reason.DEPENDENCY_FAILURE:
            continue
        code = reason.value + ("_X" if reason in PARAMETERIZED_REASONS else "")
        err = error_for_reason(code, REF)
        assert re.fullmatch(r"MINT-[A-Z0-9-]+", err.code)
        assert err.dispatch_state is DispatchState.NOT_DISPATCHED
        # 전송 전에 취소된 호출과 호출별 승인 대기(승인 뒤 같은 호출 재요청)만 다시 보내도 안전하다.
        assert err.retry_safe is (
            reason in (Reason.CANCELLED, Reason.CALL_APPROVAL_REQUIRED, Reason.CALL_APPROVAL_STALE)
        )
        assert err.reference == REF


def test_a_cancel_before_dispatch_is_the_same_error_from_either_constructor():
    assert error_for_reason("CANCELLED", REF) == cancelled_error(REF, dispatched=False)
    assert error_for_reason("CANCELLED", REF).retry_safe is True


@pytest.mark.parametrize(
    ("dependency", "code"),
    [(Dependency.DB, "MINT-DEPENDENCY-DB"), (Dependency.OPA, "MINT-DEPENDENCY-OPA")],
)
def test_dependency_failure_is_retry_safe_before_dispatch(dependency, code):
    err = error_for_reason("DEPENDENCY_FAILURE", REF, dependency)
    assert err.code == code
    assert err.dispatch_state is DispatchState.NOT_DISPATCHED
    assert err.retry_safe is True


def test_dependency_failure_requires_the_component():
    with pytest.raises(ValueError):
        error_for_reason("DEPENDENCY_FAILURE", REF)


def test_post_dispatch_errors_are_never_retry_safe():
    failed = record_failed_error(REF)
    assert (failed.code, failed.dispatch_state, failed.retry_safe) == (
        "MINT-RECORD-FAILED",
        DispatchState.DISPATCHED_UNKNOWN,
        False,
    )
    blocked = output_blocked_error(REF)
    assert (blocked.code, blocked.dispatch_state, blocked.retry_safe) == (
        "MINT-OUTPUT-BLOCKED",
        DispatchState.DISPATCHED_COMPLETED,
        False,
    )


def test_cancellation_is_retry_safe_only_before_dispatch():
    before = cancelled_error(REF, dispatched=False)
    after = cancelled_error(REF, dispatched=True)
    assert (before.dispatch_state, before.retry_safe) == (DispatchState.NOT_DISPATCHED, True)
    assert (after.dispatch_state, after.retry_safe) == (DispatchState.DISPATCHED_UNKNOWN, False)
    assert before.code == after.code == "MINT-CANCELLED"


@pytest.mark.parametrize(
    "state", [DispatchState.DISPATCHED_UNKNOWN, DispatchState.DISPATCHED_COMPLETED]
)
def test_retry_safe_cannot_be_claimed_after_dispatch(state):
    with pytest.raises(ValidationError):
        MintError(code="MINT-X", dispatch_state=state, retry_safe=True, reference=REF)


def test_code_must_carry_the_product_prefix():
    with pytest.raises(ValidationError):
        MintError(
            code="DENIED",
            dispatch_state=DispatchState.NOT_DISPATCHED,
            retry_safe=False,
            reference=REF,
        )


def test_block_response_is_a_403_with_a_json_string_detail():
    block = error_for_reason("DENIED", REF).as_block()
    assert block.status_code == BLOCK_STATUS_CODE == 403
    assert isinstance(block.detail, str)
    parsed = json.loads(block.detail)
    assert list(parsed) == ["code", "dispatch_state", "retry_safe", "reference"]
    assert parsed == {
        "code": "MINT-DENIED",
        "dispatch_state": "not_dispatched",
        "retry_safe": False,
        "reference": REF,
    }


def test_detail_round_trips():
    err = error_for_reason("DEPENDENCY_FAILURE", REF, Dependency.OPA)
    assert MintError.from_detail(err.detail()) == err


def test_detail_survives_the_streamable_http_error_text():
    text = "Error: " + error_for_reason("CONSENT_REQUIRED", REF).detail()
    start = text.index("{")
    assert MintError.from_detail(text[start:]).code == "MINT-CONSENT-REQUIRED"


@pytest.mark.parametrize("reason", ["CALL_APPROVAL_REQUIRED", "CALL_APPROVAL_STALE"])
def test_a_call_approval_wait_tells_the_agent_to_ask_again_after_approval(reason):
    err = error_for_reason(reason, REF)
    assert (err.dispatch_state, err.retry_safe) == (DispatchState.NOT_DISPATCHED, True)
    assert "승인된 뒤 같은 작업을 다시 요청하십시오" in json.loads(err.detail())["guidance"]
    assert MintError.from_detail(err.detail()) == err
    # 다른 차단에는 안내 문구가 없다.
    assert "guidance" not in json.loads(error_for_reason("CONSENT_REQUIRED", REF).detail())
