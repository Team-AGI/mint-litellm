"""직원에게 보이는 신청 단계·사유·다음 할 일. 영어 값이 나오지 않는다."""

import re

import pytest

from mint_litellm.endpoint import intake_text as text

CASES = [
    ({"status": "received"}, "received", None, text.NEXT_WAIT),
    ({"status": "checking", "pack_ready": False}, "pack", None, text.NEXT_WAIT),
    ({"status": "checking", "pack_ready": True}, "inspect", None, text.NEXT_WAIT),
    ({"status": "passed"}, "passed", None, text.NEXT_REVIEW),
    ({"status": "indeterminate", "reason_code": "INSPECTION_FAILED"}, "indeterminate",
     "검사 중 서버가 도구 목록을 내지 못했습니다", text.NEXT_REVIEW),
    ({"status": "indeterminate", "reason_code": "PACK_SDIST_ONLY"}, "indeterminate",
     "소스 배포본만 있어 묶을 수 없습니다", text.NEXT_VERSION),
    ({"status": "indeterminate", "reason_code": "PACK_INDEX_NOT_ALLOWED"}, "indeterminate",
     "이 패키지 저장소는 허용되지 않았습니다", text.NEXT_REVIEW),
    ({"status": "indeterminate", "reason_code": "SOMETHING_NEW"}, "indeterminate",
     text.UNKNOWN, text.NEXT_REVIEW),
    ({"status": "failed", "reason_code": "NAME_INVALID"}, "failed",
     "패키지 이름 형식이 맞지 않습니다", text.NEXT_FIX),
    ({"status": "decided", "decision": "approved"}, "approved", None, text.NEXT_NONE),
    ({"status": "decided", "decision": "rejected",
      "reason": "check_failed:exec_shape:NAME_INVALID"}, "rejected",
     "패키지 이름 형식이 맞지 않습니다", text.NEXT_VERSION),
    ({"status": "decided", "decision": "withdrawn", "reason": "다시 쓰겠습니다"}, "withdrawn",
     "다시 쓰겠습니다", text.NEXT_NONE),
]


@pytest.mark.parametrize(("row", "stage", "reason", "next_step"), CASES)
def test_stage_reason_and_next_step_are_plain_korean(row, stage, reason, next_step):
    assert text.stage_of(row) == stage
    assert text.reason_of(row) == reason
    assert text.next_of(row) == next_step
    assert re.search("[가-힣]", text.next_of(row))
    assert text.next_of(row) not in ("wait", "none")


def test_every_pack_and_inspection_code_has_a_staff_reason():
    for code in ("PACK_RESOLVE_FAILED", "PACK_SDIST_ONLY", "PACK_DIRECT_URL",
                 "PACK_DIGEST_MISMATCH", "PACK_ENTRY_NOT_FOUND", "PACK_TOO_LARGE",
                 "PACK_INDEX_NOT_ALLOWED", "PACK_UNAVAILABLE", "INSPECTION_FAILED",
                 "NO_DEFINITIONS", "INPUT_MISSING"):
        assert code in text.REASON


def test_a_package_inspected_on_first_run_waits_for_approval_not_failure():
    row = {"status": "indeterminate", "decision": None, "reason_code": "INSPECT_ON_FIRST_RUN"}
    assert text.stage_of(row) == "review"
    assert text.next_of(row) == "승인 뒤 PC 첫 실행 때 검사"
    assert text.reason_of(row) is None


def test_an_approved_request_whose_approvals_all_ended_reads_as_ended():
    """QA-BUG-009: 이용 종료 뒤 PC 신청 목록이 「승인」으로 남지 않는다."""
    from mint_litellm.endpoint import intake_text

    row = {"decision": "approved", "status": "decided", "ended": True}
    assert intake_text.stage_of(row) == "ended"
    assert intake_text.next_of(row) == intake_text.NEXT_ENDED
    assert intake_text.stage_of({**row, "ended": False}) == "approved"
