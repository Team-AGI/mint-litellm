"""7. URL 선행 차단, 검사 상한, 직무 분리와 증거 만료."""

import pytest


@pytest.mark.parametrize("case", ["provider_denied", "private_literal", "allow_all_keys",
                                     "definitions_limit", "same_requester", "stale_evidence",
                                     "credentials_required", "private_ip_guard"])
def test_negative_intake(rig, case):
    rig.require("intake create", "intake approve", "intake except", handlers=("intake_run",))
    rig.fault("intake_" + case)
    observation = rig.read_observation("intake_" + case)
    rig.check_observation("intake_" + case, observation)
    if case == "private_literal":  # 신청이 없다: LiteLLM 거절만 본다
        return
    intake = rig.rows("intakes", "id=%s", [observation["intake_id"]])[0]
    if case in ("provider_denied", "allow_all_keys", "private_ip_guard"):
        assert intake["decision"] == "rejected"
        assert rig.rows("intake_checks", "intake_id=%s AND result='fail'", [intake["id"]])
    if case == "credentials_required":
        assert intake["needs_registry_credentials"] is True
        checks = rig.rows("intake_checks", "intake_id=%s AND reason_code='CREDENTIALS_REQUIRED'",
                          [intake["id"]])
        assert checks
    if case in ("same_requester", "stale_evidence"):
        # 같은 사용자(신청자)이거나 오래된 증거이면 CLI 결정이 거부되어야 한다.
        word = "신청자" if case == "same_requester" else "24시간"
        done = rig.cli("intake", "approve", str(intake["id"]), "--reason", "acceptance",
                       role="admin" if case == "same_requester" else "approver", check=False)
        assert done.returncode != 0 and word in done.stderr, rig.clean(done.stderr)
        assert rig.rows("intakes", "id=%s AND decision IS NULL", [intake["id"]])
