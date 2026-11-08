"""6. DB 되돌림, 파일 손실/키 교체, 두 사람의 해제, 정상 운영 감시."""

import pytest


@pytest.mark.parametrize("case", ["backup_before_revoke", "epoch_caught_up", "consent",
                                     "latest_missing", "hmac_changed", "previous_key",
                                     "accept_stale", "operator_revert", "steady_24h"])
def test_restore(rig, case):
    rig.require("restore check", "restore attest", "restore accept-stale",
                handlers=("export_negative_state", "export_checkpoint", "sync_target"))
    fixture = rig.active("synthetic")
    rig.fault("restore_" + case)
    observation = rig.read_observation("restore_" + case)
    rig.check_observation("restore_" + case, observation)
    if case in ("backup_before_revoke", "epoch_caught_up", "consent"):
        rig.call(fixture["server_id"], fixture["tool"], fixture["arguments"], allowed=False,
                 code="MINT-ENFORCEMENT-UNVERIFIED", cause="restore_pending")
        epoch = observation["file_epoch"]
        window = rig.begin("restore_attest", entities=[epoch])
        rig.cli("restore", "attest", "--reason", "acceptance")
        rig.check_events(window)
        rig.note(reapplied_revocations=rig.rows("approvals", "status='revoked'"),
                 reapplied_consents=rig.rows("consents", "revoked_at IS NOT NULL"))
    elif case in ("latest_missing", "hmac_changed"):
        rig.call(fixture["server_id"], fixture["tool"], fixture["arguments"], allowed=False,
                 code="MINT-ENFORCEMENT-UNVERIFIED",
                 cause="export_missing" if case == "latest_missing" else "export_unverified")
    elif case == "operator_revert":
        # 시나리오가 attest까지 마쳤다. 되돌린 뒤 호출이 다시 허용되고 운영자 상태가 유지된다.
        rig.call(fixture["server_id"], fixture["tool"], fixture["arguments"])
        assert {row["name"]: row["role"] for row in rig.rows(
            "operators", "name LIKE 'acc-demote-%'")}.values() == {"viewer"}
    elif case == "previous_key":
        rig.call(fixture["server_id"], fixture["tool"], fixture["arguments"])
