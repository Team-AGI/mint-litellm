"""5. 부정 상태 파일, 체크포인트, 쓰기 회복, 봉인 변조 검출."""

import hashlib
import hmac
import json


def export_base(rig):
    base = rig.artifact("export_dir")
    return base / rig.iid if (base / rig.iid).is_dir() else base


def verify_export(rig, path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    signature = doc.pop("hmac")
    key = rig.secret("export_hmac")
    from mint_litellm.types.fingerprint import canonical_arguments, decode_fingerprint_key

    raw = decode_fingerprint_key(key)
    assert doc["key_id"] == hashlib.sha256(raw).digest()[:8].hex()
    assert hmac.compare_digest(signature, hmac.new(
        raw, canonical_arguments(doc), hashlib.sha256,
    ).hexdigest())
    return doc


def test_export_seal(rig):
    rig.require("export status", "seal verify", handlers=(
        "export_negative_state", "export_checkpoint", "seal",
    ))
    fixture = rig.active()
    approval = rig.rows("approvals", "server_id=%s AND status='active'", [fixture["server_id"]])[0]
    rig.cli("revoke", str(approval["id"]), "--reason", "acceptance")
    epoch = rig.sql("SELECT epoch FROM mint.state_epoch WHERE instance_id=%s", [rig.iid])[0][
        "epoch"
    ]
    path = export_base(rig) / "negative" / f"{epoch}.json"
    rig.wait(path.exists, 60, "부정 상태 파일")
    doc = verify_export(rig, path)
    assert doc["state_epoch"] == epoch
    exports = rig.rows("exports", "kind='negative_state' AND state_epoch=%s AND status='written'",
                       [epoch])
    assert len(exports) == 1
    window = rig.begin("export", entities=[exports[0]["id"]])
    window["since"] = approval.get("revoked_at") or rig.rows(
        "approvals", "id=%s", [approval["id"]],
    )[0]["revoked_at"]
    rig.check_events(window)
    checkpoint = export_base(rig) / "latest.json"
    previous = checkpoint.read_bytes()
    rig.wait(lambda: checkpoint.read_bytes() != previous, 660, "10분 체크포인트")
    verify_export(rig, checkpoint)
    rig.fault("export_unwritable")
    rig.fault("trigger_negative_state", restore=False)
    rig.wait(lambda: rig.rows("exports", "status='failed'"), 90, "내보내기 실패")
    rig.restore_fault("export_unwritable")
    rig.wait(lambda: not rig.rows("exports", "status='failed'"), 120, "파일 쓰기 수렴")
    assert rig.cli("seal", "verify")["valid"] is True
    rig.fault("seal_tamper")
    result = rig.cli("seal", "verify", check=False)
    assert result.returncode != 0
    rig.note(negative_epoch=epoch, negative_files=1, seal_tamper_exit=result.returncode)
