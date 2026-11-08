"""8. 본인 확인, 원자 소비, 역할·열 보호와 v001 격리."""

import hashlib
import json

import pytest


@pytest.mark.parametrize("case", ["same_key", "other_key_once", "changed_args", "stale_policy",
                                     "concurrent", "both_atomic", "both_rollback",
                                     "limit_20", "expiry_10m", "team_no_row", "replica_unique",
                                     "plugin_insert", "plugin_confirm", "freeze_columns",
                                     "call_approval_only", "v001_isolation"])
def test_confirmation(rig, case):
    rig.require("console", handlers=("approval_expiry_scan",))
    fixture = rig.active("synthetic")
    rig.fault("confirmation_" + case)
    observation = rig.read_observation("confirmation_" + case)
    rig.check_observation("confirmation_" + case, observation)
    rows = rig.rows("self_confirmations", "server_id=%s", [fixture["server_id"]])
    assert all(row["display"] is None for row in rows if row["status"] in (
        "consumed", "rejected", "cancelled", "expired",
    ))
    if case in ("other_key_once", "concurrent", "replica_unique"):
        assert sum(row["status"] == "consumed" for row in rows) == 1
    if case in ("both_atomic", "both_rollback"):
        consumed = observation["invocation_id"]
        counts = [len(rig.rows(table, "consumed_invocation_id=%s", [consumed]))
                  for table in ("call_approvals", "self_confirmations")]
        assert counts == ([1, 1] if case == "both_atomic" else [0, 0])


def test_console_high_risk_approval(rig):
    """DS-179 1: 콘솔 승인도 고위험 도구를 호출별 승인 대상으로 저장하고, 승인 없이는 호출이 막힌다."""
    rig.require("console", handlers=("approval_expiry_scan",))
    fixture = rig.active("playwright")
    server = fixture["server_id"]
    user = rig.site.get("caller_user", "acc-caller")
    approved = rig.rows("tool_contracts", "server_id=%s AND status='approved'", [server])
    high = sorted({row["tool"] for row in approved if row["risk_grade"] in ("high", "critical")})
    assert high, "승인된 고위험 도구 계약이 없음"
    candidates = {fixture["tool"]: fixture["arguments"], **fixture["changed_tools"]}
    tool = next((t for t in candidates if t in high), None)
    assert tool, f"시험 호출에 쓸 고위험 도구를 정하지 못함: {high}"
    relation = rig.rows("usage_relations", "server_id=%s AND status='active'", [server])[0]
    key = rig.request("POST", "/key/generate", {
        "user_id": user, "object_permission": {"mcp_servers": [server]},
    }, role="litellm_admin", base="litellm_admin")["key"]
    created = rig.api("POST", "/approvals", {
        "relation_id": str(relation["id"]), "state_version": relation["state_version"],
        "scope_type": "key", "scope_id": hashlib.sha256(key.encode()).hexdigest(),
        "tools": sorted({row["tool"] for row in approved}), "basis": "acceptance",
        "requested_by": user, "valid_days": 1,
    })
    row = rig.wait(lambda: rig.rows("approvals", "id=%s AND status='active'", [created["id"]]),
                   120, "콘솔 승인 활성화")[0]
    assert sorted(row["conditions"].get("high_risk_tools", [])) == high, row["conditions"]
    arguments = candidates[tool]
    rig.call(server, tool, arguments, key=key, allowed=False, approve=False,
             code="MINT-CALL-APPROVAL-REQUIRED")
    request = rig.cli("call-approval", "request", "--org", rig.site["intake"]["org_id"],
                      "--principal-type", "user", "--principal-id", user, "--server", server,
                      "--tool", tool, "--arguments", json.dumps(arguments),
                      "--requested-by", user)["id"]
    rig.cli("call-approval", "approve", request)
    rig.call(server, tool, arguments, key=key)
    rig.call(server, tool, arguments, key=key, allowed=False, approve=False,
             code="MINT-CALL-APPROVAL-REQUIRED")  # 승인은 한 번 쓰면 소진된다
    rig.note(console_approval=str(created["id"]), high_risk_tools=high)
