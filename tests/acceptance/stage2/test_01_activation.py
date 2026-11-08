"""1. 첫 활성화, pin 전수·해시, 제어 키의 발견 면제와 호출 차단."""

import hashlib
import json

import pytest


@pytest.mark.parametrize("name", ["playwright", "context7", "grafana"])
def test_activation(rig, name):
    rig.require("intake create", "intake approve", handlers=(
        "submission_poll", "intake_run", "sync_server", "sync_target", "activation_finalize",
    ))
    entry = rig.site["servers"][name]
    server = entry["server_id"]
    window = rig.begin("activation", server=server)
    fixture = rig.fixture(name)
    intake_id = fixture["intake_id"]
    window["entities"].append(intake_id)
    checks = rig.rows("intake_checks", "intake_id=%s", [intake_id])
    window["entities"].extend(row["id"] for row in checks)
    assert {row["check"] for row in checks} == set(rig.expected["intake_checks"])
    assert len(checks) == 8 and all(row["result"] == "pass" for row in checks)
    state = rig.rows("servers", "server_id=%s", [server])[0]
    assert state["status"] == "awaiting_approval" and state["last_observed_at"] is None
    rig.call(server, fixture["tool"], fixture["arguments"], allowed=False,
             code="MINT-SERVER-NOT-APPROVED", litellm_rejects=True)
    # 제어 키의 pin은 호출 권한을 갖지 않는다. 목록 면제는 최초 pin에서도 필요하다.
    pin = rig.request("POST", f"/v1/mcp/server/{server}/pin", role="control", base="litellm_admin")
    assert len(pin["pinned_tools"]) == fixture["tool_count"]
    candidates = rig.rows("tool_contracts", "server_id=%s AND status='candidate'", [server])
    assert {row["tool"] for row in candidates} == set(pin["pinned_tools"])
    from mint_litellm.types.fingerprint import canonical_arguments

    for row in candidates:
        definition = pin["pinned_tools"][row["tool"]]
        digest = hashlib.sha256(canonical_arguments({
            "description": definition["description"], "input_schema": definition["input_schema"],
        })).hexdigest()
        assert digest == row["pin_sha256"]
    rig.request("DELETE", f"/v1/mcp/server/{server}/pin", role="control", base="litellm_admin")
    contracts = rig.activate(fixture)
    window["entities"].extend(row["id"] for row in contracts)
    deployment = rig.rows("deployment_contracts", "server_id=%s AND status='approved'", [server])
    window["entities"].extend(row["id"] for row in deployment)
    approvals = rig.rows("approvals", "server_id=%s", [server])
    window["entities"].extend(row["id"] for row in approvals)
    rig.call(server, fixture["tool"], fixture["arguments"])
    rig.check_events(window, tool_count=fixture["tool_count"])
    rig.note(pin_tool_count=len(pin["pinned_tools"]), checks=[row["check"] for row in checks],
             canonical_contracts_sha256=hashlib.sha256(json.dumps(
                 [row["pin_sha256"] for row in contracts], sort_keys=True,
             ).encode()).hexdigest())


def test_pending_key_blocked(rig):
    """DS-176 ③: 키 권한은 있으나 MINT 승인·pin이 없는 호출은 MINT가 막고 업스트림은 0이다.

    활성화 뒤 같은 호출은 허용 1회로 대조한다.
    """
    rig.require("intake create", "intake approve", handlers=(
        "submission_poll", "intake_run", "sync_server", "sync_target", "activation_finalize",
    ))
    name = "context7"
    fixture = rig.fixture(name)
    server = fixture["server_id"]
    before = rig.counter(server)
    snapshot = rig.call(server, fixture["tool"], fixture["arguments"], allowed=False,
                        code="MINT-", litellm_rejects=False)
    assert rig.counter(server) == before, "미승인 호출이 업스트림에 닿음"
    rig.note(pending_blocked_event=bool(snapshot))
    rig.activate(fixture)
    rig.call(server, fixture["tool"], fixture["arguments"])
