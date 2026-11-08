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
    pin = {"pinned_tools": pin.get("pinned_tools", pin)}  # 응답이 도구 이름 맵 그대로인 판본이 있다
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


CONTROL_KEY_HANDLERS = ("submission_poll", "intake_run", "sync_server", "sync_target",
                        "activation_finalize")


def control_key_waiting(rig, name):
    """DS-175 4: 제어 키 토큰을 비운 채 승인한다. 핀 작업은 시도 횟수 0으로 대기하고 경보가 뜬다."""
    rig.require("intake create", "intake approve", "settings control-key",
                handlers=CONTROL_KEY_HANDLERS)
    fixture = rig.fixture(name)
    server = fixture["server_id"]
    # 시험이 끝나면 어떤 경우에도 제어 키를 다시 저장한다(실패해도 무시).
    rig.undo.append(lambda: rig.cli("settings", "control-key", check=False))
    rig.cli("settings", "control-key", "--clear")
    scope = rig.approval_scope()
    extra = ["--team", scope["team"]] if scope.get("team") else []
    rig.cli("intake", "approve", fixture["intake_id"], "--reason", "acceptance", "--scope",
            scope["type"], "--scope-id", scope["id"], *extra, role="approver")
    rig.wait(lambda: rig.rows(
        "alerts", "kind='sync_divergence' AND status <> 'resolved' "
        "AND subject->>'reason'='control_key_not_set' AND subject->>'server_id'=%s", [server]),
        240, "제어 키 없음 경보")
    waiting = rig.rows("jobs", "last_error_code='control_key_not_set'")
    assert waiting and all(j["status"] == "pending" and j["attempts"] == 0 for j in waiting), waiting
    assert not rig.rows("litellm_grants", "server_id=%s AND item='pin' AND observed", [server])
    return fixture, server


def test_control_key_wait(rig):
    fixture, server = control_key_waiting(rig, "context7")
    rig.fault("worker_stop")
    rig.restore_fault("worker_stop")  # 작업 실행기를 다시 올린다(대기 중 재시작)
    rig.wait(lambda: rig.rows("jobs", "last_error_code='control_key_not_set'"), 60,
             "재시작 뒤에도 대기 작업")
    assert not rig.rows("jobs", "status='failed'")
    assert all(j["attempts"] == 0 for j in rig.rows("jobs", "last_error_code='control_key_not_set'"))
    rig.cli("settings", "control-key")
    rig.wait(lambda: rig.rows("litellm_grants", "server_id=%s AND item='pin' AND observed",
                              [server]), 420, "키 저장 뒤 핀 맞춰짐")
    assert not rig.rows("jobs", "status='failed'")
    contracts = rig.rows("tool_contracts", "server_id=%s AND status='approved'", [server])
    assert len(contracts) == fixture["tool_count"]
    rig.call(server, fixture["tool"], fixture["arguments"])


def test_control_key_wait_revoked(rig):
    """대기 중에 철회하면 키를 저장해도 실행 시점의 상태(철회)로 판정되어 핀이 적용되지 않는다."""
    fixture, server = control_key_waiting(rig, "context7")
    for approval in rig.rows("approvals", "server_id=%s AND status IN ('pending','active')",
                             [server]):
        rig.cli("revoke", str(approval["id"]), "--reason", "acceptance")
    rig.cli("settings", "control-key")
    rig.wait(lambda: not rig.rows("jobs", "last_error_code='control_key_not_set' "
                                  "AND status IN ('pending','running')"), 420, "대기 작업 처리")
    assert not rig.rows("litellm_grants", "server_id=%s AND item='pin' AND observed", [server])
    assert not rig.rows("approvals", "server_id=%s AND status='active'", [server])
    rig.call(server, fixture["tool"], fixture["arguments"], allowed=False, code="MINT-",
             litellm_rejects=True)
