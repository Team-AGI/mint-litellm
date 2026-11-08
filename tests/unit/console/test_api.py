"""HTTP API: 인증(세션·운영자 토큰), CSRF, 역할별 권한, 직무 분리, 낙관적 잠금, 오류 본문."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from console_fixtures import HEX, TOKENS, Keys

from mint_litellm.console.api import (
    EXCEPTION_MAX_DAYS,
    STANDARD_DAYS,
    STRICT_DAYS,
    approval_days,
)
from mint_litellm.control.errors import AdminCode

INSTANCE = "inst1"


def bearer(role: str) -> dict:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def server_row(world, server_id: str):
    return world.query(
        "SELECT status, state_version FROM mint.servers WHERE server_id = %s", server_id)[0]


def assert_error(response, status: int, code: str):
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"code", "message", "reference"}
    assert body["code"] == code
    assert response.headers["X-Request-Id"] == body["reference"]
    return body


def add_call_approval(world, principal: str, requested_by: str = "someone") -> str:
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s) ON CONFLICT DO NOTHING", INSTANCE, HEX, HEX)
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at) VALUES (%s, %s, 'acme', 'user', %s, 'srv-ok', 'echo', %s, 1, 'v1',"
        " 'pending', %s, now() + interval '1 hour')",
        call_id, INSTANCE, principal, HEX, requested_by)
    return call_id


# --- 인증과 오류 본문 ----------------------------------------------------------------------


def test_an_unauthenticated_request_is_401_with_the_documented_error_body(world):
    assert_error(world.client.get("/api/v1/servers"), 401, AdminCode.FORBIDDEN)


def test_an_operator_token_authenticates_the_api(world):
    response = world.client.get("/api/v1/servers", headers=bearer("viewer"))
    assert response.status_code == 200
    assert {s["server_id"] for s in response.json()["items"]} == {"srv-ok", "srv-wait"}


def test_a_wrong_operator_token_is_refused(world):
    response = world.client.get("/api/v1/servers", headers={"Authorization": "Bearer nope"})
    assert_error(response, 401, AdminCode.FORBIDDEN)


def test_unknown_resources_are_not_found_with_the_admin_code(world):
    response = world.client.get("/api/v1/servers/nothing", headers=bearer("viewer"))
    assert_error(response, 404, AdminCode.NOT_FOUND)


def test_an_invalid_body_is_a_400_with_the_same_error_shape(world):
    response = world.client.post("/api/v1/servers/srv-ok/suspend", headers=bearer("admin"),
                                 json={"confirm_name": "srv-ok"})
    body = assert_error(response, 400, "MINT-ADMIN-INVALID-INPUT")
    assert "state_version" in body["message"]


# --- 낙관적 잠금과 위험 동작 -----------------------------------------------------------------


def test_a_stale_state_version_is_a_conflict_and_changes_nothing(world):
    status, version = server_row(world, "srv-ok")
    response = world.client.post(
        "/api/v1/servers/srv-ok/suspend", headers=bearer("admin"),
        json={"state_version": version + 1, "confirm_name": "srv-ok"})
    assert_error(response, 409, AdminCode.CONFLICT)
    assert server_row(world, "srv-ok") == (status, version)


def test_suspending_needs_the_server_name_typed_exactly(world):
    _, version = server_row(world, "srv-ok")
    response = world.client.post(
        "/api/v1/servers/srv-ok/suspend", headers=bearer("admin"),
        json={"state_version": version, "confirm_name": "srv"})
    assert_error(response, 400, "MINT-ADMIN-INVALID-INPUT")
    assert server_row(world, "srv-ok")[0] == "approved"


def test_an_admin_suspends_and_resumes_a_server_with_the_current_version(world):
    _, version = server_row(world, "srv-ok")
    response = world.client.post(
        "/api/v1/servers/srv-ok/suspend", headers=bearer("admin"),
        json={"state_version": version, "confirm_name": "srv-ok"})
    assert response.status_code == 200 and response.json()["ok"] is True
    assert response.json()["events"][0].endswith(":server_suspended")
    status, version = server_row(world, "srv-ok")
    assert status == "suspended"
    again = world.client.post("/api/v1/servers/srv-ok/suspend", headers=bearer("admin"),
                              json={"state_version": version - 1, "confirm_name": "srv-ok"})
    assert_error(again, 409, AdminCode.CONFLICT)
    resumed = world.client.post("/api/v1/servers/srv-ok/resume", headers=bearer("admin"),
                                json={"state_version": version})
    assert resumed.status_code == 200
    assert server_row(world, "srv-ok")[0] == "approved"


# --- 역할 ------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "approver"])
def test_only_an_admin_may_suspend_a_server(world, role):
    _, version = server_row(world, "srv-ok")
    response = world.client.post(
        "/api/v1/servers/srv-ok/suspend", headers=bearer(role),
        json={"state_version": version, "confirm_name": "srv-ok"})
    assert_error(response, 403, AdminCode.FORBIDDEN)
    assert server_row(world, "srv-ok")[0] == "approved"


def test_an_approver_cannot_create_an_org_but_an_admin_can(world):
    body = {"org_id": "beta", "name": "B사"}
    assert_error(world.client.post("/api/v1/orgs", headers=bearer("approver"), json=body),
                 403, AdminCode.FORBIDDEN)
    assert world.client.post("/api/v1/orgs", headers=bearer("admin"), json=body).status_code == 200
    names = [o["name"] for o in world.client.get("/api/v1/orgs", headers=bearer("viewer"))
             .json()["items"]]
    assert "B사" in names


def test_a_viewer_cannot_list_operators_and_the_list_has_no_secrets(world):
    assert_error(world.client.get("/api/v1/operators", headers=bearer("viewer")),
                 403, AdminCode.FORBIDDEN)
    rows = world.client.get("/api/v1/operators", headers=bearer("approver")).json()["items"]
    assert {r["name"] for r in rows} == {"admin", "approver", "viewer"}
    assert all(set(r) == {"name", "role", "user_id", "expires_at", "state_version"} for r in rows)


def test_a_session_carries_the_operators_role_into_the_services(world):
    viewer = world.session_client("viewer")
    _, version = server_row(world, "srv-ok")
    response = viewer.post(
        "/api/v1/servers/srv-ok/suspend",
        headers={"X-CSRF-Token": world.csrf(viewer)},
        json={"state_version": version, "confirm_name": "srv-ok"})
    assert_error(response, 403, AdminCode.FORBIDDEN)


# --- 직무 분리 -------------------------------------------------------------------------------


def test_the_call_subject_cannot_approve_their_own_call(world):
    call_id = add_call_approval(world, principal="human-2")  # 승인자 본인
    row = world.query("SELECT state_version FROM mint.call_approvals")[0]
    response = world.client.post(
        f"/api/v1/call-approvals/{call_id}/approve", headers=bearer("approver"),
        json={"state_version": row[0]})
    assert_error(response, 403, AdminCode.SEPARATION_OF_DUTIES)
    assert world.query("SELECT status FROM mint.call_approvals")[0][0] == "pending"


def test_a_requester_who_is_the_operator_needs_a_second_approver(world):
    call_id = add_call_approval(world, principal="human-7", requested_by="human-2")
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    path = f"/api/v1/call-approvals/{call_id}/approve"
    refused = world.client.post(path, headers=bearer("approver"), json={"state_version": version})
    assert_error(refused, 403, AdminCode.SEPARATION_OF_DUTIES)
    approved = world.client.post(
        path, headers=bearer("approver"),
        json={"state_version": version, "second_approver_token": TOKENS["admin"]})
    assert approved.status_code == 200
    assert world.query("SELECT status FROM mint.call_approvals")[0][0] == "approved"


# --- CSRF ------------------------------------------------------------------------------------


def post_suspend(world, client, headers=None):
    _, version = server_row(world, "srv-ok")
    return client.post("/api/v1/servers/srv-ok/suspend", headers=headers or {},
                       json={"state_version": version, "confirm_name": "srv-ok"})


def test_a_session_request_without_a_csrf_token_is_refused(world):
    client = world.session_client()
    assert_error(post_suspend(world, client), 403, AdminCode.FORBIDDEN)
    assert server_row(world, "srv-ok")[0] == "approved"


def test_a_session_request_with_a_wrong_csrf_token_is_refused(world):
    client = world.session_client()
    response = post_suspend(world, client, {"X-CSRF-Token": "0" * 64})
    assert_error(response, 403, AdminCode.FORBIDDEN)


def test_the_csrf_token_of_another_session_is_refused(world):
    first, second = world.session_client(), world.session_client("approver")
    assert_error(post_suspend(world, first, {"X-CSRF-Token": world.csrf(second)}),
                 403, AdminCode.FORBIDDEN)


def test_a_session_request_with_the_csrf_header_succeeds(world):
    client = world.session_client()
    response = post_suspend(world, client, {"X-CSRF-Token": world.csrf(client)})
    assert response.status_code == 200
    assert server_row(world, "srv-ok")[0] == "suspended"


def test_a_request_from_another_origin_is_refused_even_with_a_valid_token(world):
    client = world.session_client()
    headers = {"X-CSRF-Token": world.csrf(client), "Origin": "https://evil.example"}
    assert_error(post_suspend(world, client, headers), 403, AdminCode.FORBIDDEN)


def test_the_logout_form_also_needs_the_csrf_token(world):
    client = world.session_client()
    assert client.post("/logout", data={"csrf": "bad"}).status_code == 403
    live = world.query("SELECT count(*) FROM mint.console_sessions WHERE revoked_at IS NULL")
    assert live[0][0] == 1


# --- 승인 ------------------------------------------------------------------------------------


def test_the_default_approval_period_follows_the_risk_of_the_tools():
    assert approval_days("standard", ["read"], []) == STANDARD_DAYS == 90
    assert approval_days("standard", ["delete"], ["delete"]) == STRICT_DAYS == 30
    assert approval_days("exception", ["read"], []) == STRICT_DAYS
    assert EXCEPTION_MAX_DAYS == 90


def relation_of(world, server_id: str):
    return world.query(
        "SELECT id, state_version FROM mint.usage_relations WHERE server_id = %s", server_id)[0]


def grant(world, relation, **overrides):
    body = {"relation_id": str(relation[0]), "state_version": relation[1],
            "scope_type": "key", "scope_id": "k-token", "tools": ["echo"],
            "basis": "업무 필요", "requested_by": "human-9"}
    body.update(overrides)
    return world.client.post("/api/v1/approvals", headers=bearer("admin"), json=body)


def test_granting_needs_the_control_key_the_console_normally_lacks(world):
    response = grant(world, relation_of(world, "srv-wait"))
    body = assert_error(response, 403, AdminCode.FORBIDDEN)
    assert "제어 평면 키" in body["message"]


def test_an_exception_approval_cannot_exceed_ninety_days(world):
    world.with_control_key()
    response = grant(world, relation_of(world, "srv-wait"), **{"class": "exception"},
                     valid_days=EXCEPTION_MAX_DAYS + 1)
    assert_error(response, 400, "MINT-ADMIN-INVALID-INPUT")


def test_granting_with_the_control_key_prefills_the_period_and_approves_the_server(world):
    world.with_control_key()
    world.query("UPDATE mint.settings SET default_org_id = 'acme'")
    server = {"server_id": "srv-wait", "mcp_access_groups": []}
    world.stub.routes[("/v1/mcp/server", "control-plane-key", None)] = (200, [server])
    world.stub.routes[("/key/info", "control-plane-key", "k-token")] = (200, {
        "key": "k-token",
        "info": {"user_id": "human-1", "team_id": None,
                 "object_permission": {"mcp_servers": ["srv-wait"]}}})
    response = grant(world, relation_of(world, "srv-wait"))
    assert response.status_code == 200, response.text
    valid_until, status = world.query(
        "SELECT valid_until, status FROM mint.approvals")[0]
    assert status == "active"
    days = (valid_until - datetime.now(UTC)).total_seconds() / 86400
    assert 89 < days <= 90
    assert server_row(world, "srv-wait")[0] == "approved"


# --- 원장 ------------------------------------------------------------------------------------


def test_the_ledger_lists_the_last_seven_days_and_filters_by_kind(world):
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, actor,"
        " payload) VALUES (%s, %s, now() - interval '9 days', 'org_created',"
        " 'org:old:1:org_created', 'admin', '{}')", uuid.uuid4(), INSTANCE)
    world.client.post("/api/v1/orgs", headers=bearer("admin"), json={"org_id": "n", "name": "N"})
    rows = world.client.get("/api/v1/ledger", headers=bearer("viewer")).json()["items"]
    assert [r["kind"] for r in rows] == ["org_created"]
    assert rows[0]["source_key"] == "org:n:1:org_created"
    only = world.client.get("/api/v1/ledger?kind=server_suspended", headers=bearer("viewer"))
    assert only.json()["items"] == []
    wide = world.client.get(
        "/api/v1/ledger", headers=bearer("viewer"),
        params={"since": (datetime.now(UTC) - timedelta(days=30)).isoformat()}).json()["items"]
    assert len(wide) == 2


def test_the_ledger_exports_csv_and_json(world):
    world.client.post("/api/v1/orgs", headers=bearer("admin"), json={"org_id": "n", "name": "N"})
    csv_response = world.client.get("/api/v1/ledger/export?format=csv", headers=bearer("viewer"))
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert csv_response.text.startswith("﻿event_id,inserted_at,kind")
    assert "org:n:1:org_created" in csv_response.text
    json_response = world.client.get("/api/v1/ledger/export?format=json",
                                     headers=bearer("viewer"))
    assert json_response.json()[0]["kind"] == "org_created"


def test_the_viewer_key_constant_is_a_registered_operator_key(world):
    assert world.client.post("/login", data={"key": Keys.viewer}).status_code == 303


def approval_conditions_of(world, **overrides):
    world.with_control_key()
    world.query("UPDATE mint.settings SET default_org_id = 'acme'")
    world.stub.routes[("/v1/mcp/server", "control-plane-key", None)] = (
        200, [{"server_id": "srv-wait", "mcp_access_groups": []}])
    world.stub.routes[("/key/info", "control-plane-key", "k-token")] = (200, {
        "key": "k-token",
        "info": {"user_id": "human-1", "team_id": None,
                 "object_permission": {"mcp_servers": ["srv-wait"]}}})
    response = grant(world, relation_of(world, "srv-wait"), **overrides)
    return response, world.query("SELECT conditions FROM mint.approvals")


def test_unset_paths_store_no_path_condition(world):
    response, rows = approval_conditions_of(world, allowed_hosts=["example.org"])
    assert response.status_code == 200
    assert rows[0][0] == {"allowed_hosts": ["example.org"]}


def test_listed_paths_are_stored_and_need_at_least_one(world):
    response, rows = approval_conditions_of(world, paths_mode="listed", allowed_paths=["/data"])
    assert response.status_code == 200 and rows[0][0] == {"allowed_paths": ["/data"]}


def test_listed_paths_without_a_path_are_refused(world):
    response, _ = approval_conditions_of(world, paths_mode="listed")
    assert_error(response, 400, "MINT-ADMIN-INVALID-INPUT")


def test_unrestricted_paths_are_an_explicit_choice(world):
    response, rows = approval_conditions_of(world, paths_mode="unrestricted")
    assert response.status_code == 200
    assert rows[0][0] == {"allowed_paths_unrestricted": True}


def test_console_approval_records_the_high_risk_tools_like_the_cli_does(world):
    server = "srv-wait"
    world.query(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (gen_random_uuid(), %s, %s, 'server', 'drop', '{}', repeat('a', 64),"
        " repeat('b', 64), 'high', 'delete', 'intake', 'candidate')", INSTANCE, server)
    world.query("UPDATE mint.tool_contracts SET status = 'approved' WHERE server_id = %s", server)
    response, rows = approval_conditions_of(world, tools=["drop"])
    assert response.status_code == 200
    assert rows[0][0] == {"high_risk_tools": ["drop"]}
