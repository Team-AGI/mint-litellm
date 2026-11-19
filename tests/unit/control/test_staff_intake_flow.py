import uuid
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, as_login

from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import AdminError
from mint_litellm.control.services import intakes, staff, staff_intakes

from . import test_intakes as base

world = base.world
strict = base.strict


def submit(world, user="employee", **changes):
    with as_login(world.url, "mint_staff") as sc, as_login(world.url, "mint_control") as control:
        sctx = staff.StaffContext(sc, control, INSTANCE, user)
        session = uuid.uuid4().hex * 2
        now = datetime.now(UTC)
        staff.start_session(sctx, session, "ab" * 32,
                            now + timedelta(minutes=30), now + timedelta(hours=1))
        return staff_intakes.submit(sctx, session, str(uuid.uuid4()), {
            "server_id": "staff-docs", "url": base.URL, "transport": "http",
            "purpose": "문서 조회", "data_grade": "internal", "resources": "docs",
            "credential_notice": "mail", "revocation_record": "log", "audit_access_days": "90",
            "data_return_terms": "종료 후 삭제", **changes},
            allowed_ports=(443, 8443, 9000))  # 시험 서버 포트도 허용해 접수 뒤 검사까지 간다


def test_staff_request_runs_the_existing_checks_and_requires_a_different_approver(
    world, strict
):
    identifier = submit(world)
    world.drain()
    row = world.intake(identifier)
    assert row["status"] == "passed"
    assert {c["result"] for c in world.checks(identifier)} == {"pass"}
    assert len(world.checks(identifier)) == 8
    registered = world.stub.servers["staff-docs"]
    assert registered["allow_all_keys"] is False
    assert registered["mcp_info"]["mint_intake_id"] == identifier
    assert world.server("staff-docs")["status"] == "awaiting_approval"
    with pytest.raises(AdminError):  # 직무 분리는 설정을 켰을 때만 건다
        world.call(lambda ctx: intakes.decide(ctx, identifier, "approve"),
                   name="helper", user="employee", role="approver")
    assert world.decide(identifier, "approve")["decision"] == "approved"
    assert world.intake(identifier)["requested_by"] == "employee"


def test_an_unallowed_address_is_rejected_before_registry_or_network_probing(world):
    identifier = submit(world, url="http://127.0" + ".0.1:9000/mcp")
    world.drain()
    row = world.intake(identifier)
    assert (row["status"], row["decision"]) == ("failed", None)  # 자동 거절하지 않고 결정을 기다린다
    assert "staff-docs" not in world.stub.servers
    assert not any(path in ("/v1/mcp/server", "/mcp-rest/test/connection",
                            "/mcp-rest/test/tools/list") for _, path, _ in world.stub.requests)


def test_a_conflicting_registry_is_not_overwritten_or_used_for_probing(world):
    world.stub.servers["staff-docs"] = {"server_id": "staff-docs", "allow_all_keys": False,
                                      "mcp_info": {"mint_intake_id": "someone-else"}}
    identifier = submit(world)
    world.drain()
    assert world.intake(identifier)["status"] == "indeterminate"
    assert world.stub.servers["staff-docs"]["mcp_info"]["mint_intake_id"] == "someone-else"
    assert not any(path in ("/v1/mcp/server", "/mcp-rest/test/connection",
                            "/mcp-rest/test/tools/list") for _, path, _ in world.stub.requests)


def test_an_unlisted_provider_waits_for_an_administrator_without_probing(world):
    # 직원은 제공자 허용 목록을 모르므로 자동 거절 대신 관리자 판단으로 넘기고, 접속은 하지 않는다.
    world.conn.execute("UPDATE mint.allowlists SET status = 'lifted' WHERE kind = 'provider'")
    identifier = submit(world)
    world.drain()
    row = world.intake(identifier)
    assert row["status"] == "indeterminate" and row["decision"] is None
    assert "staff-docs" not in world.stub.servers
    assert not any(path in ("/v1/mcp/server", "/mcp-rest/test/connection",
                            "/mcp-rest/test/tools/list") for _, path, _ in world.stub.requests)


def test_a_second_employee_joins_an_approved_server_without_new_checks(world):
    first = submit(world)
    world.drain()
    world.decide(first, "approve")
    world.conn.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'staff-docs'")
    world.conn.execute("DELETE FROM mint.jobs WHERE kind = 'sync_server'")
    second = submit(world, user="employee2", purpose="다른 업무")
    world.drain()
    row = world.intake(second)
    assert row["status"] == "passed" and world.checks(second) == []  # 검사를 되풀이하지 않는다
    assert world.decide(second, "approve")["decision"] == "approved"
    scopes = {r["scope_id"]: r for r in fetchall(
        world.conn, "SELECT scope_id, status, tools FROM mint.approvals")}
    assert set(scopes) == {"employee", "employee2"}
    assert scopes["employee2"]["tools"] == ["*"]  # 이미 승인된 서버: 이 직원의 이용 범위만 더한다
    assert world.server("staff-docs")["status"] == "approved"
    assert fetchall(world.conn, "SELECT 1 FROM mint.deployment_contracts"
                    " WHERE status = 'candidate'") == []
