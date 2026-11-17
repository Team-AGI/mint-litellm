import uuid
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, as_login

from mint_litellm.control.errors import AdminError
from mint_litellm.control.services import intakes, staff, staff_intakes

from . import test_intakes as base

world = base.world


def submit(world, **changes):
    with as_login(world.url, "mint_staff") as sc, as_login(world.url, "mint_control") as control:
        sctx = staff.StaffContext(sc, control, INSTANCE, "employee")
        session = uuid.uuid4().hex * 2
        now = datetime.now(UTC)
        staff.start_session(sctx, session, "ab" * 32,
                            now + timedelta(minutes=30), now + timedelta(hours=1))
        return staff_intakes.submit(sctx, session, str(uuid.uuid4()), {
            "server_id": "staff-docs", "url": base.URL, "transport": "http",
            "purpose": "문서 조회", "data_grade": "internal", "resources": "docs",
            "credential_notice": "mail", "revocation_record": "log", "audit_access_days": "90",
            "data_return_terms": "종료 후 삭제", **changes})


def test_staff_request_runs_the_existing_checks_and_requires_a_different_approver(world):
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
    with pytest.raises(AdminError):
        world.call(lambda ctx: intakes.decide(ctx, identifier, "approve"),
                   name="helper", user="employee")
    assert world.decide(identifier, "approve")["decision"] == "approved"
    assert world.intake(identifier)["requested_by"] == "employee"


def test_an_unallowed_address_is_rejected_before_registry_or_network_probing(world):
    identifier = submit(world, url="http://127.0" + ".0.1:9000/mcp")
    world.drain()
    row = world.intake(identifier)
    assert row["decision"] == "rejected"
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
