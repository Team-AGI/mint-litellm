"""권한 요청(FM-60): 직원이 열고, 승인자가 기존 조치로 푼다."""

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, as_login

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import access_requests as svc
from mint_litellm.control.services import denials, staff

from . import test_intakes as base

world = base.world


def approved_server(world) -> str:
    identifier = world.create()
    world.drain()
    world.decide(identifier, "approve", reason="심사 결과")
    return fetchone(
        world.conn, "SELECT org_id FROM mint.usage_relations WHERE server_id = 'srv-a'"
    )["org_id"]


@contextmanager
def employee(world, user="employee"):
    with as_login(world.url, "mint_staff") as sc, as_login(world.url, "mint_control") as control:
        sctx = staff.StaffContext(sc, control, INSTANCE, user)
        session = uuid.uuid4().hex * 2
        now = datetime.now(UTC)
        staff.start_session(
            sctx, session, "ab" * 32, now + timedelta(minutes=30), now + timedelta(hours=1)
        )
        yield sctx, session


def open_request(world, tool="search", reason="DENIED", user="employee"):
    with employee(world, user) as (sctx, session):
        return svc.staff_open(
            sctx, session, server_id="srv-a", tool=tool, reason_code=reason, note="업무에 필요"
        )


def request_row(world):
    return fetchone(world.conn, "SELECT * FROM mint.access_requests")


def test_an_employee_opens_one_request_per_target_and_only_they_can_cancel(world):
    approved_server(world)
    first = open_request(world)
    assert open_request(world) == first  # 같은 대상의 대기 요청은 하나
    with employee(world, "other") as (sctx, session):
        assert svc.staff_cancel(sctx, session, first) is False
        assert svc.mine(sctx) == []
    with employee(world) as (sctx, session):
        assert [r["status"] for r in svc.mine(sctx)] == ["open"]
        assert svc.staff_cancel(sctx, session, first) is True
        assert svc.mine(sctx)[0]["status"] == "cancelled"
    assert len(world.events("access_request_opened")) == 1
    assert len(world.events("access_request_cancelled")) == 1


def test_an_unknown_reason_or_server_is_refused(world):
    approved_server(world)
    with pytest.raises(ControlError):
        open_request(world, reason="MASTER_KEY_FORBIDDEN")
    with employee(world) as (sctx, session), pytest.raises(ControlError):
        svc.staff_open(sctx, session, server_id="nope", tool=None, reason_code="DENIED", note="")


def test_lifting_resolves_the_request_with_the_denials_it_lifted(world):
    org = approved_server(world)
    denial = world.call(
        lambda ctx: denials.deny(
            ctx,
            scope_type="user",
            scope_id="employee",
            server_id="srv-a",
            tools=["search"],
            reason="검토 중",
            org_id=org,
        )
    )
    other = world.call(
        lambda ctx: denials.deny(
            ctx,
            scope_type="user",
            scope_id="someone-else",
            server_id="srv-a",
            tools=["search"],
            reason="다른 사람",
            org_id=org,
        )
    )
    rid = open_request(world)
    waiting = svc.pending(world.conn, INSTANCE)
    assert waiting[0]["suggested"] == "lift"
    assert [str(d["id"]) for d in waiting[0]["denials"]] == [denial]  # 남의 차단은 후보가 아니다
    assert world.call(lambda ctx: svc.resolve_lift(ctx, rid, [])) == [denial]
    lifted = {
        str(r["id"]): r["lifted_at"] is not None
        for r in fetchall(world.conn, "SELECT id, lifted_at FROM mint.denials")
    }
    assert lifted == {denial: True, other: False}
    row = request_row(world)
    assert (row["status"], row["resolution"], row["resolution_ref"]) == ("resolved", "lift", denial)
    with pytest.raises(ControlError):  # 이미 처리된 요청
        world.call(lambda ctx: svc.resolve_lift(ctx, rid, []))
    assert len(world.events("access_request_resolved")) == 1


def test_reject_needs_a_reason_and_a_viewer_cannot_decide(world):
    approved_server(world)
    rid = open_request(world, tool=None, reason="APPROVAL_ABSENT")
    with pytest.raises(ControlError):
        world.call(lambda ctx: svc.reject(ctx, rid, " "))
    with pytest.raises(ControlError):
        world.call(lambda ctx: svc.reject(ctx, rid, "범위 밖"), role="viewer")
    world.call(lambda ctx: svc.reject(ctx, rid, "범위 밖"), role="approver")
    row = request_row(world)
    assert (row["status"], row["decision_note"]) == ("rejected", "범위 밖")


def test_temporary_permission_is_a_thirty_minute_rule_for_the_requester_only(world):
    approved_server(world)
    rid = open_request(world, reason="CALL_APPROVAL_REQUIRED")
    world.call(lambda ctx: svc.resolve_temp(ctx, rid))
    rules = fetchall(
        world.conn,
        "SELECT principal_type, scope_id, server_id, tool_pattern,"
        " window_minutes, valid_until < now() + interval '31 minutes' AS short"
        " FROM mint.call_approval_rules",
    )
    assert rules and all(
        (
            r["principal_type"],
            r["scope_id"],
            r["server_id"],
            r["tool_pattern"],
            r["window_minutes"],
            r["short"],
        )
        == ("user", "employee", "srv-a", "search", 30, True)
        for r in rules
    )
    assert request_row(world)["resolution"] == "temp"


def test_grant_adds_a_user_approval_on_the_servers_relation(world, monkeypatch):
    approved_server(world)
    relation = fetchone(world.conn, "SELECT id FROM mint.usage_relations WHERE server_id = 'srv-a'")
    seen = {}

    def fake_approve(ctx, litellm, **kwargs):  # 승인 자체는 승인 서비스 시험이 다룬다
        seen.update(kwargs)
        return "approval-1", []

    monkeypatch.setattr(svc.approval_service, "approve", fake_approve)
    rid = open_request(world, tool=None, reason="APPROVAL_ABSENT")
    assert world.call(lambda ctx: svc.resolve_grant(ctx, None, rid, valid_days=30)) == "approval-1"
    assert (seen["relation_id"], seen["scope_type"], seen["scope_id"], seen["tools"]) == (
        str(relation["id"]),
        "user",
        "employee",
        ["*"],
    )
    assert (seen["valid_until"] - seen["valid_from"]).days == 30
    row = request_row(world)
    assert (row["status"], row["resolution"], row["resolution_ref"]) == (
        "resolved",
        "grant",
        "approval-1",
    )
    other = open_request(world, tool="x", reason="APPROVAL_ABSENT")
    with pytest.raises(ControlError):  # 기간은 7·30·90일 중 하나
        world.call(lambda ctx: svc.resolve_grant(ctx, None, other, valid_days=5))
