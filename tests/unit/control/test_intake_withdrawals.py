import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from ctl_fixtures import INSTANCE, as_login

from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import exception_holds, reads, staff
from mint_litellm.control.services import intake_withdrawals as svc

from . import test_intakes as base
from .test_staff_intake_flow import submit

world = base.world


def withdraw(world, identifier, **options):
    version = options.pop("version", world.intake(identifier)["state_version"])
    reason = options.pop("reason", "잘못된 신청 철회")
    return world.call(lambda ctx: svc.withdraw(ctx, identifier, version, reason), **options)


def test_pending_withdrawal_stops_queued_probe_and_allows_new_request(world):
    identifier = world.create()
    row = withdraw(world, identifier)
    assert row["decision"] == "withdrawn"
    before = len(world.stub.requests)
    world.drain()
    assert len(world.stub.requests) == before
    assert world.checks(identifier) == []
    assert world.create() != identifier


def test_passed_withdrawal_preserves_checks_and_is_idempotent(world):
    identifier = world.create()
    world.drain()
    version = world.intake(identifier)["state_version"]
    assert len(world.checks(identifier)) == 8
    withdraw(world, identifier, version=version)
    withdraw(world, identifier, version=version)
    assert len(world.checks(identifier)) == 8
    assert (
        len(
            [
                e
                for e in world.events("intake_decided")
                if e["payload"].get("decision") == "withdrawn"
            ]
        )
        == 1
    )
    assert world.server()["status"] == "rejected"
    assert world.create() != identifier


def test_other_user_and_stale_version_cannot_withdraw(world):
    identifier = world.create()
    with pytest.raises(ControlError):
        withdraw(world, identifier, user="other-user")
    with pytest.raises(ControlError):
        withdraw(world, identifier, version=999)
    assert world.intake(identifier)["status"] == "received"


def test_empty_reason_cannot_withdraw_but_a_stuck_check_can(world):
    identifier = world.create()
    with pytest.raises(ControlError):
        withdraw(world, identifier, reason=" ")
    # 검사가 실패해 재시도를 기다리는(실행 중이 아닌) 신청은 화면에서 철회할 수 있다.
    world.conn.execute("UPDATE mint.intakes SET status='checking' WHERE id=%s", (identifier,))
    assert withdraw(world, identifier)["decision"] == "withdrawn"


def test_withdrawing_while_the_server_is_validating_closes_the_server_too(world):
    """검사 중(서버 validating)에도 철회되고, 서버가 「검사 중」에 남지 않는다(QA-BUG-201)."""
    identifier = world.create()
    world.conn.execute("UPDATE mint.intakes SET status='checking' WHERE id=%s", (identifier,))
    world.conn.execute("UPDATE mint.servers SET status='validating' WHERE status='pending'")
    assert withdraw(world, identifier)["decision"] == "withdrawn"
    assert world.server()["status"] == "rejected"


def test_leased_validation_job_blocks_withdrawal_even_before_checking(world):
    identifier = world.create()
    world.conn.execute(
        "UPDATE mint.jobs SET status='running',lease_owner='test',"
        "lease_until=now()+interval '1 minute' WHERE kind='intake_run'"
        " AND target_ref=%s",
        (identifier,),
    )
    with pytest.raises(ControlError):
        withdraw(world, identifier)
    assert world.intake(identifier)["status"] == "received"


def test_incomplete_input_cannot_enter_checking_but_requester_can_withdraw(world):
    identifier = world.create()
    world.conn.execute("UPDATE mint.intakes SET purpose=NULL WHERE id=%s", (identifier,))
    with pytest.raises(psycopg.errors.CheckViolation):
        world.conn.execute("UPDATE mint.intakes SET status='checking' WHERE id=%s", (identifier,))
    assert withdraw(world, identifier)["decision"] == "withdrawn"


def test_employee_withdraws_a_validated_request_through_session_function(world):
    identifier = submit(world)
    world.drain()
    with as_login(world.url, "mint_staff") as sc, as_login(world.url, "mint_control") as control:
        sctx = staff.StaffContext(sc, control, INSTANCE, "employee")
        session = uuid.uuid4().hex * 2
        now = datetime.now(UTC)
        staff.start_session(
            sctx, session, "ab" * 32, now + timedelta(minutes=30), now + timedelta(hours=1)
        )
        assert not sc.execute(
            "SELECT has_function_privilege(current_user,"
            "'mint.withdraw_intake_row(text,uuid,text,bigint,text,text)','EXECUTE')"
        ).fetchone()[0]
        sc.commit()
        version = world.intake(identifier)["state_version"]
        assert (
            svc.staff_withdraw(sctx, session, identifier, version, "업무 취소")["decision"]
            == "withdrawn"
        )
    assert len(world.checks(identifier)) == 8
    assert submit(world) != identifier


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_terminal_approval_or_rejection_cannot_be_withdrawn(world, decision):
    identifier = world.create()
    world.drain()
    world.decide(identifier, decision, reason="심사 결과")
    with pytest.raises(ControlError):
        withdraw(world, identifier)
    assert world.intake(identifier)["decision"] in ("approved", "rejected")


@pytest.mark.parametrize("decision", ["withdrawn", "rejected"])
def test_terminal_intake_leaves_the_second_approval_queue(world, decision):
    identifier = base.passed(world, readiness={**base.READINESS, "audit_access_days": 0})
    version = world.intake(identifier)["state_version"]
    hold = world.call(
        lambda ctx: exception_holds.request(
            ctx, identifier, {"reason": "예외 검토"}, expected_version=version
        ),
        name="boss",
        user="boss-1",
        role="approver",
    )
    assert [item["id"] for item in exception_holds.pending(world.conn, INSTANCE)] == [hold["id"]]
    assert reads.menu_counts(world.conn, INSTANCE) == {"approvals": 2, "intakes": 1}
    if decision == "withdrawn":
        withdraw(world, identifier, version=version)
    else:
        world.decide(identifier, "reject", name="boss2", user="boss-2", reason="심사 종료")

    intake = world.intake(identifier)
    assert (intake["status"], intake["decision"]) == ("decided", decision)
    assert exception_holds.pending(world.conn, INSTANCE, identifier) == []
    assert exception_holds.count(world.conn, INSTANCE) == 0
    assert reads.menu_counts(world.conn, INSTANCE) == {"approvals": 0, "intakes": 0}

    def unexpected_approval(_hold):
        pytest.fail("a terminal intake cannot proceed to approval")

    for action in (
        lambda ctx: exception_holds.confirm(ctx, hold["id"], unexpected_approval),
        lambda ctx: exception_holds.reject(ctx, hold["id"]),
    ):
        with pytest.raises(AdminError) as raised:
            world.call(action, name="boss2", user="boss-2", role="approver")
        assert raised.value.code == AdminCode.CONFLICT

    assert world.intake(identifier) == intake
    assert len(world.events("intake_exception_requested")) == 1
    assert world.events("intake_exception_cancelled") == []


def test_rechecked_intake_needs_a_new_second_approval_request(world):
    identifier = base.passed(world, readiness={**base.READINESS, "audit_access_days": 0})
    version = world.intake(identifier)["state_version"]

    def request(expected_version):
        return world.call(
            lambda ctx: exception_holds.request(
                ctx, identifier, {"reason": "예외 검토"}, expected_version=expected_version
            ),
            name="boss",
            user="boss-1",
            role="approver",
        )

    old = request(version)
    world.call(lambda ctx: base.svc.recheck(ctx, identifier, expected_version=version))
    world.drain()
    checked = world.intake(identifier)
    assert checked["status"] == "indeterminate"
    assert checked["state_version"] > version
    assert exception_holds.pending(world.conn, INSTANCE, identifier) == []
    assert reads.menu_counts(world.conn, INSTANCE) == {"approvals": 1, "intakes": 1}

    current = request(checked["state_version"])
    assert [item["id"] for item in exception_holds.pending(world.conn, INSTANCE)] == [current["id"]]
    world.call(lambda ctx: exception_holds.reject(ctx, current["id"]),
               name="boss2", user="boss-2", role="approver")
    assert world.intake(identifier) == checked
    assert exception_holds.count(world.conn, INSTANCE) == 0
    assert reads.menu_counts(world.conn, INSTANCE) == {"approvals": 1, "intakes": 1}
    cancellations = world.events("intake_exception_cancelled")
    assert {e["payload"]["hold_id"]: e["payload"]["reason"] for e in cancellations} == {
        str(old["id"]): "superseded", str(current["id"]): "rejected"
    }
    assert old["id"] != current["id"]
