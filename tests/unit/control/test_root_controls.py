"""Root 통제(FM-55~59): 기존 조치를 부르고 강제 조치 기록·사건을 남긴다."""

import pytest

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import root_controls as root

from . import test_intakes as base

world = base.world


def as_root(world, fn):
    return world.call(fn, name="root", user="root-user", role="admin")


def as_admin(world, fn):
    return world.call(fn, name="boss", user="boss-1", role="admin")


def actions(world):
    return [
        r["action"]
        for r in fetchall(world.conn, "SELECT action FROM mint.forced_actions ORDER BY created_at")
    ]


def test_only_root_halts_and_the_halt_is_recorded_and_lifted(world):
    with pytest.raises(ControlError):
        as_admin(world, lambda ctx: root.set_halt(ctx, "all", "침해 의심"))
    with pytest.raises(ControlError):
        as_root(world, lambda ctx: root.set_halt(ctx, "all", " "))
    as_root(world, lambda ctx: root.set_halt(ctx, "all", "침해 의심"))
    state = root.halt_state(world.conn, base.INSTANCE)
    assert (state["halt_scope"], state["halt_reason"], state["halt_by"]) == (
        "all",
        "침해 의심",
        "root",
    )
    with pytest.raises(ControlError):  # 같은 범위로 다시 걸 수 없다
        as_root(world, lambda ctx: root.set_halt(ctx, "all", "다시"))
    as_root(world, lambda ctx: root.lift_halt(ctx, "확인 끝"))
    assert root.halt_state(world.conn, base.INSTANCE) is None
    rows = fetchall(
        world.conn, "SELECT action, undone_by FROM mint.forced_actions ORDER BY created_at"
    )
    assert [r["action"] for r in rows] == ["halt", "halt_lift"] and rows[0]["undone_by"]
    assert (
        len(world.events("global_halt_set")) == 1 and len(world.events("global_halt_lifted")) == 1
    )
    assert len(world.events("forced_action_recorded")) == 2


def test_a_named_root_operator_is_root_too(world):
    world.conn.execute("UPDATE mint.settings SET root_operators = ARRAY['root', 'boss']")
    world.conn.commit()
    as_admin(world, lambda ctx: root.set_halt(ctx, "freeze", "배포 동결"))
    assert root.halt_state(world.conn, base.INSTANCE)["halt_scope"] == "freeze"


def test_root_rejects_an_intake_that_is_still_being_checked(world):
    identifier = world.create()
    assert world.intake(identifier)["status"] == "received"
    with pytest.raises(ControlError):  # 관리자는 검사 전 신청을 결정할 수 없다
        world.decide(identifier, "reject", reason="이른 반려")
    as_root(world, lambda ctx: root.force_reject(ctx, identifier, "출처 불명"))
    row = world.intake(identifier)
    assert (row["status"], row["decision"]) == ("decided", "rejected")
    assert actions(world) == ["intake_reject"]


def test_root_rejects_an_intake_whose_checks_are_running(world):
    """검사 중인 신청도 Root는 닫는다(QA-BUG-006). 일반 결정은 DB 불변식이 막는다."""
    checking = world.create()
    world.conn.execute("UPDATE mint.intakes SET status = 'checking' WHERE id = %s", (checking,))
    world.conn.commit()
    with pytest.raises(ControlError):
        world.decide(checking, "reject", reason="이른 반려")
    as_root(world, lambda ctx: root.force_reject(ctx, checking, "출처 불명"))
    assert world.intake(checking)["decision"] == "rejected"


def test_root_suspends_and_resumes_a_server_with_impact_recorded(world):
    identifier = world.create()
    world.drain()
    world.decide(identifier, "approve", reason="심사 결과")
    world.drain()
    # 시험 대역은 LiteLLM 등록을 끝내지 않으므로 승인 상태로 둔다(등록 경로는 신청 시험이 다룬다)
    world.conn.execute(
        "UPDATE mint.servers SET status = 'approved' WHERE server_id = 'srv-a'"
        " AND status = 'awaiting_approval'"
    )
    world.conn.commit()
    as_root(world, lambda ctx: root.server_action(ctx, "srv-a", "suspend", "유출 의심"))
    assert world.server()["status"] == "suspended"
    as_root(world, lambda ctx: root.server_action(ctx, "srv-a", "resume", "확인 끝"))
    assert world.server()["status"] == "approved"
    first = fetchone(
        world.conn, "SELECT impact FROM mint.forced_actions ORDER BY created_at LIMIT 1"
    )
    assert set(first["impact"]) == {"approvals", "users"}  # 확인 창과 같은 영향 수치
    assert actions(world) == ["server_suspend", "server_resume"]


def test_lockout_denies_everything_for_the_person_and_unlock_lifts_only_that(world):
    world.conn.execute(
        "INSERT INTO mint.console_sessions (id_hash, instance_id, subject, user_id, key_token,"
        " role, idle_expiry, absolute_expiry) VALUES (repeat('a', 64), %s, 'staff', 'emp-1',"
        " 'sk-x', 'staff', now() + interval '1 hour', now() + interval '2 hours')",
        (base.INSTANCE,),
    )
    world.conn.commit()
    with pytest.raises(ControlError):  # 본인은 막을 수 없다
        as_admin(world, lambda ctx: root.lockout(ctx, None, "boss-1", "실수"))
    as_admin(world, lambda ctx: root.lockout(ctx, None, "emp-1", "퇴사"))
    denial = fetchone(
        world.conn, "SELECT scope_type, scope_id, server_id, tools, lifted_at FROM mint.denials"
    )
    assert (
        denial["scope_type"],
        denial["scope_id"],
        denial["server_id"],
        denial["tools"],
        denial["lifted_at"],
    ) == ("user", "emp-1", None, None, None)
    assert fetchone(world.conn, "SELECT revoked_at FROM mint.console_sessions")["revoked_at"]
    as_admin(world, lambda ctx: root.lockout(ctx, None, "emp-1", "다시"))  # 차단은 하나만
    assert fetchone(world.conn, "SELECT count(*) AS n FROM mint.denials")["n"] == 1
    as_admin(world, lambda ctx: root.unlock(ctx, "emp-1", "복직"))
    assert fetchone(world.conn, "SELECT lifted_at FROM mint.denials")["lifted_at"]
    assert actions(world) == ["person_lockout", "person_lockout", "person_unlock"]
    with pytest.raises(ControlError):
        as_admin(world, lambda ctx: root.unlock(ctx, "emp-1", "또"))


def test_an_admin_cannot_lock_out_root(world):
    world.conn.execute(
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES (%s, 'root', 'admin', repeat('b', 64), 'root-user')"
        " ON CONFLICT (instance_id, name) DO UPDATE SET user_id = 'root-user'",
        (base.INSTANCE,),
    )
    world.conn.commit()
    with pytest.raises(ControlError):
        as_admin(world, lambda ctx: root.lockout(ctx, None, "root-user", "권한 다툼"))


def test_propagation_lists_each_point_and_verify_stores_it(world):
    action_id = as_root(world, lambda ctx: root.set_halt(ctx, "local", "PC 점검"))
    points = as_root(world, lambda ctx: root.verify(ctx, action_id))
    assert [p["point"] for p in points] == [
        "MINT 판정",
        "LiteLLM 키 권한",
        "PC 수신",
        "관리 밖 경로",
    ]
    assert points[-1]["state"] == "확인되지 않음"
    row = fetchone(world.conn, "SELECT verified_at, propagation FROM mint.forced_actions")
    assert row["verified_at"] and len(row["propagation"]) == 4


def test_a_freeze_blocks_new_approvals_but_not_rejections(world):
    identifier = world.create()
    world.drain()
    as_root(world, lambda ctx: root.set_halt(ctx, "freeze", "배포 동결"))
    with pytest.raises(ControlError):
        world.decide(identifier, "approve", reason="심사 결과")
    world.decide(identifier, "reject", reason="동결 중 반려")
    assert world.intake(identifier)["decision"] == "rejected"


def test_lockout_does_not_take_over_an_ordinary_user_block(world):
    """「MCP 차단」으로 걸린 사용자 차단이 있어도 전체 차단은 따로 걸리고 해제도 그것만 푼다."""
    from mint_litellm.control import approvals as approval_domain

    as_admin(world, lambda ctx: approval_domain.create_denial(
        ctx, scope_type="user", scope_id="emp-1", server_id=None, tools=None,
        reason="MCP 차단", org_id=None))
    as_admin(world, lambda ctx: root.lockout(ctx, None, "emp-1", "퇴사"))
    rows = fetchall(world.conn, "SELECT reason, lifted_at FROM mint.denials ORDER BY id")
    assert [r["reason"] for r in rows] == ["MCP 차단", root.LOCKOUT_REASON_PREFIX + "퇴사"]
    as_admin(world, lambda ctx: root.unlock(ctx, "emp-1", "복직"))
    rows = fetchall(world.conn, "SELECT reason, lifted_at FROM mint.denials ORDER BY id")
    assert rows[0]["lifted_at"] is None and rows[1]["lifted_at"] is not None


def test_root_skips_the_checks_and_approves_an_intake_as_an_exception(world):
    identifier = world.create()
    assert world.intake(identifier)["status"] == "received"
    with pytest.raises(ControlError):  # 관리자는 검사 전 신청을 결정할 수 없다
        world.decide(identifier, "except", reason="이른 승인")
    as_root(world, lambda ctx: root.force_except(ctx, identifier, "긴급 업무"))
    row = world.intake(identifier)
    assert (row["status"], row["decision"]) == ("decided", "exception")
    assert actions(world) == ["intake_except"]


def test_cancel_runs_takes_back_pending_and_unused_call_approvals_only(world):
    from mint_litellm.control import approvals as approval_domain

    identifier = world.create()
    world.drain()
    world.decide(identifier, "approve", reason="심사 결과")
    org = fetchone(world.conn, "SELECT org_id FROM mint.usage_relations"
                   " WHERE server_id = 'srv-a'")["org_id"]

    def ask(ctx, who):
        return approval_domain.call_request(
            ctx, org_id=org, principal_type="user", principal_id=who, server_id="srv-a",
            tool="echo", args_fp="c" * 64, fp_key_version=1, policy_version_id=None,
            expires_in_minutes=30, requested_by=who)

    as_admin(world, lambda ctx: ask(ctx, "emp-1"))
    as_admin(world, lambda ctx: ask(ctx, "emp-2"))
    with pytest.raises(ControlError):
        as_admin(world, lambda ctx: root.cancel_runs(ctx, "server", "srv-a", "사고 대응"))
    as_root(world, lambda ctx: root.cancel_runs(ctx, "person", "emp-1", "사고 대응"))
    statuses = {r["principal_id"]: r["status"] for r in fetchall(
        world.conn, "SELECT principal_id, status FROM mint.call_approvals")}
    assert statuses == {"emp-1": "cancelled", "emp-2": "pending"}
    as_root(world, lambda ctx: root.cancel_runs(ctx, "server", "srv-a", "사고 대응"))
    assert {r["status"] for r in fetchall(
        world.conn, "SELECT status FROM mint.call_approvals")} == {"cancelled"}
    done = fetchall(world.conn, "SELECT target, impact FROM mint.forced_actions"
                    " WHERE action = 'run_cancel' ORDER BY created_at")
    assert [(d["target"], d["impact"]["call_approvals"]) for d in done] == [
        ("person:emp-1", 1), ("server:srv-a", 1)]
    with pytest.raises(ControlError):
        as_root(world, lambda ctx: root.cancel_runs(ctx, "team", "t1", "x"))
