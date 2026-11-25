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
