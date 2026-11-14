"""거부 기억·승인 화면 표시용 열을 실제 DB에서 확인한다."""

from uuid import uuid4

import ctl_fixtures
import test_confirmation_database as base
from test_call_approval_window import requested, with_database
from test_plugin_database import ARGS_FP

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.plugin.call_display import call_display

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world


def query(scene, fp=ARGS_FP, minutes=30):
    return {
        "iid": scene.iid, "principal_type": "user", "principal_id": "u1", "server_id": "srv-1",
        "tool": "search", "args_fp": fp, "fp_key_version": 1, "minutes": minutes,
    }


def reject(scene, call_id, reason):
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    approvals.call_reject(approver, call_id, reason)


def test_a_rejection_is_remembered_for_the_same_call_only_and_carries_the_reason(world):
    scene, dsn = world
    call_id = requested(scene)
    reject(scene, call_id, "  범위를 벗어난 요청  ")
    assert scene.conn.execute(
        "SELECT status, decision_reason, decided_at IS NOT NULL FROM mint.call_approvals"
        " WHERE id = %s", (call_id,)).fetchone() == ("rejected", "범위를 벗어난 요청", True)

    async def body(live):
        assert await live.recent_call_outcome(query(scene)) == ("rejected", "범위를 벗어난 요청")
        assert await live.recent_call_outcome(query(scene, fp="0" * 64)) is None
        assert await live.recent_call_outcome(query(scene, minutes=0)) is None

    with_database(dsn, body)


def test_an_approval_that_ran_out_is_reported_as_expired(world):
    scene, dsn = world
    call_id = requested(scene)
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    approvals.call_approve(approver, call_id, None, 10)
    scene.conn.execute("ALTER TABLE mint.call_approvals DISABLE TRIGGER USER")
    scene.conn.execute(
        "UPDATE mint.call_approvals SET valid_until = now() - interval '1 minute' WHERE id = %s",
        (call_id,))

    async def body(live):
        assert await live.recent_call_outcome(query(scene)) == ("expired", None)

    with_database(dsn, body)


def test_the_opened_request_keeps_masked_arguments_and_the_request_time(world):
    scene, dsn = world
    policy = scene.conn.execute(
        "SELECT id FROM mint.policy_versions WHERE status = 'active'").fetchone()[0]
    shown = call_display({"q": "mail a@b.co", "api_key": "abc", "n": 3})

    async def body(live):
        return await live.request_call_approval({
            "id": uuid4(), "iid": scene.iid, "org_id": "org1", "principal_type": "user",
            "principal_id": "u1", "server_id": "srv-1", "tool": "search", "args_fp": ARGS_FP,
            "fp_key_version": 1, "policy_version_id": policy, "requested_by": "mint-auto",
            "minutes": 30, "contract_id": None, "exec_contract_sha256": None, "target": None,
            "action": None, "display": shown,
        })

    call_id = with_database(dsn, body)
    display, at = scene.conn.execute(
        "SELECT display, requested_at FROM mint.call_approvals WHERE id = %s",
        (call_id,)).fetchone()
    assert display == shown and at is not None
    assert "abc" not in str(display) and "a@b.co" not in str(display)
