"""호출별 승인의 사용 기간(1회·10분·30분)을 실제 DB에서 확인한다."""

import asyncio
import dataclasses
import time
from uuid import uuid4

import ctl_fixtures
import pytest
import test_confirmation_database as base
from plugin_helpers import config, request, user_principal
from test_plugin_database import ARGS_FP, run

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import expiry
from mint_litellm.plugin.buffer import ConsumptionLost
from mint_litellm.plugin.pipeline import match_call_approval
from mint_litellm.plugin.snapshot import PluginDatabase
from mint_litellm.types.identity import OrgSource

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world


def requested(scene, *, ttl_minutes=30):
    requester = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
    return approvals.call_request(
        requester, org_id="org1", principal_type="user", principal_id="u1", server_id="srv-1",
        tool="search", args_fp=ARGS_FP, fp_key_version=1, policy_version_id=None,
        expires_in_minutes=ttl_minutes, requested_by="boss",
    )


def granted(scene, window=None):
    """운영자 명령과 같은 경로(요청·승인)로 호출별 승인을 하나 받는다."""
    call_id = requested(scene)
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    approvals.call_approve(approver, call_id, None, window)
    return call_id


def row(scene, call_id, columns="status, state_version, valid_until"):
    return scene.conn.execute(
        f"SELECT {columns} FROM mint.call_approvals WHERE id = %s", (call_id,)).fetchone()


def uses(scene, call_id):
    return scene.conn.execute(
        "SELECT count(*) FROM mint.call_approval_uses WHERE call_approval_id = %s",
        (call_id,)).fetchone()[0]


def principal(scene):
    return user_principal(instance_id=scene.iid).model_copy(
        update={"org_id": "org1", "org_source": OrgSource.TEAM})


async def match(scene, live, tmp_path, arguments=None):
    snap = await live.read_snapshot(scene.query())
    return match_call_approval(
        snap, principal(scene), request().resolved, "search", arguments or {"q": "x"},
        config(tmp_path, instance_id=scene.iid), uuid4())


def with_database(dsn, body):
    async def go():
        live = PluginDatabase(dsn, acquire_timeout=3, max_size=8)
        try:
            return await body(live)
        finally:
            await live.close()

    return run(go())


def test_the_default_is_single_use_and_unchanged(world, tmp_path):
    scene, dsn = world
    call_id = granted(scene)
    assert row(scene, call_id, "window_minutes, valid_until") == (None, None)

    async def body(live):
        failure, consume = await match(scene, live, tmp_path)
        assert failure is None and consume.windowed is False
        await live.insert_event(scene.event(), consume)
        with pytest.raises(ConsumptionLost):
            await live.insert_event(scene.event(), consume)

    with_database(dsn, body)
    assert row(scene, call_id)[0] == "consumed" and uses(scene, call_id) == 0


@pytest.mark.parametrize("minutes", [10, 30])
def test_a_window_allows_repeated_matching_calls_and_records_each_use(world, tmp_path, minutes):
    scene, dsn = world
    call_id = granted(scene, minutes)
    before = row(scene, call_id)
    assert before[0] == "approved"
    window, span = scene.conn.execute(
        "SELECT window_minutes, valid_until - now() FROM mint.call_approvals WHERE id = %s",
        (call_id,)).fetchone()
    assert window == minutes and 0 < span.total_seconds() <= minutes * 60

    async def body(live):
        for _ in range(3):
            failure, consume = await match(scene, live, tmp_path)
            assert failure is None and consume.windowed is True
            await live.insert_event(scene.event(), consume)

    with_database(dsn, body)
    assert row(scene, call_id) == before and uses(scene, call_id) == 3
    assert scene.conn.execute(
        "SELECT count(*) FROM mint.events WHERE instance_id = %s AND invocation_id IS NOT NULL",
        (scene.iid,)
    ).fetchone()[0] == 3


def test_a_window_outlives_the_request_deadline_and_stops_at_its_own_end(world, tmp_path):
    scene, dsn = world
    call_id = requested(scene, ttl_minutes=1)
    # 요청 기한(expires_at)은 승인 직후 지나지만 기간은 이어진다.
    scene.conn.execute("ALTER TABLE mint.call_approvals DISABLE TRIGGER call_approvals_2_frozen")
    scene.conn.execute(
        "UPDATE mint.call_approvals SET expires_at = now() + interval '1 second' WHERE id = %s",
        (call_id,))
    scene.conn.execute("ALTER TABLE mint.call_approvals ENABLE TRIGGER call_approvals_2_frozen")
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    approvals.call_approve(approver, call_id, None, 10)
    time.sleep(1.5)
    assert expiry.expire_due(scene.conn, scene.iid)["call_approvals"] == 0
    assert row(scene, call_id)[0] == "approved"

    async def body(live):
        failure, consume = await match(scene, live, tmp_path)
        assert failure is None and consume.windowed is True
        await live.insert_event(scene.event(), consume)
        return consume

    consume = with_database(dsn, body)
    # 기간이 끝난 뒤에는 같은 요청으로도 사용 기록이 남지 않는다.
    scene.conn.execute("ALTER TABLE mint.call_approvals DISABLE TRIGGER USER")
    scene.conn.execute(
        "UPDATE mint.call_approvals SET valid_until = now() - interval '1 second'"
        " WHERE id = %s", (call_id,))
    scene.conn.execute("ALTER TABLE mint.call_approvals ENABLE TRIGGER USER")

    async def after(live):
        with pytest.raises(ConsumptionLost):
            await live.insert_event(scene.event(), consume)

    with_database(dsn, after)
    assert uses(scene, call_id) == 1
    assert expiry.expire_due(scene.conn, scene.iid)["call_approvals"] == 1
    assert row(scene, call_id)[0] == "expired"


def test_different_arguments_do_not_match_a_window(world, tmp_path):
    scene, dsn = world
    granted(scene, 10)

    async def body(live):
        failure, consume = await match(scene, live, tmp_path, {"q": "other"})
        assert consume is None and failure is not None

    with_database(dsn, body)


def test_a_mismatching_binding_is_not_recorded_as_a_use(world, tmp_path):
    scene, dsn = world
    call_id = granted(scene, 10)

    async def body(live):
        _, consume = await match(scene, live, tmp_path)
        wrong = dataclasses.replace(consume, args_fp="c" * 64)
        with pytest.raises(ConsumptionLost):
            await live.insert_event(scene.event(), wrong)

    with_database(dsn, body)
    assert uses(scene, call_id) == 0


def test_revoking_a_window_stops_it_immediately(world, tmp_path):
    scene, dsn = world
    call_id = granted(scene, 30)

    async def body(live):
        _, consume = await match(scene, live, tmp_path)
        await live.insert_event(scene.event(), consume)
        admin = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
        approvals.call_cancel(admin, call_id)
        with pytest.raises(ConsumptionLost):
            await live.insert_event(scene.event(), consume)
        failure, again = await match(scene, live, tmp_path)
        assert again is None and failure is not None

    with_database(dsn, body)
    assert row(scene, call_id)[0] == "cancelled" and uses(scene, call_id) == 1


def test_replicas_use_a_window_concurrently_and_one_invocation_counts_once(world, tmp_path):
    scene, dsn = world
    call_id = granted(scene, 10)
    events = [scene.event() for _ in range(8)]

    async def body(live):
        _, consume = await match(scene, live, tmp_path)

        async def one(event):
            mine = dataclasses.replace(consume, invocation_id=event.invocation_id)
            await live.insert_event(event, mine)
            return mine

        results = await asyncio.gather(*(one(e) for e in events))
        with pytest.raises(ConsumptionLost):
            await live.insert_event(scene.event(), results[0])

    with_database(dsn, body)
    assert uses(scene, call_id) == 8 and row(scene, call_id)[0] == "approved"


def test_single_use_is_still_exactly_once_under_concurrency(world, tmp_path):
    scene, dsn = world
    call_id = granted(scene)

    async def body(live):
        _, consume = await match(scene, live, tmp_path)

        async def one():
            event = scene.event()
            mine = dataclasses.replace(consume, invocation_id=event.invocation_id)
            try:
                await live.insert_event(event, mine)
                return 1
            except ConsumptionLost:
                return 0

        return sum(await asyncio.gather(*(one() for _ in range(8))))

    assert with_database(dsn, body) == 1
    assert row(scene, call_id)[0] == "consumed"


def test_the_window_choice_is_validated_and_sealed(world):
    scene, _ = world
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    call_id = requested(scene)
    with pytest.raises(ControlError):
        approvals.call_approve(approver, call_id, None, 15)
    approvals.call_approve(approver, call_id, None, 30)
    for statement in (
        "UPDATE mint.call_approvals SET valid_until = valid_until + interval '1 hour'",
        "UPDATE mint.call_approvals SET window_minutes = 10",
        "UPDATE mint.call_approvals SET status = 'consumed',"
        " consumed_invocation_id = gen_random_uuid()",
    ):
        with pytest.raises(Exception):  # noqa: B017
            scene.conn.execute(f"{statement} WHERE id = %s", (call_id,))
    # 승인 전이가 아닌 곳에서는 기간을 새로 정할 수도 없다.
    other = granted(scene)
    with pytest.raises(Exception, match="only be set when approving"):
        scene.conn.execute(
            "UPDATE mint.call_approvals SET window_minutes = 10,"
            " valid_until = now() + interval '10 minutes' WHERE id = %s", (other,))


def test_the_use_table_is_append_only(world, tmp_path):
    scene, dsn = world
    call_id = granted(scene, 10)

    async def body(live):
        _, consume = await match(scene, live, tmp_path)
        await live.insert_event(scene.event(), consume)

    with_database(dsn, body)
    for statement in (
        "UPDATE mint.call_approval_uses SET used_at = now()",
        "DELETE FROM mint.call_approval_uses",
        "TRUNCATE mint.call_approval_uses",
    ):
        with pytest.raises(Exception, match="append-only"):
            scene.conn.execute(statement)
    assert uses(scene, call_id) == 1
