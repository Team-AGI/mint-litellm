"""호출별 승인의 대상·행위 결속을 실제 DB에서 확인한다: 기록, 매칭, 소비, 변경 불가."""

from dataclasses import replace
from uuid import uuid4

import ctl_fixtures
import pytest
import test_confirmation_database as base
from psycopg import errors
from test_approval_contract_binding import snapshot_and_match
from test_plugin_database import ARGS_FP, run

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.plugin.buffer import ConsumptionLost
from mint_litellm.plugin.pipeline import match_call_approval
from mint_litellm.plugin.snapshot import PluginDatabase
from mint_litellm.types.target import WRITE, Target

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world

BOUND = Target("acme/app", "search.run", WRITE)


def granted(scene, **bound):
    requester = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
    call_id = approvals.call_request(
        requester, org_id="org1", principal_type="user", principal_id="u1", server_id="srv-1",
        tool="search", args_fp=ARGS_FP, fp_key_version=1, policy_version_id=None,
        expires_in_minutes=30, requested_by="boss", **bound,
    )
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    approvals.call_approve(approver, call_id, None)
    return call_id


def matcher(binding):
    return lambda *args: match_call_approval(*args, binding)


def status(scene, call_id):
    return scene.conn.execute(
        "SELECT status FROM mint.call_approvals WHERE id = %s", (call_id,)).fetchone()[0]


def test_the_request_records_the_target_and_action_and_they_cannot_change(world):
    scene, _ = world
    call_id = granted(scene, target=BOUND.target, action=BOUND.action)
    assert scene.conn.execute(
        "SELECT target, action FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone() == (BOUND.target, BOUND.action)
    for column in ("target", "action"):
        with pytest.raises(errors.CheckViolation):
            with scene.conn.transaction():
                scene.conn.execute(
                    f"UPDATE mint.call_approvals SET {column} = 'x' WHERE id = %s", (call_id,))


def test_a_target_without_an_action_is_refused(world):
    scene, _ = world
    with pytest.raises(errors.CheckViolation):
        with scene.conn.transaction():
            granted(scene, target="acme/app")


def test_a_bound_approval_is_consumed_only_by_a_call_with_the_same_target_and_action(
    world, tmp_path
):
    scene, dsn = world
    call_id = granted(scene, target=BOUND.target, action=BOUND.action)

    async def go():
        live, (failure, consume) = await snapshot_and_match(
            scene, dsn, tmp_path, matcher(BOUND))
        try:
            assert failure is None and consume.target == BOUND.target
            for forged in (replace(consume, target="acme/other"),
                           replace(consume, action="search.other")):
                with pytest.raises(ConsumptionLost):
                    await live.insert_event(scene.event(), forged)
            assert status(scene, call_id) == "approved"
            assert await live.insert_event(scene.event(), consume)
        finally:
            await live.close()

    run(go())
    assert status(scene, call_id) == "consumed"


@pytest.mark.parametrize(
    "binding",
    [None, Target("acme/other", "search.run", WRITE), Target("acme/app", "search.other", WRITE)],
    ids=["unbound-call", "other-target", "other-action"],
)
def test_a_bound_approval_does_not_match_a_call_with_another_binding(world, tmp_path, binding):
    scene, dsn = world
    granted(scene, target=BOUND.target, action=BOUND.action)

    async def go():
        live, result = await snapshot_and_match(scene, dsn, tmp_path, matcher(binding))
        await live.close()
        return result

    failure, consume = run(go())
    assert failure is not None and consume is None


def test_an_unbound_approval_does_not_match_a_bound_call(world, tmp_path):
    scene, dsn = world
    granted(scene)

    async def go():
        live, result = await snapshot_and_match(scene, dsn, tmp_path, matcher(BOUND))
        await live.close()
        return result

    failure, consume = run(go())
    assert failure is not None and consume is None


def approve_deployment(scene, url, allowed_tools=None):
    scene.conn.execute(
        "UPDATE mint.deployment_contracts SET status = 'superseded'"
        " WHERE instance_id = %s AND server_id = 'srv-1' AND status = 'approved'", (scene.iid,))
    deployment_id = uuid4()
    scene.conn.execute(
        "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text,"
        " sha256, url, url_sha256, transport, auth_type, allowed_tools, status)"
        " VALUES (%s, %s, 'srv-1', '{}', repeat('a', 64), %s, repeat('b', 64), 'http', 'none',"
        " %s, 'candidate')", (deployment_id, scene.iid, url, allowed_tools))
    scene.conn.execute(
        "UPDATE mint.deployment_contracts SET status = 'approved' WHERE id = %s", (deployment_id,))


@pytest.mark.parametrize(
    ("url", "tools", "expected"),
    [
        ("https://api.githubcopilot.com/mcp/", None, "github"),
        ("https://n8n.corp.example/mcp", ["n8n_get_workflow", "n8n_test_workflow"], "n8n"),
        ("https://n8n.corp.example/mcp", ["n8n_get_workflow"], None),
        ("https://mcp.example/api", ["search"], None),
    ],
)
def test_the_snapshot_selects_the_profile_from_the_approved_deployment(
    world, tmp_path, url, tools, expected
):
    scene, dsn = world
    approve_deployment(scene, url, tools)

    async def go():
        live = PluginDatabase(dsn, acquire_timeout=3)
        try:
            return (await live.read_snapshot(scene.query())).auto_profile
        finally:
            await live.close()

    assert run(go()) == expected
