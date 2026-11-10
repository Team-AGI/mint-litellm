"""승인과 도구 계약의 결속을 실제 DB에서 확인한다.

- 계약의 위험 등급은 승인이 어떤 경로로 만들어졌든 정책 입력에 들어간다.
- 호출별 승인과 본인 확인은 받은 때의 도구 계약에서만 소비된다.
"""

from uuid import uuid4

import ctl_fixtures
import pytest
import test_confirmation_database as base
from plugin_helpers import config, request, user_principal
from test_plugin_database import ARGS_FP, run

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.plugin.buffer import ConsumptionLost
from mint_litellm.plugin.pipeline import match_call_approval, match_confirmation
from mint_litellm.plugin.snapshot import PluginDatabase
from mint_litellm.types.identity import OrgSource

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world


def add_contract(scene, grade, *, tool="search"):
    """도구 계약 후보를 만들어 곧바로 승인 상태로 올린다. 새 계약의 식별자를 돌려준다."""
    contract_id = uuid4()
    scene.conn.execute(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (%s, %s, 'srv-1', 'server', %s, '{}', repeat('a', 64), repeat('b', 64), %s,"
        " 'read', 'intake', 'candidate')",
        (contract_id, scene.iid, tool, grade),
    )
    scene.conn.execute("UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s",
                       (contract_id,))
    return contract_id


def make_managed(scene, grade):
    scene.conn.execute(
        "UPDATE mint.servers SET contract_status = 'managed', last_observed_at = now()"
        " WHERE instance_id = %s", (scene.iid,))
    return add_contract(scene, grade)


def replace_contract(scene, old, grade):
    scene.conn.execute("UPDATE mint.tool_contracts SET status = 'superseded' WHERE id = %s", (old,))
    return add_contract(scene, grade)


def granted_call_approval(scene):
    """운영자 명령과 같은 경로(요청·승인)로 호출별 승인을 하나 받는다."""
    requester = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
    call_id = approvals.call_request(
        requester, org_id="org1", principal_type="user", principal_id="u1", server_id="srv-1",
        tool="search", args_fp=ARGS_FP, fp_key_version=1, policy_version_id=None,
        expires_in_minutes=30, requested_by="boss",
    )
    approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
    approvals.call_approve(approver, call_id, None)
    return call_id


def principal(scene):
    return user_principal(instance_id=scene.iid).model_copy(
        update={"org_id": "org1", "org_source": OrgSource.TEAM})


async def snapshot_and_match(scene, dsn, tmp_path, matcher):
    live = PluginDatabase(dsn, acquire_timeout=3)
    try:
        snap = await live.read_snapshot(scene.query())
        cfg = config(tmp_path, instance_id=scene.iid)
        result = matcher(
            snap, principal(scene), request().resolved, "search", {"q": "x"}, cfg, uuid4())
        return live, result
    except BaseException:
        await live.close()
        raise


def test_the_policy_input_carries_the_contract_grade_not_only_approval_conditions(
    world, tmp_path
):
    scene, dsn = world
    contract = make_managed(scene, "low")
    (conditions,) = scene.conn.execute(
        "SELECT conditions FROM mint.approvals WHERE id = %s", (scene.approval,)).fetchone()
    assert conditions == {}
    calls = []

    async def go():
        live, deps = base.replica(scene, dsn, tmp_path, calls=calls)
        try:
            await base.ask(scene, deps)
            replace_contract(scene, contract, "high")
            await base.ask(scene, deps)
        finally:
            await live.close()

    run(go())
    assert [c["tool"].get("risk_grade") for c in calls] == ["low", "high"]


def test_a_call_approval_given_under_a_replaced_contract_does_not_match(world, tmp_path):
    scene, dsn = world
    contract = make_managed(scene, "high")
    granted_call_approval(scene)
    replace_contract(scene, contract, "high")

    async def go():
        live, (failure, consume) = await snapshot_and_match(
            scene, dsn, tmp_path, match_call_approval)
        await live.close()
        return failure, consume

    failure, consume = run(go())
    assert failure is not None and consume is None


def test_a_call_approval_matched_before_the_replacement_is_not_consumed_after_it(
    world, tmp_path
):
    scene, dsn = world
    contract = make_managed(scene, "high")
    call_id = granted_call_approval(scene)

    async def go():
        live, (failure, consume) = await snapshot_and_match(
            scene, dsn, tmp_path, match_call_approval)
        try:
            assert failure is None and consume is not None
            replace_contract(scene, contract, "high")
            with pytest.raises(ConsumptionLost):
                await live.insert_event(scene.event(), consume)
        finally:
            await live.close()

    run(go())
    assert scene.conn.execute(
        "SELECT status FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone()[0] != "consumed"


def test_a_self_confirmation_given_under_a_replaced_contract_does_not_match(world, tmp_path):
    scene, dsn = world
    contract = make_managed(scene, "high")

    async def first():
        live, deps = base.replica(scene, dsn, tmp_path)
        try:
            await base.ask(scene, deps)
        finally:
            await live.close()

    run(first())
    base.decide_as_staff(scene)
    replace_contract(scene, contract, "high")

    async def go():
        live, (failure, consume) = await snapshot_and_match(
            scene, dsn, tmp_path, match_confirmation)
        await live.close()
        return failure, consume

    failure, consume = run(go())
    assert failure is not None and consume is None
