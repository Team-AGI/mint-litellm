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
from mint_litellm.control.errors import ControlError
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


def test_the_policy_input_carries_defaults_filled_from_the_contract_and_the_intake(
    world, tmp_path
):
    scene, dsn = world
    scene.conn.execute(
        "UPDATE mint.servers SET contract_status = 'managed', last_observed_at = now()"
        " WHERE instance_id = %s", (scene.iid,))
    contract_id = uuid4()
    scene.conn.execute(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (%s, %s, 'srv-1', 'server', 'search', %s, repeat('a', 64), repeat('b', 64),"
        " 'high', 'delete', 'intake', 'candidate')",
        (contract_id, scene.iid,
         '{"description":"d","input_schema":{"properties":{"q":{},"limit":{}}}}'),
    )
    scene.conn.execute("UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s",
                       (contract_id,))
    scene.conn.execute(
        "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, status, purpose,"
        " data_grade, allowed_resources, provider, owner_user_id, readiness, data_return_terms,"
        " requested_by, decided_by, decision, decided_at) VALUES (%s, %s, 'org1', 'srv-1',"
        " 'operator', 'decided', 'support', 'restricted', '[]'::jsonb, 'p', 'u1',"
        " '{\"credential_notice\":1,\"revocation_record\":1,\"audit_access_days\":1}'::jsonb,"
        " 'terms', 'u1', 'boss', 'approved', now())",
        (uuid4(), scene.iid),
    )
    calls = []

    async def go():
        live, deps = base.replica(scene, dsn, tmp_path, calls=calls)
        try:
            await base.ask(scene, deps)
        finally:
            await live.close()

    run(go())
    (doc,) = calls
    conditions = doc["approval"]["conditions"]
    assert conditions["allowed_arg_keys"] == ["limit", "q"]
    assert conditions["require_user_confirmation"]["tools"] == ["search"]
    assert conditions["require_consent"] == "support"
    assert doc["tool"]["action_type"] == "delete"


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


def status_of(scene, table, row_id):
    return scene.conn.execute(
        f"SELECT status FROM mint.{table} WHERE id = %s", (row_id,)).fetchone()[0]


def test_a_call_approval_is_bound_to_the_approved_contract_when_requested(world):
    scene, _ = world
    contract = make_managed(scene, "high")
    call_id = granted_call_approval(scene)
    assert scene.conn.execute(
        "SELECT contract_id FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone()[0] == contract


def test_a_call_approval_cannot_be_requested_for_a_tool_without_an_approved_contract(world):
    scene, _ = world
    make_managed(scene, "high")
    requester = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
    with pytest.raises(ControlError, match="승인된 계약이 없어"):
        approvals.call_request(
            requester, org_id="org1", principal_type="user", principal_id="u1",
            server_id="srv-1", tool="other", args_fp=ARGS_FP, fp_key_version=1,
            policy_version_id=None, expires_in_minutes=30, requested_by="boss")


def test_a_call_approval_for_a_server_without_contracts_stays_unbound(world, tmp_path):
    scene, dsn = world
    call_id = granted_call_approval(scene)
    assert scene.conn.execute(
        "SELECT contract_id FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone()[0] is None

    async def go():
        live, (failure, consume) = await snapshot_and_match(
            scene, dsn, tmp_path, match_call_approval)
        try:
            assert failure is None and consume.contract_id is None
            await live.insert_event(scene.event(), consume)
        finally:
            await live.close()

    run(go())
    assert status_of(scene, "call_approvals", call_id) == "consumed"


def test_a_bound_call_approval_is_consumed_while_its_contract_is_current(world, tmp_path):
    scene, dsn = world
    contract = make_managed(scene, "high")
    call_id = granted_call_approval(scene)

    async def go():
        live, (failure, consume) = await snapshot_and_match(
            scene, dsn, tmp_path, match_call_approval)
        try:
            assert failure is None and consume.contract_id == str(contract)
            await live.insert_event(scene.event(), consume)
        finally:
            await live.close()

    run(go())
    assert status_of(scene, "call_approvals", call_id) == "consumed"


def test_replacing_a_contract_expires_the_unused_approvals_bound_to_it(world, tmp_path):
    scene, dsn = world
    contract = make_managed(scene, "high")
    pending = approvals.call_request(
        Context(scene.conn, scene.iid, Operator("boss", "admin", "boss")),
        org_id="org1", principal_type="user", principal_id="u1", server_id="srv-1",
        tool="search", args_fp=ARGS_FP, fp_key_version=1, policy_version_id=None,
        expires_in_minutes=30, requested_by="boss")
    approved = granted_call_approval(scene)

    async def first():
        live, deps = base.replica(scene, dsn, tmp_path)
        try:
            await base.ask(scene, deps)
        finally:
            await live.close()

    run(first())
    base.decide_as_staff(scene)
    (confirmation,) = scene.conn.execute(
        "SELECT id FROM mint.self_confirmations WHERE instance_id = %s", (scene.iid,)
    ).fetchone()
    assert status_of(scene, "self_confirmations", confirmation) == "confirmed"
    replace_contract(scene, contract, "high")
    assert status_of(scene, "call_approvals", pending) == "expired"
    assert status_of(scene, "call_approvals", approved) == "expired"
    assert status_of(scene, "self_confirmations", confirmation) == "expired"


def test_a_request_racing_a_replacement_ends_expired_without_a_deadlock(world):
    """요청이 계약 행의 공유 잠금을 쥔 채 교체가 대기하고, 요청이 커밋되면 새 승인도 만료된다."""
    import threading

    import psycopg

    scene, _ = world
    contract = make_managed(scene, "high")
    requesting = psycopg.connect(scene.url)
    replaced = threading.Event()
    failure: list[BaseException] = []

    def replace_in_thread():
        try:
            with psycopg.connect(scene.url, autocommit=True) as other:
                other.execute("SET lock_timeout = '20s'")
                other.execute(
                    "UPDATE mint.tool_contracts SET status = 'superseded' WHERE id = %s",
                    (contract,))
        except BaseException as exc:
            failure.append(exc)
        finally:
            replaced.set()

    try:
        call_id = approvals.call_request(
            Context(requesting, scene.iid, Operator("boss", "admin", "boss")),
            org_id="org1", principal_type="user", principal_id="u1", server_id="srv-1",
            tool="search", args_fp=ARGS_FP, fp_key_version=1, policy_version_id=None,
            expires_in_minutes=30, requested_by="boss")
        worker = threading.Thread(target=replace_in_thread)
        worker.start()
        for _ in range(100):
            waiting = scene.conn.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
                " AND wait_event_type = 'Lock'").fetchone()[0]
            if waiting:
                break
            replaced.wait(0.1)
        assert waiting == 1 and not replaced.is_set()
        requesting.commit()
        worker.join(30)
    finally:
        requesting.close()
    assert not failure
    assert status_of(scene, "call_approvals", call_id) == "expired"
