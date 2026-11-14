"""상시 승인 규칙: 맞는 호출은 규칙이 정한 기간 승인으로 열리고, 나머지는 대기로 남는다."""

from uuid import uuid4

import ctl_fixtures
import pytest
import test_confirmation_database as base
from test_call_approval_window import with_database
from test_plugin_database import ARGS_FP

from mint_litellm.control import call_approval_rules as rules
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.errors import ControlError

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world

ADMIN = Operator("boss", "admin", "boss")


@pytest.fixture(autouse=True)
def plugin_may_open_requests(world):
    world[0].conn.execute("GRANT INSERT (target, action) ON mint.call_approvals TO mint_plugin")


def contract(scene, action="read", tool="search"):
    cid = uuid4()
    scene.conn.execute(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (%s, %s, 'srv-1', 'server', %s, '{}', repeat('a', 64), repeat('b', 64),"
        " 'low', %s, 'intake', 'candidate')", (cid, scene.iid, tool, action))
    scene.conn.execute("UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s", (cid,))
    return cid


def managed(scene):
    scene.conn.execute(
        "UPDATE mint.servers SET contract_status = 'managed' WHERE instance_id = %s", (scene.iid,))


def ctx(scene):
    return Context(scene.conn, scene.iid, ADMIN)


def add_rule(scene, **kw):
    args = {"org_id": "org1", "action_class": "read", "window_minutes": 30, **kw}
    return rules.add(ctx(scene), **args)


def params(scene, contract_id, *, tool="search", principal_id="u1", args_fp=ARGS_FP):
    return {
        "id": str(uuid4()), "iid": scene.iid, "org_id": "org1", "principal_type": "user",
        "principal_id": principal_id, "server_id": "srv-1", "tool": tool, "args_fp": args_fp,
        "fp_key_version": 1, "policy_version_id": "pv1", "requested_by": "mint-auto",
        "minutes": 30, "contract_id": str(contract_id) if contract_id else None,
        "exec_contract_sha256": None, "target": None, "action": None,
    }


def opened(scene, p):
    async def body(live):
        return await live.request_call_approval(p)

    call_id = with_database(world_dsn[0], body)
    return scene.conn.execute(
        "SELECT status, approved_by, window_minutes, valid_until IS NOT NULL"
        " FROM mint.call_approvals WHERE id = %s", (call_id,)).fetchone()


world_dsn: list[str] = []


@pytest.fixture(autouse=True)
def remember_dsn(world):
    world_dsn[:] = [world[1]]


def test_a_matching_rule_opens_a_window_approval_recorded_to_the_rule(world):
    scene, _ = world
    managed(scene)
    cid = contract(scene)
    rule = add_rule(scene)
    status, by, minutes, has_until = opened(scene, params(scene, cid))
    assert (status, by, minutes, has_until) == ("approved", f"rule:{rule}", 30, True)


def test_no_rule_leaves_the_request_pending(world):
    scene, _ = world
    managed(scene)
    assert opened(scene, params(scene, contract(scene)))[0] == "pending"


@pytest.mark.parametrize("action", ["delete", "external_send", "credential_access"])
def test_one_shot_actions_never_match_and_cannot_have_rules(world, action):
    scene, _ = world
    managed(scene)
    cid = contract(scene, action)
    add_rule(scene)
    assert opened(scene, params(scene, cid))[0] == "pending"
    with pytest.raises(ControlError):
        add_rule(scene, action_class=action)


def test_a_call_without_a_contract_class_never_matches(world):
    scene, _ = world
    managed(scene)
    add_rule(scene)
    assert opened(scene, params(scene, None))[0] == "pending"


def test_a_write_rule_does_not_cover_reads_and_the_reverse(world):
    scene, _ = world
    managed(scene)
    add_rule(scene, action_class="write")
    assert opened(scene, params(scene, contract(scene, "read")))[0] == "pending"


def test_scope_server_and_tool_pattern_narrow_the_match(world):
    scene, _ = world
    managed(scene)
    cid = contract(scene)
    add_rule(scene, principal_type="user", principal_id="someone-else")
    add_rule(scene, tool_pattern="fetch_*")
    assert opened(scene, params(scene, cid))[0] == "pending"
    mine = add_rule(scene, principal_type="user", principal_id="u1", server_id="srv-1",
                    tool_pattern="sea*")
    assert opened(scene, params(scene, cid, args_fp="c" * 64))[1] == f"rule:{mine}"


def test_the_underscore_in_a_pattern_is_not_a_wildcard(world):
    scene, _ = world
    managed(scene)
    cid = contract(scene, tool="a_c")
    add_rule(scene, tool_pattern="a_c")
    other = contract(scene, tool="abc")
    assert opened(scene, params(scene, cid, tool="a_c"))[0] == "approved"
    assert opened(scene, params(scene, other, tool="abc"))[0] == "pending"


def test_a_disabled_or_expired_rule_does_not_match(world):
    scene, _ = world
    managed(scene)
    cid = contract(scene)
    old = add_rule(scene)
    rules.disable(ctx(scene), old)
    assert opened(scene, params(scene, cid))[0] == "pending"
    scene.conn.execute(
        "INSERT INTO mint.call_approval_rules (id, instance_id, org_id, scope_type, action_class,"
        " window_minutes, valid_until, created_by) VALUES (%s, %s, 'org1', 'org', 'read', 10,"
        " now() - interval '1 minute', 'boss')", (uuid4(), scene.iid))
    assert opened(scene, params(scene, cid, args_fp="d" * 64))[0] == "pending"


def test_creating_and_disabling_write_events_and_validate_input(world):
    scene, _ = world
    managed(scene)
    rule = add_rule(scene, window_minutes=10)
    rules.disable(ctx(scene), rule)
    kinds = [r[0] for r in scene.conn.execute(
        "SELECT kind FROM mint.events WHERE instance_id = %s ORDER BY inserted_at",
        (scene.iid,)).fetchall()]
    assert kinds == ["call_approval_rule_created", "call_approval_rule_disabled"]
    with pytest.raises(ControlError):
        rules.disable(ctx(scene), rule)
    for bad in ({"window_minutes": 20}, {"tool_pattern": "a b"}, {"principal_id": "u1"},
                {"server_id": "nope"}):
        with pytest.raises(ControlError):
            add_rule(scene, **bad)
