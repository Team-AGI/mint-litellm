"""승인 대기 보류가 쓰는 DB 동작: 같은 대기 요청 재사용과 요청 상태 읽기를 실제 DB에서 확인한다."""

from uuid import uuid4

import ctl_fixtures
import pytest
import test_confirmation_database as base
from test_call_approval_window import with_database
from test_plugin_database import ARGS_FP

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world


@pytest.fixture(autouse=True)
def plugin_may_open_requests(world):
    world[0].conn.execute("GRANT INSERT (target, action) ON mint.call_approvals TO mint_plugin")


def params(scene, args_fp=ARGS_FP):
    return {
        "id": str(uuid4()),
        "iid": scene.iid,
        "org_id": "org1",
        "principal_type": "user",
        "principal_id": "u1",
        "server_id": "srv-1",
        "tool": "search",
        "args_fp": args_fp,
        "fp_key_version": 1,
        "policy_version_id": "pv1",
        "requested_by": "auto",
        "minutes": 30,
        "contract_id": None,
        "exec_contract_sha256": None,
        "target": None,
        "action": None,
    }


def count(scene):
    return scene.conn.execute(
        "SELECT count(*) FROM mint.call_approvals WHERE instance_id = %s", (scene.iid,)
    ).fetchone()[0]


def test_an_identical_pending_request_is_reused_not_duplicated(world):
    scene, dsn = world

    async def body(live):
        first = await live.request_call_approval(params(scene))
        again = await live.request_call_approval(params(scene))
        other = await live.request_call_approval(params(scene, "f" * 64))
        return first, again, other

    first, again, other = with_database(dsn, body)
    assert first == again and other not in (None, first) and count(scene) == 2


def test_the_request_state_is_read_through_its_life(world):
    scene, dsn = world

    async def body(live):
        call_id = await live.request_call_approval(params(scene))
        states = [await live.call_approval_status(scene.iid, call_id)]
        approver = Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))
        approvals.call_approve(approver, call_id, None, None)
        states.append(await live.call_approval_status(scene.iid, call_id))
        states.append(await live.call_approval_status(scene.iid, str(uuid4())))
        return states

    assert with_database(dsn, body) == ["pending", "approved", None]
