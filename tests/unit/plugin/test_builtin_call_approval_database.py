"""내장 도구 가상 서버의 호출별 승인: 서버 행이 없어도 열리고, 그 밖의 미등록 서버는 여전히 막힌다."""

import ctl_fixtures
import psycopg
import pytest
import test_confirmation_database as base
from test_call_approval_window import requested
from test_plugin_database import ARGS_FP

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = base.world


def open_for(scene, server_id):
    ctx = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
    return approvals.call_request(
        ctx, org_id="org1", principal_type="user", principal_id="u1", server_id=server_id,
        tool="Bash", args_fp=ARGS_FP, fp_key_version=1, policy_version_id=None,
        expires_in_minutes=30, requested_by="boss",
    )


def test_a_call_approval_opens_for_a_built_in_server_without_a_server_row(world):
    scene, _ = world
    assert requested(scene)
    call_id = open_for(scene, "builtin:claude")
    stored = scene.conn.execute(
        "SELECT server_id FROM mint.call_approvals WHERE id = %s", (call_id,)).fetchone()
    assert stored[0] == "builtin:claude"


def test_an_unregistered_server_that_is_not_built_in_is_still_refused(world):
    scene, _ = world
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        open_for(scene, "builtin:other")
