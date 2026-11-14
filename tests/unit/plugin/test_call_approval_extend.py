"""기간 승인의 한 번 연장, 기본 기간, 알림 미리보기를 실제 DB에서 확인한다."""

import ctl_fixtures
import pytest
import test_call_approval_window as win
from test_call_approval_window import granted, requested, row

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import expiry

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = win.world


def carol(scene):
    return Context(scene.conn, scene.iid, Operator("carol", "approver", "carol"))


def test_a_window_nearing_its_end_is_extended_once_by_the_same_window(world):
    scene, _ = world
    call_id = granted(scene, 10)
    before = row(scene, call_id, "valid_until")[0]
    dave = Context(scene.conn, scene.iid, Operator("dave", "approver", "dave"))
    approvals.call_extend(dave, call_id)
    after, by, at = row(scene, call_id, "valid_until, extended_by, extended_at")
    assert (after - before).total_seconds() == 600 and by == "dave" and at is not None
    with pytest.raises(ControlError, match="한 번"):
        approvals.call_extend(carol(scene), call_id)
    assert row(scene, call_id, "valid_until")[0] == after


def test_a_window_far_from_its_end_or_a_single_use_approval_cannot_be_extended(world):
    scene, _ = world
    long_window = granted(scene, 30)
    with pytest.raises(ControlError):
        approvals.call_extend(carol(scene), long_window)
    single = granted(scene)
    with pytest.raises(ControlError):
        approvals.call_extend(carol(scene), single)


def test_the_validity_end_cannot_be_moved_except_by_the_one_time_extension(world):
    scene, _ = world
    call_id = granted(scene, 10)
    with pytest.raises(Exception, match="validity window"):
        scene.conn.execute(
            "UPDATE mint.call_approvals SET valid_until = valid_until + interval '1 hour'"
            " WHERE id = %s", (call_id,))


def test_the_default_window_is_thirty_minutes(world):
    scene, _ = world
    call_id = requested(scene)
    approvals.call_approve(carol(scene), call_id, None, None, True)
    assert row(scene, call_id, "window_minutes")[0] == approvals.DEFAULT_CALL_WINDOW == 30
    explicit = requested(scene)
    approvals.call_approve(carol(scene), explicit, None, None, False)
    assert row(scene, explicit, "window_minutes")[0] is None


def test_the_request_alert_carries_the_tool_action_and_masked_preview(world):
    scene, _ = world
    opener = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))
    call_id = approvals.call_request(
        opener, org_id="org1", principal_type="user", principal_id="u1", server_id="srv-1",
        tool="search", args_fp=win.ARGS_FP, fp_key_version=1, policy_version_id=None,
        expires_in_minutes=30, requested_by=expiry.AUTO_REQUESTER, target="docs", action="read",
    )
    scene.conn.execute(
        "UPDATE mint.call_approvals SET display = '{\"q\": \"hello\", \"token\": \"[MASKED]\"}'"
        " WHERE id = %s", (call_id,))
    assert expiry.announce_requests(scene.conn, scene.iid) == 1
    subject = scene.conn.execute(
        "SELECT subject FROM mint.alerts WHERE kind = 'call_approval_requested'").fetchone()[0]
    assert subject["tool"] == "search" and subject["action"] == "read"
    assert subject["preview"] == "q=hello, token=[MASKED]"
