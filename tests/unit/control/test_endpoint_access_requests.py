"""PC(설치 키)에서 여는 권한 요청: 키가 사용자를 정하고, 직원 화면의 요청과 같은 표·사건을 쓴다."""

import uuid

import pytest
from ctl_fixtures import as_login

from mint_litellm.control.db.connection import fetchall

from . import test_access_requests as staff_side
from . import test_endpoint_intake as kit_side

world = kit_side.world
KEY = kit_side.KEY


def call(world, sql, *args):
    with as_login(world.url, "mint_plugin") as conn:
        return conn.execute(sql, args).fetchall()


def open_(world, tool="search", token=KEY, server="srv-a", reason="DENIED"):
    return call(world, "SELECT mint.endpoint_open_access_request(%s, %s, %s, %s, %s, %s)",
                token, uuid.uuid4(), server, tool, reason, "업무에 필요")[0][0]


def test_the_key_decides_who_asks_and_one_open_request_per_target(world):
    staff_side.approved_server(world)
    kit_side.install(world)
    first = open_(world)
    assert open_(world) == first
    row = fetchall(world.conn, "SELECT requested_by, server_id, tool, status"
                   " FROM mint.access_requests")
    assert row == [{"requested_by": kit_side.USER, "server_id": "srv-a", "tool": "search",
                    "status": "open"}]
    kinds = [r["kind"] for r in fetchall(world.conn, "SELECT kind FROM mint.events"
                                         " WHERE kind LIKE 'access_request%%'")]
    assert kinds == ["access_request_opened"]
    mine = call(world, "SELECT id, status FROM mint.endpoint_my_access_requests(%s)", KEY)
    assert mine == [(first, "open")]
    # 직원 화면 쪽 승인자 목록에도 같은 요청이 보인다
    from mint_litellm.control.services import access_requests as svc

    assert [str(r["id"]) for r in svc.pending(world.conn, kit_side.INSTANCE)] == [str(first)]


def test_cancel_takes_only_the_owners_open_request(world):
    staff_side.approved_server(world)
    kit_side.install(world)
    kit_side.install(world, token="key-2", user="emp-2")
    made = open_(world)
    sql = "SELECT mint.endpoint_cancel_access_request(%s, %s)"
    assert call(world, sql, "key-2", made) == [(False,)]
    assert call(world, sql, KEY, made) == [(True,)]
    assert call(world, sql, KEY, made) == [(False,)]
    assert call(world, "SELECT count(*) FROM mint.endpoint_my_access_requests(%s)", "key-2") == [
        (0,)]


def test_bad_keys_unknown_servers_and_bad_input_are_refused(world):
    staff_side.approved_server(world)
    kit_side.install(world, token="gone", revoked_at=kit_side.datetime.now(kit_side.UTC))
    kit_side.install(world)
    with pytest.raises(Exception, match="MINT-KEY"):
        open_(world, token="gone")
    with pytest.raises(Exception, match="MINT-KEY"):
        open_(world, token="nobody")
    with pytest.raises(Exception, match="MINT-NOTFOUND"):
        open_(world, server="nope")
    with pytest.raises(Exception, match="MINT-INVALID"):
        open_(world, reason="bad reason")
    with pytest.raises(Exception, match="MINT-KEY"):
        call(world, "SELECT * FROM mint.endpoint_my_access_requests(%s)", "gone")


def test_live_servers_follow_the_approvals_of_the_instance(world):
    staff_side.approved_server(world)
    kit_side.install(world)
    live = {r[0] for r in call(world, "SELECT * FROM mint.endpoint_live_servers(%s)", KEY)}
    expected = {r["server_id"] for r in fetchall(
        world.conn, "SELECT server_id FROM mint.approvals WHERE status IN ('active', 'pending')"
        " AND valid_until > now()")}
    assert live == expected
    with pytest.raises(Exception, match="MINT-KEY"):
        call(world, "SELECT * FROM mint.endpoint_live_servers(%s)", "nobody")


def test_without_a_reason_the_db_uses_the_active_block_to_classify(world):
    """QA-BUG-104: 막힌 도구를 PC에서 요청하면 승인 없음이 아니라 차단(DENIED)으로 분류한다."""
    from mint_litellm.control import approvals as approval_domain

    staff_side.approved_server(world)
    kit_side.install(world)
    sql = "SELECT reason_code FROM mint.access_requests WHERE tool = %s"
    open_(world, tool="search", reason=None)
    assert call_one(world, sql, "search") == "APPROVAL_ABSENT"
    world.call(lambda ctx: approval_domain.create_denial(
        ctx, scope_type="user", scope_id=kit_side.USER, server_id="srv-a", tools=["delete"],
        reason="위험", org_id=None))
    open_(world, tool="delete", reason=None)
    assert call_one(world, sql, "delete") == "DENIED"


def call_one(world, sql, *args):
    return fetchall(world.conn, sql, args)[0]["reason_code"]
