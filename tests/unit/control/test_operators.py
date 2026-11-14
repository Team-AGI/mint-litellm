"""운영자 등록·인증·직무 분리. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE

pytest.importorskip("psycopg")

from mint_litellm.control import operators  # noqa: E402
from mint_litellm.control.context import Operator  # noqa: E402
from mint_litellm.control.db.connection import fetchone  # noqa: E402
from mint_litellm.control.errors import AuthError, ControlError  # noqa: E402
from mint_litellm.types.cli_commands import OperatorRole  # noqa: E402


def test_bootstrap_only_works_on_an_empty_table_and_records_the_actor(conn, litellm):
    token = operators.bootstrap(conn, INSTANCE, litellm, "boss", "human-1")
    assert token.startswith(operators.TOKEN_PREFIX)
    row = fetchone(conn, "SELECT * FROM mint.operators WHERE name = 'boss'")
    assert row["role"] == "admin" and row["user_id"] == "human-1"
    assert row["token_hash"] == operators.hash_token(token) != token
    event = fetchone(conn, "SELECT actor, kind FROM mint.events WHERE kind = 'operator_added'")
    assert event["actor"] == "bootstrap"
    with pytest.raises(ControlError, match="이미 있어"):
        operators.bootstrap(conn, INSTANCE, litellm, "boss2", "human-1")


def test_bootstrap_on_another_instance_is_independent(conn, litellm):
    operators.bootstrap(conn, INSTANCE, litellm, "boss", "human-1")
    operators.bootstrap(conn, "inst2", litellm, "boss", "human-1")
    count = fetchone(conn, "SELECT count(*) AS n FROM mint.events WHERE kind = 'operator_added'")
    assert count["n"] == 2


def test_bootstrap_requires_a_human_litellm_user(conn, litellm, stub):
    with pytest.raises(ControlError, match="없습니다"):
        operators.bootstrap(conn, INSTANCE, litellm, "boss", "nobody")
    body = dict(stub.routes[("/user/info", frozenset({("user_id", "human-1")}))][1])
    body["user_info"] = {**body["user_info"], "user_role": "customer"}
    stub.set("/user/info", body, user_id="human-1")
    with pytest.raises(ControlError, match="사람 사용자가 아닙니다"):
        operators.bootstrap(conn, INSTANCE, litellm, "boss", "human-1")
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.operators")["n"] == 0


def test_add_requires_user_binding_for_admin_and_approver_only(conn, litellm, ctx):
    for role in (OperatorRole.ADMIN, OperatorRole.APPROVER):
        with pytest.raises(ControlError, match="--user-id"):
            operators.add(ctx, litellm, f"x-{role.value}", role, None, None)
    token = operators.add(ctx, litellm, "watcher", OperatorRole.VIEWER, None, None)
    assert operators.authenticate(conn, INSTANCE, token).role == "viewer"
    with pytest.raises(ControlError, match="이미 있습니다"):
        operators.add(ctx, litellm, "watcher", OperatorRole.VIEWER, None, None)
    with pytest.raises(ControlError, match="없습니다"):
        operators.add(ctx, litellm, "ghost", OperatorRole.APPROVER, "nobody", None)
    event = fetchone(
        conn, "SELECT actor FROM mint.events WHERE source_key = 'operator:watcher:1:operator_added'"
    )
    assert event["actor"] == "root"


def test_authentication_failures(conn, litellm, ctx):
    with pytest.raises(AuthError, match="필요"):
        operators.authenticate(conn, INSTANCE, None)
    with pytest.raises(AuthError, match="올바르지"):
        operators.authenticate(conn, INSTANCE, "mint_unknown")
    token = operators.add(ctx, litellm, "temp", OperatorRole.VIEWER, None, 1)
    conn.execute(
        "UPDATE mint.operators SET expires_at = %s WHERE name = 'temp'",
        (datetime.now(UTC) - timedelta(seconds=1),),
    )
    with pytest.raises(AuthError, match="만료"):
        operators.authenticate(conn, INSTANCE, token)
    other = operators.add(ctx, litellm, "temp2", OperatorRole.VIEWER, None, None)
    with pytest.raises(AuthError):
        operators.authenticate(conn, "inst2", other)


def test_distinct_person_rule():
    me = Operator("a", "approver", "u1")
    assert operators.require_distinct_person(me, "someone", None, "승인") is None
    assert operators.require_distinct_person(me, None, None, "승인") is None
    with pytest.raises(ControlError, match="--second-approver"):
        operators.require_distinct_person(me, "u1", None, "승인")
    second = Operator("b", "admin", "u2")
    assert operators.require_distinct_person(me, "u1", second, "승인") == {
        "name": "b",
        "user_id": "u2",
    }
    same_person_other_token = Operator("c", "approver", "u1")
    with pytest.raises(ControlError, match="두 번째 승인자"):
        operators.require_distinct_person(me, "u1", same_person_other_token, "승인")


def test_a_removed_operator_name_is_reported_as_removed_by_both_remove_and_add(conn, litellm, ctx):
    from mint_litellm.control.services import operators as service

    service.add(ctx, litellm, "temp", OperatorRole.VIEWER, None, None)
    with pytest.raises(ControlError, match="이미 있습니다"):
        service.add(ctx, litellm, "temp", OperatorRole.VIEWER, None, None)
    service.remove(ctx, "temp")
    with pytest.raises(ControlError, match="삭제되어 같은 이름으로"):
        service.add(ctx, litellm, "temp", OperatorRole.VIEWER, None, None)
    with pytest.raises(ControlError, match="이미 삭제되었습니다"):
        service.remove(ctx, "temp")
    with pytest.raises(ControlError, match="없습니다"):
        service.remove(ctx, "never-existed")
