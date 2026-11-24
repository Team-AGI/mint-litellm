"""직원 앱 자격: 권한 계산, 목록, 회수, 연결 해제와 함께 회수.

데이터베이스 시험은 MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.control import endpoint_apps, endpoint_kits, kit_key_sync
from mint_litellm.control.errors import AdminError


def test_the_permission_of_an_app_is_the_users_approvals_folded_like_the_gateway_key():
    rows = [
        {"server_id": "a", "tools": ["x", "y"], "open_tools": False},
        {"server_id": "a", "tools": ["z"], "open_tools": False},
        {"server_id": "b", "tools": ["*"], "open_tools": True},
    ]
    assert kit_key_sync.fold_permission(rows) == (["a", "b"], {"a": ["x", "y", "z"]})
    assert kit_key_sync.fold_permission([]) == ([], {})
    assert kit_key_sync.applicable_params("i", "u1", None, "")["team"] == ""


class Issuer:
    def __init__(self):
        self.deleted = []

    def generate_kit_key(self, *, user_id, team_id, alias, permission=None):
        return f"sk-{alias}"

    def delete_kit_keys(self, aliases):
        self.deleted.append(list(aliases))


def add_app(conn, user="u1", name="bot", days=30, revoked=False):
    return conn.execute(
        "INSERT INTO mint.endpoint_apps (instance_id, user_id, team_id, install_key_token, name,"
        " key_alias, key_token, expires_at, revoked_at)"
        " VALUES (%s, %s, 't1', 'k', %s, %s, 'h', now() + make_interval(days => %s),"
        " CASE WHEN %s THEN now() END) RETURNING id",
        (INSTANCE, user, name, f"mint-kit-app-{name}-aa11bb", days, revoked),
    ).fetchone()[0]


def test_apps_are_listed_by_state_and_never_show_a_key(conn):
    add_app(conn, name="live")
    add_app(conn, name="old", days=-1)
    add_app(conn, name="gone", revoked=True)
    add_app(conn, user="u2", name="theirs")
    rows = endpoint_apps.list_apps(conn, INSTANCE, "u1")
    assert {r["name"]: r["state"] for r in rows} == {
        "live": "active", "old": "expired", "gone": "revoked"}
    assert all("key_token" not in r for r in rows)
    assert len(endpoint_apps.list_apps(conn, INSTANCE)) == 4


def test_revoking_one_app_deletes_its_key_records_the_actor_and_repeats_are_harmless(conn):
    issuer = Issuer()
    app_id = str(add_app(conn))
    with pytest.raises(AdminError):  # 다른 사람의 앱은 없는 것으로 본다
        endpoint_apps.revoke_app(conn, issuer, INSTANCE, app_id, actor="u2", user_id="u2")
    assert issuer.deleted == []
    endpoint_apps.revoke_app(conn, issuer, INSTANCE, app_id, actor="u1", user_id="u1")
    endpoint_apps.revoke_app(conn, issuer, INSTANCE, app_id, actor="admin1")
    assert issuer.deleted == [["mint-kit-app-bot-aa11bb"]]
    row = conn.execute("SELECT revoked_by FROM mint.endpoint_apps").fetchone()
    assert row == ("u1",)
    events = conn.execute(
        "SELECT payload FROM mint.events WHERE kind = 'endpoint_app_revoked'").fetchall()
    assert len(events) == 1 and "key" not in events[0][0]
    with pytest.raises(AdminError):
        endpoint_apps.revoke_app(conn, issuer, INSTANCE, "not-a-uuid", actor="u1")


def test_disconnecting_a_person_revokes_their_apps_but_a_new_device_key_does_not(conn):
    issuer = Issuer()
    endpoint_kits.issue_key(conn, issuer, INSTANCE, user_id="u1", team_id="t1", issued_by="u1")
    add_app(conn)
    add_app(conn, user="u2", name="other")
    endpoint_kits.issue_key(conn, issuer, INSTANCE, user_id="u1", team_id="t1", issued_by="u1")
    states = {r["name"]: r["state"] for r in endpoint_apps.list_apps(conn, INSTANCE)}
    assert states == {"bot": "active", "other": "active"}  # 다시 발급해도 앱은 그대로
    endpoint_kits.revoke_keys(conn, issuer, INSTANCE, "u1")
    states = {r["name"]: r["state"] for r in endpoint_apps.list_apps(conn, INSTANCE)}
    assert states == {"bot": "revoked", "other": "active"}
    assert ["mint-kit-app-bot-aa11bb"] in issuer.deleted
