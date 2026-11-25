"""사람 명부: 비밀번호·개인 키·SSO가 한 사람에 닿고, LiteLLM 변화가 사본에 반영된다."""

import hashlib

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.control import directory
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.services import console_sessions

PW = console_sessions.PASSWORD_PREFIX + "a" * 64
SSO = console_sessions.SSO_PREFIX + "b" * 64
KEY1 = hashlib.sha256(b"sk-one").hexdigest()
KEY2 = hashlib.sha256(b"sk-two").hexdigest()


def user(uid, role="internal_user", teams=(), email=None):
    return {"user_id": uid, "user_email": email or f"{uid}@acme.test", "user_role": role,
            "teams": list(teams)}


class FakeLiteLLM:
    def __init__(self, users, teams=(), keys=()):
        self.users, self.teams, self.keys = list(users), list(teams), list(keys)
        self.fail = False

    def _read(self, rows):
        if self.fail:
            raise LiteLLMError("읽을 수 없음")
        return rows

    def list_users(self):
        return self._read(self.users)

    def list_teams(self):
        return self._read(self.teams)

    def list_keys(self):
        return self._read(self.keys)


def key(token, uid, team=None, **extra):
    return {"token": token, "user_id": uid, "team_id": team, "blocked": None, **extra}


def rows(conn, sql, *params):
    return conn.execute(sql, params or None).fetchall()


def test_password_two_keys_and_sso_all_connect_to_one_person(conn):
    person = user("u1", teams=["t1"])
    for token in (PW, KEY1, KEY2, SSO):
        directory.record_login(conn, INSTANCE, "u1", token, person)
    assert rows(conn, "SELECT user_id, team_ids::text FROM mint.directory_users") == [
        ("u1", '["t1"]')]
    kinds = [c["kind"] for c in directory.credentials_of(conn, INSTANCE, "u1")]
    assert sorted(kinds) == ["key", "key", "password", "sso"]
    directory.record_login(conn, INSTANCE, "u1", KEY1, person)  # 같은 자격 재로그인은 한 줄
    assert len(directory.credentials_of(conn, INSTANCE, "u1")) == 4


def test_litellm_admin_gets_a_mint_admin_and_everyone_else_none(conn):
    directory.record_login(conn, INSTANCE, "root", PW, user("root", "proxy_admin", email="root"))
    directory.record_login(conn, INSTANCE, "emp", KEY1, user("emp"))
    ops = rows(conn, "SELECT name, role, user_id FROM mint.operators ORDER BY name")
    assert ops == [("root", "admin", "root")]
    # 다시 로그인해도 행이 늘지 않는다
    directory.record_login(conn, INSTANCE, "root", KEY2, user("root", "proxy_admin", email="root"))
    assert rows(conn, "SELECT count(*) FROM mint.operators") == [(1,)]


def test_an_operator_role_already_decided_is_kept(conn):
    conn.execute(
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES (%s, 'owner', 'viewer', %s, 'adm')", (INSTANCE, "ab" * 32))
    directory.record_login(conn, INSTANCE, "adm", PW, user("adm", "proxy_admin"))
    assert rows(conn, "SELECT name, role FROM mint.operators") == [("owner", "viewer")]
    # 사람이 지운(만료시킨) 운영자도 다시 만들지 않는다
    conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'owner'")
    directory.record_login(conn, INSTANCE, "adm", PW, user("adm", "proxy_admin"))
    assert rows(conn, "SELECT count(*) FROM mint.operators") == [(1,)]


def test_a_demoted_litellm_admin_loses_only_the_automatic_operator(conn):
    directory.record_login(conn, INSTANCE, "first", PW, user("first", "proxy_admin"))
    directory.record_login(conn, INSTANCE, "second", PW, user("second", "proxy_admin"))
    [(_,)] = rows(conn, "SELECT 1 FROM mint.operators WHERE user_id = 'second'")
    directory.record_login(conn, INSTANCE, "second", PW, user("second", "internal_user"))
    assert rows(conn, "SELECT user_id FROM mint.operators"
                " WHERE expires_at IS NULL OR expires_at > now()") == [("first",)]
    # 마지막 관리자는 거두지 않는다
    directory.record_login(conn, INSTANCE, "first", PW, user("first", "internal_user"))
    assert rows(conn, "SELECT count(*) FROM mint.operators WHERE expires_at IS NULL") == [(1,)]


def test_sync_follows_team_moves_renames_and_revoked_keys(conn):
    people = [user("u1", teams=["t1"]), user("u2", "proxy_admin")]
    keys = [key(KEY1, "u1"), key(KEY2, "u1"), key("ui" * 32, "u1", "litellm-dashboard")]
    lite = FakeLiteLLM(people, [{"team_id": "t1", "members_with_roles": [{"user_id": "u1"}]}],
                       keys)
    assert directory.sync(conn, INSTANCE, lite) == directory.SyncResult(2, 2, 0, 0)
    assert len(directory.credentials_of(conn, INSTANCE, "u1")) == 2  # 화면 세션 키는 제외
    # 팀 이동·이름 변경(같은 ID)·키 하나 폐기
    lite.users[0] = user("u1", teams=["t2"], email="renamed@acme.test")
    lite.teams = [{"team_id": "t2", "members_with_roles": [{"user_id": "u1"}]}]
    lite.keys = [key(KEY1, "u1")]
    result = directory.sync(conn, INSTANCE, lite)
    assert (result.gone_keys, result.gone_users) == (1, 0)
    assert rows(conn, "SELECT email, team_ids::text FROM mint.directory_users"
                " WHERE user_id = 'u1'") == [("renamed@acme.test", '["t2"]')]
    gone = {c["ref"]: c["gone_at"] is not None for c in directory.credentials_of(
        conn, INSTANCE, "u1")}
    assert gone == {KEY1: False, KEY2: True}


def test_a_partial_or_empty_read_never_deletes_anyone(conn):
    lite = FakeLiteLLM([user("u1"), user("u2")], keys=[key(KEY1, "u1")])
    directory.sync(conn, INSTANCE, lite)
    lite.fail = True
    with pytest.raises(LiteLLMError):
        directory.sync(conn, INSTANCE, lite)
    lite.fail = False
    lite.users = []  # 읽기 이상으로 본다
    directory.sync(conn, INSTANCE, lite)
    assert rows(conn, "SELECT count(*) FROM mint.directory_users WHERE gone_at IS NOT NULL") == [
        (0,)]
    lite.users = [user("u1")]  # 정상 목록에서 빠진 사람만 사라진 것으로 표시
    assert directory.sync(conn, INSTANCE, lite).gone_users == 1


def test_sync_moves_a_kit_installs_team_and_queues_the_gateway_key_resync(conn):
    def install(token, team="t1"):
        conn.execute(
            "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
            " team_id, issued_by) VALUES (%s, %s, 'u1', %s, %s, 'u1')",
            (INSTANCE, token, "a-" + token, team))
        conn.execute(
            "INSERT INTO mint.endpoint_apps (instance_id, user_id, team_id, install_key_token,"
            " name, key_alias, key_token, expires_at) VALUES (%s, 'u1', %s, %s, 'app', %s, %s,"
            " now() + interval '1 day')", (INSTANCE, team, token, "p-" + token, "app-" + token))

    def teams(*ids):
        return FakeLiteLLM([user("u1", teams=ids)],
                           [{"team_id": t, "members_with_roles": [{"user_id": "u1"}]}
                            for t in ids])

    def state():
        return (rows(conn, "SELECT team_id FROM mint.endpoint_installs"),
                rows(conn, "SELECT team_id FROM mint.endpoint_apps"))

    def queued():
        return rows(conn, "SELECT count(*) FROM mint.jobs WHERE kind = 'kit_key_sync'")[0][0]

    install("k1")
    directory.sync(conn, INSTANCE, teams("t1"))  # 그대로면 아무것도 바뀌지 않는다
    assert state() == ([("t1",)], [("t1",)]) and queued() == 0
    directory.sync(conn, INSTANCE, teams("t0", "t1"))  # 아직 소속이면 유지
    assert state() == ([("t1",)], [("t1",)]) and queued() == 0
    directory.sync(conn, INSTANCE, teams("t2"))  # 팀을 옮기면 현재 팀으로
    assert state() == ([("t2",)], [("t2",)]) and queued() == 1
    directory.sync(conn, INSTANCE, teams())  # 팀에서 모두 빠지면 비운다
    assert state() == ([(None,)], [(None,)])
    directory.sync(conn, INSTANCE, teams("t3"))  # 다시 들어오면 채운다
    assert state() == ([("t3",)], [("t3",)])
