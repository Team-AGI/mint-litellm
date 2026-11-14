"""operator chat-bind: 결속·해제·거절 경로. 실 Postgres로 돌린다."""

import pytest

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def bound(mint):
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        return conn.execute(
            "SELECT operator_name, external_id FROM mint.operator_chat_bindings"
        ).fetchall()


def test_admin_binds_replaces_and_clears_a_slack_user(mint):
    boss = bootstrap(mint)
    mint.run("operator", "add", "ap", "--role", "approver", "--user-id", "human-1", token=boss)
    code, _, err = mint.run("operator", "chat-bind", "ap", "--slack-user", "U0AP1", token=boss)
    assert code == 0, err
    assert bound(mint) == [("ap", "U0AP1")]
    assert mint.run("operator", "chat-bind", "ap", "--slack-user", "U0AP2", token=boss)[0] == 0
    assert bound(mint) == [("ap", "U0AP2")]
    assert mint.run("operator", "chat-bind", "ap", "--clear", token=boss)[0] == 0
    assert bound(mint) == []


def test_bad_ids_viewers_and_non_admins_are_refused(mint):
    boss = bootstrap(mint)
    mint.run("operator", "add", "eye", "--role", "viewer", token=boss)
    ap = mint.token(
        mint.run("operator", "add", "ap", "--role", "approver", "--user-id", "human-1", token=boss)[
            1
        ]
    )
    code, _, err = mint.run("operator", "chat-bind", "ap", "--slack-user", "nope", token=boss)
    assert code == 1 and "Slack 사용자 식별자" in err
    code, _, err = mint.run("operator", "chat-bind", "eye", "--slack-user", "U0EYE", token=boss)
    assert code == 1 and "admin·approver" in err
    code, _, err = mint.run("operator", "chat-bind", "ap", "--slack-user", "U0AP1", token=ap)
    assert code == 4 and "역할로 실행할 수 없습니다" in err
    assert bound(mint) == []
