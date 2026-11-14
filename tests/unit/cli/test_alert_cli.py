"""경보 명령: 조회, 확인, 해결, 역할과 상태 전이 오류, 사건 기록. 실 Postgres로 돌린다."""

import pytest

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import alerts  # noqa: E402

INSTANCE = "clitest"


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def raise_alert(mint, dedup="job_failed:seal:seal"):
    with psycopg.connect(mint.env["MINT_DATABASE_URL"], autocommit=True) as conn:
        alerts.raise_alert(
            conn, INSTANCE, kind="job_failed", severity="high", dedup_key=dedup, subject={}
        )
        return str(conn.execute("SELECT id FROM mint.alerts").fetchone()[0])


def test_list_ack_and_resolve_follow_the_status_path(mint):
    token = bootstrap(mint)
    alert_id = raise_alert(mint)
    code, out, _ = mint.run("alert", "list", token=token)
    assert code == 0 and "job_failed" in out and "open" in out
    code, _, err = mint.run("alert", "ack", alert_id, token=token)
    assert code == 0, err
    code, out, _ = mint.run("alert", "list", "--status", "acknowledged", token=token)
    assert code == 0 and alert_id in out
    code, _, err = mint.run("alert", "ack", alert_id, token=token)
    assert code == 1 and "열린 경보만" in err
    code, _, _ = mint.run("alert", "resolve", alert_id, token=token)
    assert code == 0
    code, _, err = mint.run("alert", "resolve", alert_id, token=token)
    assert code == 1 and "이미 해결된" in err


def test_ack_and_resolve_write_the_events_once(mint):
    token = bootstrap(mint)
    alert_id = raise_alert(mint)
    code, out, _ = mint.run("--json", "alert", "ack", alert_id, token=token)
    assert code == 0
    assert f"alert:{alert_id}:1:alert_acknowledged" in out
    code, out, _ = mint.run("--json", "alert", "resolve", alert_id, token=token)
    assert f"alert:{alert_id}:2:alert_resolved" in out


def test_only_admins_acknowledge_and_resolve(mint):
    boss = bootstrap(mint)
    approver = mint.token(
        mint.run("operator", "add", "ap", "--role", "approver", "--user-id", "human-1",
                 token=boss)[1]
    )
    alert_id = raise_alert(mint)
    assert mint.run("alert", "ack", alert_id, token=approver)[0] == 4
    assert mint.run("alert", "list", token=approver)[0] == 0


def test_an_unknown_alert_is_not_found(mint):
    token = bootstrap(mint)
    code, _, err = mint.run("alert", "ack", "not-a-uuid", token=token)
    assert code == 1 and "없습니다" in err


def test_short_ids_resolve_and_never_surface_database_errors(mint):
    token = bootstrap(mint)
    alert_id = raise_alert(mint)
    code, out, err = mint.run("--json", "alert", "ack", alert_id[-5:], token=token)
    assert code == 0, err
    for text in ("deadbeef", "zz", "40353"):
        code, _, err = mint.run("alert", "ack", text, token=token)
        assert code == 1 and "없습니다" in err and "uuid" not in err.lower()
