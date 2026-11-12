"""운영 편의: doctor, status의 할 일, 식별자 줄임, 토큰 파일 저장, 토큰이 없을 때의 안내."""

import os
import stat

import pytest

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import alerts  # noqa: E402

INSTANCE = "clitest"


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def test_doctor_runs_without_a_token_and_names_the_next_command(mint):
    mint.run("init")
    code, out, err = mint.run("doctor")
    assert code == 0, err
    assert "운영자가 아직 없습니다" in out
    assert "mint-litellm operator bootstrap --name <이름>" in out
    assert "적용된 정책 판본이 없어" in out


def test_doctor_on_an_unprepared_database_points_to_init(fresh_db, stub, capsys, tmp_path):
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("DROP SCHEMA mint CASCADE")
    code, out, err = Cli(fresh_db, stub.url, capsys, tmp_path).run("doctor")
    assert code == 0, err
    assert "mint-litellm init" in out


def test_doctor_asks_for_the_litellm_settings_when_the_environment_lacks_them(mint):
    mint.run("init")
    del mint.env["MINT_LITELLM_KEY"]
    code, out, _ = mint.run("doctor")
    assert code == 0 and "MINT_LITELLM_URL·MINT_LITELLM_KEY가 없어" in out


def test_init_without_a_control_key_lists_every_route_the_key_needs(mint):
    del mint.env["MINT_LITELLM_KEY"]
    code, _, err = mint.run("init")
    assert code == 0 and "deploy/mint.sh up이 자동으로 만들어 넣습니다" in err
    assert "/v1/mcp/server" in err and "/mcp-rest/test/tools/list" in err


def test_status_ends_with_the_todo_list_and_json_carries_it(mint):
    token = bootstrap(mint)
    code, out, _ = mint.run("status", token=token)
    assert code == 0 and "할 일" in out and "다음: mint-litellm policy activate initial" in out
    code, out, _ = mint.run("--json", "status", token=token)
    assert code == 0 and '"todo"' in out


def test_todo_lists_open_alerts_and_failed_jobs(mint):
    bootstrap(mint)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"], autocommit=True) as conn:
        alerts.raise_alert(
            conn, INSTANCE, kind="job_failed", severity="high", dedup_key="k", subject={}
        )
        conn.execute(
            "INSERT INTO mint.jobs (id, instance_id, kind, target_ref) VALUES"
            " (gen_random_uuid(), %s, 'seal', 'x')",
            (INSTANCE,),
        )
        conn.execute(
            "UPDATE mint.jobs SET status = 'running', lease_owner = 'w',"
            " lease_until = now() + interval '1 minute'"
        )
        conn.execute(
            "UPDATE mint.jobs SET status = 'failed', attempts = 8, last_error_code = 'E_X'"
        )
    _, out, _ = mint.run("doctor")
    assert "열린 경보 1건" in out and "mint-litellm alert list --status open" in out
    assert "실패한 작업 seal 1건(오류 코드 E_X)" in out


def test_a_missing_token_says_what_to_do_next(mint):
    mint.run("init")
    code, _, err = mint.run("status")
    assert code == 4 and "운영자가 아직 없습니다" in err and "operator bootstrap" in err
    bootstrap(mint)
    code, _, err = mint.run("status")
    assert code == 4 and "운영자 토큰이 필요합니다" in err and "operator add" in err


def test_a_token_can_be_saved_to_a_private_file_instead_of_the_screen(mint):
    mint.run("init")
    path = mint.tmp / "operator.token"
    code, out, err = mint.run(
        "operator", "bootstrap", "--name", "boss", "--user-id", "human-2",
        "--save-token", str(path),
    )
    assert code == 0, err
    token = path.read_text(encoding="utf-8").strip()
    assert token and token not in out
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    code, out, _ = mint.run("--token-file", str(path), "status")
    assert code == 0
    again = mint.run(
        "--token-file", str(path), "operator", "add", "second", "--role", "viewer",
        "--save-token", str(path),
    )
    assert again[0] == 1 and "이미 있어 덮어쓰지 않습니다" in again[2]


def test_a_failed_token_save_does_not_leave_the_operator_behind(mint):
    mint.run("init")
    path = mint.tmp / "taken.token"
    path.write_text("x", encoding="utf-8")
    code, _, err = mint.run(
        "operator", "bootstrap", "--name", "boss", "--user-id", "human-2",
        "--save-token", str(path),
    )
    assert code == 1 and "덮어쓰지 않습니다" in err
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        assert conn.execute("SELECT count(*) FROM mint.operators").fetchone()[0] == 0


def raise_alerts(mint, *dedups):
    with psycopg.connect(mint.env["MINT_DATABASE_URL"], autocommit=True) as conn:
        for dedup in dedups:
            alerts.raise_alert(
                conn, INSTANCE, kind="job_failed", severity="high", dedup_key=dedup, subject={}
            )
        return [str(r[0]) for r in conn.execute("SELECT id FROM mint.alerts ORDER BY first_at")]


def test_an_identifier_can_be_given_by_its_last_eight_characters_or_its_start(mint):
    token = bootstrap(mint)
    first, second = raise_alerts(mint, "a", "b")
    code, _, err = mint.run("alert", "ack", first[-8:], token=token)
    assert code == 0, err
    code, _, err = mint.run("alert", "ack", second[:30], token=token)
    assert code == 0, err
    code, out, _ = mint.run("alert", "list", "--status", "acknowledged", token=token)
    assert first in out and second in out


def test_an_ambiguous_or_unknown_short_identifier_is_not_guessed(mint):
    token = bootstrap(mint)
    first, second = raise_alerts(mint, "a", "b")
    common = os.path.commonprefix([first, second])
    assert len(common) >= 6  # 같은 순간에 만든 식별자는 앞부분이 같다
    code, _, err = mint.run("alert", "ack", common, token=token)
    assert code == 1 and "둘 이상" in err
    code, _, err = mint.run("alert", "ack", "ffffffff", token=token)
    assert code == 1 and "없습니다" in err
