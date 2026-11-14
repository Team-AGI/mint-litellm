"""siem add|list|remove|test 명령. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json
import threading
import time

import pytest

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def test_add_list_remove_keep_the_secret_out_of_the_database(mint):
    token = bootstrap(mint)
    code, out, err = mint.run(
        "siem",
        "add",
        "main",
        "--kind",
        "hec",
        "--endpoint",
        "https://s.test:8088",
        "--token-env",
        "SPLUNK_TOKEN",
        "--index",
        "mint",
        token=token,
    )
    assert code == 0, err
    code, out, err = mint.run("siem", "list", "--json", token=token)
    (row,) = json.loads(out)["targets"]
    assert (row["name"], row["kind"], row["address"], row["secret_source"]) == (
        "main",
        "hec",
        "https://s.test:8088",
        "env",
    )
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        endpoint, ref, options = conn.execute(
            "SELECT endpoint, secret_ref, options FROM mint.siem_targets"
        ).fetchone()
        kinds = [r[0] for r in conn.execute("SELECT kind FROM mint.events ORDER BY inserted_at")]
    assert endpoint.endswith("/services/collector/event") and ref == "env:SPLUNK_TOKEN"
    assert options == {"index": "mint"} and "siem_target_added" in kinds
    code, _, err = mint.run(
        "siem", "add", "main", "--kind", "cef", "--endpoint", "tcp://s.test:514", token=token
    )
    assert code != 0 and "이미 있습니다" in err
    code, _, err = mint.run(
        "siem", "add", "bad", "--kind", "syslog", "--endpoint", "https://s.test", token=token
    )
    assert code != 0 and "주소 형식" in err
    code, _, err = mint.run("siem", "remove", "main", token=token)
    assert code == 0, err
    code, _, err = mint.run("siem", "remove", "main", token=token)
    assert code != 0
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        kinds = [r[0] for r in conn.execute("SELECT kind FROM mint.events")]
    assert "siem_target_removed" in kinds


def test_test_waits_for_the_runner_result(mint, monkeypatch):
    token = bootstrap(mint)
    mint.run(
        "siem", "add", "main", "--kind", "syslog", "--endpoint", "udp://s.test:514", token=token
    )
    url = mint.env["MINT_DATABASE_URL"]

    def runner():  # 작업 실행기 대신 요청이 올라오면 성공으로 답한다
        with psycopg.connect(url, autocommit=True) as conn:
            for _ in range(100):
                done = conn.execute(
                    "UPDATE mint.siem_targets SET last_test_at = now()"
                    " WHERE test_requested_at IS NOT NULL"
                ).rowcount
                if done:
                    return
                time.sleep(0.1)

    thread = threading.Thread(target=runner)
    thread.start()
    code, out, err = mint.run("siem", "test", "main", token=token)
    thread.join()
    assert code == 0, err
    assert "성공" in out
    code, _, err = mint.run("siem", "test", "none", "--no-wait", token=token)
    assert code != 0
