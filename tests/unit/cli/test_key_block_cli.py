"""key-block 명령: 목록·승인·거절·역할. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json
import uuid

import pytest

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


def seed(mint) -> str:
    proposal = str(uuid.uuid4())
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(
            "INSERT INTO mint.key_block_proposals (id, instance_id, signal, key_token, key_alias,"
            " evidence, expires_at) SELECT %s, instance_id, 'repeated_denials', 'tok', 'k1', %s,"
            " now() + interval '1 day' FROM mint.settings",
            (proposal, json.dumps({"denials": 12, "event_ids": []})),
        )
    return proposal


def test_list_show_and_reject_with_a_short_id(mint):
    token = bootstrap(mint)
    proposal = seed(mint)
    code, out, err = mint.run("key-block", "list", "--json", token=token)
    assert code == 0, err
    (row,) = json.loads(out)["proposals"]
    assert (row["id"], row["status"], row["signal"]) == (proposal, "proposed", "repeated_denials")
    code, out, err = mint.run("key-block", "show", proposal[-8:], "--json", token=token)
    assert code == 0 and json.loads(out)["evidence"]["denials"] == 12
    code, _, err = mint.run("key-block", "reject", proposal[-8:], "--reason", "오탐", token=token)
    assert code == 0, err
    code, out, _ = mint.run("key-block", "list", "--status", "rejected", "--json", token=token)
    assert [r["id"] for r in json.loads(out)["proposals"]] == [proposal]
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        kinds = {r[0] for r in conn.execute("SELECT kind FROM mint.events")}
    assert "key_block_rejected" in kinds
