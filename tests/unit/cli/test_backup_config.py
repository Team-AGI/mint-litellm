"""backup create/restore와 config export/import. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import ctl_fixtures
import pytest

from mint_litellm.control import allowlists, approvals, backup, orgs, relations
from mint_litellm.control.context import Context, Operator

from .test_cli import Cli, bootstrap

psycopg = pytest.importorskip("psycopg")


@pytest.fixture
def mint(fresh_db, stub, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return Cli(fresh_db, stub.url, capsys, tmp_path)


@pytest.fixture
def other(fresh_db, stub, capsys, tmp_path):
    """같은 인스턴스 이름의 두 번째 빈 데이터베이스."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    import mint_litellm.control.db.migrate as migrate

    name = f"mint_ctl_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ctl_fixtures.DATABASE_URL, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    url = make_conninfo(**{**conninfo_to_dict(ctl_fixtures.DATABASE_URL), "dbname": name})
    try:
        with psycopg.connect(url) as conn:
            migrate.apply_migrations(conn)
        yield Cli(url, stub.url, capsys, tmp_path)
    finally:
        with psycopg.connect(ctl_fixtures.DATABASE_URL, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


SERVER = (
    "INSERT INTO mint.servers (id, instance_id, server_id, status, transport, auth_type,"
    " registered_by, url_sha256) VALUES (gen_random_uuid(), 'clitest', 'docs',"
    " 'awaiting_approval', 'http', 'none', 'boss', repeat('a', 64))"
)


def seed(cli, *, with_server=True):
    with psycopg.connect(cli.env["MINT_DATABASE_URL"]) as conn:
        ctx = Context(conn, "clitest", Operator("boss", "admin", "human-2"))
        orgs.add(ctx, "sales", "Sales")
        if with_server:
            conn.execute(SERVER)
            relations.add(ctx, "sales", "docs", "search", None)
            approvals.create_denial(ctx, scope_type="user", scope_id="u1", server_id="docs",
                                    tools=["drop"], reason="위험", org_id="sales")
        now = datetime.now(UTC)
        allowlists.add(ctx, "provider", "docs.example.com", now, now + timedelta(days=30),
                       "sales", "메모")
        conn.commit()


def add_server(cli):
    with psycopg.connect(cli.env["MINT_DATABASE_URL"]) as conn:
        conn.execute(SERVER)


def counts(cli):
    with psycopg.connect(cli.env["MINT_DATABASE_URL"]) as conn:
        return {t: conn.execute(f"SELECT count(*) FROM mint.{t}").fetchone()[0]
                for t in ("orgs", "usage_relations", "denials", "allowlists", "events")}


def test_config_round_trip_is_idempotent_and_excludes_secrets(mint, other, tmp_path):
    token = bootstrap(mint)
    seed(mint)
    path = tmp_path / "cfg.json"
    code, out, err = mint.run("config", "export", str(path), token=token)
    assert code == 0, err
    text = path.read_text(encoding="utf-8")
    for secret in (token, "token_hash", "control_key_token"):
        assert secret not in text
    doc = json.loads(text)
    assert [o["name"] for o in doc["operators"]] == ["boss"]

    token2 = bootstrap(other)
    add_server(other)
    before = counts(other)
    code, out, err = other.run("config", "import", str(path), "--dry-run", token=token2)
    assert code == 0, err
    assert "시험 실행" in out and "relations: 새로 1" in out and "denials: 새로 1" in out
    assert counts(other) == before  # 시험 실행은 아무것도 남기지 않는다
    code, out, err = other.run("config", "import", str(path), token=token2)
    assert code == 0, err
    after = counts(other)
    assert after["usage_relations"] == 1 and after["denials"] == 1 and after["allowlists"] == 1
    code, out, _ = other.run("--json", "config", "import", str(path), token=token2)
    result = json.loads(out)["result"]
    assert all(result[s]["created"] == 0 for s in ("orgs", "relations", "allowlists", "denials"))
    assert counts(other)["usage_relations"] == 1 and counts(other)["denials"] == 1
    with psycopg.connect(other.env["MINT_DATABASE_URL"]) as conn:
        kinds = {r[0] for r in conn.execute("SELECT kind FROM mint.events")}
    assert {"config_imported", "relation_created"} <= kinds


def test_import_without_the_server_skips_dependents_and_lists_the_command(mint, other, tmp_path):
    token = bootstrap(mint)
    seed(mint)
    path = tmp_path / "cfg.json"
    mint.run("config", "export", str(path), token=token)
    token2 = bootstrap(other)
    code, out, _ = other.run("config", "import", str(path), token=token2)
    assert code == 0
    assert "할 일: mint-litellm server register docs" in out and "건너뜀 relations" in out
    assert counts(other)["usage_relations"] == 0 and counts(other)["allowlists"] == 1


def test_backup_restore_round_trip_with_the_json_fallback(mint, tmp_path):
    token = bootstrap(mint)
    seed(mint)
    path = tmp_path / "b.mbk"
    code, out, err = mint.run("backup", "create", str(path), "--format", "json", token=token)
    assert code == 0, err
    snapshot = counts(mint)
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("DELETE FROM mint.denials")
        conn.execute("DELETE FROM mint.allowlists")
        conn.commit()
    assert mint.run("backup", "restore", str(path), token=token)[0] != 0  # --yes 없이 거부
    code, out, err = mint.run("backup", "restore", str(path), "--yes", token=token)
    assert code == 0, err
    after = counts(mint)
    assert {k: v for k, v in after.items() if k != "events"} == {
        k: v for k, v in snapshot.items() if k != "events"}
    # 백업 뒤에 남긴 백업 생성 사건은 되돌아가고 복원 사건이 하나 남는다.
    assert after["events"] == snapshot["events"]
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        kinds = {r[0] for r in conn.execute("SELECT kind FROM mint.events")}
    assert "backup_restored" in kinds


def test_restore_refuses_a_different_migration_level(mint, tmp_path):
    token = bootstrap(mint)
    path = tmp_path / "b.mbk"
    assert mint.run("backup", "create", str(path), "--format", "json", token=token)[0] == 0
    with psycopg.connect(mint.env["MINT_DATABASE_URL"]) as conn:
        conn.execute("INSERT INTO mint.schema_migrations (name, sha256) VALUES ('999_x', 'x')")
        conn.commit()
    code, _, err = mint.run("backup", "restore", str(path), "--yes", token=token)
    assert code != 0 and "마이그레이션 수준" in err and "upgrade" in err


def test_backup_encryption_needs_the_passphrase(mint, tmp_path):
    pytest.importorskip("cryptography")
    token = bootstrap(mint)
    path = tmp_path / "enc.mbk"
    mint.env[backup.PASSPHRASE_ENV] = "pw-1"
    assert mint.run("backup", "create", str(path), "--format", "json", token=token)[0] == 0
    assert b"boss" not in path.read_bytes()
    del mint.env[backup.PASSPHRASE_ENV]
    code, _, err = mint.run("backup", "restore", str(path), "--yes", token=token)
    assert code != 0 and backup.PASSPHRASE_ENV in err
    mint.env[backup.PASSPHRASE_ENV] = "wrong"
    code, _, err = mint.run("backup", "restore", str(path), "--yes", token=token)
    assert code != 0 and "복호" in err
