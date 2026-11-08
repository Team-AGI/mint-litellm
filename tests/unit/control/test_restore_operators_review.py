"""운영자 부정 상태의 보강: 지문·동시성·부정 방향만 복원·업그레이드 예약. 실 Postgres."""

from datetime import UTC, datetime

import pytest

from control import test_restore_acceptance as base
from control.test_restore_acceptance import (
    INSTANCE,
    attest_restored,
    overtake_epoch,
    run_worker,
)
from control.test_restore_operators import (
    TOKENS,
    authenticate,
    export_all,
    operator_row,
    seed_operators,
    verdicts,
)

world = base.world  # 같은 시험 세계(픽스처)를 쓴다

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import exports, ledger, operators  # noqa: E402
from mint_litellm.control.db.connection import fetchone  # noqa: E402
from mint_litellm.control.errors import AuthError  # noqa: E402
from mint_litellm.restore import files, judge  # noqa: E402
from mint_litellm.types.events import EventKind  # noqa: E402


@pytest.fixture
def seeded(world):
    seed_operators(world["live"], world["restored"])
    return world


def read_items(world):
    path = files.newest_negative(world["settings"].export_dir, INSTANCE)
    return files.read_verified(path, exports.keys(world["settings"]))["items"]


def test_the_files_carry_a_fingerprint_instead_of_the_token_hash(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'bob'")
        conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'eve'")
    export_all(world)
    rows = {i["id"]: i["row"] for i in read_items(world)}
    assert "token_hash" not in rows["bob"] and len(rows["bob"]["token_fp"]) == 64
    assert rows["eve"]["token_fp"] is None  # 만료된 운영자의 토큰은 의미가 없다
    hashes = [operators.hash_token(t) for t in TOKENS.values()]
    for path in world["settings"].export_dir.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert not any(h in text for h in hashes)


def test_a_promotion_then_a_demotion_is_exported_and_restored_as_the_demotion(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET role = 'admin' WHERE name = 'bob'")  # v2 승격
        conn.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'bob'")  # v3 강등
    file_epoch = export_all(world)
    items = read_items(world)
    assert [(i["id"], i["state"], i["state_version"]) for i in items] == [("bob", "viewer", 3)]
    assert verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    assert authenticate(world["restored"], TOKENS["bob"]).role == "viewer"
    assert operator_row(world["restored"], "bob")["state_version"] == 3
    assert run_worker(world).state == judge.OK


def test_the_last_role_event_must_name_the_current_role(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'bob'")
    export_all(world)
    with psycopg.connect(world["live"], autocommit=True) as conn:
        for to, role in (("approver", "approver"), ("viewer", "admin")):  # 둘째 사건은 맞지 않는다
            version = fetchone(
                conn, "UPDATE mint.operators SET role = %s WHERE name = 'bob'"
                " RETURNING state_version", (role,))["state_version"]
            ledger.record(conn, INSTANCE, EventKind.OPERATOR_ROLE_CHANGED, entity_id="bob",
                          state_version=version, actor="root",
                          payload={"name": "bob", "from": "x", "to": to})
    assert verdicts(world["live"], world["settings"], 1)[0].state == judge.HOLD


def test_a_concurrent_demotion_is_not_undone_by_attest(seeded):
    import threading
    import time

    from mint_litellm.control.services import restore_rows

    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET role = 'approver' WHERE name = 'eve'")
    export_all(world)
    item = read_items(world)[0]
    assert (item["id"], item["row"]["role"]) == ("eve", "approver")
    other = psycopg.connect(world["restored"])  # 다른 관리자의 강등(아직 커밋 전)
    other.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'eve'")

    def attest_side():
        with psycopg.connect(world["restored"]) as conn:
            restore_rows.restore_item(conn, INSTANCE, item)
            conn.commit()

    thread = threading.Thread(target=attest_side)
    thread.start()
    time.sleep(0.5)
    other.commit()
    other.close()
    thread.join(10)
    assert not thread.is_alive()
    assert operator_row(world["restored"], "eve")["role"] == "viewer"  # 재승격하지 않았다


def test_a_replaced_token_does_not_come_back_with_the_rolled_back_database(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET token_hash = %s WHERE name = 'bob'",
                     (operators.hash_token("mint_bob_new"),))
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.jobs WHERE kind ="
                        " 'export_negative_state'")["n"] == 1  # 토큰 교체도 내보낸다
    file_epoch = export_all(world)
    overtake_epoch(world["restored"], file_epoch)  # 교체 전 DB: 옛 토큰이 살아 있다
    assert authenticate(world["restored"], TOKENS["bob"]).role == "approver"
    assert verdicts(world["restored"], world["settings"], 1)[0].state == judge.HOLD
    out = attest_restored(world)
    assert out["reapplied"] == [{"kind": "operator", "id": "bob", "was": "reapply"}]
    with pytest.raises(AuthError, match="만료"):
        authenticate(world["restored"], TOKENS["bob"])  # 새 토큰을 알 수 없어 만료시킨다
    assert run_worker(world).state == judge.OK


def add_zed(conn, role="approver"):
    conn.execute(
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES (%s, 'zed', %s, %s, 'zed-user')",
        (INSTANCE, role, operators.hash_token("mint_zed")))


def test_an_active_operator_missing_from_the_database_is_never_created(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        add_zed(conn)
        conn.execute("UPDATE mint.operators SET role = 'admin' WHERE name = 'zed'")  # 활성 v2
    file_epoch = export_all(world)
    assert [i["id"] for i in read_items(world)] == ["zed"]
    overtake_epoch(world["restored"], file_epoch)
    assert verdicts(world["restored"], world["settings"], 1)[0].state == judge.OK
    assert attest_restored(world)["reapplied"] == []
    assert operator_row(world["restored"], "zed") is None


def test_a_removed_operator_put_back_has_an_unusable_token(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        add_zed(conn, "admin")
        conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'zed'")
    file_epoch = export_all(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    row = operator_row(world["restored"], "zed")
    assert row["expires_at"] is not None and row["token_hash"] != operators.hash_token("mint_zed")
    assert run_worker(world).state == judge.OK


def test_the_export_functions_are_not_executable_by_public(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        rows = conn.execute(
            "SELECT p.proname FROM pg_proc p, aclexplode(coalesce(p.proacl,"
            " acldefault('f', p.proowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'"
            " AND p.proname IN ('enqueue_export_operator', 'enqueue_export_negative',"
            " 'operator_rank')").fetchall()
    assert rows == []


def test_the_upgrade_schedules_the_first_export_for_existing_operator_history(fresh_db):
    """이미 삭제·강등된 운영자가 있는 DB를 올리면 마이그레이션이 첫 내보내기를 예약한다."""
    from mint_litellm.control.db import migrate

    text = dict(migrate._migration_files())["014_operator_negative"]
    statement = text[text.index("WITH instances"):]
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        for name, expires, version, digit in (
            ("old_admin", True, 2, "a"), ("plain", False, 1, "b")):
            conn.execute(
                "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id,"
                " expires_at, state_version) VALUES (%s, %s, 'admin', repeat(%s, 64),"
                " 'u', CASE WHEN %s THEN now() END, %s)",
                (INSTANCE, name, digit, expires, version))
        conn.execute("SET session_replication_role = DEFAULT")
        jobs = "SELECT count(*) AS n FROM mint.jobs WHERE kind = 'export_negative_state'"
        before = fetchone(conn, jobs)["n"]
        epoch = fetchone(conn, "SELECT coalesce(max(epoch), 0) AS e FROM mint.state_epoch")["e"]
        conn.execute(statement)
        conn.execute(statement)  # 다시 실행해도 같은 키가 아니라 새 세대지만 한 건씩이다
        assert fetchone(conn, jobs)["n"] == before + 2
        assert fetchone(conn, "SELECT epoch FROM mint.state_epoch")["epoch"] == epoch + 2


def test_an_operator_due_to_expire_is_put_back_already_expired(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        add_zed(conn, "admin")
        conn.execute("UPDATE mint.operators SET expires_at = now() + interval '30 days'"
                     " WHERE name = 'zed'")
    file_epoch = export_all(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    row = operator_row(world["restored"], "zed")
    assert row["expires_at"] <= datetime.now(UTC)
    with pytest.raises(AuthError):
        authenticate(world["restored"], "mint_zed")
