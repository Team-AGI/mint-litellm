"""운영자 삭제·강등은 부정 상태다: 내보내기 -> 되돌림 판정 -> attest 재적용. 실 Postgres."""

import pytest
from ctl_fixtures import as_login

from control import test_restore_acceptance as base
from control.test_restore_acceptance import (
    INSTANCE,
    attest_restored,
    overtake_epoch,
    run_worker,
)

world = base.world  # 같은 시험 세계(픽스처)를 쓴다

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import exports, ledger, operators  # noqa: E402
from mint_litellm.control.db.connection import fetchone  # noqa: E402
from mint_litellm.control.errors import AuthError  # noqa: E402
from mint_litellm.restore import files, judge  # noqa: E402
from mint_litellm.types.events import EventKind  # noqa: E402

TOKENS = {"root": "mint_root", "bob": "mint_bob", "eve": "mint_eve"}


def seed_operators(*urls):
    """같은 운영자 셋(admin 둘과 approver 하나)을 두 DB에 넣는다."""
    for url in urls:
        with psycopg.connect(url, autocommit=True) as conn:
            for name, role, user in (
                ("root", "admin", "root-user"), ("bob", "approver", "bob-user"),
                ("eve", "admin", "eve-user"),
            ):
                conn.execute(
                    "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (INSTANCE, name, role, operators.hash_token(TOKENS[name]), user))


def export_all(world):
    with psycopg.connect(world["live"], autocommit=True) as conn:
        exports.write_export(conn, INSTANCE, world["settings"], "negative_state")
        exports.write_export(conn, INSTANCE, world["settings"], "checkpoint")
        return fetchone(conn, "SELECT epoch FROM mint.state_epoch")["epoch"]


def verdicts(url, settings, times=2):
    judge_ = judge.Judge()
    out = []
    with psycopg.connect(url, autocommit=True) as conn:
        for _ in range(times):
            out.append(judge_.evaluate(
                conn, settings.export_dir, INSTANCE, exports.keys(settings)))
    return out


def operator_row(url, name):
    with psycopg.connect(url, autocommit=True) as conn:
        return fetchone(conn, "SELECT * FROM mint.operators WHERE name = %s", (name,))


def authenticate(url, token):
    with psycopg.connect(url, autocommit=True) as conn:
        return operators.authenticate(conn, INSTANCE, token)


@pytest.fixture
def seeded(world):
    seed_operators(world["live"], world["restored"])
    return world


def test_a_removal_is_exported_and_the_old_token_stays_dead_after_a_rollback_and_attest(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'bob'")
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.jobs WHERE kind ="
                        " 'export_negative_state'")["n"] == 1
    file_epoch = export_all(world)
    items = files.read_verified(
        files.newest_negative(world["settings"].export_dir, INSTANCE),
        exports.keys(world["settings"]))["items"]
    assert [(i["kind"], i["id"], i["state"]) for i in items] == [("operator", "bob", "removed")]
    overtake_epoch(world["restored"], file_epoch)  # 삭제 전 시점의 DB로 되돌렸다
    assert authenticate(world["restored"], TOKENS["bob"]).role == "approver"  # 되살아난 권한
    first, second = verdicts(world["restored"], world["settings"])
    assert (first.state, second.state) == (judge.HOLD, judge.BLOCKED)
    assert first.detail["missing_items"] == 1
    out = attest_restored(world)
    assert out["reapplied"] == [{"kind": "operator", "id": "bob", "was": "reapply"}]
    with pytest.raises(AuthError, match="만료"):
        authenticate(world["restored"], TOKENS["bob"])
    assert authenticate(world["restored"], TOKENS["root"]).role == "admin"
    assert run_worker(world).state == judge.OK
    assert attest_restored(world, "한 번 더")["reapplied"] == []  # 반복해도 같은 결과다


def test_a_demotion_comes_back_as_a_demotion(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'bob'")
        conn.execute("UPDATE mint.operators SET role = 'approver' WHERE name = 'eve'")
    file_epoch = export_all(world)
    overtake_epoch(world["restored"], file_epoch)
    assert verdicts(world["restored"], world["settings"], 1)[0].state == judge.HOLD
    out = attest_restored(world)
    assert sorted((r["id"], r["was"]) for r in out["reapplied"]) == [
        ("bob", "reapply"), ("eve", "reapply")]
    assert authenticate(world["restored"], TOKENS["bob"]).role == "viewer"
    assert authenticate(world["restored"], TOKENS["eve"]).role == "approver"
    assert operator_row(world["restored"], "bob")["state_version"] >= 2
    assert run_worker(world).state == judge.OK


def test_an_operator_added_after_the_backup_is_put_back_already_removed(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
            " VALUES (%s, 'zed', 'admin', %s, 'zed-user')",
            (INSTANCE, operators.hash_token("mint_zed")))
        conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'zed'")
    file_epoch = export_all(world)
    overtake_epoch(world["restored"], file_epoch)
    out = attest_restored(world)
    assert out["reapplied"] == [{"kind": "operator", "id": "zed", "was": "missing_row"}]
    with pytest.raises(AuthError, match="만료"):
        authenticate(world["restored"], "mint_zed")


def test_a_later_legitimate_promotion_does_not_hold_the_judge(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'bob'")
    export_all(world)
    assert verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
    with psycopg.connect(world["live"], autocommit=True) as conn:
        version = fetchone(conn, "UPDATE mint.operators SET role = 'approver' WHERE name = 'bob'"
                           " RETURNING state_version")["state_version"]
        # 승격은 내보내기 대상이 아니므로 파일은 강등 시점 그대로다. 사건이 없으면 되돌림이다.
        assert verdicts(world["live"], world["settings"], 1)[0].state == judge.HOLD
        ledger.record(conn, INSTANCE, EventKind.OPERATOR_ROLE_CHANGED, entity_id="bob",
                      state_version=version, actor="root",
                      payload={"name": "bob", "from": "viewer", "to": "approver"})
    assert verdicts(world["live"], world["settings"], 1)[0].state == judge.OK


def test_an_expiry_that_was_pushed_back_is_a_rollback(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'bob'")
    export_all(world)
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET expires_at = NULL WHERE name = 'bob'")
    assert verdicts(world["live"], world["settings"], 1)[0].state == judge.HOLD


def test_the_plugin_login_can_judge_operators_without_reading_token_hashes(seeded):
    world = seeded
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.operators SET expires_at = now() WHERE name = 'bob'")
    file_epoch = export_all(world)
    overtake_epoch(world["restored"], file_epoch)
    state = judge.read_files(
        world["settings"].export_dir, INSTANCE, exports.keys(world["settings"]))
    with as_login(world["restored"], "mint_plugin") as conn:
        facts = fetchone(conn, judge.FACTS_SQL, judge.facts_params(state, INSTANCE))
        assert facts["missing"] == 1
        conn.rollback()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT token_hash FROM mint.operators")
