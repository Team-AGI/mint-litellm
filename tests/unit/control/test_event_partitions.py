"""사건 원장 월 분할: 분할 만들기, 닫힌 달 내보내기, 선택적 보관. 실 Postgres."""

import gzip
import json
from datetime import UTC, date, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, as_login

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import event_partitions, jobs, seal  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.exports import ExportFailed  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402

KEY = "A" * 43


def make_settings(tmp_path, retention=None) -> Stage2Settings:
    env = {"MINT_EXPORT_DIR": str(tmp_path / "export"), "MINT_EXPORT_HMAC_KEY": KEY}
    if retention is not None:
        env["MINT_EVENT_RETENTION_DAYS"] = str(retention)
    return Stage2Settings.from_env(env)


@pytest.fixture
def admin(fresh_db):
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("INSERT INTO mint.settings (instance_id) VALUES (%s)", (INSTANCE,))
        yield conn


@pytest.fixture
def worker_conn(fresh_db, login_roles):
    with as_login(fresh_db, "mint_worker") as conn:
        conn.autocommit = True
        yield conn


def ctx(conn, settings):
    return jobs.JobContext(conn, INSTANCE, {"kind": "event_partition_maintain"}, settings)


def old_month() -> date:
    return (datetime.now(UTC).date().replace(day=1) - timedelta(days=100)).replace(day=1)


def add_events(admin, month: date, count: int, prefix="k") -> None:
    admin.execute("SELECT mint.ensure_event_partition(%s)", (month,))
    for n in range(count):
        admin.execute(
            "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key,"
            " payload) VALUES (gen_random_uuid(), %s, %s, 'org_created', %s, '{}')",
            (INSTANCE, datetime(month.year, month.month, 2 + n, tzinfo=UTC), f"{prefix}:{n}"),
        )


def seal_all(conn) -> None:
    old = seal.SETTLE_SECONDS
    seal.SETTLE_SECONDS = -1
    try:
        seal.seal_once(conn, INSTANCE)
    finally:
        seal.SETTLE_SECONDS = old


def partitions(admin) -> set[str]:
    return {
        r["relname"] for r in fetchall(
            admin,
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
            " WHERE i.inhparent = 'mint.events'::regclass")
    }


def test_the_events_table_is_partitioned_with_a_default_and_future_months(admin):
    names = partitions(admin)
    assert "events_default" in names
    this = datetime.now(UTC).date().replace(day=1)
    assert f"events_{this:%Y%m}" in names
    assert len([n for n in names if n != "events_default"]) == 4


def test_ensure_partitions_is_idempotent_and_creates_missing_months(admin, worker_conn, tmp_path):
    before = partitions(admin)
    assert event_partitions.ensure_partitions(worker_conn) == []
    assert partitions(admin) == before
    assert event_partitions.ensure_partitions(worker_conn, date(2040, 1, 15)) != []
    assert "events_204004" in partitions(admin)


def test_a_month_that_the_default_partition_already_holds_cannot_be_created(admin, worker_conn):
    admin.execute(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, payload)"
        " VALUES (gen_random_uuid(), %s, %s, 'org_created', 'd:1', '{}')",
        (INSTANCE, datetime(2041, 2, 3, tzinfo=UTC)))
    with pytest.raises(ControlError, match="204102"):
        event_partitions.ensure_partitions(worker_conn, date(2041, 1, 10))
    assert "events_204103" in partitions(admin)  # 나머지 달은 만들었다


def test_the_partition_guards_still_hold(admin):
    add_events(admin, old_month(), 1)
    part = f"events_{old_month():%Y%m}"
    for sql in (f"TRUNCATE mint.{part}", "TRUNCATE mint.events", "DELETE FROM mint.events",
                "UPDATE mint.events SET kind = 'x'"):
        with pytest.raises(psycopg.errors.CheckViolation):
            admin.execute(sql)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_events(admin, old_month(), 1)  # 같은 source_key를 다시 넣는다
    with pytest.raises(psycopg.errors.CheckViolation):
        admin.execute("DELETE FROM mint.event_keys")


def test_claiming_a_key_makes_the_second_insert_a_no_op(admin):
    sql = (
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
        " SELECT gen_random_uuid(), %s, 'org_created', 'c:1', '{}'::jsonb"
        " WHERE mint.claim_event_key(%s, 'c:1', gen_random_uuid())")
    # claim이 만든 event_id와 삽입한 event_id가 달라 삽입은 키 충돌로 거부된다(같은 id를 써야 한다)
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin.execute(sql, (INSTANCE, INSTANCE))
    ev = "11111111-1111-1111-1111-111111111111"
    good = (
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
        " SELECT %s::uuid, %s, 'org_created', 'c:2', '{}'::jsonb"
        " WHERE mint.claim_event_key(%s, 'c:2', %s::uuid)")
    params = (ev, INSTANCE, INSTANCE, ev)
    assert admin.execute(good, params).rowcount == 1
    other = ("22222222-2222-2222-2222-222222222222",) * 2
    assert admin.execute(good, (other[0], INSTANCE, INSTANCE, other[1])).rowcount == 0


def test_seal_sequence_stays_unique_per_instance(admin):
    add_events(admin, old_month(), 2)
    admin.execute("UPDATE mint.events SET seal_seq = 1, row_hash = decode(repeat('ab', 32), 'hex'),"
                  " sealed_at = now() WHERE source_key = 'k:0'")
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin.execute(
            "UPDATE mint.events SET seal_seq = 1, row_hash = decode(repeat('ab', 32), 'hex'),"
            " sealed_at = now() WHERE source_key = 'k:1'")


def test_closed_sealed_months_are_exported_with_a_manifest(admin, worker_conn, tmp_path):
    month = old_month()
    add_events(admin, month, 3)
    settings = make_settings(tmp_path)
    event_partitions.maintain(ctx(worker_conn, settings))
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.event_exports")["n"] == 0  # 봉인 전
    seal_all(worker_conn)
    event_partitions.maintain(ctx(worker_conn, settings))
    row = fetchone(admin, "SELECT * FROM mint.event_exports")
    assert (row["month"], row["row_count"], row["revision"]) == (month, 3, 1)
    data, manifest = event_partitions._paths(settings.export_dir, month)
    lines = gzip.decompress(data.read_bytes()).splitlines()
    assert len(lines) == 3 and json.loads(lines[0])["kind"] == "org_created"
    assert json.loads(manifest.read_text(encoding="utf-8"))["file_sha256"] == row["file_sha256"]
    kinds = [r["kind"] for r in fetchall(admin, "SELECT kind FROM mint.events")]
    assert "event_partition_exported" in kinds
    event_partitions.maintain(ctx(worker_conn, settings))  # 같은 내용이면 다시 쓰지 않는다
    assert fetchone(admin, "SELECT revision FROM mint.event_exports")["revision"] == 1


def test_retention_is_off_unless_configured(admin, worker_conn, tmp_path):
    month = old_month()
    add_events(admin, month, 2)
    seal_all(worker_conn)
    settings = make_settings(tmp_path)
    assert settings.event_retention_days is None
    event_partitions.maintain(ctx(worker_conn, settings))
    event_partitions.retain(ctx(worker_conn, settings))
    assert f"events_{month:%Y%m}" in partitions(admin)


def test_retention_drops_only_verified_old_months_and_records_it(admin, worker_conn, tmp_path):
    month = old_month()
    add_events(admin, month, 3)
    seal_all(worker_conn)
    settings = make_settings(tmp_path, retention=31)
    event_partitions.maintain(ctx(worker_conn, settings))
    before = seal.verify(admin, INSTANCE)
    assert before["ok"]
    event_partitions.retain(ctx(worker_conn, settings))
    assert f"events_{month:%Y%m}" not in partitions(admin)
    assert fetchone(admin, "SELECT dropped_at FROM mint.event_exports")["dropped_at"]
    dropped = fetchall(admin, "SELECT * FROM mint.events WHERE kind = 'event_partition_dropped'")
    assert len(dropped) == 1 and dropped[0]["payload"]["row_count"] == 3
    # 지운 달의 키는 남아 같은 키의 재적재가 다시 들어오지 않는다
    with pytest.raises(psycopg.errors.UniqueViolation):
        add_events(admin, month, 1)
    after = seal.verify(admin, INSTANCE)
    assert after["ok"], after["errors"]


def test_retention_keeps_months_younger_than_the_period(admin, worker_conn, tmp_path):
    month = old_month()
    add_events(admin, month, 1)
    seal_all(worker_conn)
    settings = make_settings(tmp_path, retention=365)
    event_partitions.maintain(ctx(worker_conn, settings))
    event_partitions.retain(ctx(worker_conn, settings))
    assert f"events_{month:%Y%m}" in partitions(admin)


@pytest.mark.parametrize("damage", ["flip", "delete", "manifest"])
def test_retention_never_drops_when_the_export_cannot_be_verified(
    admin, worker_conn, tmp_path, damage
):
    month = old_month()
    add_events(admin, month, 2)
    seal_all(worker_conn)
    settings = make_settings(tmp_path, retention=31)
    event_partitions.maintain(ctx(worker_conn, settings))
    data, manifest = event_partitions._paths(settings.export_dir, month)
    if damage == "flip":
        data.write_bytes(gzip.compress(b"{}\n{}\n"))
    elif damage == "delete":
        data.unlink()
    else:
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("row_count", "rows"))
    with pytest.raises(ExportFailed):
        event_partitions.retain(ctx(worker_conn, settings))
    assert f"events_{month:%Y%m}" in partitions(admin)
    alerts = fetchone(admin, "SELECT count(*) AS n FROM mint.alerts WHERE kind = 'export_failed'")
    assert alerts["n"] == 1


def test_the_database_refuses_to_drop_a_changed_or_unrecorded_partition(
    fresh_db, admin, worker_conn, tmp_path
):
    month = old_month()
    add_events(admin, month, 2)
    seal_all(worker_conn)
    settings = make_settings(tmp_path)
    event_partitions.maintain(ctx(worker_conn, settings))
    row = fetchone(admin, "SELECT * FROM mint.event_exports")
    drop = "SELECT mint.drop_event_partition(%s, %s, %s)"
    for args in ((month, row["row_count"] + 1, row["file_sha256"]),
                 (month, row["row_count"], "0" * 64),
                 (date.today().replace(day=1), 0, row["file_sha256"])):
        with pytest.raises(psycopg.Error):
            admin.execute(drop, args)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with as_login(fresh_db, "mint_plugin") as plugin:
            plugin.execute(drop, (month, row["row_count"], row["file_sha256"]))
    assert f"events_{month:%Y%m}" in partitions(admin)


def test_a_row_added_after_the_export_is_exported_again_and_blocks_the_drop(
    admin, worker_conn, tmp_path
):
    month = old_month()
    add_events(admin, month, 2)
    seal_all(worker_conn)
    settings = make_settings(tmp_path, retention=31)
    event_partitions.maintain(ctx(worker_conn, settings))
    add_events(admin, month, 1, prefix="late")
    with pytest.raises(ExportFailed):
        event_partitions.retain(ctx(worker_conn, settings))  # 내보낸 행 수와 다르다
    assert f"events_{month:%Y%m}" in partitions(admin)
    seal_all(worker_conn)
    event_partitions.maintain(ctx(worker_conn, settings))
    assert fetchone(admin, "SELECT row_count, revision FROM mint.event_exports") == {
        "row_count": 3, "revision": 2}
    event_partitions.retain(ctx(worker_conn, settings))
    assert f"events_{month:%Y%m}" not in partitions(admin)


def test_retention_days_setting_rules(tmp_path):
    base = {"MINT_EXPORT_DIR": str(tmp_path), "MINT_EXPORT_HMAC_KEY": KEY}
    def days(value):
        env = {**base, "MINT_EVENT_RETENTION_DAYS": value}
        return Stage2Settings.from_env(env).event_retention_days

    assert Stage2Settings.from_env(base).event_retention_days is None
    assert days(" ") is None
    assert days("400") == 400
    for bad in ("0", "30", "abc"):
        with pytest.raises(ControlError):
            days(bad)
