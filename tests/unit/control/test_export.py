"""부정 상태 등록 트리거(003), 내보내기 파일(원자성·HMAC·낮은 세대 보호·키 교체), 되돌림 판정.
실 Postgres. 파일은 임시 디렉터리에 쓴다."""

import os

import pytest
from ctl_fixtures import INSTANCE, as_login

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import exports, seal  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402
from mint_litellm.restore import files, judge  # noqa: E402

KEY = "A" * 43
KEY2 = "B" * 43


def make_settings(tmp_path, key=KEY, previous=None) -> Stage2Settings:
    env = {"MINT_EXPORT_DIR": str(tmp_path / "export"), "MINT_EXPORT_HMAC_KEY": key}
    if previous:
        env["MINT_EXPORT_HMAC_KEY_PREVIOUS"] = previous
    return Stage2Settings.from_env(env)


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


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


def add_org(admin, name):
    admin.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, %s, %s)",
                  (INSTANCE, name, name))


def close_org(admin, name):
    admin.execute("UPDATE mint.orgs SET status = 'closed' WHERE instance_id = %s AND org_id = %s",
                  (INSTANCE, name))


def negative_jobs(conn):
    return fetchall(conn, "SELECT * FROM mint.jobs WHERE kind = 'export_negative_state'"
                    " ORDER BY idempotency_key")


def epoch(admin):
    return fetchone(admin, "SELECT epoch FROM mint.state_epoch")["epoch"]


def seal_rows(admin, worker_conn):
    old = seal.SETTLE_SECONDS
    seal.SETTLE_SECONDS = -1  # 방금 넣은 행도 봉인한다
    try:
        seal.seal_once(worker_conn, INSTANCE)
    finally:
        seal.SETTLE_SECONDS = old


def event(admin, key):
    admin.execute(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
        " VALUES (gen_random_uuid(), %s, 'org_created', %s, '{}')", (INSTANCE, key))


# --- 트리거 ----------------------------------------------------------------------


def test_a_negative_transition_registers_the_export_job_at_commit_with_the_commit_epoch(admin):
    add_org(admin, "a")
    assert negative_jobs(admin) == []  # 긍정 전이는 작업이 없다
    close_org(admin, "a")
    [job] = negative_jobs(admin)
    assert job["idempotency_key"] == f"export_negative:{epoch(admin)}"
    assert job["target_ref"] == "negative_state" and job["status"] == "pending"


def test_several_negative_transitions_in_one_transaction_register_one_job(fresh_db, admin):
    for name in ("a", "b", "c"):
        add_org(admin, name)
    with psycopg.connect(fresh_db) as conn:
        for name in ("a", "b", "c"):
            conn.execute("UPDATE mint.orgs SET status = 'closed' WHERE org_id = %s", (name,))
        conn.execute("INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id,"
                     " reason, created_by) VALUES (gen_random_uuid(), %s, 'a', 'org', 'a', 'r',"
                     " 'x')", (INSTANCE,))
        assert negative_jobs(conn) == []  # 커밋 전에는 걸리지 않는다
        conn.commit()
    [job] = negative_jobs(admin)
    assert job["idempotency_key"] == f"export_negative:{epoch(admin)}"


def test_a_rolled_back_or_savepoint_rolled_back_transition_leaves_no_job(fresh_db, admin):
    add_org(admin, "a")
    add_org(admin, "b")
    with psycopg.connect(fresh_db) as conn:
        conn.execute("UPDATE mint.orgs SET status = 'closed' WHERE org_id = 'a'")
        conn.rollback()
    assert negative_jobs(admin) == []
    with psycopg.connect(fresh_db) as conn:
        try:
            with conn.transaction():
                conn.execute("UPDATE mint.orgs SET status = 'closed' WHERE org_id = 'a'")
                raise RuntimeError
        except RuntimeError:
            pass
        conn.commit()
    assert negative_jobs(admin) == []
    close_org(admin, "b")
    assert len(negative_jobs(admin)) == 1


def test_denials_and_rejected_servers_register_jobs_too(admin):
    add_org(admin, "o")
    admin.execute("INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, reason,"
                  " created_by) VALUES (gen_random_uuid(), %s, 'o', 'org', 'o', 'r', 'x')",
                  (INSTANCE,))
    assert len(negative_jobs(admin)) == 1
    admin.execute("INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256,"
                  " transport, auth_type, registered_by) VALUES (gen_random_uuid(), %s, 's',"
                  " 'awaiting_approval', repeat('a', 64), 'http', 'none', 'x')", (INSTANCE,))
    admin.execute("UPDATE mint.servers SET status = 'rejected'")
    assert len(negative_jobs(admin)) == 2


# --- 내보내기 파일 -----------------------------------------------------------------


def test_the_negative_state_file_is_signed_received_and_latest_follows(
    admin, worker_conn, settings
):
    add_org(admin, "a")
    close_org(admin, "a")
    seal_rows(admin, worker_conn)
    out = exports.write_export(worker_conn, INSTANCE, settings, "negative_state")
    assert out["latest_written"] is True
    keys = exports.keys(settings)
    path = files.negative_path(settings.export_dir, INSTANCE, epoch(admin))
    doc = files.read_verified(path, keys)
    [item] = doc["items"]  # 항목마다 행 전체 스냅숏(모든 열)이 들어 있다
    assert (item["kind"], item["id"], item["state_version"], item["state"]) == (
        "org", "a", 2, "closed")
    assert item["row"] == {"instance_id": INSTANCE, "org_id": "a", "name": "a",
                           "status": "closed", "state_version": 2}
    assert doc["key_id"] == files.key_id(settings.export_hmac_key)
    latest = files.read_verified(files.latest_path(settings.export_dir, INSTANCE), keys)
    assert latest["state_epoch"] == epoch(admin) and latest["to_seal_seq"] == doc["to_seal_seq"]
    row = fetchone(admin, "SELECT * FROM mint.exports")
    assert row["status"] == "written" and row["written_at"] is not None
    assert row["payload_sha256"] == files.content_sha256(
        {k: v for k, v in doc.items() if k != "written_at"})
    assert "export_written" in [r["kind"] for r in fetchall(admin, "SELECT kind FROM mint.events")]
    # 같은 세대는 완료로 끝난다
    assert exports.write_export(worker_conn, INSTANCE, settings, "negative_state") is None
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.exports")["n"] == 1


def test_latest_is_never_overwritten_with_a_lower_epoch(admin, worker_conn, settings):
    add_org(admin, "a")
    close_org(admin, "a")
    exports.write_export(worker_conn, INSTANCE, settings, "negative_state")
    path = files.latest_path(settings.export_dir, INSTANCE)
    high = files.read_verified(path, exports.keys(settings))
    files.atomic_write(path, files.sign({**high, "state_epoch": 999}, settings.export_hmac_key))
    out = exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    assert out["latest_written"] is False
    assert files.read_verified(path, exports.keys(settings))["state_epoch"] == 999
    forced = exports.write_export(
        worker_conn, INSTANCE, settings, "checkpoint", force_latest=True)
    assert forced["latest_written"] is True
    assert files.read_verified(path, exports.keys(settings))["state_epoch"] == epoch(admin)


def test_a_checkpoint_is_written_every_time_and_refreshes_latest(admin, worker_conn, settings):
    first = exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    second = exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    assert first["path"] != second["path"]
    latest = files.read_verified(files.latest_path(settings.export_dir, INSTANCE),
                                 exports.keys(settings))
    assert latest["written_at"] == second["written_at"]
    n = fetchone(admin, "SELECT count(*) AS n FROM mint.exports WHERE status = 'written'")["n"]
    assert n == 2


def test_a_failed_write_leaves_the_old_file_marks_failed_and_retries(
    admin, worker_conn, settings, monkeypatch
):
    add_org(admin, "a")
    close_org(admin, "a")
    exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    path = files.latest_path(settings.export_dir, INSTANCE)
    before = path.read_bytes()
    add_org(admin, "b")
    close_org(admin, "b")
    real = os.replace

    def broken(*args, **kwargs):
        raise OSError("disk")

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(exports.ExportFailed):
        exports.write_export(worker_conn, INSTANCE, settings, "negative_state")
    assert path.read_bytes() == before  # 반쯤 쓴 파일이 보이지 않는다
    assert not list(settings.export_dir.rglob("*.tmp"))
    row = fetchone(admin, "SELECT * FROM mint.exports WHERE kind = 'negative_state'")
    assert row["status"] == "failed" and row["attempts"] == 1
    assert "export_failed" in [r["kind"] for r in fetchall(admin, "SELECT kind FROM mint.events")]
    alert = fetchone(admin, "SELECT * FROM mint.alerts WHERE kind = 'export_failed'")
    assert alert["severity"] == "high" and alert["status"] == "open"
    monkeypatch.setattr(os, "replace", real)
    exports.write_export(worker_conn, INSTANCE, settings, "negative_state")
    row = fetchone(admin, "SELECT * FROM mint.exports WHERE kind = 'negative_state'")
    assert row["status"] == "written" and row["attempts"] == 2


def test_hmac_key_rotation_verifies_old_files_and_resigns_the_newest_negative(
    admin, worker_conn, tmp_path
):
    old = make_settings(tmp_path, key=KEY)
    add_org(admin, "a")
    close_org(admin, "a")
    exports.write_export(worker_conn, INSTANCE, old, "negative_state")
    new_only = make_settings(tmp_path, key=KEY2)
    with pytest.raises(files.ExportUnverified):
        files.read_verified(files.latest_path(new_only.export_dir, INSTANCE),
                            exports.keys(new_only))
    rotated = make_settings(tmp_path, key=KEY2, previous=KEY)
    path = files.latest_path(rotated.export_dir, INSTANCE)
    assert files.read_verified(path, exports.keys(rotated))  # 옛 키 파일도 검증된다
    exports.write_export(worker_conn, INSTANCE, rotated, "checkpoint")
    assert exports.resign_newest_negative(rotated, INSTANCE) is True
    # 옛 키를 뺀 설정으로도 latest와 최근 부정 상태 파일이 모두 검증된다
    state = judge.read_files(new_only.export_dir, INSTANCE, exports.keys(new_only))
    assert state.error is None and state.negative is not None


def test_tampered_files_are_rejected(settings, tmp_path):
    doc = files.sign({"state_epoch": 3}, settings.export_hmac_key)
    path = tmp_path / "x.json"
    files.atomic_write(path, doc)
    path.write_text(path.read_text().replace('"state_epoch": 3', '"state_epoch": 2'))
    with pytest.raises(files.ExportUnverified):
        files.read_verified(path, exports.keys(settings))
    path.write_text("{")
    with pytest.raises(files.ExportUnverified):
        files.read_verified(path, exports.keys(settings))
    with pytest.raises(FileNotFoundError):
        files.read_verified(tmp_path / "none.json", exports.keys(settings))


# --- 판정 ------------------------------------------------------------------------


def evaluate(j, conn, settings):
    return j.evaluate(conn, settings.export_dir, INSTANCE, exports.keys(settings))


def test_no_file_and_no_written_row_is_not_judged_but_a_written_row_blocks(
    admin, worker_conn, settings
):
    j = judge.Judge()
    assert evaluate(j, worker_conn, settings).state == judge.SKIP
    exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    assert evaluate(j, worker_conn, settings).state == judge.OK
    files.latest_path(settings.export_dir, INSTANCE).unlink()
    verdict = evaluate(j, worker_conn, settings)
    assert verdict.blocked and verdict.cause == judge.EXPORT_MISSING


def test_a_missing_negative_file_with_a_written_negative_row_is_export_missing(
    admin, worker_conn, settings
):
    add_org(admin, "a")
    close_org(admin, "a")
    exports.write_export(worker_conn, INSTANCE, settings, "negative_state")
    j = judge.Judge()
    assert evaluate(j, worker_conn, settings).state == judge.OK
    import shutil

    shutil.rmtree(settings.export_dir / INSTANCE / "negative")  # latest.json은 남아 있다
    verdict = evaluate(j, worker_conn, settings)
    assert verdict.blocked and verdict.cause == judge.EXPORT_MISSING


def test_unreadable_unknown_key_or_bad_hmac_blocks_at_once(admin, worker_conn, settings, tmp_path):
    exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    path = files.latest_path(settings.export_dir, INSTANCE)
    good = path.read_text()
    j = judge.Judge()
    path.write_text(good.replace('"state_epoch"', '"state_epochs"'))
    assert evaluate(j, worker_conn, settings).cause == judge.EXPORT_UNVERIFIED
    path.write_text(good)
    other = make_settings(tmp_path, key=KEY2)
    assert evaluate(j, worker_conn, other).cause == judge.EXPORT_UNVERIFIED
    path.write_text("not json")
    assert evaluate(j, worker_conn, settings).blocked
    path.write_text(good)
    assert evaluate(j, worker_conn, settings).state == judge.OK


def forge(settings, **latest_changes):
    """파일만 바꿔 DB가 되돌려진 것처럼 만든다(서명은 올바르다)."""
    path = files.latest_path(settings.export_dir, INSTANCE)
    doc = files.read_verified(path, exports.keys(settings))
    doc.update(latest_changes)
    files.atomic_write(path, files.sign(doc, settings.export_hmac_key))


def test_a_missing_negative_item_holds_then_blocks_on_the_second_mismatch(
    admin, worker_conn, settings
):
    add_org(admin, "a")
    close_org(admin, "a")
    exports.write_export(worker_conn, INSTANCE, settings, "negative_state")
    j = judge.Judge()
    assert evaluate(j, worker_conn, settings).state == judge.OK
    # 철회 직전 시점으로 DB를 복구한 것과 같다: 파일의 항목이 DB보다 앞서 있다
    npath = files.newest_negative(settings.export_dir, INSTANCE)
    doc = files.read_verified(npath, exports.keys(settings))
    doc["items"][0]["state_version"] = 9
    files.atomic_write(npath, files.sign(doc, settings.export_hmac_key))
    first = evaluate(j, worker_conn, settings)
    assert first.state == judge.HOLD and first.held and not first.blocked
    second = evaluate(j, worker_conn, settings)
    assert second.blocked and second.cause == judge.RESTORE_PENDING
    assert second.detail["missing_items"] == 1


def test_a_seal_anchor_mismatch_is_caught_even_when_the_db_epoch_overtook_the_file(
    admin, worker_conn, settings
):
    add_org(admin, "a")
    event(admin, "org:a:1:org_created")
    seal_rows(admin, worker_conn)
    exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    j = judge.Judge()
    assert evaluate(j, worker_conn, settings).state == judge.OK
    forge(settings, tail_hash="00" * 32)
    evaluate(j, worker_conn, settings)
    verdict = evaluate(j, worker_conn, settings)
    assert verdict.blocked and verdict.detail["anchor_ok"] is False
    assert verdict.detail["db_epoch"] >= verdict.detail["file_epoch"]  # 세대는 추월했다


def test_a_lower_db_epoch_alone_is_a_supporting_signal(admin, worker_conn, settings):
    exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    forge(settings, state_epoch=500)
    j = judge.Judge()
    evaluate(j, worker_conn, settings)
    assert evaluate(j, worker_conn, settings).blocked


def test_canonical_json_is_fixed_and_rejects_floats():
    import json

    value = {"b": [1, "한글", None, True], "a": {"z": 1, "y": "x"}}
    assert files.canonical_json(value) == json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert files.canonical_json(value) == (
        '{"a":{"y":"x","z":1},"b":[1,"한글",null,true]}'.encode())
    with pytest.raises(ValueError, match="실수"):
        files.canonical_json({"a": [1.5]})
    with pytest.raises(ValueError):
        files.sign({"x": 0.1}, b"k" * 32)


# 공통 시험 벡터: 다른 구현이 같은 서명을 만들어 내는지 확인하는 고정 값이다.
VECTOR_DOC = {"b": [3, 1, 2], "a": {"z": "한글", "y": None, "x": True}, "key_id": "x"}
VECTOR_CANONICAL = '{"a":{"x":true,"y":null,"z":"한글"},"b":[3,1,2],"key_id":"x"}'
VECTOR_HMAC = "017223bfcfe283c6d7d669ae50c869dded2723fbc166dafd7c7ebc96317d0847"


def test_signature_test_vector_is_fixed():
    import hashlib
    import hmac
    import re

    key = b"k" * 32
    assert files.canonical_json(VECTOR_DOC) == VECTOR_CANONICAL.encode("utf-8")
    digest = hmac.new(key, VECTOR_CANONICAL.encode("utf-8"), hashlib.sha256).hexdigest()
    assert digest == VECTOR_HMAC
    # 서명 입력은 hmac 필드를 뺀 본문 전체(key_id 포함)이고 배열은 저장 순서 그대로다
    signed = files.sign({k: v for k, v in VECTOR_DOC.items() if k != "key_id"}, key)
    assert signed["key_id"] == files.key_id(key)
    body = {k: v for k, v in signed.items() if k != "hmac"}
    assert signed["hmac"] == hmac.new(key, files.canonical_json(body), hashlib.sha256).hexdigest()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", files.now())  # UTC 초 단위 Z


def test_events_refuse_float_payloads():
    from datetime import UTC, datetime

    from mint_litellm.types.events import Event, EventKind

    base = dict(instance_id="i", inserted_at=datetime.now(UTC), kind=EventKind.ORG_CREATED,
                source_key="org:a:1:org_created", actor="x")
    Event(**base, payload={"n": 1})
    with pytest.raises(ValueError):
        Event(**base, payload={"n": [1.5]})


def test_an_export_job_does_not_recreate_a_vanished_latest_file(admin, worker_conn, settings):
    from types import SimpleNamespace

    from mint_litellm.control.jobs import RestoreBlocked

    job = SimpleNamespace(conn=worker_conn, instance_id=INSTANCE, settings=settings)
    exports._refuse_when_latest_vanished(job)  # 첫 설치: 쓴 내보내기가 없으면 통과한다
    exports.write_export(worker_conn, INSTANCE, settings, "checkpoint")
    exports._refuse_when_latest_vanished(job)
    files.latest_path(settings.export_dir, INSTANCE).unlink()
    with pytest.raises(RestoreBlocked):
        exports._refuse_when_latest_vanished(job)
    assert not files.latest_path(settings.export_dir, INSTANCE).exists()
