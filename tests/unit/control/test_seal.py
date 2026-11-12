"""봉인: 연쇄·최초 prev·빈 배치 없음·변조 탐지·동시 봉인·검증 명령의 대조. 실 Postgres."""

import threading

import pytest
from ctl_fixtures import INSTANCE, as_login

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import seal  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402


@pytest.fixture
def admin(fresh_db):
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        yield conn


@pytest.fixture
def sealer(fresh_db, login_roles):
    with as_login(fresh_db, "mint_worker") as conn:
        conn.autocommit = True
        yield conn


def add(admin, n, age=60):
    for i in range(n):
        admin.execute(
            "INSERT INTO mint.events"
            " (event_id, instance_id, inserted_at, kind, source_key, payload)"
            " VALUES (gen_random_uuid(), %s, now() - make_interval(secs => %s), 'org_created',"
            " %s, '{\"n\": 1}')",
            (INSTANCE, age - i * 0.001, f"org:o{i}:{n}:{age}:org_created".replace(".", "")),
        )


def test_the_first_batch_starts_from_a_zero_prev_and_chains_rows(admin, sealer):
    add(admin, 3)
    assert seal.seal_once(sealer, INSTANCE) == (1, 3)
    batch = fetchone(admin, "SELECT * FROM mint.seal_batches")
    assert bytes(batch["prev_tail_hash"]) == bytes(32)
    rows = fetchall(admin, "SELECT * FROM mint.events ORDER BY seal_seq")
    assert [r["seal_seq"] for r in rows] == [1, 2, 3]
    assert bytes(rows[0]["prev_hash"]) == bytes(32)
    assert bytes(rows[1]["prev_hash"]) == bytes(rows[0]["row_hash"])
    assert bytes(batch["tail_hash"]) == bytes(rows[2]["row_hash"])
    assert all(r["sealed_at"] is not None for r in rows)


def test_nothing_unsealed_makes_no_batch_and_no_event(admin, sealer):
    assert seal.seal_once(sealer, INSTANCE) is None
    add(admin, 2)
    seal.seal_once(sealer, INSTANCE)
    events = fetchone(admin, "SELECT count(*) AS n FROM mint.events")["n"]
    assert seal.seal_once(sealer, INSTANCE) is None
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.seal_batches")["n"] == 1
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.events")["n"] == events


def test_rows_inserted_just_now_wait_and_later_batches_continue_the_chain(admin, sealer):
    add(admin, 2)
    seal.seal_once(sealer, INSTANCE)
    add(admin, 1, age=1)
    assert seal.seal_once(sealer, INSTANCE) is None  # 5초가 지나지 않았다
    add(admin, 2, age=30)
    assert seal.seal_once(sealer, INSTANCE) == (3, 4)
    first, second = fetchall(admin, "SELECT * FROM mint.seal_batches ORDER BY to_seal_seq")
    assert bytes(second["prev_tail_hash"]) == bytes(first["tail_hash"])
    assert seal.verify(sealer, INSTANCE)["ok"]


def test_verify_recomputes_the_chain_and_reports_tampering(admin, sealer):
    add(admin, 4)
    seal.seal_once(sealer, INSTANCE)
    result = seal.verify(sealer, INSTANCE)
    assert result == {"ok": True, "batches": 1, "rows": 4, "to_seal_seq": 4,
                      "checkpoint_ok": None, "errors": []}
    # 봉인 열을 다시 써서(슈퍼유저) 행 해시를 바꾸면 다시 계산한 값과 어긋난다.
    admin.execute("ALTER TABLE mint.events DISABLE TRIGGER events_guard")
    admin.execute("UPDATE mint.events SET payload = '{\"n\": 2}' WHERE seal_seq = 2")
    admin.execute("ALTER TABLE mint.events ENABLE TRIGGER events_guard")
    bad = seal.verify(sealer, INSTANCE)
    assert not bad["ok"] and any("seal_seq 2" in e for e in bad["errors"])
    assert seal.verify(sealer, INSTANCE, from_seq=3, to_seq=4)["errors"] == []


def test_a_recomputed_chain_is_caught_by_the_checkpoint_anchor(admin, sealer):
    """DB 안에서 연쇄 전체를 다시 계산해 맞춰 놓아도 파일의 tail_hash와 어긋난다."""
    add(admin, 2)
    seal.seal_once(sealer, INSTANCE)
    tail = fetchone(admin, "SELECT encode(tail_hash, 'hex') AS t FROM mint.seal_batches")["t"]
    assert seal.verify(sealer, INSTANCE, checkpoint=(2, tail))["checkpoint_ok"] is True
    assert seal.verify(sealer, INSTANCE, checkpoint=(2, "00" * 32))["checkpoint_ok"] is False
    assert seal.verify(sealer, INSTANCE, checkpoint=(9, tail))["checkpoint_ok"] is False


KEY = b"k" * 32


def test_signed_batches_verify_and_a_recomputed_chain_fails_the_signature(admin, sealer):
    add(admin, 3)
    seal.seal_once(sealer, INSTANCE, KEY)
    batch = fetchone(admin, "SELECT * FROM mint.seal_batches")
    assert len(bytes(batch["tail_sig"])) == 32 and len(batch["sig_key_id"]) == 16
    assert seal.verify(sealer, INSTANCE, keys=[KEY])["ok"]
    wrong = seal.verify(sealer, INSTANCE, keys=[b"x" * 32])
    assert not wrong["ok"] and "서명" in wrong["errors"][0]
    # 끝 해시를 바꿔 맞춰도(키가 없으면) 서명이 맞지 않는다.
    admin.execute("ALTER TABLE mint.seal_batches DISABLE TRIGGER seal_batches_1_append_only")
    admin.execute("UPDATE mint.seal_batches SET tail_hash = decode(repeat('aa', 32), 'hex')")
    admin.execute("ALTER TABLE mint.seal_batches ENABLE TRIGGER seal_batches_1_append_only")
    assert any("서명" in e for e in seal.verify(sealer, INSTANCE, keys=[KEY])["errors"])


def test_unsigned_old_batches_pass_but_a_batch_after_a_signed_one_must_be_signed(admin, sealer):
    add(admin, 2, age=60)
    seal.seal_once(sealer, INSTANCE)  # 서명 도입 전 배치
    assert seal.verify(sealer, INSTANCE, keys=[KEY])["ok"]
    add(admin, 2, age=50)
    seal.seal_once(sealer, INSTANCE, KEY)
    assert seal.verify(sealer, INSTANCE, keys=[KEY])["ok"]
    add(admin, 2, age=40)
    seal.seal_once(sealer, INSTANCE)  # 서명 뒤에 서명 없는 배치
    result = seal.verify(sealer, INSTANCE, keys=[KEY])
    assert not result["ok"] and any("서명이 없습니다" in e for e in result["errors"])
    assert seal.verify(sealer, INSTANCE)["ok"]  # 키 없이는 서명을 보지 않는다


def test_a_gap_in_the_batches_is_reported(admin, sealer):
    add(admin, 3)
    seal.seal_once(sealer, INSTANCE)
    admin.execute("ALTER TABLE mint.seal_batches DISABLE TRIGGER seal_batches_1_append_only")
    admin.execute("UPDATE mint.seal_batches SET from_seal_seq = 2")
    admin.execute("ALTER TABLE mint.seal_batches ENABLE TRIGGER seal_batches_1_append_only")
    assert not seal.verify(sealer, INSTANCE)["ok"]


def test_two_sealers_never_seal_the_same_rows_twice(fresh_db, login_roles, admin):
    add(admin, 40)
    results: list = []

    def run():
        with as_login(fresh_db, "mint_worker") as conn:
            conn.autocommit = True
            results.append(seal.seal_once(conn, INSTANCE))

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r for r in results if r) == [(1, 40)]
    with as_login(fresh_db, "mint_worker") as conn:
        conn.autocommit = True
        assert seal.verify(conn, INSTANCE)["ok"]


def test_the_sealer_cannot_change_anything_but_the_seal_columns(sealer, admin):
    add(admin, 1)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        sealer.execute("UPDATE mint.events SET kind = 'x'")
