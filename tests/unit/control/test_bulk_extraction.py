"""대량 추출 탐지: 기준 없음, 바닥값 미달, 급증, 평소 수준 회복, 거부(hold)와 해제."""

import pytest
from ctl_fixtures import INSTANCE, make_ctx

from mint_litellm.control import approvals, bulk_extraction, jobs
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.types.ids import new_uuid7

BUCKETS = 672  # 15분 구간 7일치
MIB = 1024 * 1024
# 배수, 바이트 바닥, 항목 바닥
ARGS = (5, 5 * MIB, 2000)


def test_no_baseline_still_needs_the_floor():
    assert bulk_extraction.is_bulk(5 * MIB, 0, 0, 0, BUCKETS, *ARGS)
    assert not bulk_extraction.is_bulk(5 * MIB - 1, 0, 0, 0, BUCKETS, *ARGS)
    assert bulk_extraction.is_bulk(0, 2000, 0, 0, BUCKETS, *ARGS)
    assert not bulk_extraction.is_bulk(0, 1999, 0, 0, BUCKETS, *ARGS)


def test_below_the_floor_is_never_bulk():
    # 평균의 수천 배여도 바닥 미달이면 아니다
    assert not bulk_extraction.is_bulk(MIB, 100, 1, 1, BUCKETS, *ARGS)


def test_five_times_the_average_is_bulk():
    history = 10 * MIB * BUCKETS  # 구간당 평균 10 MiB
    assert not bulk_extraction.is_bulk(49 * MIB, 0, history, 0, BUCKETS, *ARGS)
    assert bulk_extraction.is_bulk(50 * MIB, 0, history, 0, BUCKETS, *ARGS)


def test_items_alone_can_trigger():
    history = 1000 * BUCKETS
    assert not bulk_extraction.is_bulk(0, 4999, 0, history, BUCKETS, *ARGS)
    assert bulk_extraction.is_bulk(0, 5000, 0, history, BUCKETS, *ARGS)


def test_back_to_normal_is_not_bulk():
    history = 10 * MIB * BUCKETS
    assert bulk_extraction.is_bulk(60 * MIB, 0, history, 0, BUCKETS, *ARGS)
    assert not bulk_extraction.is_bulk(12 * MIB, 0, history, 0, BUCKETS, *ARGS)


def settings(action="alert", window=900):
    return Stage2Settings(
        export_dir=None, export_hmac_key=b"k" * 32, bulk_action=action, bulk_window_seconds=window,
    )


@pytest.fixture
def server(conn):
    conn.execute(
        "INSERT INTO mint.servers(id,instance_id,server_id,status,url_sha256,transport,"
        "auth_type,registered_by) VALUES (%s,%s,'srv','pending',repeat('a',64),'http','none','x')",
        (new_uuid7(), INSTANCE),
    )


def respond(conn, user, nbytes, items, age_seconds, server_id="srv"):
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, subject,"
        " payload) VALUES (%s, %s, now() - make_interval(secs => %s), 'call_response_received',"
        " %s, jsonb_build_object('principal_type', 'user', 'principal_id', %s::text),"
        " jsonb_build_object('server_id', %s::text, 'size_bytes', %s::bigint,"
        " 'items', %s::bigint))",
        (new_uuid7(), INSTANCE, age_seconds, f"t:{new_uuid7()}", user, server_id, nbytes, items),
    )


def scan(conn, action="alert", window=900):
    bulk_extraction.run(jobs.JobContext(conn, INSTANCE, {}, settings(action, window)))


def alert_rows(conn):
    return fetchall(
        conn, "SELECT status, dedup_key, subject FROM mint.alerts WHERE kind = 'bulk_extraction'"
        " ORDER BY dedup_key"
    )


def seed_history(conn, user):
    for day in range(1, 7):  # 평소: 하루 한 번 1 MiB
        respond(conn, user, MIB, 10, day * 86400)


def test_a_spike_opens_one_alert_per_principal_and_server_then_recovers(conn, server):
    seed_history(conn, "alice")
    respond(conn, "alice", 40 * MIB, 50, 60)
    scan(conn)
    rows = alert_rows(conn)
    assert [r["dedup_key"] for r in rows] == [
        "bulk_extraction:srv:*", "bulk_extraction:srv:alice",
    ]
    assert rows[1]["subject"]["principal_id"] == "alice" and rows[1]["subject"]["held"] is False
    scan(conn)  # 열려 있는 동안 다시 열지 않는다
    assert [r["status"] for r in alert_rows(conn)] == ["open", "open"]
    assert fetchall(conn, "SELECT count FROM mint.alerts WHERE kind='bulk_extraction'") == [
        {"count": 1}, {"count": 1},
    ]
    # 큰 응답이 최근 구간을 벗어나면 닫힌다(사건은 지울 수 없어 구간을 줄여 흉내 낸다)
    scan(conn, window=30)
    assert {r["status"] for r in alert_rows(conn)} == {"resolved"}


def test_normal_volume_and_small_spikes_stay_quiet(conn, server):
    seed_history(conn, "alice")
    respond(conn, "alice", 4 * MIB, 50, 60)  # 평소의 수 배지만 바닥값 미만
    scan(conn)
    assert alert_rows(conn) == []


def test_alert_only_by_default_makes_no_denial(conn, server):
    respond(conn, "bob", 40 * MIB, 50, 60)
    scan(conn)
    assert alert_rows(conn)
    assert fetchall(conn, "SELECT 1 FROM mint.denials") == []


def test_hold_denies_the_principal_on_that_server_until_an_admin_lifts_it(conn, server):
    respond(conn, "bob", 40 * MIB, 50, 60)
    scan(conn, "hold")
    denials = fetchall(
        conn, "SELECT scope_type, scope_id, server_id, tools, reason, created_by, lifted_at"
        " FROM mint.denials",
    )
    assert len(denials) == 1  # 서버 합계 경보는 막지 않는다
    d = denials[0]
    assert (d["scope_type"], d["scope_id"], d["server_id"], d["tools"]) == (
        "user", "bob", "srv", None,
    )
    assert d["created_by"] == "bulk-extraction" and d["lifted_at"] is None
    scan(conn, "hold")  # 다시 훑어도 거부는 하나
    assert len(fetchall(conn, "SELECT 1 FROM mint.denials")) == 1
    denial_id = str(fetchall(conn, "SELECT id FROM mint.denials")[0]["id"])
    approvals.lift_denial(make_ctx(conn), denial_id)
    assert fetchall(conn, "SELECT lifted_by FROM mint.denials") == [{"lifted_by": "root"}]


def test_invalid_action_is_refused():
    from mint_litellm.control.errors import ControlError

    env = {
        "MINT_EXPORT_DIR": "/tmp/x", "MINT_EXPORT_HMAC_KEY": "A" * 43,
        "MINT_BULK_EXTRACTION_ACTION": "kill",
    }
    with pytest.raises(ControlError):
        Stage2Settings.from_env(env)
    held = Stage2Settings.from_env({**env, "MINT_BULK_EXTRACTION_ACTION": "HOLD"})
    assert held.bulk_action == "hold"
