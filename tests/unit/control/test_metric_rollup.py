"""지표 롤업: 롤업 + 꼬리가 전체를 센 값과 같다. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from ctl_fixtures import INSTANCE

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import metric_rollup  # noqa: E402
from mint_litellm.control.services import metrics  # noqa: E402


def add(conn, kind, payload, age_seconds, instance=INSTANCE):
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, payload)"
        " VALUES (%s, %s, %s, %s, %s, %s)",
        (uuid4(), instance, datetime.now(UTC) - timedelta(seconds=age_seconds), kind,
         f"t:{uuid4()}", json.dumps(payload)),
    )


def seed(conn, age):
    add(conn, "decision_evaluated",
        {"resolved_server_id": "s1", "outcome": "allowed", "decision_us": 800}, age)
    add(conn, "decision_evaluated",
        {"resolved_server_id": "s1", "enforced_action": "deny", "decision_us": 40_000}, age)
    add(conn, "decision_evaluated", {"enforced_action": "allow"}, age)
    add(conn, "call_response_received", {"is_error": "true"}, age)
    add(conn, "call_response_received", {"outcome": "success"}, age)
    add(conn, "call_outcome_unknown", {}, age)


def full(conn):
    return sorted(metric_rollup.counted(conn, INSTANCE, None, None))


def test_rollup_plus_tail_equals_the_full_count_at_every_step(conn):
    assert metric_rollup.totals(conn, INSTANCE) == []
    seed(conn, 3600)
    seed(conn, 3500)
    assert sorted(metric_rollup.totals(conn, INSTANCE)) == full(conn)  # 롤업 전: 전부 꼬리
    assert metric_rollup.advance(conn, INSTANCE) > 0
    assert sorted(metric_rollup.totals(conn, INSTANCE)) == full(conn)
    seed(conn, 5)  # 마지막 LAG 안: 꼬리에만 있다
    seed(conn, 20)  # 워터마크 뒤, 다음 컷오프 앞
    assert sorted(metric_rollup.totals(conn, INSTANCE)) == full(conn)
    metric_rollup.advance(conn, INSTANCE)
    metric_rollup.advance(conn, INSTANCE)  # 더할 것이 없으면 그대로
    assert sorted(metric_rollup.totals(conn, INSTANCE)) == full(conn)
    counts = conn.execute(
        "SELECT n FROM mint.metric_counts WHERE instance_id = %s AND family = 'decision'"
        " AND label_a = 's1' AND label_b = 'allowed'",
        (INSTANCE,),
    ).fetchone()[0]
    assert counts == 2  # 마지막 LAG 안의 두 건은 꼬리에만 있다


def test_other_instances_are_not_counted(conn):
    seed(conn, 3600)
    add(conn, "decision_evaluated", {"outcome": "allowed"}, 3600, instance="other")
    metric_rollup.advance(conn, INSTANCE)
    assert sorted(metric_rollup.totals(conn, INSTANCE)) == full(conn)
    assert not any(r[0] == "decision" and r[1] == "" and r[2] == "allowed" and r[3] > 1
                   for r in metric_rollup.totals(conn, INSTANCE))


def test_a_replayed_late_event_triggers_a_recount(conn):
    seed(conn, 3600)
    metric_rollup.advance(conn, INSTANCE)
    add(conn, "decision_evaluated",
        {"resolved_server_id": "s9", "outcome": "allowed", "decision_us": 100}, 7200)  # 옛 시각
    # 시간이 흘러 되살림 표지가 워터마크 뒤에 놓인 것으로 만든다.
    conn.execute("UPDATE mint.metric_state SET watermark_at = watermark_at - interval '1 hour'")
    # 되살림 표지가 없으면 워터마크 앞의 늦은 사건은 아직 반영되지 않는다.
    assert sorted(metric_rollup.totals(conn, INSTANCE)) != full(conn)
    add(conn, "buffer_replayed", {"replayed": 1, "duplicates": 0, "unreadable": 0}, 60)
    metric_rollup.advance(conn, INSTANCE)
    assert sorted(metric_rollup.totals(conn, INSTANCE)) == full(conn)


def test_collect_renders_the_same_numbers_as_a_direct_count(conn):
    seed(conn, 3600)
    metric_rollup.advance(conn, INSTANCE)
    seed(conn, 1)
    data = metrics.collect(conn, INSTANCE)
    text = metrics.render(data)
    assert 'mint_decisions_total{result="allowed",server_id="s1"} 2' in text
    assert "mint_decision_seconds_count 4" in text
    assert 'mint_decision_seconds_bucket{le="0.001"} 2' in text
    assert 'mint_call_results_total{result="unknown"} 2' in text
    assert 'mint_call_results_total{result="tool_error"} 2' in text


def test_the_job_is_registered_with_a_schedule():
    from mint_litellm.control import jobs

    assert "metric_rollup" in jobs.KINDS and "metric_rollup" in jobs.HANDLERS
    assert jobs.SCHEDULES["metric_rollup"](None) == 60
