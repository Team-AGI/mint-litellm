"""대시보드·호출 기록·경보·정책 화면의 집계와 표시."""

import json
import re
import uuid
from datetime import datetime, timedelta
from html import unescape

import psycopg
import pytest
from console_pages_support import INSTANCE

from mint_litellm.console import labels
from mint_litellm.console.pages.dashboard import choices, percent
from mint_litellm.control.services import dashboard_reads
from mint_litellm.types.reason_codes import Reason

from .test_approval_metrics import seed


@pytest.fixture
def conn(world):
    with psycopg.connect(world.admin_url) as connection:
        yield connection


def shown(html: str) -> str:
    return re.sub(r"<[^>]+>", "\n", html)


def decision(
    world, outcome=None, enforced="allow", reason=None, policies=(), server="srv-ok", hours_ago=0
):
    payload = {"enforced_action": enforced, "resolved_server_id": server, "policy_ids": policies}
    if outcome:
        payload["outcome"] = outcome
    if reason:
        payload["stop"] = {"status": "stop", "reason_code": reason}
    event_id = uuid.uuid4()
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key,"
        " invocation_id, attempt_id, payload) VALUES (%s, %s, now() - make_interval(hours => %s),"
        " 'decision_evaluated', %s, %s, 1, %s::jsonb)",
        event_id,
        INSTANCE,
        hours_ago,
        f"call:{uuid.uuid4()}:1:decision_evaluated",
        uuid.uuid4(),
        json.dumps(payload),
    )
    return str(event_id)


def alert(world, severity="high", kind="sync_divergence", status="open"):
    alert_id = uuid.uuid4()
    world.query(
        "INSERT INTO mint.alerts (id, instance_id, kind, severity, dedup_key, subject)"
        ' VALUES (%s, %s, %s, %s, %s, \'{"server_id": "srv-ok"}\'::jsonb)',
        alert_id,
        INSTANCE,
        kind,
        severity,
        str(uuid.uuid4()),
    )
    if status != "open":
        world.query(
            "UPDATE mint.alerts SET status = %s, resolved_at = now() WHERE id = %s",
            status,
            alert_id,
        )


# --- 표시명과 보조 함수 (데이터베이스 없이) ---------------------------------------------------


def test_every_reason_code_has_a_korean_name():
    assert {r.value for r in Reason} <= set(labels.OUTCOME_REASON)
    assert all(re.search("[가-힣]", t) for t in labels.OUTCOME_REASON.values())
    assert labels.outcome_reason("CONTRACT_DRIFT_input_schema") == "계약 변경"
    assert labels.outcome_reason("NEW_CODE") == "기타" and labels.outcome_reason("") == "사유 없음"


def test_choices_keep_other_filters_and_mark_the_current_one():
    items = choices(
        "/ledger",
        {"kind": "k", "result": "deny"},
        "result",
        [("", "전체"), ("deny", "차단")],
        "deny",
    )
    assert items == [
        ("전체", "/ledger?kind=k", False),
        ("차단", "/ledger?kind=k&result=deny", True),
    ]


def test_percent_and_bucket_units():
    assert percent(1, 4) == "25%" and percent(0, 0) == "—"
    assert dashboard_reads.unit_of(1)[0] == "minute"
    assert dashboard_reads.unit_of(24) == ("hour", 24, "HH24:00")
    assert dashboard_reads.unit_of(168)[:2] == ("day", 7)
    assert dashboard_reads.unit_of(720)[:2] == ("day", 30)


# --- 집계 -------------------------------------------------------------------------------------


def test_decisions_are_split_into_four_outcomes(world, conn):
    decision(world)  # outcome 없는 옛 행: 집행 값으로 허용
    decision(world, "allowed")
    decision(world, "observed", enforced="allow")
    decision(world, "pending_approval", enforced="deny", reason="CALL_APPROVAL_REQUIRED")
    decision(world, "blocked", enforced="deny", reason="SERVER_NOT_APPROVED")
    decision(world, "contract_drift", enforced="deny", reason="CONTRACT_DRIFT_input_schema")
    decision(world, enforced="deny", hours_ago=30 * 24)  # 기간 밖
    totals = dashboard_reads.decision_totals(conn, INSTANCE, 168)
    assert totals == {"total": 6, "allow": 2, "approve": 1, "block": 2, "observe": 1}
    series = dashboard_reads.decision_series(conn, INSTANCE, 168, "UTC")
    assert len(series["labels"]) == 7 and series["unit"] == "day"
    assert [sum(series[b]) for b in dashboard_reads.BUCKETS] == [2, 1, 2, 1]
    assert sum(dashboard_reads.decision_series(conn, INSTANCE, 24, "UTC")["total"]) == 6
    reasons = dashboard_reads.block_reasons(conn, INSTANCE, 168)
    assert {r["code"] for r in reasons} == {"SERVER_NOT_APPROVED", "CONTRACT_DRIFT_input_schema"}


def test_the_previous_period_is_the_same_length_one_step_back(world, conn):
    decision(world, hours_ago=200)
    now = dashboard_reads.decision_series(conn, INSTANCE, 168, "UTC")
    before = dashboard_reads.decision_series(conn, INSTANCE, 168, "UTC", shift=168)
    assert sum(now["total"]) == 0 and sum(before["total"]) == 1


def test_policies_count_the_calls_they_checked_blocked_and_held(world, conn):
    decision(world, "blocked", enforced="deny", policies=["P1", "P2"])
    decision(world, "pending_approval", enforced="deny", policies=["P1"])
    decision(world, "allowed", policies=["P1"])
    decision(world)  # 정책 없음
    rows = {r["policy_id"]: r for r in dashboard_reads.policy_effect(conn, INSTANCE, 168)}
    assert (rows["P1"]["checks"], rows["P1"]["blocked"], rows["P1"]["approval"]) == (3, 1, 1)
    assert (rows["P2"]["checks"], rows["P2"]["blocked"]) == (1, 1)


def test_top_servers_and_alert_stats(world, conn):
    for _ in range(2):
        decision(world, "blocked", enforced="deny", server="srv-b")
    decision(world, server="srv-a")
    top = dashboard_reads.top_servers(conn, INSTANCE, 168)
    assert [(r["server_id"], r["calls"], r["blocked"]) for r in top] == [
        ("srv-b", 2, 2),
        ("srv-a", 1, 0),
    ]
    alert(world, "critical")
    alert(world, "high", kind="job_failed")
    alert(world, "high", status="resolved")
    stats = dashboard_reads.alert_stats(conn, INSTANCE)
    assert stats["severity"] == {"critical": 1, "high": 1}
    assert {r["kind"] for r in stats["kinds"]} == {"sync_divergence", "job_failed"}
    assert stats["oldest_seconds"] is not None


# --- 화면 -------------------------------------------------------------------------------------


def test_the_dashboard_has_five_cards_four_charts_and_status_rows(world, admin):
    decision(world, "blocked", enforced="deny", reason="SERVER_NOT_APPROVED")
    alert(world, "critical")
    html = admin.get("/").text
    for label in (
        "승인 대기",
        "열린 경보(치명·높음)",
        "차단률",
        "호출 수(7일)",
        "적용 엔드포인트",
    ):
        assert label in html
    assert html.count('class="card kpi') >= 5 + 4
    assert html.count("data-chart=") == 4
    assert "승인되지 않은 서버" in html and "SERVER_NOT_APPROVED" not in shown(html)
    assert "원장 봉인" in html and "내보내기" in html
    assert 'class="card kpi danger" href="/alerts?status=open"' in html


def test_a_slow_approval_queue_is_highlighted_and_cards_link_to_screens(world, admin):
    seed(world, age="10 minutes")
    html = admin.get("/").text
    assert 'class="card kpi wait" href="/approvals"' in html
    for href in ('href="/ledger?result=deny"', 'href="/endpoints"', 'href="/ledger"'):
        assert href in html


def test_the_dashboard_range_changes_the_labels_and_ignores_unknown_values(world, admin):
    assert "호출 수(24시간)" in admin.get("/?range=24h").text
    assert "호출 수(1시간)" in admin.get("/?range=1h").text
    assert "호출 수(7일)" in admin.get("/?range=zz").text


def test_a_small_sample_still_shows_a_percentage_with_the_counts(world, admin):
    decision(world, "blocked", enforced="deny")
    html = shown(admin.get("/").text)
    assert "100%" in html and "호출 1건 중 1건" in html and "%p" not in html


def test_the_ledger_has_a_chart_chips_and_a_row_drawer(world, admin):
    event = decision(
        world, "blocked", enforced="deny", reason="CALL_APPROVAL_REQUIRED", policies=["P1"]
    )
    listing = admin.get("/ledger?range=24h")
    assert listing.status_code == 200 and "data-chart=" in listing.text
    assert f"/ledger?range=24h&amp;open={event}" in listing.text
    text = shown(admin.get(f"/ledger?range=24h&open={event}").text)
    assert "호출 승인 필요" in text and "P1" in text and "차단" in text
    assert "CALL_APPROVAL_REQUIRED" not in text
    assert admin.get("/ledger?open=not-an-id").status_code == 404
    assert admin.get(f"/ledger?open={uuid.uuid4()}").status_code == 404
    chip = admin.get("/ledger?result=deny").text
    assert 'aria-current="true"><strong>차단</strong>' in chip


def test_the_ledger_range_replaces_the_default_but_a_date_wins(world, admin):
    decision(world, hours_ago=3)
    assert (
        "조건에 맞는 기록이 없습니다" in admin.get("/ledger?range=1h&kind=decision_evaluated").text
    )
    assert "조건에 맞는 기록이 없습니다" not in admin.get("/ledger?range=24h").text
    year_ago = f"{datetime.now() - timedelta(days=365):%Y-%m-%d}"
    html = admin.get(f"/ledger?range=1h&since={year_ago}").text
    assert "조건에 맞는 기록이 없습니다" not in html


def test_the_alert_screen_shows_severity_cards_a_kind_chart_and_a_drawer(world, admin):
    alert(world, "critical")
    alert(world, "low", kind="job_failed")
    html = admin.get("/alerts").text
    assert "가장 오래 열린 경보" in html and html.count("data-chart=") == 1
    assert 'class="card kpi danger" href="/alerts?status=open&amp;severity=critical"' in html
    assert "<aside" not in html
    row = world.query("SELECT id FROM mint.alerts WHERE severity = 'critical'")[0][0]
    opened = admin.get(f"/alerts?open={row}").text
    assert "<aside" in opened and "확인함" in opened
    assert 'data-close="/alerts"' in opened
    only = admin.get(f"/alerts?severity=critical&open={row}").text
    assert 'data-close="/alerts?severity=critical"' in only


def test_the_policy_screen_shows_effect_per_policy_and_the_trial_tiles(world, admin):
    decision(world, "blocked", enforced="deny", policies=["P1"])
    decision(world, "pending_approval", enforced="deny", policies=["P1"])
    html = admin.get("/policy").text
    assert "정책별 효과" in html and ">P1<" in html and "승인 필요" in html
    assert "시험 중인 판본이 없습니다" in html
    assert admin.get("/policy?range=24h").status_code == 200
    from .test_pages_dashboard import add_shadow

    add_shadow(world)
    text = shown(admin.get("/policy").text)
    for label in ("허용에서 차단", "차단에서 허용", "그 밖의 변경", "평가 오류"):
        assert label in text
    assert "허용 → 차단" in text


@pytest.mark.parametrize("path", ["/", "/ledger", "/alerts", "/policy"])
def test_empty_screens_render_without_fake_zeros_in_charts(world, admin, path):
    html = admin.get(path).text
    assert admin.get(path).status_code == 200
    assert 'class="chart muted">—</div>' in html or "data-chart=" not in html


def chart_payloads(html: str) -> list[dict]:
    return [json.loads(unescape(m)) for m in re.findall(r'data-chart="([^"]*)"', html)]


def test_empty_charts_collapse_to_one_line_instead_of_a_blank_box(world, admin):
    for path in ("/", "/ledger"):
        html = admin.get(path).text
        assert "data-chart=" not in html and 'class="chart' not in html
        assert 'class="empty slim"' in html and "이 기간에 기록이 없습니다" in html


def test_the_charts_carry_well_formed_data_once_there_are_records(world, admin):
    decision(world, "blocked", enforced="deny", reason="SERVER_NOT_APPROVED", server="srv-a")
    decision(world, server="srv-a")
    alert(world, "critical")
    for path, expected in (("/", {"stacked", "donut", "bars"}), ("/ledger", {"stacked", "donut"})):
        charts = chart_payloads(admin.get(path).text)
        assert {c["kind"] for c in charts} == expected
        for c in charts:
            if c["kind"] == "stacked":
                assert c["labels"] and all(len(s["data"]) == len(c["labels"]) for s in c["series"])
            elif c["kind"] == "donut":
                assert c["items"] and all(i["value"] > 0 for i in c["items"])
            else:
                assert len(c["labels"]) == len(c["values"]) > 0
    assert len(chart_payloads(admin.get("/").text)) == 4


def test_the_status_list_has_one_litellm_row_and_one_worker_row_without_raw_ids():
    from mint_litellm.console.pages.dashboard import status_dots

    lite = {"version": "1.106.6", "grade": "A", "tested": True, "missing": []}
    workers = [
        {"worker_id": f"7f1e986fd53e:{n}", "passed": True, "litellm": lite, **at(T0)}
        for n in (277, 278)
    ]
    o = {
        "last_seal": None,
        "last_export": None,
        "unhandled_jobs": 0,
        "jobs_failed": 0,
        "jobs_pending": 0,
        "unhandled_oldest_seconds": 0,
    }
    dots = status_dots(o, workers, None)
    names = [d["name"] for d in dots]
    assert names.count("LiteLLM") == 1 and names.count("집행 워커") == 1
    worker = next(d for d in dots if d["name"] == "집행 워커")
    assert worker["status"].text == "2/2 정상"
    assert not any("7f1e" in d["name"] or "7f1e" in d["title"] for d in dots)
    workers[1]["passed"] = False
    worker = next(d for d in status_dots(o, workers, None) if d["name"] == "집행 워커")
    assert worker["status"].level == "error" and worker["status"].text == "1개 확인 불가"


T0 = "2026-11-15T01:00"


def at(stamp: str) -> dict:
    return {"last_transition_at": stamp + ":00+00:00"}


def test_workers_from_before_a_restart_are_not_counted_as_running():
    from mint_litellm.console.pages.dashboard import status_dots

    lite = {"version": "1.106.6", "grade": "A", "tested": True, "missing": []}
    workers = [
        {"worker_id": f"h:{n}", "passed": True, "litellm": lite, **at(when)}
        for n, when in ((1, "2026-11-14T20:00"), (2, "2026-11-14T20:00"), (3, "2026-11-15T01:00"),
                        (4, "2026-11-15T01:01"))
    ]
    o = {
        "last_seal": None, "last_export": None, "unhandled_jobs": 0, "jobs_failed": 0,
        "jobs_pending": 0, "unhandled_oldest_seconds": 0,
    }
    worker = next(d for d in status_dots(o, workers, None) if d["name"] == "집행 워커")
    assert worker["status"].text == "2/2 정상 · 이전 실행 2개"


def test_the_block_rate_is_a_dash_without_any_calls(world, admin):
    html = admin.get("/").text
    card = re.search(r'차단률</div>\s*<div class="value">([^<]*)<', html)
    assert card and card.group(1) == "—"


def test_policy_detections_get_operator_names_in_the_block_donut():
    from mint_litellm.console.pages.dashboard import reason_donut

    reasons = [
        {"code": "POLICY_DETECT_POL-E-05", "n": 5},
        {"code": "POLICY_DETECT_POL-E-07", "n": 4},
        {"code": "POLICY_DETECT_POL-X-99", "n": 1},
        {"code": "CONTRACT_DRIFT_input_schema", "n": 2},
        {"code": "CONTRACT_DRIFT_tool_added", "n": 1},
    ]
    items = {i["name"]: i["value"] for i in reason_donut(reasons, 13)["items"]}
    assert items == {
        "인자 속 비밀": 5, "허용 목적지 밖 URL": 4, "정책 탐지": 1, "계약 변경": 3,
    }
