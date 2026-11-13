"""승인 필요성 재확인: 기한 계산(순수), 주기 검사의 요청·보류, 재확인의 보류 해제.

DB를 쓰는 시험은 MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, make_ctx

from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import recert

PERIOD = timedelta(days=90)
GRACE = timedelta(days=14)
START = datetime(2026, 1, 1, tzinfo=UTC)


def row(**override):
    base = {"status": "active", "valid_from": START, "recert_confirmed_at": None,
            "recert_held_at": None}
    base.update(override)
    return base


# --- 기한 계산 -------------------------------------------------------------


def test_the_cycle_starts_at_the_grant_and_restarts_at_each_confirmation():
    assert recert.due_at(row(), PERIOD) == START + PERIOD
    confirmed = START + timedelta(days=80)
    assert recert.due_at(row(recert_confirmed_at=confirmed), PERIOD) == confirmed + PERIOD


@pytest.mark.parametrize(
    ("days", "expected"),
    [(0, "ok"), (89, "ok"), (90, "due"), (103, "due"), (104, "overdue"), (400, "overdue")],
)
def test_state_moves_from_ok_to_due_to_overdue_at_the_period_and_the_grace(days, expected):
    assert recert.state(row(), START + timedelta(days=days), PERIOD, GRACE) == expected


def test_a_held_approval_stays_held_and_an_inactive_one_has_no_state():
    now = START + timedelta(days=1)
    assert recert.state(row(recert_held_at=START), now, PERIOD, GRACE) == "held"
    for status in ("pending", "expired", "revoked"):
        assert recert.state(row(status=status), now, PERIOD, GRACE) is None


def test_the_periodic_expiry_job_runs_the_recertification_scan_with_the_settings(monkeypatch):
    from types import SimpleNamespace

    from mint_litellm.control import jobs
    from mint_litellm.control.services import expiry

    seen = []
    monkeypatch.setattr(expiry, "expire_due", lambda conn, instance: None)
    monkeypatch.setattr(expiry, "warn_expiring", lambda conn, instance: None)
    monkeypatch.setattr(expiry, "announce_requests", lambda conn, instance: None)
    monkeypatch.setattr(recert, "scan", lambda *args: seen.append(args))
    job = SimpleNamespace(
        conn="c", instance_id="i", settings=SimpleNamespace(recert_days=30, recert_grace_days=7)
    )
    jobs._approval_expiry_scan(job)
    # 설정이 없는 환경(옛 설정 객체)에서도 기본값 90일·14일로 돈다.
    jobs._approval_expiry_scan(SimpleNamespace(conn="c", instance_id="i", settings=None))
    assert seen == [
        ("c", "i", timedelta(days=30), timedelta(days=7)),
        ("c", "i", PERIOD, GRACE),
    ]


# --- 주기 검사와 재확인(DB) -----------------------------------------------


def seed_approval(conn, ctx, litellm, age_days):
    from mint_litellm.control.services import orgs, relations, servers

    orgs.add(ctx, "acme", "ACME")
    servers.register(ctx, litellm, "ctl-everything", "http://upstream.test/mcp")
    relation = relations.add(ctx, "acme", "ctl-everything", "ops", None)
    return conn.execute(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by,"
        " status) VALUES (gen_random_uuid(), %s, 'acme', %s, 'standard', 'ctl-everything',"
        " ARRAY['echo'], 'user', 'human-1', now() - make_interval(days => %s),"
        " now() + interval '365 days', '{}', 'root', 'someone', 'active') RETURNING id",
        (INSTANCE, relation, age_days),
    ).fetchone()[0]


def alert_kinds(conn):
    return [r[0] for r in conn.execute(
        "SELECT kind FROM mint.alerts WHERE status <> 'resolved' ORDER BY kind").fetchall()]


def event_kinds(conn):
    return [r[0] for r in conn.execute(
        "SELECT kind FROM mint.events WHERE kind IN ('approval_recert_requested',"
        " 'approval_held', 'approval_recert_confirmed') ORDER BY inserted_at, event_id"
    ).fetchall()]


def test_a_fresh_approval_is_left_alone(conn, ctx, litellm):
    seed_approval(conn, ctx, litellm, 10)
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 0, "held": 0}
    assert alert_kinds(conn) == []


def test_a_due_approval_gets_one_request_and_one_alert_however_often_it_is_scanned(
    conn, ctx, litellm
):
    approval_id = seed_approval(conn, ctx, litellm, 95)
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 1, "held": 0}
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 0, "held": 0}
    assert alert_kinds(conn) == ["approval_recert_due"]
    assert event_kinds(conn) == ["approval_recert_requested"]
    held = conn.execute("SELECT recert_held_at FROM mint.approvals WHERE id = %s",
                        (approval_id,)).fetchone()[0]
    assert held is None


def test_an_approval_past_the_grace_is_held_with_an_event_and_an_alert(conn, ctx, litellm):
    approval_id = seed_approval(conn, ctx, litellm, 120)
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 0, "held": 1}
    requested, held = conn.execute(
        "SELECT recert_requested_at, recert_held_at FROM mint.approvals WHERE id = %s",
        (approval_id,)).fetchone()
    assert requested is not None and held is not None
    assert event_kinds(conn) == ["approval_held"]
    assert alert_kinds(conn) == ["approval_recert_held"]
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 0, "held": 0}


def test_the_hold_closes_the_due_alert(conn, ctx, litellm):
    seed_approval(conn, ctx, litellm, 95)
    recert.scan(conn, INSTANCE, PERIOD, GRACE)
    conn.execute("UPDATE mint.approvals SET recert_confirmed_at = now() - interval '120 days',"
                 " recert_confirmed_by = 'earlier'")
    recert.scan(conn, INSTANCE, PERIOD, GRACE)
    assert alert_kinds(conn) == ["approval_recert_held"]


def test_confirming_lifts_the_hold_restarts_the_cycle_and_records_who(conn, ctx, litellm):
    approval_id = seed_approval(conn, ctx, litellm, 120)
    recert.scan(conn, INSTANCE, PERIOD, GRACE)
    recert.confirm(ctx, str(approval_id))
    confirmed_at, confirmed_by, requested, held = conn.execute(
        "SELECT recert_confirmed_at, recert_confirmed_by, recert_requested_at, recert_held_at"
        " FROM mint.approvals WHERE id = %s", (approval_id,)).fetchone()
    assert confirmed_by == "root" and confirmed_at is not None
    assert requested is None and held is None
    assert alert_kinds(conn) == []
    assert event_kinds(conn)[-1] == "approval_recert_confirmed"
    # 새 주기가 시작됐으므로 다시 검사해도 요청이 열리지 않는다.
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 0, "held": 0}


def test_only_an_admin_can_confirm(conn, ctx, litellm):
    approval_id = seed_approval(conn, ctx, litellm, 120)
    for role in ("approver", "viewer"):
        with pytest.raises(ControlError):
            recert.confirm(make_ctx(conn, "p", role, "human-9"), str(approval_id))


def test_a_stale_version_and_a_missing_approval_are_refused(conn, ctx, litellm):
    approval_id = seed_approval(conn, ctx, litellm, 120)
    with pytest.raises(ControlError):
        recert.confirm(ctx, str(approval_id), expected_version=999)
    with pytest.raises(ControlError):
        recert.confirm(ctx, "00000000-0000-0000-0000-000000000000")


def test_a_revoked_approval_is_not_scanned_and_its_alert_is_closed(conn, ctx, litellm):
    approval_id = seed_approval(conn, ctx, litellm, 95)
    recert.scan(conn, INSTANCE, PERIOD, GRACE)
    conn.execute("UPDATE mint.approvals SET status = 'revoked', revoked_at = now(),"
                 " revoke_reason = 'x' WHERE id = %s", (approval_id,))
    assert recert.scan(conn, INSTANCE, PERIOD, GRACE) == {"requested": 0, "held": 0}
    assert alert_kinds(conn) == []
