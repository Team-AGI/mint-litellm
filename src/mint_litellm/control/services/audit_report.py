"""감사 보고서가 읽는 기간 집계. 읽기 전용이며 새 표를 만들지 않는다.

판정 집계는 ``dashboard_reads``를 그대로 쓰고, 여기에는 기간 경계(``[start, end)``)를 받는 승인·
변경·경보·증적 집계만 둔다.
"""

from datetime import datetime
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone

# 기간 안의 변경으로 세는 제어 사건
CHANGE_KINDS = (
    "server_registered",
    "server_terminated",
    "contract_approved",
    "policy_activated",
    "policy_shadow_set",
    "settings_changed",
)
_PERSON = "left(coalesce(approved_by, ''), 5) <> 'rule:'"


def approvals(
    conn: psycopg.Connection, instance: str, start: datetime, end: datetime
) -> dict[str, Any]:
    args = (instance, start, end)
    row = (
        fetchone(
            conn,
            "SELECT count(*) AS opened,"
            f" count(*) FILTER (WHERE approved_by IS NOT NULL AND {_PERSON}) AS by_person,"
            " count(*) FILTER (WHERE left(approved_by, 5) = 'rule:') AS by_rule,"
            " count(*) FILTER (WHERE status = 'rejected') AS denied,"
            " count(*) FILTER (WHERE status = 'expired' AND approved_by IS NULL) AS expired,"
            " percentile_cont(0.5) WITHIN GROUP"
            " (ORDER BY extract(epoch FROM decided_at - requested_at))"
            "  FILTER (WHERE decided_at IS NOT NULL"
            " AND status IN ('approved', 'consumed', 'rejected')"
            f"  AND {_PERSON}) AS median_seconds"
            " FROM mint.call_approvals WHERE instance_id = %s"
            " AND requested_at >= %s AND requested_at < %s",
            args,
        )
        or {}
    )
    held = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.events WHERE instance_id = %s"
        " AND kind = 'decision_evaluated' AND payload->>'approval_hold' = 'approved'"
        " AND inserted_at >= %s AND inserted_at < %s",
        args,
    )
    reasons = fetchall(
        conn,
        "SELECT coalesce(nullif(decision_reason, ''), '') AS reason, count(*) AS n"
        " FROM mint.call_approvals WHERE instance_id = %s AND status = 'rejected'"
        " AND requested_at >= %s AND requested_at < %s GROUP BY 1 ORDER BY n DESC, 1 LIMIT 20",
        args,
    )
    median = row.get("median_seconds")
    return {
        "opened": row.get("opened") or 0,
        "by_person": row.get("by_person") or 0,
        "by_rule": row.get("by_rule") or 0,
        "held_completed": held["n"] if held else 0,
        "denied": row.get("denied") or 0,
        "expired_unused": row.get("expired") or 0,
        "median_seconds": None if median is None else int(round(float(median))),
        "denial_reasons": reasons,
    }


def changes(
    conn: psycopg.Connection, instance: str, start: datetime, end: datetime
) -> dict[str, int]:
    rows = fetchall(
        conn,
        "SELECT kind, count(*) AS n FROM mint.events WHERE instance_id = %s AND kind = ANY(%s)"
        " AND inserted_at >= %s AND inserted_at < %s GROUP BY 1",
        (instance, list(CHANGE_KINDS), start, end),
    )
    found = {r["kind"]: r["n"] for r in rows}
    return {k: found.get(k, 0) for k in CHANGE_KINDS}


def alerts(
    conn: psycopg.Connection, instance: str, start: datetime, end: datetime
) -> list[dict[str, Any]]:
    """종류·심각도마다 기간 중 열린 수, 닫힌 수, 지금 열려 있는 수."""
    return fetchall(
        conn,
        "SELECT kind, severity,"
        " count(*) FILTER (WHERE first_at >= %s AND first_at < %s) AS opened,"
        " count(*) FILTER (WHERE resolved_at >= %s AND resolved_at < %s) AS closed,"
        " count(*) FILTER (WHERE status <> 'resolved') AS still_open"
        " FROM mint.alerts WHERE instance_id = %s GROUP BY kind, severity"
        " HAVING count(*) FILTER (WHERE first_at >= %s AND first_at < %s) > 0"
        " OR count(*) FILTER (WHERE resolved_at >= %s AND resolved_at < %s) > 0"
        " OR count(*) FILTER (WHERE status <> 'resolved') > 0 ORDER BY kind, severity",
        (start, end, start, end, instance, start, end, start, end),
    )


def evidence(
    conn: psycopg.Connection, instance: str, start: datetime, end: datetime
) -> dict[str, Any]:
    """기간 안의 기록 수와 봉인된 수, 봉인 상태, 내보내기 성공·실패."""
    args = (instance, start, end)
    events = (
        fetchone(
            conn,
            "SELECT count(*) AS total, count(seal_seq) AS sealed FROM mint.events"
            " WHERE instance_id = %s AND inserted_at >= %s AND inserted_at < %s",
            args,
        )
        or {}
    )
    batches = (
        fetchone(
            conn,
            "SELECT count(*) AS n, max(to_seal_seq) AS last_seq, max(sealed_at) AS last_at"
            " FROM mint.seal_batches WHERE instance_id = %s",
            (instance,),
        )
        or {}
    )
    exports = (
        fetchone(
            conn,
            "SELECT count(*) FILTER (WHERE kind = 'export_written') AS written,"
            " count(*) FILTER (WHERE kind = 'export_failed') AS failed,"
            " max(inserted_at) FILTER (WHERE kind = 'export_written') AS last_written"
            " FROM mint.events WHERE instance_id = %s"
            " AND kind IN ('export_written', 'export_failed')"
            " AND inserted_at >= %s AND inserted_at < %s",
            args,
        )
        or {}
    )
    return {
        "events": events.get("total") or 0,
        "sealed": events.get("sealed") or 0,
        "batches": batches.get("n") or 0,
        "last_seal_seq": batches.get("last_seq"),
        "last_sealed_at": batches.get("last_at"),
        "exports_written": exports.get("written") or 0,
        "exports_failed": exports.get("failed") or 0,
        "last_export_at": exports.get("last_written"),
    }
