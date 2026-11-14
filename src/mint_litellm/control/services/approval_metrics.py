"""승인 운영 지표: 기간 안에 승인 요청이 어떻게 처리되었는지 한 번에 읽는다.

호출별 승인 표와 기간 승인 사용 표, 보류를 거친 판정 사건만 읽으며 새 표를 만들지 않는다.
"""

from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone

# 기간 이름 → (시간 수, 막대 단위, 막대 개수, 막대 표기)
RANGES: dict[str, tuple[int, str, int, str]] = {
    "24h": (24, "hour", 24, "HH24시"),
    "7d": (168, "day", 7, "MM-DD"),
    "30d": (720, "day", 30, "MM-DD"),
}
DEFAULT_RANGE = "7d"
SUGGEST_MIN = 5

_PERSON = "left(coalesce({p}approved_by, ''), 5) <> 'rule:'"


def collect(
    conn: psycopg.Connection, instance: str, range_name: str, time_zone: str = "UTC"
) -> dict[str, Any]:
    hours, unit, steps, fmt = RANGES.get(range_name, RANGES[DEFAULT_RANGE])
    base = (instance, hours)
    row = fetchone(
        conn,
        "SELECT count(*) AS opened,"
        f" count(*) FILTER (WHERE approved_by IS NOT NULL AND {_PERSON.format(p='')}) AS by_person,"
        " count(*) FILTER (WHERE left(approved_by, 5) = 'rule:') AS by_rule,"
        " count(*) FILTER (WHERE status = 'rejected') AS denied,"
        " count(*) FILTER (WHERE status = 'expired' AND approved_by IS NULL) AS expired,"
        " percentile_cont(0.5) WITHIN GROUP"
        " (ORDER BY extract(epoch FROM decided_at - requested_at))"
        f"  FILTER (WHERE decided_at IS NOT NULL AND status IN ('approved','consumed','rejected')"
        f"  AND {_PERSON.format(p='')}) AS median_seconds,"
        " percentile_cont(0.9) WITHIN GROUP"
        " (ORDER BY extract(epoch FROM decided_at - requested_at))"
        f"  FILTER (WHERE decided_at IS NOT NULL AND status IN ('approved','consumed','rejected')"
        f"  AND {_PERSON.format(p='')}) AS p90_seconds,"
        " count(*) FILTER (WHERE status = 'consumed' AND window_minutes IS NULL) AS one_shot"
        " FROM mint.call_approvals WHERE instance_id = %s"
        " AND requested_at >= now() - make_interval(hours => %s)",
        base,
    ) or {}
    held = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.events WHERE instance_id = %s"
        " AND kind = 'decision_evaluated' AND payload->>'approval_hold' = 'approved'"
        " AND inserted_at >= now() - make_interval(hours => %s)",
        base,
    )
    uses = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.call_approval_uses WHERE instance_id = %s"
        " AND used_at >= now() - make_interval(hours => %s)",
        base,
    )
    pending = fetchone(
        conn,
        "SELECT count(*) AS n, max(greatest(extract(epoch FROM now() - requested_at), 0))"
        " AS oldest FROM mint.call_approvals WHERE instance_id = %s AND status = 'pending'",
        (instance,),
    )
    top = fetchall(
        conn,
        "SELECT server_id, tool, count(*) AS n FROM mint.call_approvals WHERE instance_id = %s"
        " AND requested_at >= now() - make_interval(hours => %s)"
        " GROUP BY 1, 2 ORDER BY n DESC, server_id, tool LIMIT 5",
        base,
    )
    series = fetchall(
        conn,
        "SELECT to_char(g, %s) AS label, count(c.id) AS n FROM generate_series("
        f" date_trunc('{unit}', now() AT TIME ZONE %s) - (%s - 1) * interval '1 {unit}',"
        f" date_trunc('{unit}', now() AT TIME ZONE %s), interval '1 {unit}') g"
        " LEFT JOIN mint.call_approvals c ON c.instance_id = %s"
        f" AND c.requested_at >= now() - make_interval(hours => %s) - interval '1 {unit}'"
        f" AND date_trunc('{unit}', c.requested_at AT TIME ZONE %s) = g"
        " GROUP BY g ORDER BY g",
        (fmt, time_zone, steps, time_zone, instance, hours, time_zone),
    )
    repeat = fetchone(
        conn,
        "SELECT c.org_id, c.server_id, c.tool, t.action_type, count(*) AS n"
        " FROM mint.call_approvals c JOIN mint.tool_contracts t"
        "  ON t.instance_id = c.instance_id AND t.id = c.contract_id"
        " WHERE c.instance_id = %s AND c.requested_at >= now() - make_interval(hours => %s)"
        " AND t.action_type IN ('read', 'write') AND c.status <> 'rejected'"
        f" AND {_PERSON.format(p='c.')}"
        " GROUP BY 1, 2, 3, 4 HAVING count(*) >= %s ORDER BY n DESC, 2, 3 LIMIT 1",
        (*base, SUGGEST_MIN),
    )
    period_uses = uses["n"] if uses else 0
    one_shot = row.get("one_shot") or 0
    reused = period_uses + one_shot
    return {
        "range": range_name if range_name in RANGES else DEFAULT_RANGE,
        "opened": row.get("opened") or 0,
        "approved_by_person": row.get("by_person") or 0,
        "approved_by_rule": row.get("by_rule") or 0,
        "held_completed": held["n"] if held else 0,
        "denied": row.get("denied") or 0,
        "expired_unused": row.get("expired") or 0,
        "median_seconds": _whole(row.get("median_seconds")),
        "p90_seconds": _whole(row.get("p90_seconds")),
        "period_uses": period_uses,
        "one_shot_uses": one_shot,
        "period_share": round(period_uses / reused, 3) if reused else None,
        "top": top,
        "pending": {
            "count": pending["n"] if pending else 0,
            "oldest_seconds": _whole(pending["oldest"]) if pending else None,
        },
        "series": {"labels": [r["label"] for r in series], "values": [r["n"] for r in series]},
        "suggestion": repeat,
    }


def _whole(value: Any) -> int | None:
    return None if value is None else int(round(float(value)))
