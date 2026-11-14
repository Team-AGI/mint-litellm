"""대시보드·호출 기록·경보·정책 화면의 집계 조회. 읽기 전용이며 새 표를 만들지 않는다.

판정 사건(``decision_evaluated``)은 결과 네 갈래(허용·승인 필요·차단·관측)로 묶어 센다. 묶는
기준은 지표 롤업과 같아서 화면의 숫자가 지표와 어긋나지 않는다.
"""

from datetime import datetime
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone

# 기간 이름 → 시간 수
HOURS = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
DEFAULT_RANGE = "7d"
BUCKETS = ("allow", "approve", "block", "observe")

# 판정 한 건의 결과 갈래. outcome이 없는 옛 행은 집행 값으로 갈래를 정한다.
_BUCKET = (
    "CASE COALESCE(payload->>'outcome', CASE WHEN payload->>'enforced_action' = 'allow'"
    " THEN 'allowed' ELSE 'blocked' END)"
    " WHEN 'allowed' THEN 'allow' WHEN 'observed' THEN 'observe'"
    " WHEN 'pending_approval' THEN 'approve' ELSE 'block' END"
)
_REASON = "COALESCE(payload->'stop'->>'reason_code', payload->'findings'->0->>'reason_code', '')"


def hours_of(range_name: str) -> int:
    return HOURS.get(range_name, HOURS[DEFAULT_RANGE])


def unit_of(hours: int) -> tuple[str, int, str]:
    """막대 한 칸의 단위, 칸 수, 표기. 짧은 기간은 분·시간, 긴 기간은 날 단위다."""
    if hours <= 1:
        return "minute", 60, "HH24:MI"
    if hours <= 48:
        return "hour", hours, "HH24:00"
    return "day", min(-(-hours // 24), 92), "MM-DD"


def decision_series(
    conn: psycopg.Connection, instance: str, hours: int, time_zone: str = "UTC", shift: int = 0
) -> dict[str, Any]:
    """칸마다 결정 갈래별 건수. ``shift``시간 앞선 같은 길이의 기간을 읽으면 직전 기간이 된다."""
    unit, steps, fmt = unit_of(hours)
    anchor = "(now() - make_interval(hours => %s))"
    rows = fetchall(
        conn,
        "SELECT to_char(g, %s) AS label, to_char(g, 'YYYY-MM-DD') AS day,"
        + "".join(f" count(e.b) FILTER (WHERE e.bucket = '{b}') AS {b}," for b in BUCKETS)
        + " count(e.b) AS total FROM generate_series("
        f" date_trunc('{unit}', {anchor} AT TIME ZONE %s::text) - (%s - 1) * interval '1 {unit}',"
        f" date_trunc('{unit}', {anchor} AT TIME ZONE %s::text), interval '1 {unit}') g"
        f" LEFT JOIN (SELECT date_trunc('{unit}', inserted_at AT TIME ZONE %s::text) AS b,"
        f" {_BUCKET} AS bucket FROM mint.events WHERE instance_id = %s"
        " AND kind = 'decision_evaluated'"
        f" AND inserted_at >= {anchor} - make_interval(hours => %s) - interval '1 {unit}'"
        f" AND inserted_at < {anchor} + interval '1 {unit}') e ON e.b = g"
        " GROUP BY g ORDER BY g",
        (fmt, shift, time_zone, steps, shift, time_zone, time_zone, instance, shift, hours, shift),
    )
    return {
        "unit": unit,
        "labels": [r["label"] for r in rows],
        "days": [r["day"] for r in rows],
        "total": [r["total"] for r in rows],
        **{b: [r[b] for r in rows] for b in BUCKETS},
    }


def block_reasons(
    conn: psycopg.Connection, instance: str, hours: int, limit: int = 5
) -> list[dict[str, Any]]:
    """차단된 호출의 사유별 건수(상위 ``limit``)."""
    return fetchall(
        conn,
        f"SELECT code, count(*) AS n FROM (SELECT {_REASON} AS code, {_BUCKET} AS bucket"
        " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(hours => %s)) t"
        " WHERE bucket = 'block' GROUP BY 1 ORDER BY n DESC, code LIMIT %s",
        (instance, hours, limit),
    )


def top_servers(
    conn: psycopg.Connection, instance: str, hours: int, limit: int = 6
) -> list[dict[str, Any]]:
    return fetchall(
        conn,
        "SELECT server_id, count(*) AS calls, count(*) FILTER (WHERE bucket = 'block') AS blocked"
        f" FROM (SELECT payload->>'resolved_server_id' AS server_id, {_BUCKET} AS bucket"
        " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(hours => %s)) t"
        " WHERE server_id IS NOT NULL GROUP BY 1 ORDER BY calls DESC, server_id LIMIT %s",
        (instance, hours, limit),
    )


def pending_wait(conn: psycopg.Connection, instance: str) -> dict[str, Any]:
    """승인을 기다리는 호출의 수와 평균·최장 대기 시간(초)."""
    row = (
        fetchone(
            conn,
            "SELECT count(*) AS n,"
            " avg(greatest(extract(epoch FROM now() - requested_at), 0)) AS average,"
            " max(greatest(extract(epoch FROM now() - requested_at), 0)) AS oldest"
            " FROM mint.call_approvals WHERE instance_id = %s AND status = 'pending'"
            " AND expires_at > now()",
            (instance,),
        )
        or {}
    )
    return {
        "count": row.get("n") or 0,
        "average_seconds": None if row.get("average") is None else int(row["average"]),
        "oldest_seconds": None if row.get("oldest") is None else int(row["oldest"]),
    }


def decided_today(conn: psycopg.Connection, instance: str, time_zone: str = "UTC") -> int:
    row = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.call_approvals WHERE instance_id = %s"
        " AND decided_at >= date_trunc('day', now() AT TIME ZONE %s::text) AT TIME ZONE %s::text",
        (instance, time_zone, time_zone),
    )
    return row["n"] if row else 0


def endpoint_coverage(conn: psycopg.Connection, instance: str) -> dict[str, int]:
    """보고된 엔드포인트 가운데 관리형으로 돌고 있는 수와 전체 수."""
    row = (
        fetchone(
            conn,
            "SELECT count(*) FILTER (WHERE install_mode = 'managed') AS managed, count(*) AS total"
            " FROM mint.endpoint_installs WHERE instance_id = %s AND revoked_at IS NULL"
            " AND install_mode IN ('managed', 'user', 'removed')",
            (instance,),
        )
        or {}
    )
    return {"managed": row.get("managed") or 0, "total": row.get("total") or 0}


def alert_stats(conn: psycopg.Connection, instance: str) -> dict[str, Any]:
    """해결되지 않은 경보의 심각도별 건수, 종류별 상위 8, 가장 오래 열린 경보의 나이(초)."""
    severity = {
        r["severity"]: r["n"]
        for r in fetchall(
            conn,
            "SELECT severity, count(*) AS n FROM mint.alerts WHERE instance_id = %s"
            " AND status <> 'resolved' GROUP BY severity",
            (instance,),
        )
    }
    kinds = fetchall(
        conn,
        "SELECT kind, count(*) AS n FROM mint.alerts WHERE instance_id = %s"
        " AND status <> 'resolved' GROUP BY kind ORDER BY n DESC, kind LIMIT 8",
        (instance,),
    )
    oldest = fetchone(
        conn,
        "SELECT max(extract(epoch FROM now() - first_at)) AS age FROM mint.alerts"
        " WHERE instance_id = %s AND status = 'open'",
        (instance,),
    )
    age = oldest and oldest["age"]
    return {
        "severity": severity,
        "kinds": kinds,
        "oldest_seconds": None if age is None else max(int(age), 0),
    }


def policy_effect(
    conn: psycopg.Connection, instance: str, hours: int, limit: int = 50
) -> list[dict[str, Any]]:
    """판정에 걸린 정책마다 검사·차단·승인 필요 건수."""
    return fetchall(
        conn,
        "SELECT policy_id, count(*) AS checks,"
        " count(*) FILTER (WHERE bucket = 'block') AS blocked,"
        " count(*) FILTER (WHERE bucket = 'approve') AS approval"
        " FROM (SELECT jsonb_array_elements_text(CASE jsonb_typeof(payload->'policy_ids')"
        f" WHEN 'array' THEN payload->'policy_ids' ELSE '[]'::jsonb END) AS policy_id, {_BUCKET}"
        " AS bucket FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(hours => %s)) t"
        " GROUP BY 1 ORDER BY blocked DESC, checks DESC, policy_id LIMIT %s",
        (instance, hours, limit),
    )


def decision_totals(conn: psycopg.Connection, instance: str, hours: int) -> dict[str, int]:
    """기간 안의 판정 건수(갈래별과 합계)."""
    row = (
        fetchone(
            conn,
            "SELECT count(*) AS total,"
            + ", ".join(f"count(*) FILTER (WHERE bucket = '{b}') AS {b}" for b in BUCKETS)
            + f" FROM (SELECT {_BUCKET} AS bucket FROM mint.events WHERE instance_id = %s"
            " AND kind = 'decision_evaluated'"
            " AND inserted_at >= now() - make_interval(hours => %s)) t",
            (instance, hours),
        )
        or {}
    )
    return {k: row.get(k) or 0 for k in ("total", *BUCKETS)}


def event(conn: psycopg.Connection, instance: str, event_id: str) -> dict[str, Any] | None:
    """호출 기록 한 건과 판정 내용(사유·정책·판정 시간)."""
    row = fetchone(
        conn,
        "SELECT event_id, inserted_at, kind, actor, invocation_id, payload,"
        " COALESCE(payload->>'resolved_server_id', payload->>'server_id') AS server_id,"
        " payload->>'tool' AS tool, payload->>'enforced_action' AS result,"
        f" payload->>'outcome' AS outcome, {_BUCKET} AS bucket, {_REASON} AS reason,"
        " payload->'policy_ids' AS policy_ids, (payload->>'decision_us')::bigint AS decision_us"
        " FROM mint.events WHERE instance_id = %s AND event_id = %s",
        (instance, event_id),
    )
    if row is None:
        return None
    ids = row["policy_ids"] if isinstance(row["policy_ids"], list) else []
    row["policy_ids"] = [str(i) for i in ids]
    return row


def since_hours(since: datetime, now: datetime) -> int:
    """조회 시작부터 지금까지의 시간 수(올림, 최소 1)."""
    return max(int(-(-(now - since).total_seconds() // 3600)), 1)


def period_decisions(
    conn: psycopg.Connection, instance: str, start: datetime, end: datetime, servers: int = 10
) -> dict[str, Any]:
    """``[start, end)`` 구간의 판정 갈래별 건수, 차단 사유별 건수, 호출이 많은 서버."""
    base = (
        f"FROM (SELECT {_BUCKET} AS bucket, {_REASON} AS code,"
        " payload->>'resolved_server_id' AS server_id FROM mint.events"
        " WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= %s AND inserted_at < %s) t"
    )
    args = (instance, start, end)
    totals = (
        fetchone(
            conn,
            "SELECT count(*) AS total,"
            + ", ".join(f"count(*) FILTER (WHERE bucket = '{b}') AS {b}" for b in BUCKETS)
            + " "
            + base,
            args,
        )
        or {}
    )
    reasons = fetchall(
        conn,
        "SELECT code, count(*) AS n " + base + " WHERE bucket = 'block' GROUP BY 1 ORDER BY n DESC,"
        " code",
        args,
    )
    top = fetchall(
        conn,
        "SELECT server_id, count(*) AS calls, count(*) FILTER (WHERE bucket = 'block') AS blocked "
        + base
        + " WHERE server_id IS NOT NULL GROUP BY 1 ORDER BY calls DESC, server_id LIMIT %s",
        (*args, servers),
    )
    return {
        "totals": {k: totals.get(k) or 0 for k in ("total", *BUCKETS)},
        "reasons": reasons,
        "servers": top,
    }
