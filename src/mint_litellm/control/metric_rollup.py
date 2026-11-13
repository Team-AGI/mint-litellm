"""지표 롤업: 판정·결과·판정 시간 구간의 누적 건수를 워터마크 뒤의 사건만 읽어 더한다.

작업 ``metric_rollup``(1분마다)이 ``metric_state.watermark_at`` 이후, 지금 ``LAG_SECONDS`` 전까지
``inserted_at``이 들어온 사건만 세어 ``metric_counts``에 더하고 워터마크를 옮긴다. 지표는 롤업과
워터마크 뒤의 꼬리(짧다)를 합해 내므로 사건이 수백만 건이어도 읽는 양이 일정하다. 호출 경로에는
추가되는 쓰기나 왕복이 없다.

플러그인이 버퍼에서 되살린 사건은 옛 ``inserted_at``으로 들어온다. 되살림이 끝나면 플러그인이
``buffer_replayed``를 남기므로, 워터마크 뒤에 그 사건이 보이면 처음부터 다시 센다(되살림이 있었을
때만 드는 전체 집계). 그래서 롤업 값은 전체를 센 값과 같다.
"""

from datetime import datetime
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone

LAG_SECONDS = 30
# 판정 시간 구간(초). 마이크로초 값과 비교하므로 정수로 바꿔 둔다.
BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

Row = tuple[str, str, str, int, int]  # (family, label_a, label_b, n, total_us)


def counted(
    conn: psycopg.Connection, instance: str, since: datetime | None, until: datetime | None
) -> list[Row]:
    """``since`` 다음부터 ``until``까지(포함) 들어온 사건의 집계. 둘 다 없으면 전체를 센다."""
    window = ""
    args: list[Any] = [instance]
    if since is not None:
        window += " AND inserted_at > %s"
        args.append(since)
    if until is not None:
        window += " AND inserted_at <= %s"
        args.append(until)
    rows: list[Row] = [
        ("decision", r["server_id"], r["result"], r["n"], 0)
        for r in fetchall(
            conn,
            "SELECT COALESCE(payload->>'resolved_server_id', '') AS server_id,"
            " COALESCE(payload->>'outcome', CASE WHEN payload->>'enforced_action' = 'allow'"
            " THEN 'allowed' ELSE 'blocked' END) AS result, count(*) AS n"
            " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
            f"{window} GROUP BY 1, 2",
            args,
        )
    ]
    buckets = ", ".join(
        f"count(*) FILTER (WHERE us <= {round(b * 1_000_000)}) AS b{i}"
        for i, b in enumerate(BUCKETS)
    )
    lat = fetchall(
        conn,
        f"SELECT count(*) AS n, COALESCE(sum(us), 0) AS total, {buckets} FROM ("
        " SELECT (payload->>'decision_us')::bigint AS us FROM mint.events"
        " WHERE instance_id = %s AND kind = 'decision_evaluated'"
        f" AND payload->>'decision_us' IS NOT NULL{window}) t",
        args,
    )[0]
    rows.append(("latency", "", "all", lat["n"], int(lat["total"])))
    rows.extend(("latency", "", f"b{i}", lat[f"b{i}"], 0) for i in range(len(BUCKETS)))
    rows.extend(
        ("call_result", "", r["result"], r["n"], 0)
        for r in fetchall(
            conn,
            "SELECT COALESCE(payload->>'outcome', CASE WHEN kind = 'call_outcome_unknown'"
            " THEN 'unknown' WHEN payload->>'is_error' = 'true' THEN 'tool_error'"
            " ELSE 'success' END) AS result, count(*) AS n FROM mint.events"
            " WHERE instance_id = %s AND kind IN ('call_response_received',"
            f" 'call_outcome_unknown'){window} GROUP BY 1",
            args,
        )
    )
    return [r for r in rows if r[3] or r[4]]


def advance(conn: psycopg.Connection, instance: str) -> int:
    """워터마크를 지금 - ``LAG_SECONDS``까지 옮긴다. 이번에 더한 집계 행 수를 돌려준다."""
    with conn.transaction():
        conn.execute(
            "INSERT INTO mint.metric_state (instance_id) VALUES (%s) ON CONFLICT DO NOTHING",
            (instance,),
        )
        state = fetchone(
            conn,
            "SELECT watermark_at, clock_timestamp() - make_interval(secs => %s) AS cutoff"
            " FROM mint.metric_state WHERE instance_id = %s FOR UPDATE",
            (LAG_SECONDS, instance),
        )
        assert state is not None
        mark, cutoff = state["watermark_at"], state["cutoff"]
        replayed = mark is not None and fetchone(
            conn,
            "SELECT 1 FROM mint.events WHERE instance_id = %s AND kind = 'buffer_replayed'"
            " AND inserted_at > %s AND inserted_at <= %s LIMIT 1",
            (instance, mark, cutoff),
        )
        if replayed:
            conn.execute("DELETE FROM mint.metric_counts WHERE instance_id = %s", (instance,))
            mark = None
        rows = counted(conn, instance, mark, cutoff)
        for family, label_a, label_b, n, total in rows:
            conn.execute(
                "INSERT INTO mint.metric_counts"
                " (instance_id, family, label_a, label_b, n, total_us)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (instance_id, family, label_a, label_b) DO UPDATE"
                " SET n = mint.metric_counts.n + EXCLUDED.n,"
                " total_us = mint.metric_counts.total_us + EXCLUDED.total_us",
                (instance, family, label_a, label_b, n, total),
            )
        conn.execute(
            "UPDATE mint.metric_state SET watermark_at = %s, updated_at = now()"
            " WHERE instance_id = %s",
            (cutoff, instance),
        )
    return len(rows)


def totals(conn: psycopg.Connection, instance: str) -> list[Row]:
    """롤업 + 워터마크 뒤의 꼬리. 롤업과 워터마크는 한 문장으로 읽어 서로 어긋나지 않는다."""
    stored = fetchall(
        conn,
        "SELECT s.watermark_at, c.family, c.label_a, c.label_b, c.n, c.total_us"
        " FROM mint.metric_state s LEFT JOIN mint.metric_counts c USING (instance_id)"
        " WHERE s.instance_id = %s",
        (instance,),
    )
    mark = stored[0]["watermark_at"] if stored else None
    base = [
        (r["family"], r["label_a"], r["label_b"], r["n"], r["total_us"])
        for r in stored
        if r["family"] is not None
    ]
    merged: dict[tuple[str, str, str], list[int]] = {}
    for family, a, b, n, total in [*base, *counted(conn, instance, mark, None)]:
        cell = merged.setdefault((family, a, b), [0, 0])
        cell[0] += n
        cell[1] += total
    return [(f, a, b, n, t) for (f, a, b), (n, t) in sorted(merged.items())]


def run(job) -> None:
    advance(job.conn, job.instance_id)
