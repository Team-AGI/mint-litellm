"""대량 추출 탐지: 호출한 쪽·서버별로 최근 구간에 받은 결과량을 지난 7일 평균과 견준다.

양은 응답 사건(``call_response_received``)의 결과 바이트 수와 항목 수로 센다. 최근 구간(기본 15분)의
양이 구간당 평균의 ``bulk_factor``배 이상이고 바닥값(기본 5 MiB 또는 2000항목) 이상이면
``bulk_extraction`` 경보를 열고, 평소 수준으로 돌아오면 닫는다. 열려 있는 동안에는 다시 열지
않는다. 서버 전체 합계도 같은 규칙으로 본다. 호출한 쪽의 식별자는 경보 대상에만 남고 지표
라벨에는 쓰지 않는다.

``MINT_BULK_EXTRACTION_ACTION=hold``이면 경보를 새로 열 때 그 호출한 쪽의 해당 서버 호출을
거부(``denials``)로 막는다. 거부는 관리자가 콘솔의 거부 목록에서 해제할 때까지 남는다.
"""

from mint_litellm.control import alerts, approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.types.events import AlertKind

KIND = AlertKind.BULK_EXTRACTION.value
ACTOR = "bulk-extraction"
HOLD_REASON = "대량 추출 의심: 짧은 시간에 평소보다 훨씬 많은 결과를 받아 호출을 막았습니다."


def key_for(server: str, principal: str | None) -> str:
    return f"{KIND}:{server}:{principal or '*'}"[:512]


def is_bulk(
    cur_bytes: int, cur_items: int, hist_bytes: int, hist_items: int, buckets: int,
    factor: int, min_bytes: int, min_items: int,
) -> bool:
    """``hist_*``는 최근 구간 앞 ``buckets``개 구간의 합이다(조용한 구간도 평균에 든다)."""
    n = max(1, buckets)
    return (cur_bytes >= min_bytes and cur_bytes >= factor * hist_bytes / n) or (
        cur_items >= min_items and cur_items >= factor * hist_items / n
    )


def run(job) -> None:
    s = job.settings
    window = s.bulk_window_seconds
    buckets = max(1, s.bulk_baseline_seconds // window)
    # 응답 사건 부분 색인으로 7일치 범위만 읽는다. 호출한 쪽별과 서버별 두 묶음.
    rows = fetchall(
        job.conn,
        "WITH r AS (SELECT inserted_at, payload->>'server_id' AS server,"
        " subject->>'principal_type' AS ptype, subject->>'principal_id' AS pid,"
        " COALESCE((payload->>'size_bytes')::bigint, 0) AS b,"
        " COALESCE((payload->>'items')::bigint, 0) AS n FROM mint.events"
        " WHERE instance_id = %(i)s AND kind = 'call_response_received'"
        " AND inserted_at >= now() - make_interval(secs => %(w)s + %(b)s)"
        " AND payload->>'server_id' IS NOT NULL)"
        " SELECT server, ptype, pid,"
        + "".join(
            f" COALESCE(sum({col}) FILTER (WHERE inserted_at {op}"
            f" now() - make_interval(secs => %(w)s)), 0)::bigint AS {name},"
            for name, col, op in (
                ("cur_bytes", "b", ">="), ("cur_items", "n", ">="),
                ("hist_bytes", "b", "<"), ("hist_items", "n", "<"),
            )
        ).rstrip(",")
        + " FROM r GROUP BY GROUPING SETS ((server, ptype, pid), (server))",
        {"w": window, "b": s.bulk_baseline_seconds, "i": job.instance_id},
    )
    found = {}
    for r in rows:
        if is_bulk(
            r["cur_bytes"], r["cur_items"], r["hist_bytes"], r["hist_items"], buckets,
            s.bulk_factor, s.bulk_min_bytes, s.bulk_min_items,
        ):
            found[key_for(r["server"], r["pid"])] = r
    open_keys = {
        r["dedup_key"]
        for r in fetchall(
            job.conn,
            "SELECT dedup_key FROM mint.alerts WHERE instance_id = %s AND kind = %s"
            " AND status <> 'resolved'",
            (job.instance_id, KIND),
        )
    }
    ctx = Context(job.conn, job.instance_id, Operator(ACTOR, "system", None))
    with job.conn.transaction():
        for key, r in found.items():
            if key in open_keys:
                continue
            holding = bool(r["pid"]) and s.bulk_action == "hold"
            created = alerts.raise_alert(
                job.conn, job.instance_id, kind=KIND, severity="high", dedup_key=key,
                subject={
                    "server_id": r["server"], "principal_id": r["pid"],
                    "bytes": r["cur_bytes"], "items": r["cur_items"], "window_seconds": window,
                    "baseline_bytes": round(r["hist_bytes"] / buckets),
                    "baseline_items": round(r["hist_items"] / buckets, 1),
                    "held": holding,
                },
            )
            if created and holding:
                hold(ctx, r["server"], r["ptype"], r["pid"])
        for key in open_keys - found.keys():
            alerts.resolve(job.conn, job.instance_id, key)


def hold(ctx: Context, server: str, principal_type: str, principal_id: str) -> str | None:
    """호출한 쪽의 서버 호출을 거부로 막는다. 같은 거부가 이미 있으면 만들지 않는다."""
    scope = "user" if principal_type == "user" else "key"
    if fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.denials WHERE instance_id = %s AND scope_type = %s"
        " AND scope_id = %s AND server_id = %s AND tools IS NULL AND lifted_at IS NULL",
        (ctx.instance_id, scope, principal_id, server),
    ):
        return None
    return approvals.create_denial(
        ctx, scope_type=scope, scope_id=principal_id, server_id=server, tools=None,
        reason=HOLD_REASON, org_id=None,
    )
