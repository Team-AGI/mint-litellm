"""전달된 호출자 토큰의 대상 불일치 경보: aud가 서버와 다른 토큰이 업스트림에 간 서버를 알린다.

기본 설정(``MINT_TOKEN_AUDIENCE=observe``)에서는 호출을 막지 않고 응답(또는 결과 불명) 사건의
``aud_mismatch``와 ``server_id``에 남긴다. 이 작업은 최근 구간의 그런 사건을 서버별로 모아
``token_audience_mismatch`` 경보를 연다. 같은 서버의 미해결 경보가 있으면 다시 열지 않는다.
"""

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "token_audience_mismatch"
SCOPE_KIND = "token_scope_exceeded"
WINDOW_SECONDS = 900
# 경보 종류마다 사건에서 걸린 호출을 고르는 조건
_FLAGGED = {
    KIND: "e.payload->>'aud_mismatch' = 'true'",
    SCOPE_KIND: "jsonb_array_length(COALESCE(e.payload->'scope_exceeded', '[]')) > 0",
}


def run(job) -> None:
    for kind, flagged in _FLAGGED.items():
        _raise(job, kind, flagged)


def _raise(job, kind: str, flagged: str) -> None:
    rows = fetchall(
        job.conn,
        "SELECT e.payload->>'server_id' AS server, count(*) AS calls FROM mint.events e"
        " WHERE e.instance_id = %s AND e.kind IN ('call_response_received', 'call_outcome_unknown')"
        " AND e.inserted_at >= now() - make_interval(secs => %s)"
        f" AND {flagged} AND e.payload->>'server_id' IS NOT NULL"
        " GROUP BY 1",
        (job.instance_id, WINDOW_SECONDS),
    )
    if not rows:
        return
    open_keys = {
        r["dedup_key"]
        for r in fetchall(
            job.conn,
            "SELECT dedup_key FROM mint.alerts WHERE instance_id = %s AND kind = %s"
            " AND status <> 'resolved'",
            (job.instance_id, kind),
        )
    }
    with job.conn.transaction():
        for r in rows:
            key = f"{kind}:{r['server']}"[:512]
            if key not in open_keys:
                alerts.raise_alert(
                    job.conn,
                    job.instance_id,
                    kind=kind,
                    severity="medium",
                    dedup_key=key,
                    subject={
                        "server_id": r["server"],
                        "calls": r["calls"],
                        "window_seconds": WINDOW_SECONDS,
                    },
                )
