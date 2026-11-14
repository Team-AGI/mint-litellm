"""전달된 호출자 토큰의 대상 불일치 경보: aud가 서버와 다른 토큰이 업스트림에 간 서버를 알린다.

기본 설정(``MINT_TOKEN_AUDIENCE=observe``)에서는 호출을 막지 않고 응답(또는 결과 불명) 사건의
``aud_mismatch``와 ``server_id``에 남긴다. 이 작업은 최근 구간의 그런 사건을 서버별로 모아
``token_audience_mismatch`` 경보를 연다. 같은 서버의 미해결 경보가 있으면 다시 열지 않는다.
"""

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "token_audience_mismatch"
WINDOW_SECONDS = 900


def run(job) -> None:
    rows = fetchall(
        job.conn,
        "SELECT e.payload->>'server_id' AS server, count(*) AS calls FROM mint.events e"
        " WHERE e.instance_id = %s AND e.kind IN ('call_response_received', 'call_outcome_unknown')"
        " AND e.inserted_at >= now() - make_interval(secs => %s)"
        " AND e.payload->>'aud_mismatch' = 'true' AND e.payload->>'server_id' IS NOT NULL"
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
            (job.instance_id, KIND),
        )
    }
    with job.conn.transaction():
        for r in rows:
            key = f"{KIND}:{r['server']}"[:512]
            if key not in open_keys:
                alerts.raise_alert(
                    job.conn,
                    job.instance_id,
                    kind=KIND,
                    severity="medium",
                    dedup_key=key,
                    subject={
                        "server_id": r["server"],
                        "calls": r["calls"],
                        "window_seconds": WINDOW_SECONDS,
                    },
                )
