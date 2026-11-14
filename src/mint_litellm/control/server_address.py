"""원격 서버 주소가 내부 주소로 풀린 서버의 경보: 호출 직전 이름 조회 재확인에 걸린 서버를 알린다.

플러그인은 원격 서버 URL의 호스트를 호출 직전에 조회해 내부 대역으로 풀리면 막거나(enforce) 기록만
한다(observe). 막힌 호출은 판정 사건의 정지 사유로, 통과한 호출은 응답·결과 불명 사건의
``resolve_findings``로 남는다. 이 작업은 최근 구간의 그런 사건을 서버별로 모아
``server_address_internal`` 경보를 연다. 같은 서버의 미해결 경보가 있으면 다시 열지 않는다.
이름 조회가 실패한 호출(``unresolved``)은 경보를 열지 않는다.
"""

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "server_address_internal"
WINDOW_SECONDS = 900
ALERTING = ("private", "rebind")


def key_for(server: str) -> str:
    return f"{KIND}:{server}"[:512]


def run(job) -> None:
    rows = fetchall(
        job.conn,
        "SELECT server, array_agg(DISTINCT kind ORDER BY kind) AS kinds, count(*) AS calls FROM ("
        " SELECT e.payload->>'server_id' AS server, f.finding AS kind FROM mint.events e"
        " CROSS JOIN LATERAL jsonb_array_elements_text(e.payload->'resolve_findings')"
        " AS f(finding)"
        " WHERE e.instance_id = %(i)s"
        " AND e.kind IN ('call_response_received', 'call_outcome_unknown')"
        " AND e.inserted_at >= now() - make_interval(secs => %(w)s)"
        " AND jsonb_typeof(e.payload->'resolve_findings') = 'array'"
        " UNION ALL"
        " SELECT e.payload->>'resolved_server_id', split_part(e.payload->'stop'->>'detail', ' ', 1)"
        " FROM mint.events e"
        " WHERE e.instance_id = %(i)s AND e.kind = 'decision_evaluated'"
        " AND e.inserted_at >= now() - make_interval(secs => %(w)s)"
        " AND e.payload->'stop'->>'reason_code' = 'RESOLVED_ADDRESS_FORBIDDEN'"
        ") t WHERE server IS NOT NULL AND kind = ANY(%(k)s) GROUP BY server",
        {"i": job.instance_id, "w": WINDOW_SECONDS, "k": list(ALERTING)},
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
            key = key_for(r["server"])
            if key not in open_keys:
                alerts.raise_alert(
                    job.conn,
                    job.instance_id,
                    kind=KIND,
                    severity="high",
                    dedup_key=key,
                    subject={
                        "server_id": r["server"],
                        "kinds": list(r["kinds"]),
                        "calls": r["calls"],
                        "window_seconds": WINDOW_SECONDS,
                    },
                )
