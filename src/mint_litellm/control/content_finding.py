"""계약 관리가 아닌 서버의 내용 검사 경보: 호출은 통과했지만 결과·인자 검사에 걸린 서버를 알린다.

플러그인은 계약 관리가 아닌 서버의 결과(지시문 표지)와 인자(비밀)를 같은 검사기로 보고, 기본
설정에서는 막지 않고 응답·결과 불명 사건에 걸린 정책 식별자와 서버를 남긴다. 이 작업은 최근
구간의 그런 사건을 서버별로 모아 ``content_finding_unmanaged`` 경보를 연다. 같은 서버의 미해결
경보가 있으면 다시 열지 않는다. 사건만 읽으므로 호출 경로에 DB 왕복이 늘지 않는다.
"""

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "content_finding_unmanaged"
# 작업 주기(60초)보다 넉넉히 길게 본다. 미해결 경보가 있으면 중복해서 열지 않는다.
WINDOW_SECONDS = 900


def key_for(server: str) -> str:
    return f"{KIND}:{server}"[:512]


def run(job) -> None:
    rows = fetchall(
        job.conn,
        "SELECT e.payload->>'server_id' AS server, count(*) AS calls,"
        " array_agg(DISTINCT f.finding ORDER BY f.finding) AS findings"
        " FROM mint.events e"
        " CROSS JOIN LATERAL jsonb_array_elements_text(e.payload->'unmanaged_findings')"
        " AS f(finding)"
        " WHERE e.instance_id = %s AND e.kind IN ('call_response_received', 'call_outcome_unknown')"
        " AND e.inserted_at >= now() - make_interval(secs => %s)"
        " AND jsonb_typeof(e.payload->'unmanaged_findings') = 'array'"
        " AND e.payload->>'server_id' IS NOT NULL GROUP BY 1",
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
            key = key_for(r["server"])
            if key not in open_keys:
                alerts.raise_alert(
                    job.conn, job.instance_id, kind=KIND, severity="medium", dedup_key=key,
                    subject={
                        "server_id": r["server"], "findings": list(r["findings"]),
                        "calls": r["calls"], "window_seconds": WINDOW_SECONDS,
                    },
                )
