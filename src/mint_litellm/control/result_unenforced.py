"""결과 단계 가드레일이 없는 LiteLLM(저하 운용)에서 막지 못한 결과를 경보로 알린다.

이 LiteLLM에서는 결과 검사가 관측만 하므로, 걸린 결과(크기 상한·지시문 표지·비밀·개인정보)도
호출자에게 그대로 갔다. 응답 사건(``call_response_received``)이 ``result_unenforced``와 걸린 정책
식별자를 담고 있으면 최근 구간에 몇 건인지 세어 경보 ``result_unenforced``를 연다. 구간에 없으면
닫는다. 열려 있는 동안에는 건수만 올라간다.
"""

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "result_unenforced"
WINDOW_SECONDS = 600


def run(job) -> None:
    rows = fetchall(
        job.conn,
        "SELECT count(*) AS calls FROM mint.events"
        " WHERE instance_id = %(i)s AND kind = 'call_response_received'"
        " AND inserted_at >= now() - make_interval(secs => %(w)s)"
        " AND payload->>'result_unenforced' = 'true'"
        " AND jsonb_array_length(COALESCE(payload->'output_findings', '[]'::jsonb)) > 0",
        {"i": job.instance_id, "w": WINDOW_SECONDS},
    )
    calls = rows[0]["calls"] if rows else 0
    with job.conn.transaction():
        if calls:
            alerts.raise_alert(
                job.conn, job.instance_id, kind=KIND, severity="high", dedup_key=KIND,
                subject={"calls": calls, "window_seconds": WINDOW_SECONDS},
            )
        else:
            alerts.resolve(job.conn, job.instance_id, KIND)
