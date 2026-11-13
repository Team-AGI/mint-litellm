"""호출량 급증 탐지: 서버·도구별 최근 구간의 호출 수를 지난 하루의 평균과 견준다.

호출 수는 판정 사건(``decision_evaluated``)에서 센다. 최근 구간(기본 5분)이 구간당 평균 호출 수의
``spike_factor``배 이상이고 ``spike_min_calls``건 이상이면 ``call_spike`` 경보를 열고, 평소 수준으로
돌아오면 닫는다. 경보가 열려 있는 동안에는 다시 열지 않는다(알림이 반복되지 않는다).
"""

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "call_spike"


def key_for(server: str, tool: str) -> str:
    return f"{KIND}:{server}:{tool}"[:512]


def is_spike(current: int, history: int, buckets: int, factor: int, min_calls: int) -> bool:
    """``history``는 최근 구간 앞 ``buckets``개 구간의 호출 수 합이다(조용한 구간도 평균에 든다)."""
    return current >= min_calls and current >= factor * history / max(1, buckets)


def run(job) -> None:
    s = job.settings
    window = s.spike_window_seconds
    buckets = max(1, s.spike_baseline_seconds // window)
    # (instance_id, inserted_at) 부분 색인으로 하루치 범위만 읽는다.
    rows = fetchall(
        job.conn,
        "SELECT COALESCE(payload->>'resolved_server_id',"
        " payload->>'requested_server_name') AS server,"
        " payload->>'tool' AS tool,"
        " count(*) FILTER (WHERE inserted_at >= now() - make_interval(secs => %(w)s)) AS current,"
        " count(*) FILTER (WHERE inserted_at < now() - make_interval(secs => %(w)s)) AS history"
        " FROM mint.events WHERE instance_id = %(i)s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(secs => %(w)s + %(b)s)"
        " AND payload->>'operation' = 'tool_call' AND payload->>'tool' IS NOT NULL"
        " GROUP BY 1, 2",
        {"w": window, "b": s.spike_baseline_seconds, "i": job.instance_id},
    )
    spiking = {}
    for r in rows:
        if r["server"] and is_spike(
            r["current"], r["history"], buckets, s.spike_factor, s.spike_min_calls
        ):
            spiking[key_for(r["server"], r["tool"])] = r
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
        for key, r in spiking.items():
            if key not in open_keys:
                alerts.raise_alert(
                    job.conn, job.instance_id, kind=KIND, severity="medium", dedup_key=key,
                    subject={
                        "server_id": r["server"], "tool": r["tool"], "calls": r["current"],
                        "window_seconds": window,
                        "baseline_calls": round(r["history"] / buckets, 1),
                    },
                )
        for key in open_keys - spiking.keys():
            alerts.resolve(job.conn, job.instance_id, key)
