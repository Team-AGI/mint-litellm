"""판정·작업·관측·경보 지표. Prometheus 텍스트 형식으로 그린다.

제어면 콘솔의 ``/api/v1/metrics``가 운영자 토큰으로 내보낸다. 값은 모두 DB에서 읽으므로 플러그인
쪽에 별도 포트나 의존 패키지가 필요 없다. 라벨은 서버 식별자와 종류·결과·심각도처럼 값이 한정된
것만 쓰고, 사용자·인자·도구 이름은 쓰지 않는다(도구 이름은 승인되지 않은 호출자가 정한다).
"""

import time
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall

# 판정 시간 구간(초). 마이크로초 값과 비교하므로 정수로 바꿔 둔다.
BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
CACHE_SECONDS = 15.0

_cache: dict[str, tuple[float, str]] = {}


def collect(conn: psycopg.Connection, instance: str) -> dict[str, Any]:
    decisions = fetchall(
        conn,
        "SELECT COALESCE(payload->>'resolved_server_id', '') AS server_id,"
        " COALESCE(payload->>'outcome', CASE WHEN payload->>'enforced_action' = 'allow'"
        " THEN 'allowed' ELSE 'blocked' END) AS result, count(*) AS n"
        " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated' GROUP BY 1, 2",
        (instance,),
    )
    buckets = ", ".join(
        f"count(*) FILTER (WHERE us <= {round(b * 1_000_000)}) AS b{i}"
        for i, b in enumerate(BUCKETS)
    )
    latency = fetchall(
        conn,
        f"SELECT count(*) AS n, COALESCE(sum(us), 0) AS total, {buckets} FROM ("
        " SELECT (payload->>'decision_us')::bigint AS us FROM mint.events"
        " WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND payload->>'decision_us' IS NOT NULL) t",
        (instance,),
    )[0]
    results = fetchall(
        conn,
        "SELECT COALESCE(payload->>'outcome', CASE WHEN kind = 'call_outcome_unknown'"
        " THEN 'unknown' WHEN payload->>'is_error' = 'true' THEN 'tool_error'"
        " ELSE 'success' END) AS result, count(*) AS n FROM mint.events"
        " WHERE instance_id = %s AND kind IN ('call_response_received', 'call_outcome_unknown')"
        " GROUP BY 1",
        (instance,),
    )
    jobs = fetchall(
        conn,
        "SELECT kind, count(*) AS n, max(EXTRACT(EPOCH FROM now() - created_at)) AS oldest"
        " FROM mint.jobs WHERE instance_id = %s AND status = 'pending' GROUP BY kind",
        (instance,),
    )
    observed = fetchall(
        conn,
        "SELECT server_id, EXTRACT(EPOCH FROM now() - last_observed_at) AS age"
        " FROM mint.servers WHERE instance_id = %s AND last_observed_at IS NOT NULL",
        (instance,),
    )
    alerts = fetchall(
        conn,
        "SELECT kind, severity, count(*) AS n FROM mint.alerts WHERE instance_id = %s"
        " AND status <> 'resolved' GROUP BY 1, 2",
        (instance,),
    )
    return {
        "decisions": decisions,
        "latency": latency,
        "results": results,
        "jobs": jobs,
        "observed": observed,
        "alerts": alerts,
    }


def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\n")


def _line(name: str, labels: dict[str, Any], value: float) -> str:
    inner = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
    return f"{name}{{{inner}}} {value:g}" if inner else f"{name} {value:g}"


def render(data: dict[str, Any]) -> str:
    """``collect``가 돌려준 값을 Prometheus 텍스트로 그린다. 종류별로 정렬해 출력이 안정적이다."""
    out: list[str] = []

    def head(name: str, kind: str, text: str) -> None:
        out.extend([f"# HELP {name} {text}", f"# TYPE {name} {kind}"])

    head("mint_decisions_total", "counter", "Tool call decisions by result.")
    for r in sorted(data["decisions"], key=lambda r: (r["result"], r["server_id"])):
        labels = {"result": r["result"], "server_id": r["server_id"]}
        out.append(_line("mint_decisions_total", labels, r["n"]))

    head("mint_call_results_total", "counter", "Tool call outcomes after dispatch.")
    for r in sorted(data["results"], key=lambda r: r["result"]):
        out.append(_line("mint_call_results_total", {"result": r["result"]}, r["n"]))

    head("mint_decision_seconds", "histogram", "Time MINT spent reaching a decision.")
    lat = data["latency"]
    for i, bound in enumerate(BUCKETS):
        out.append(_line("mint_decision_seconds_bucket", {"le": f"{bound:g}"}, lat[f"b{i}"]))
    out.append(_line("mint_decision_seconds_bucket", {"le": "+Inf"}, lat["n"]))
    out.append(_line("mint_decision_seconds_sum", {}, float(lat["total"]) / 1_000_000))
    out.append(_line("mint_decision_seconds_count", {}, lat["n"]))

    jobs = sorted(data["jobs"], key=lambda r: r["kind"])
    head("mint_jobs_pending", "gauge", "Pending jobs by kind.")
    out.extend(_line("mint_jobs_pending", {"kind": r["kind"]}, r["n"]) for r in jobs)
    head("mint_jobs_oldest_pending_seconds", "gauge", "Age of the oldest pending job by kind.")
    out.extend(
        _line("mint_jobs_oldest_pending_seconds", {"kind": r["kind"]}, float(r["oldest"] or 0))
        for r in jobs
    )

    head(
        "mint_server_last_observed_age_seconds", "gauge",
        "Seconds since the last successful contract observation per server.",
    )
    out.extend(
        _line(
            "mint_server_last_observed_age_seconds", {"server_id": r["server_id"]}, float(r["age"])
        )
        for r in sorted(data["observed"], key=lambda r: r["server_id"])
    )

    head("mint_alerts_open", "gauge", "Unresolved alerts by kind and severity.")
    out.extend(
        _line("mint_alerts_open", {"kind": r["kind"], "severity": r["severity"]}, r["n"])
        for r in sorted(data["alerts"], key=lambda r: (r["kind"], r["severity"]))
    )
    return "\n".join(out) + "\n"


def exposition(conn: psycopg.Connection, instance: str) -> str:
    """짧은 시간 안의 반복 수집은 같은 결과를 준다. 사건이 많아도 수집 부하를 한 번으로 묶는다."""
    now = time.monotonic()
    hit = _cache.get(instance)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    text = render(collect(conn, instance))
    _cache[instance] = (now, text)
    return text
