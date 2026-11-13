"""판정·작업·관측·경보 지표. Prometheus 텍스트 형식으로 그린다.

제어면 콘솔의 ``/api/v1/metrics``가 운영자 토큰으로 내보낸다. 값은 모두 DB에서 읽으므로 플러그인
쪽에 별도 포트나 의존 패키지가 필요 없다. 라벨은 서버 식별자와 종류·결과·심각도처럼 값이 한정된
것만 쓰고, 사용자·인자·도구 이름은 쓰지 않는다(도구 이름은 승인되지 않은 호출자가 정한다).
"""

import time
from typing import Any

import psycopg

from mint_litellm.control import metric_rollup
from mint_litellm.control.db.connection import fetchall

BUCKETS = metric_rollup.BUCKETS
CACHE_SECONDS = 15.0

_cache: dict[str, tuple[float, str]] = {}


def collect(conn: psycopg.Connection, instance: str) -> dict[str, Any]:
    """판정·결과·판정 시간은 롤업과 워터마크 뒤 꼬리에서 읽는다(사건 표 전체를 세지 않는다)."""
    decisions, results, latency = [], [], {"n": 0, "total": 0}
    for i in range(len(BUCKETS)):
        latency[f"b{i}"] = 0
    for family, a, b, n, total in metric_rollup.totals(conn, instance):
        if family == "decision":
            decisions.append({"server_id": a, "result": b, "n": n})
        elif family == "call_result":
            results.append({"result": b, "n": n})
        elif b == "all":
            latency["n"], latency["total"] = n, total
        else:
            latency[b] = n
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
