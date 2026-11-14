"""작업 ``package_vuln_scan``: 서버가 쓰는 패키지의 알려진 취약점 조회와 치명 취약점의 조치 기한.

조회처는 OSV 형식 API(``POST {주소}/v1/querybatch``, 취약점마다 ``GET {주소}/v1/vulns/{id}``)이며
주소는 설정(``MINT_VULN_FEED_URL``, 기본 공개 OSV)이다. 조회가 안 돼도 호출은 막지 않는다. 경보
``vuln_feed_unreachable`` 하나만 열고, 이미 알고 있는 결과로 기한 판정을 이어 간다.

고정된 패키지가 끌고 오는 의존 패키지(전이 의존성)는 deps.dev 형식 API(``MINT_DEPS_GRAPH_URL``)로
구해 같은 조회에 넣는다. 의존 그래프는 하루에 한 번만 다시 받고, 의존 패키지에서 나온 취약점은
서버와 경로("A → B")를 경보에 적는다. 의존 그래프 조회가 안 돼도 경보 ``dep_graph_unreachable``
하나만 열고 알고 있는 그래프로 이어 간다. 컨테이너 이미지는 조회할 공개 API가 없어 다루지 않는다.

치명(점수 9.0 이상, 평가 등급 CRITICAL, 또는 악용 확인 표지)은 처음 확인한 시각부터 48시간 안에
조치해야 한다. 확인 즉시 경보하고, 남은 시간이 24시간 이하가 되면 경보를 올리며, 기한이 지나면 그
서버의 호출을 막는다(서버 행의 ``vuln_blocked_at``을 판정이 읽는다). 패키지를 고쳐 취약점이 조회에서
사라지거나, 관리자가 서버에 ``vuln_exception`` 증빙(예외)을 붙이면 막힘이 풀린다.
"""

import logging
import math
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx

from mint_litellm.control import alerts, depgraph
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.packages import OSV_ECOSYSTEM
from mint_litellm.types.ids import new_uuid7

log = logging.getLogger(__name__)

KIND_VULNERABLE = "package_vulnerable"
KIND_DUE = "package_vuln_due"
KIND_UNREACHABLE = "vuln_feed_unreachable"
KIND_GRAPH_UNREACHABLE = "dep_graph_unreachable"
DEADLINE = timedelta(hours=48)
ESCALATE_REMAINING = timedelta(hours=24)
BATCH = 500
# 한 번에 새로 받는 취약점 상세의 상한. 넘으면 다음 주기에 이어 받는다.
DETAIL_LIMIT = 200
RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ALERT_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium"}
_LABEL = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
          "LOW": "low"}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    return scaled / 100000 if scaled % 10000 == 0 else (math.floor(scaled / 10000) + 1) / 10


def cvss3(vector: str | None) -> float | None:
    """CVSS 3.x 벡터 문자열의 기본 점수. 3.x가 아니거나 해석할 수 없으면 None."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = (
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        )
        exploit = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1.0) * (impact + exploit), 10))


def label_of_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def rate(doc: dict[str, Any]) -> dict[str, Any]:
    """취약점 상세(OSV 형식)에서 등급·점수·악용 확인 표지·요약을 뽑는다. 점수와 등급 중 높은 쪽."""
    scores = [
        s for s in (cvss3(e.get("score")) for e in doc.get("severity") or []
                    if isinstance(e, dict)) if s is not None
    ]
    score = max(scores) if scores else None
    extra = doc.get("database_specific") or {}
    label = _LABEL.get(str(extra.get("severity", "")).upper(), "unknown")
    severity = max(label, label_of_score(score), key=RANK.__getitem__)
    exploited = bool(extra.get("known_exploited") or extra.get("cisa_kev"))
    summary = str(doc.get("summary") or doc.get("details") or "")[:300] or None
    return {"severity": severity, "cvss": score, "exploited": exploited, "summary": summary}


def is_critical(finding: dict[str, Any]) -> bool:
    return finding["severity"] == "critical" or bool(finding["exploited"])


def clock(first_seen: datetime, now: datetime) -> str:
    """상태: ``running``(24시간 넘게 남음), ``escalated``(24시간 이하), ``overdue``(기한 지남)"""
    left = first_seen + DEADLINE - now
    if left <= timedelta(0):
        return "overdue"
    return "escalated" if left <= ESCALATE_REMAINING else "running"


def parse_batch(doc: dict[str, Any], expected: int) -> list[list[str]]:
    """querybatch 응답에서 질의 순서대로 취약점 식별자 목록을 꺼낸다. 형식이 어긋나면 ValueError."""
    results = doc.get("results")
    if not isinstance(results, list) or len(results) != expected:
        raise ValueError("조회 응답의 결과 수가 질의 수와 다릅니다.")
    return [[str(v["id"]) for v in (r or {}).get("vulns") or []] for r in results]


def fetch(
    http: httpx.Client, base: str, keys: list[tuple[str, str, str]], known: dict[str, dict]
) -> dict[tuple[str, str, str], dict[str, dict]]:
    """패키지 (생태계, 이름, 버전)마다 {취약점 식별자: 등급 정보}. 실패하면 예외를 그대로 낸다.

    ponytail: 질의 결과의 쪽 넘김(next_page_token)은 따르지 않는다. 한 버전에 취약점이 수백 건이
    아니면 영향이 없다. 필요해지면 토큰으로 같은 질의를 반복한다.
    """
    found: dict[tuple[str, str, str], list[str]] = {}
    for i in range(0, len(keys), BATCH):
        chunk = keys[i:i + BATCH]
        body = {"queries": [
            {"package": {"name": n, "ecosystem": OSV_ECOSYSTEM[e]}, "version": v}
            for e, n, v in chunk
        ]}
        response = http.post(f"{base}/v1/querybatch", json=body)
        response.raise_for_status()
        for key, ids in zip(chunk, parse_batch(response.json(), len(chunk)), strict=True):
            found[key] = ids
    details = dict(known)
    budget = DETAIL_LIMIT
    for ids in found.values():
        for vuln_id in ids:
            if vuln_id in details and details[vuln_id]["severity"] != "unknown":
                continue
            if budget <= 0:
                details.setdefault(vuln_id, rate({}))
                continue
            budget -= 1
            response = http.get(f"{base}/v1/vulns/{quote(vuln_id, safe='')}")
            response.raise_for_status()
            details[vuln_id] = rate(response.json())
    return {key: {v: details[v] for v in ids} for key, ids in found.items()}


def _desired_packages(conn: Any, instance: str) -> list[tuple[str, str, str]]:
    rows = fetchall(
        conn,
        "SELECT DISTINCT p.ecosystem, p.name, p.version FROM mint.servers s"
        " JOIN mint.server_packages p ON p.instance_id = s.instance_id"
        " AND p.server_id = s.server_id AND p.exec_contract_sha256 = s.exec_contract_sha256"
        " WHERE s.instance_id = %s AND s.identity_kind = 'stdio'"
        " AND s.status NOT IN ('rejected', 'terminating', 'terminated')"
        " AND p.pinned AND p.ecosystem = ANY(%s)",
        (instance, list(OSV_ECOSYSTEM)),
    )
    return [(r["ecosystem"], r["name"], r["version"]) for r in rows]


def _store(conn: Any, instance: str, results: dict[tuple[str, str, str], dict[str, dict]]) -> None:
    for (eco, name, version), vulns in results.items():
        for vuln_id, f in vulns.items():
            conn.execute(
                "INSERT INTO mint.package_vulns (id, instance_id, ecosystem, name, version,"
                " vuln_id, severity, cvss, exploited, summary)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (instance_id, ecosystem, name, version, vuln_id) DO UPDATE SET"
                " severity = EXCLUDED.severity, cvss = EXCLUDED.cvss,"
                " exploited = EXCLUDED.exploited, summary = EXCLUDED.summary,"
                " last_seen_at = now(), cleared_at = NULL",
                (new_uuid7(), instance, eco, name, version, vuln_id, f["severity"], f["cvss"],
                 f["exploited"], f["summary"]),
            )
        conn.execute(
            "UPDATE mint.package_vulns SET cleared_at = now() WHERE instance_id = %s"
            " AND ecosystem = %s AND name = %s AND version = %s AND cleared_at IS NULL"
            " AND vuln_id <> ALL(%s)",
            (instance, eco, name, version, list(vulns)),
        )


_FINDING_COLUMNS = (
    "s.server_id, s.vuln_blocked_at, v.ecosystem, v.name, v.version, v.vuln_id,"
    " v.severity, v.cvss, v.exploited, v.summary, v.first_seen_at"
)
_FINDING_WHERE = (
    " WHERE s.instance_id = %s AND s.identity_kind = 'stdio'"
    " AND s.status NOT IN ('rejected', 'terminated')"
)
_SERVER_PACKAGES = (
    " FROM mint.servers s JOIN mint.server_packages p ON p.instance_id = s.instance_id"
    " AND p.server_id = s.server_id AND p.exec_contract_sha256 = s.exec_contract_sha256"
)


def _findings(conn: Any, instance: str) -> list[dict]:
    """서버의 현재 계약 패키지와 그 의존 패키지에 걸린, 아직 조회에서 사라지지 않은 취약점.

    의존 패키지에서 나온 행은 ``path``(예: ``A → B``)에 서버가 쓰는 패키지부터의 경로가 있다.
    """
    return fetchall(
        conn,
        "SELECT " + _FINDING_COLUMNS + ", NULL::text AS path" + _SERVER_PACKAGES
        + " JOIN mint.package_vulns v ON v.instance_id = p.instance_id"
        " AND v.ecosystem = p.ecosystem AND v.name = p.name AND v.version = p.version"
        " AND v.cleared_at IS NULL" + _FINDING_WHERE
        + " UNION ALL SELECT " + _FINDING_COLUMNS + ", d.path" + _SERVER_PACKAGES
        + " JOIN mint.package_deps t ON t.instance_id = p.instance_id"
        " AND t.ecosystem = p.ecosystem AND t.name = p.name AND t.version = p.version"
        " AND t.dep_name = t.name AND t.dep_version = t.version"
        " JOIN mint.package_deps d ON d.instance_id = t.instance_id"
        " AND d.ecosystem = t.ecosystem AND d.name = t.name AND d.version = t.version"
        " AND d.resolved_at = t.resolved_at"
        " AND NOT (d.dep_name = d.name AND d.dep_version = d.version)"
        " JOIN mint.package_vulns v ON v.instance_id = d.instance_id"
        " AND v.ecosystem = d.ecosystem AND v.name = d.dep_name AND v.version = d.dep_version"
        " AND v.cleared_at IS NULL" + _FINDING_WHERE
        + " ORDER BY first_seen_at",
        (instance, instance),
    )


def _excepted(conn: Any, instance: str, now: datetime) -> set[str]:
    """지금 유효한 ``vuln_exception`` 증빙(관리자가 기록한 예외)이 있는 서버."""
    rows = fetchall(
        conn,
        "SELECT DISTINCT ON (subject_id) subject_id, valid_until FROM mint.policy_evidence"
        " WHERE instance_id = %s AND kind = 'vuln_exception' AND subject_kind = 'server'"
        " ORDER BY subject_id, attached_at DESC, id DESC",
        (instance,),
    )
    return {r["subject_id"] for r in rows if r["valid_until"] is None or r["valid_until"] > now}


def finding_key(f: dict) -> str:
    return f"{f['server_id']}:{f['ecosystem']}:{f['name']}@{f['version']}:{f['vuln_id']}"


def plan(
    rows: list[dict], excepted: set[str], now: datetime
) -> tuple[list[tuple[str, str, str, dict]], set[str]]:
    """저장된 취약점에서 열려 있을 경보 (종류, 키, 심각도, 본문)와 호출을 막을 서버를 정한다."""
    wanted: list[tuple[str, str, str, dict]] = []
    blocked: set[str] = set()
    unique: dict[str, dict] = {}
    for f in rows:  # 같은 취약점이 직접·의존으로 겹치면 직접 쪽을 남긴다
        key = finding_key(f)
        if key not in unique or (unique[key].get("path") and not f.get("path")):
            unique[key] = f
    for key, f in unique.items():
        subject = {
            "server_id": f["server_id"], "ecosystem": f["ecosystem"], "package": f["name"],
            "version": f["version"], "vuln_id": f["vuln_id"], "severity": f["severity"],
            "cvss": None if f["cvss"] is None else float(f["cvss"]),
            "exploited": f["exploited"], "summary": f["summary"],
        }
        if f.get("path"):
            subject["path"] = f["path"]
        wanted.append((KIND_VULNERABLE, f"{KIND_VULNERABLE}:{key}", f["severity"], subject))
        if not is_critical(f):
            continue
        state = clock(f["first_seen_at"], now)
        if state == "running":
            continue
        excused = f["server_id"] in excepted
        due = {**subject, "state": state, "excepted": excused,
               "deadline_at": (f["first_seen_at"] + DEADLINE).isoformat()}
        wanted.append((KIND_DUE, f"{KIND_DUE}:{state}:{key}", "critical", due))
        if state == "overdue" and not excused:
            blocked.add(f["server_id"])
    return wanted, blocked


def evaluate(conn: Any, instance: str, now: datetime) -> set[str]:
    """저장된 취약점으로 경보와 호출 막힘을 맞춘다. 막아야 하는 서버를 돌려준다."""
    wanted, blocked = plan(_findings(conn, instance), _excepted(conn, instance, now), now)
    open_keys = {
        r["dedup_key"]
        for r in fetchall(
            conn,
            "SELECT dedup_key FROM mint.alerts WHERE instance_id = %s AND kind = ANY(%s)"
            " AND status <> 'resolved'",
            (instance, [KIND_VULNERABLE, KIND_DUE]),
        )
    }
    with conn.transaction():
        for kind, dedup, severity, body in wanted:
            if dedup not in open_keys:  # 열려 있는 동안 다시 올리지 않는다(알림이 반복되지 않는다)
                alerts.raise_alert(
                    conn, instance, kind=kind, severity=ALERT_SEVERITY.get(severity, "low"),
                    dedup_key=dedup, subject=body,
                )
        for dedup in open_keys - {w[1] for w in wanted}:
            alerts.resolve(conn, instance, dedup)
        # 막힘은 서버 행에 건다. 취약점이 사라졌거나 예외가 생겼거나 계약이 바뀐 서버는 푼다.
        conn.execute(
            "UPDATE mint.servers SET vuln_blocked_at = now() WHERE instance_id = %s"
            " AND server_id = ANY(%s) AND vuln_blocked_at IS NULL", (instance, sorted(blocked)))
        conn.execute(
            "UPDATE mint.servers SET vuln_blocked_at = NULL WHERE instance_id = %s"
            " AND vuln_blocked_at IS NOT NULL AND NOT (server_id = ANY(%s))",
            (instance, sorted(blocked)),
        )
    return blocked


def _flag(conn: Any, instance: str, kind: str, failed: Exception | None, subject: dict) -> None:
    """조회 실패 경보를 하나만 열어 두고, 성공하면 닫는다(호출은 막지 않는다)."""
    with conn.transaction():
        if failed is None:
            alerts.resolve(conn, instance, kind)
        elif not fetchall(
            conn,
            "SELECT 1 FROM mint.alerts WHERE instance_id = %s AND dedup_key = %s"
            " AND status <> 'resolved'",
            (instance, kind),
        ):
            alerts.raise_alert(
                conn, instance, kind=kind, severity="medium", dedup_key=kind,
                subject={**subject, "error": type(failed).__name__},
            )


Key = tuple[str, str, str]


def _load_deps(
    conn: Any, instance: str
) -> tuple[dict[Key, datetime], dict[Key, list[depgraph.Dep]]]:
    """저장된 의존 그래프: 패키지 버전별 조회 시각과 의존 패키지(가장 최근 조회분만)."""
    rows = fetchall(
        conn,
        "SELECT ecosystem, name, version, dep_name, dep_version, path, resolved_at"
        " FROM mint.package_deps WHERE instance_id = %s",
        (instance,),
    )
    at = {
        (r["ecosystem"], r["name"], r["version"]): r["resolved_at"]
        for r in rows if (r["dep_name"], r["dep_version"]) == (r["name"], r["version"])
    }
    deps: dict[Key, list[depgraph.Dep]] = {k: [] for k in at}
    for r in rows:
        key = (r["ecosystem"], r["name"], r["version"])
        own = (r["dep_name"], r["dep_version"]) == key[1:]
        if key in at and r["resolved_at"] == at[key] and not own:
            deps[key].append((r["dep_name"], r["dep_version"], r["path"]))
    return at, deps


def _store_deps(
    conn: Any, instance: str, fresh: dict[Key, list[depgraph.Dep]], at: datetime
) -> None:
    for (eco, name, version), deps in fresh.items():
        for dep_name, dep_version, path in [(name, version, name), *deps]:
            conn.execute(
                "INSERT INTO mint.package_deps (instance_id, ecosystem, name, version, dep_name,"
                " dep_version, path, resolved_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (instance_id, ecosystem, name, version, dep_name, dep_version)"
                " DO UPDATE SET path = EXCLUDED.path, resolved_at = EXCLUDED.resolved_at",
                (instance, eco, name, version, dep_name, dep_version, path, at),
            )


def with_deps(tops: list[Key], graph: dict[Key, list[depgraph.Dep]]) -> list[Key]:
    """고정된 패키지와 그 의존 패키지를 한 목록으로(중복 없이, 순서 유지)."""
    keys = list(tops)
    for top in tops:
        keys += [(top[0], name, version) for name, version, _ in graph.get(top, ())]
    return list(dict.fromkeys(keys))


def run(job) -> None:
    s = job.settings
    conn, instance = job.conn, job.instance_id
    tops = _desired_packages(conn, instance)
    if tops:
        known = {
            r["vuln_id"]: {k: r[k] if k != "cvss" else (None if r[k] is None else float(r[k]))
                           for k in ("severity", "cvss", "exploited", "summary")}
            for r in fetchall(
                conn,
                "SELECT DISTINCT ON (vuln_id) vuln_id, severity, cvss, exploited, summary"
                " FROM mint.package_vulns WHERE instance_id = %s"
                " ORDER BY vuln_id, last_seen_at DESC",
                (instance,),
            )
        }
        job.checkpoint()
        with httpx.Client(timeout=s.vuln_feed_timeout_seconds, follow_redirects=False) as http:
            keys = list(tops)
            if s.deps_graph_url:
                at, graph = _load_deps(conn, instance)
                now = datetime.now(UTC)
                fresh, failed = depgraph.resolve(http, s.deps_graph_url, tops, at, now)
                if failed:
                    log.warning("의존 그래프 조회 실패: %s", type(failed).__name__)
                with conn.transaction():
                    _store_deps(conn, instance, fresh, now)
                _flag(conn, instance, KIND_GRAPH_UNREACHABLE, failed, {"feed": s.deps_graph_url})
                keys = with_deps(tops, {**graph, **fresh})
            try:
                results = fetch(http, s.vuln_feed_url, keys, known)
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                log.warning("취약점 조회 실패: %s", type(error).__name__)
                _flag(conn, instance, KIND_UNREACHABLE, error, {"feed": s.vuln_feed_url})
            else:
                with conn.transaction():
                    _store(conn, instance, results)
                _flag(conn, instance, KIND_UNREACHABLE, None, {})
    job.checkpoint()
    # 조회가 실패해도 이미 알고 있는 결과로 기한을 판정한다(조회 실패가 호출을 막거나 풀지 않는다).
    evaluate(conn, instance, datetime.now(UTC))
