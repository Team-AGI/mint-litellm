"""호출·차단·첫 성공 한 화면의 자료와 MINT 판정 지연. 모두 MINT 기록에서 읽는다.

MINT의 판정은 모델을 부르지 않으므로 비용은 MINT가 만들지 않는다. 비용은 LiteLLM의 일별
사용자 지출 기록에서 읽어 사람별로 붙이고(``attach_spend``), 읽지 못하면 미집계로 둔다. 판정
사건에 남은 판정 시간(``decision_us``)의 중앙값·95번째 값도 보인다. 같은 호출의 재시도는 한
건으로 센다. 기간은 UTC 날짜 단위(끝은 지금)다.
"""

from datetime import UTC, datetime, timedelta

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone

PERIODS = {"today": ("오늘", 1), "7d": ("7일", 7), "30d": ("30일", 30), "month": ("이번 달", 0)}
DEFAULT_PERIOD = "7d"

# 차단은 대시보드와 같은 갈래(허용·관측·승인 필요가 아닌 모두)로 센다.
_BLOCKED = (
    "COALESCE(payload->>'outcome', CASE WHEN payload->>'enforced_action' = 'allow'"
    " THEN 'allowed' ELSE 'blocked' END) NOT IN ('allowed', 'observed', 'pending_approval')"
)
_CALL = "COALESCE(invocation_id::text, event_id::text)"
# 판정 본문은 주체를 principal 안에 남긴다(사람 키는 principal_id가 LiteLLM 사용자 식별자).
_USER = (
    "COALESCE(payload->>'user_id', CASE WHEN payload#>>'{principal,principal_type}' = 'user'"
    " THEN payload#>>'{principal,principal_id}' END, '')"
)
_TEAM = "COALESCE(payload->>'team_id', payload#>>'{principal,team_id}', '')"


def window(period: str, now: datetime | None = None) -> tuple[datetime, datetime]:
    now = now or datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    days = PERIODS[period][1]
    start = today.replace(day=1) if period == "month" else today - timedelta(days=days - 1)
    return start, now


def read_ledger(conn: psycopg.Connection, instance: str, start: datetime, end: datetime,
                user: str | None) -> list[dict]:
    """(팀, 사람, 서버)별 호출·차단 수. 같은 호출의 재시도는 한 건이다."""
    who, args = "", [instance, start, end]
    if user:
        who, args = f" AND {_USER} = %s", [*args, user]
    return fetchall(
        conn,
        f"SELECT {_TEAM} AS team_id, {_USER} AS user_id,"
        " COALESCE(payload->>'resolved_server_id', payload->>'server_id', '') AS server_id,"
        f" count(DISTINCT {_CALL}) AS calls,"
        f" count(DISTINCT {_CALL}) FILTER (WHERE {_BLOCKED}) AS blocked"
        " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
        f" AND inserted_at >= %s AND inserted_at < %s{who} GROUP BY 1, 2, 3",
        tuple(args),
    )


def read_first_success(conn: psycopg.Connection, instance: str, user: str | None) -> list[dict]:
    """(사람, 서버)별 처음 성공한 시각. ponytail: 전체 기간을 훑는다. 느려지면 롤업 표로 옮긴다."""
    who, args = "", [instance]
    if user:
        who, args = f" AND {_USER.replace('payload', 'd.payload')} = %s", [instance, user]
    return fetchall(
        conn,
        f"SELECT {_USER.replace('payload', 'd.payload')} AS user_id,"
        " COALESCE(d.payload->>'resolved_server_id', d.payload->>'server_id', '') AS server_id,"
        " min(r.inserted_at) AS first_at FROM mint.events r JOIN mint.events d"
        " ON d.instance_id = r.instance_id AND d.invocation_id = r.invocation_id"
        " AND d.attempt_id = r.attempt_id AND d.kind = 'decision_evaluated'"
        " WHERE r.instance_id = %s AND r.kind = 'call_response_received'"
        " AND COALESCE(r.payload->>'outcome', 'success') = 'success'"
        f" AND COALESCE(r.payload->>'is_error', 'false') <> 'true'{who} GROUP BY 1, 2",
        tuple(args),
    )


# --- 합치기 -----------------------------------------------------------------------------------


def decision_latency(
    conn: psycopg.Connection, instance: str, start: datetime, end: datetime,
    user: str | None = None,
) -> dict:
    """기간 안 판정 사건의 판정 시간(ms): ``{"p50", "p95", "count"}``. 기록이 없으면 값은 None."""
    who, args = "", [instance, start, end]
    if user:
        who, args = f" AND {_USER} = %s", [*args, user]
    row = fetchone(
        conn,
        "SELECT count(*) AS n,"
        " percentile_cont(0.5) WITHIN GROUP (ORDER BY us) AS p50,"
        " percentile_cont(0.95) WITHIN GROUP (ORDER BY us) AS p95 FROM ("
        " SELECT (payload->>'decision_us')::bigint AS us FROM mint.events"
        " WHERE instance_id = %s AND kind = 'decision_evaluated'"
        f" AND payload->>'decision_us' IS NOT NULL AND inserted_at >= %s AND inserted_at < %s{who}"
        ") t",
        tuple(args),
    )
    n = int(row["n"])
    return {"p50": round(row["p50"] / 1000, 1) if n else None,
            "p95": round(row["p95"] / 1000, 1) if n else None, "count": n}


def combine(ledger: list[dict], first: list[dict], names: dict, *, scoped: bool) -> dict:
    """호출·차단 집계를 하나로 합친다."""

    def fold(key: str) -> dict[str, list[int]]:
        out: dict[str, list[int]] = {}
        for r in ledger:
            if r[key]:
                row = out.setdefault(r[key], [0, 0])
                row[0] += r["calls"]
                row[1] += r["blocked"]
        return out

    def rows(folded, label=lambda n: n, firsts=None):
        return [{"name": label(name), "calls": calls, "blocked": blocked,
                 "first": (firsts or {}).get(name)}
                for name, (calls, blocked) in sorted(folded.items(), key=lambda i: -i[1][0])]

    first_server: dict[str, datetime] = {}
    first_user: dict[str, datetime] = {}
    for f in first:
        for table, key in ((first_server, f["server_id"]), (first_user, f["user_id"])):
            if key and (key not in table or f["first_at"] < table[key]):
                table[key] = f["first_at"]
    servers = rows(fold("server_id"), lambda n: names.get(n) or n, first_server)
    return {
        "calls": sum(r["calls"] for r in ledger),
        "blocked": sum(r["blocked"] for r in ledger),
        "teams": [] if scoped else rows(fold("team_id")),
        "users": rows(fold("user_id"), firsts=first_user),
        "servers": servers,
        "bars": {"labels": [r["name"] for r in servers[:8]],
                 "values": [r["calls"] for r in servers[:8]]},
    }


def attach_spend(report: dict, admin, start: datetime, end: datetime, user: str | None) -> None:
    """LiteLLM 지출 기록의 비용을 붙인다. 읽지 못하면 ``report["spend"]``는 None(미집계).

    사람 줄의 ``spend``는 기록이 있으면 숫자(0 포함), 지출 기록에 없으면 None이다.
    """
    got = None
    if admin is not None:
        try:
            got = admin.user_spend(start.date().isoformat(), end.date().isoformat(), user)
        except Exception:  # 화면은 비용 없이도 열려야 한다(오류·시간 초과·경로 막힘 모두)
            got = None
    report["spend"] = None if got is None else got["total"]
    for r in report["users"]:
        r["spend"] = None if got is None else got["by_user"].get(r["id"])


def build(conn, instance, names: dict, period: str, user: str | None = None, admin=None) -> dict:
    """사용량 화면의 자료. ``user``가 있으면 그 사람의 것만 읽고 센다."""
    start, end = window(period)
    ledger = read_ledger(conn, instance, start, end, user)
    first = read_first_success(conn, instance, user)
    report = combine(ledger, first, names, scoped=user is not None)
    for r in report["users"]:
        r["id"] = r["name"]
    attach_spend(report, admin, start, end, user)
    report["latency"] = decision_latency(conn, instance, start, end, user)
    emails = {r["user_id"]: r["email"] for r in fetchall(
        conn, "SELECT user_id, email FROM mint.directory_users"
        " WHERE instance_id = %s AND user_id = ANY(%s) AND email IS NOT NULL",
        (instance, [r["name"] for r in report["users"]]))}
    for r in report["users"]:  # 사용자 번호 대신 이메일(없으면 번호)
        r["name"] = emails.get(r["name"], r["name"])
    return {"period": period, **report}


def has_response(conn: psycopg.Connection, instance: str, server_id: str) -> bool:
    """이 서버에서 성공 응답이 돌아온 호출이 있는지(허용만 되고 응답이 없던 호출은 세지 않는다)."""
    return fetchone(
        conn,
        "SELECT 1 FROM mint.events r JOIN mint.events d ON d.instance_id = r.instance_id"
        " AND d.invocation_id = r.invocation_id AND d.attempt_id = r.attempt_id"
        " AND d.kind = 'decision_evaluated'"
        " WHERE r.instance_id = %s AND r.kind = 'call_response_received'"
        " AND COALESCE(r.payload->>'outcome', 'success') = 'success'"
        " AND COALESCE(r.payload->>'is_error', 'false') <> 'true'"
        " AND COALESCE(d.payload->>'resolved_server_id', d.payload->>'server_id') = %s LIMIT 1",
        (instance, server_id),
    ) is not None


def read_tools(conn: psycopg.Connection, instance: str, server_id: str) -> list[dict]:
    """서버에서 실제로 발견·호출된 도구별 호출·차단 수(도구 목록 판정 포함)."""
    return fetchall(
        conn,
        "SELECT payload->>'tool' AS tool,"
        f" count(DISTINCT {_CALL}) FILTER (WHERE kind = 'decision_evaluated') AS calls,"
        f" count(DISTINCT {_CALL}) FILTER (WHERE {_BLOCKED}) AS blocked,"
        f" max(COALESCE(payload->'stop'->>'reason_code',"
        f" payload->'findings'->0->>'reason_code')) FILTER (WHERE {_BLOCKED}) AS reason"
        " FROM mint.events WHERE instance_id = %s"
        " AND kind IN ('decision_evaluated', 'discovery_evaluated')"
        " AND COALESCE(payload->>'resolved_server_id', payload->>'server_id') = %s"
        " AND payload->>'tool' IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1",
        (instance, server_id),
    )
