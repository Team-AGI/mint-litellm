"""비용·호출·차단 한 화면의 자료. 지출은 LiteLLM 관리 API로만 읽고, 호출·차단은 MINT 기록에서 센다.

LiteLLM 일별 활동(``/team/daily/activity``, ``/user/daily/activity``)은 날짜별 누적 값이라 다시
읽어도 합계가 겹치지 않는다. MINT 쪽 호출은 같은 호출의 재시도를 한 건으로 센다. 기간은 UTC 날짜
단위(끝은 지금)다. 지출을 읽지 못하면 비용 칸은 ``missing``이고, 호출 수는 그대로 보인다.
"""

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import ControlError

USAGE_ROUTES = ("/team/daily/activity", "/user/daily/activity")
PERIODS = {"today": ("오늘", 1), "7d": ("7일", 7), "30d": ("30일", 30), "month": ("이번 달", 0)}
DEFAULT_PERIOD = "7d"
TOP_USERS = 20  # 사람별 지출은 호출이 많은 순으로 이만큼만 읽는다
CACHE_SECONDS = 60
_cache: dict[tuple, tuple[float, Any]] = {}

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


def cost_cell(value: float | None, listed: bool) -> dict:
    """``missing``은 못 읽음, ``none``은 지출에 대상 없음, ``ok``는 읽은 값(0원 포함)."""
    if value is None:
        return {"state": "missing", "text": "미수집", "value": 0.0}
    if not listed:
        return {"state": "none", "text": "해당 없음", "value": 0.0}
    return {"state": "ok", "text": f"${value:,.2f}", "value": value}


# --- LiteLLM 지출 -----------------------------------------------------------------------------


def _daily(admin, path: str, start: datetime, end: datetime, **extra) -> list[dict]:
    key = (id(admin), path, start.date(), end.date(), tuple(sorted(extra.items())))
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    results: list[dict] = []
    page = 1
    while True:
        body = admin._ok(
            path,
            {"start_date": start.date().isoformat(), "end_date": end.date().isoformat(),
             "page": page, "page_size": 1000, **extra},
            key="results", shape=list,
        )
        results.extend(r for r in body["results"] if isinstance(r, dict))
        if page >= int((body.get("metadata") or {}).get("total_pages", 1)):
            break
        page += 1
    _cache[key] = (time.monotonic(), results)
    return results


def _sum(days: list[dict], section: str) -> dict[str, tuple[float, int]]:
    """날짜별 분해 값을 이름별로 더한다: 이름 → (지출, 요청 수)."""
    out: dict[str, tuple[float, int]] = {}
    for day in days:
        for name, item in ((day.get("breakdown") or {}).get(section) or {}).items():
            metrics = (item or {}).get("metrics") or {}
            spend, calls = out.get(name, (0.0, 0))
            out[name] = (spend + float(metrics.get("spend") or 0),
                         calls + int(metrics.get("api_requests") or 0))
    return out


def _total(days: list[dict]) -> tuple[float, int]:
    return (sum(float((d.get("metrics") or {}).get("spend") or 0) for d in days),
            sum(int((d.get("metrics") or {}).get("api_requests") or 0) for d in days))


def read_spend(admin, start: datetime, end: datetime, users: list[str], user: str | None):
    """(팀별, 서버별, 사람별) 지출. 못 읽은 부분은 None이다. 직원이면 본인 호출만 읽는다."""
    teams = servers = people = None
    errors = (ControlError, ValueError, TypeError, AttributeError)
    try:
        if user is None:
            days = _daily(admin, "/team/daily/activity", start, end)
            teams, servers = _sum(days, "entities"), _sum(days, "mcp_servers")
        else:
            days = _daily(admin, "/user/daily/activity", start, end, user_id=user)
            servers, people = _sum(days, "mcp_servers"), {user: _total(days)}
    except errors:
        pass
    if user is None:
        try:
            people = {u: _total(_daily(admin, "/user/daily/activity", start, end, user_id=u))
                      for u in users[:TOP_USERS]}
        except errors:
            people = None
    return teams, servers, people


# --- MINT 기록 --------------------------------------------------------------------------------


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


def combine(ledger: list[dict], first: list[dict], spend, names: dict, *, scoped: bool) -> dict:
    """호출·차단 집계와 지출을 하나로 합친다. ``spend``는 (팀별, 서버별, 사람별) 읽은 결과."""
    teams_s, servers_s, people_s = spend

    def fold(key: str) -> dict[str, list[int]]:
        out: dict[str, list[int]] = {}
        for r in ledger:
            if r[key]:
                row = out.setdefault(r[key], [0, 0])
                row[0] += r["calls"]
                row[1] += r["blocked"]
        return out

    def rows(folded, source, label=lambda n: n, firsts=None):
        result = []
        for name, (calls, blocked) in sorted(folded.items(), key=lambda i: -i[1][0]):
            spent = None if source is None else source.get(name, (0.0, 0))[0]
            result.append({"name": label(name), "calls": calls, "blocked": blocked,
                           "cost": cost_cell(spent, source is not None and name in source),
                           "first": (firsts or {}).get(name)})
        return result

    first_server: dict[str, datetime] = {}
    first_user: dict[str, datetime] = {}
    for f in first:
        for table, key in ((first_server, f["server_id"]), (first_user, f["user_id"])):
            if key and (key not in table or f["first_at"] < table[key]):
                table[key] = f["first_at"]
    # LiteLLM은 서버를 이름으로 묶으므로 식별자로도 찾을 수 있게 한다.
    server_source = None if servers_s is None else {
        **servers_s, **{k: servers_s[v] for k, v in names.items() if v in servers_s}}
    servers = rows(fold("server_id"), server_source, lambda n: names.get(n) or n, first_server)
    # 전체 합계는 팀별 지출에서만 낸다(사람별은 상위 몇 명뿐). 못 읽었으면 어디서나 미수집이다.
    known = people_s if scoped else teams_s
    return {
        "calls": sum(r["calls"] for r in ledger),
        "blocked": sum(r["blocked"] for r in ledger),
        "cost": cost_cell(None if known is None else sum(v[0] for v in known.values()), True),
        "teams": [] if scoped else rows(fold("team_id"), teams_s),
        "users": rows(fold("user_id"), people_s, firsts=first_user),
        "servers": servers,
        "bars": {"labels": [r["name"] for r in servers[:8]],
                 "values": [r["calls"] for r in servers[:8]]},
    }


def build(conn, instance, admin, names: dict, period: str, user: str | None = None) -> dict:
    """사용량 화면의 자료. ``user``가 있으면 그 사람의 것만 읽고 센다."""
    start, end = window(period)
    ledger = read_ledger(conn, instance, start, end, user)
    per_user: dict[str, int] = {}
    for r in ledger:
        if r["user_id"]:
            per_user[r["user_id"]] = per_user.get(r["user_id"], 0) + r["calls"]
    users = sorted(per_user, key=lambda u: -per_user[u])
    spend = read_spend(admin, start, end, users, user) if admin else (None, None, None)
    first = read_first_success(conn, instance, user)
    report = combine(ledger, first, spend, names, scoped=user is not None)
    emails = {r["user_id"]: r["email"] for r in fetchall(
        conn, "SELECT user_id, email FROM mint.directory_users"
        " WHERE instance_id = %s AND user_id = ANY(%s) AND email IS NOT NULL",
        (instance, [r["name"] for r in report["users"]]))}
    for r in report["users"]:  # 사용자 번호 대신 이메일(없으면 번호)
        r["name"] = emails.get(r["name"], r["name"])
    return {"period": period, **report}


def read_tools(conn: psycopg.Connection, instance: str, server_id: str) -> list[dict]:
    """서버에서 실제로 발견·호출된 도구별 호출·차단 수(도구 목록 판정 포함)."""
    return fetchall(
        conn,
        "SELECT payload->>'tool' AS tool,"
        f" count(DISTINCT {_CALL}) FILTER (WHERE kind = 'decision_evaluated') AS calls,"
        f" count(DISTINCT {_CALL}) FILTER (WHERE {_BLOCKED}) AS blocked"
        " FROM mint.events WHERE instance_id = %s"
        " AND kind IN ('decision_evaluated', 'discovery_evaluated')"
        " AND COALESCE(payload->>'resolved_server_id', payload->>'server_id') = %s"
        " AND payload->>'tool' IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1",
        (instance, server_id),
    )
