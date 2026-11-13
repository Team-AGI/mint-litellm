"""조직 연결 제안: LiteLLM 팀·사용자를 읽어 묶이지 않은 주체의 조직을 규칙으로 추정한다.

규칙은 팀 메타데이터의 조직 값(``team_metadata``), 팀 별칭의 조직 접두사(``team_alias``),
사용자 이메일 도메인의 대응표(``email_domain``) 세 가지이며 이 순서로 처음 맞는 것을 쓴다.
제안은 저장만 하고 묶지 않는다. 최근 7일 안에 호출한 주체가 앞에 온다.
"""

from mint_litellm.control.db.connection import fetchall
from mint_litellm.types.ids import new_uuid7

RULES = ("team_metadata", "team_alias", "email_domain")
CALL_DAYS = 7


def _alias_org(alias: str, orgs: dict[str, str]) -> tuple[str, str] | None:
    """별칭이 조직 식별자나 이름으로 시작하고 그 뒤가 문자·숫자가 아니면 가장 긴 접두사의 조직."""
    low = alias.lower()
    hits: dict[str, str] = {}
    for org_id, name in orgs.items():
        for token in (org_id, name):
            t = token.lower()
            if t and low.startswith(t) and (len(low) == len(t) or not low[len(t)].isalnum()):
                hits[org_id] = token
    if not hits:
        return None
    best = max(len(t) for t in hits.values())
    top = {o: t for o, t in hits.items() if len(t) == best}
    return next(iter(top.items())) if len(top) == 1 else None


def propose(
    teams: list[dict],
    users: list[dict],
    orgs: dict[str, str],
    bound: set[tuple[str, str]],
    domains: dict[str, str],
    meta_key: str,
    calls: dict[tuple[str, str], int],
) -> list[dict]:
    """``orgs``는 활성 조직(식별자 -> 이름), ``bound``는 이미 묶인 (구분, 식별자)이다."""
    out = []

    def add(kind: str, subject: str, org_id: str, rule: str, matched: str) -> None:
        out.append({
            "subject_type": kind, "subject_id": subject, "org_id": org_id, "rule": rule,
            "matched": matched[:512], "calls": calls.get((kind, subject), 0),
        })

    for team in teams:
        tid = team.get("team_id")
        if not isinstance(tid, str) or not tid or ("team", tid) in bound:
            continue
        meta = team.get("metadata")
        value = meta.get(meta_key) if isinstance(meta, dict) else None
        alias = team.get("team_alias")
        if isinstance(value, str) and value in orgs:
            add("team", tid, value, "team_metadata", value)
        elif isinstance(alias, str) and (hit := _alias_org(alias, orgs)):
            add("team", tid, hit[0], "team_alias", hit[1])
    for user in users:
        uid, email = user.get("user_id"), user.get("user_email")
        if not isinstance(uid, str) or not uid or ("user", uid) in bound:
            continue
        domain = email.rpartition("@")[2].strip().lower() if isinstance(email, str) else ""
        if domain in domains and domains[domain] in orgs:
            add("user", uid, domains[domain], "email_domain", domain)
    out.sort(key=lambda p: (-p["calls"], p["subject_type"], p["subject_id"]))
    return out


def _recent_calls(conn, instance_id: str) -> dict[tuple[str, str], int]:
    """최근 판정 사건의 호출 수. 팀이 있는 호출은 팀, 없으면 사용자에게 센다(조직 유도와 같다)."""
    calls: dict[tuple[str, str], int] = {}
    for r in fetchall(
        conn,
        "SELECT payload->>'team_id' AS team_id, payload->>'user_id' AS user_id, count(*) AS n"
        " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(days => %s) GROUP BY 1, 2",
        (instance_id, CALL_DAYS),
    ):
        key = ("team", r["team_id"]) if r["team_id"] else ("user", r["user_id"])
        if key[1]:
            calls[key] = calls.get(key, 0) + r["n"]
    return calls


def run(job) -> None:
    if job.litellm is None:
        return
    conn, iid = job.conn, job.instance_id
    teams = job.litellm.list_teams()
    users = job.litellm.list_users()
    orgs = {
        r["org_id"]: r["name"]
        for r in fetchall(
            conn, "SELECT org_id, name FROM mint.orgs WHERE instance_id = %s AND status = 'active'",
            (iid,),
        )
    }
    bound = {
        (r["subject_type"], r["subject_id"])
        for r in fetchall(
            conn, "SELECT subject_type, subject_id FROM mint.org_bindings WHERE instance_id = %s",
            (iid,),
        )
    }
    domains = {
        r["domain"]: r["org_id"]
        for r in fetchall(
            conn, "SELECT domain, org_id FROM mint.org_suggest_domains WHERE instance_id = %s",
            (iid,),
        )
    }
    wanted = propose(
        teams, users, orgs, bound, domains, job.settings.org_meta_key, _recent_calls(conn, iid)
    )
    keep = {(p["subject_type"], p["subject_id"]) for p in wanted}
    with conn.transaction():
        for r in fetchall(
            conn,
            "SELECT id, subject_type, subject_id FROM mint.org_suggestions"
            " WHERE instance_id = %s AND status = 'open'",
            (iid,),
        ):
            if (r["subject_type"], r["subject_id"]) not in keep:
                conn.execute("DELETE FROM mint.org_suggestions WHERE id = %s", (r["id"],))
        for p in wanted:
            conn.execute(
                "INSERT INTO mint.org_suggestions (id, instance_id, subject_type, subject_id,"
                " org_id, rule, matched, calls) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (instance_id, subject_type, subject_id) DO UPDATE SET"
                " org_id = EXCLUDED.org_id, rule = EXCLUDED.rule, matched = EXCLUDED.matched,"
                " calls = EXCLUDED.calls, status = 'open', decided_by = NULL, decided_at = NULL"
                " WHERE mint.org_suggestions.status IN ('open', 'applied')",
                (new_uuid7(), iid, p["subject_type"], p["subject_id"], p["org_id"], p["rule"],
                 p["matched"], p["calls"]),
            )
