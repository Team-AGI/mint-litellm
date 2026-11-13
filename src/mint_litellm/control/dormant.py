"""미사용 승인: 활성 승인 가운데 최근 ``days``일 동안 판정에 한 번도 선택되지 않은 것.

기준 시각은 마지막 재확인(없으면 승인의 유효 시작)이므로 갓 승인한 건은 ``days``일이 지나기 전에는
들지 않고, 관리자가 「유지」(재확인)하면 그 시각부터 다시 센다. 사용 여부는 판정 사건
(``decision_evaluated``)의 ``selected_approval_id``로 본다. 점검 작업은 서버마다 요약 경보
``approval_dormant`` 하나를 열고, 해당 승인이 없어지면 닫는다.
"""

import psycopg

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall

KIND = "approval_dormant"
LIMIT = 200


def find(conn: psycopg.Connection, instance_id: str, days: int) -> list[dict]:
    return fetchall(
        conn,
        "WITH used AS (SELECT DISTINCT payload->>'selected_approval_id' AS id FROM mint.events"
        " WHERE instance_id = %(i)s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(days => %(d)s)"
        " AND payload->>'selected_approval_id' IS NOT NULL)"
        " SELECT a.id, a.server_id, a.tools, a.scope_type, a.scope_id, a.class, a.valid_from,"
        " a.valid_until, a.granted_by, a.status, a.state_version, a.recert_confirmed_at,"
        " a.recert_held_at FROM mint.approvals a WHERE a.instance_id = %(i)s"
        " AND a.status = 'active' AND a.valid_until > now()"
        " AND COALESCE(a.recert_confirmed_at, a.valid_from) <= now() - make_interval(days => %(d)s)"
        " AND NOT EXISTS (SELECT 1 FROM used u WHERE u.id = a.id::text)"
        " ORDER BY a.server_id, a.valid_from, a.id LIMIT %(n)s",
        {"i": instance_id, "d": days, "n": LIMIT},
    )


def by_server(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["server_id"]] = counts.get(row["server_id"], 0) + 1
    return counts


def key_for(server_id: str) -> str:
    return f"{KIND}:{server_id}"[:512]


def run(job) -> None:
    days = job.settings.dormant_days
    counts = by_server(find(job.conn, job.instance_id, days))
    wanted = {key_for(server): server for server in counts}
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
        for key, server in wanted.items():
            if key not in open_keys:  # 열려 있는 동안 다시 열지 않는다(알림이 반복되지 않는다)
                alerts.raise_alert(
                    job.conn, job.instance_id, kind=KIND, severity="low", dedup_key=key,
                    subject={"server_id": server, "approvals": counts[server], "days": days},
                )
        for key in open_keys - wanted.keys():
            alerts.resolve(job.conn, job.instance_id, key)
