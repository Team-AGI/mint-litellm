"""만료 검사 작업이 쓰는 서비스.

작업 실행기의 로그인 역할은 제어 그룹을 함께 받아 데이터베이스가 전이를 더 좁히지 못하므로,
``expired``로만 바꾸는 규칙은 이 계층의 문장이 지킨다.
"""

from datetime import timedelta

import psycopg

from mint_litellm.control import alerts


def expire_due(conn: psycopg.Connection, instance_id: str) -> dict[str, int]:
    """만료 시각이 지난 호출별 승인과 본인 확인을 ``expired``로 바꾼다. 바꾼 행 수를 돌려준다."""
    with conn.transaction():
        approvals = conn.execute(
            "UPDATE mint.call_approvals SET status = 'expired' WHERE instance_id = %s"
            " AND status IN ('pending', 'approved') AND expires_at <= now()",
            (instance_id,),
        ).rowcount
        confirmations = conn.execute(
            "UPDATE mint.self_confirmations SET status = 'expired' WHERE instance_id = %s"
            " AND status IN ('pending', 'confirmed') AND expires_at <= now()",
            (instance_id,),
        ).rowcount
    return {"call_approvals": approvals, "self_confirmations": confirmations}


def close_settled_requests(conn: psycopg.Connection, instance_id: str) -> int:
    """결정되거나 만료·취소된 승인 요청의 열린 경보(호출별 승인 요청, 신청 승인 대기)를 닫는다."""
    closed = 0
    with conn.transaction():
        for kind, table, pending, key in (
            ("call_approval_requested", "call_approvals", "t.status = 'pending'",
             "call_approval_id"),
            ("intake_pending", "intakes", "t.status <> 'decided'", "intake_id"),
        ):
            for (dedup_key,) in conn.execute(
                "SELECT a.dedup_key FROM mint.alerts a WHERE a.instance_id = %s"
                " AND a.kind = %s AND a.status <> 'resolved' AND NOT EXISTS ("
                f"SELECT 1 FROM mint.{table} t WHERE t.instance_id = a.instance_id"
                f" AND t.id::text = a.subject->>'{key}' AND {pending})",
                (instance_id, kind),
            ).fetchall():
                closed += alerts.resolve(conn, instance_id, dedup_key)
    return closed


# 만료 전 경보를 내는 기간. 호출별 승인과 본인 확인(대기·확정 상태)에만 건다.
WARN_WITHIN = timedelta(days=7)
_SOURCES = (
    ("call_approval", "call_approvals", ("pending", "approved")),
    ("self_confirmation", "self_confirmations", ("pending", "confirmed")),
)


def warn_expiring(conn: psycopg.Connection, instance_id: str) -> int:
    """7일 안에 만료될 대기·확정 건마다 경보 ``approval_expiring``을 하나 연다.

    한 번 연 건은 이후 해결돼도 다시 열지 않는다(운영자가 닫은 경보가 매분 되살아나지 않게).
    대기·확정 상태를 벗어난 건의 경보는 해결됨으로 닫는다. 새로 연 경보 수를 돌려준다.
    """
    opened = 0
    with conn.transaction():
        for source, table, statuses in _SOURCES:
            rows = conn.execute(
                f"SELECT t.id, t.expires_at FROM mint.{table} t"
                " WHERE t.instance_id = %s AND t.status = ANY(%s)"
                " AND t.expires_at > now() AND t.expires_at <= now() + %s"
                " AND NOT EXISTS (SELECT 1 FROM mint.alerts a WHERE a.instance_id = t.instance_id"
                "  AND a.dedup_key = 'approval_expiring:' || %s || ':' || t.id::text)",
                (instance_id, list(statuses), WARN_WITHIN, source),
            ).fetchall()
            for row_id, expires_at in rows:
                opened += alerts.raise_alert(
                    conn,
                    instance_id,
                    kind="approval_expiring",
                    severity="medium",
                    dedup_key=f"approval_expiring:{source}:{row_id}",
                    subject={
                        "source": source,
                        "id": str(row_id),
                        "expires_at": expires_at.isoformat(),
                    },
                )
        for source, table, statuses in _SOURCES:
            closed = conn.execute(
                "UPDATE mint.alerts a SET status = 'resolved', resolved_at = now()"
                " WHERE a.instance_id = %s AND a.kind = 'approval_expiring'"
                " AND a.status <> 'resolved' AND a.subject->>'source' = %s"
                f" AND NOT EXISTS (SELECT 1 FROM mint.{table} t WHERE t.instance_id = a.instance_id"
                "  AND t.id::text = a.subject->>'id' AND t.status = ANY(%s))"
                " RETURNING a.id",
                (instance_id, source, list(statuses)),
            ).fetchall()
            for (alert_id,) in closed:
                alerts.record_resolved(
                    conn, instance_id, str(alert_id), "approval_expiring", alerts.AUTO_ACTOR
                )
    return opened
