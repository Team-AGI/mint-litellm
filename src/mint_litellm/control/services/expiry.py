"""만료 검사 작업이 쓰는 서비스.

작업 실행기의 로그인 역할은 제어 그룹을 함께 받아 데이터베이스가 전이를 더 좁히지 못하므로,
``expired``로만 바꾸는 규칙은 이 계층의 문장이 지킨다.
"""

from datetime import timedelta

import psycopg

from mint_litellm.control import alerts, ledger
from mint_litellm.plugin.policy.sensitive_scan import mask_text
from mint_litellm.types.events import EventKind


def expire_due(conn: psycopg.Connection, instance_id: str) -> dict[str, int]:
    """만료 시각이 지난 호출별 승인과 본인 확인을 ``expired``로 바꾼다. 바꾼 행 수를 돌려준다."""
    with conn.transaction():
        approvals = conn.execute(
            "UPDATE mint.call_approvals SET status = 'expired' WHERE instance_id = %s"
            " AND status IN ('pending', 'approved')"
            " AND coalesce(valid_until, expires_at) <= now()",
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
             "id"),
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


# 만료 전 경보를 내는 기간.
WARN_WITHIN = timedelta(days=7)
# (알림 출처, 표, 상태, 만료 시각 열, 추가 조건). 승인(approvals)은 이미 같은 범위·도구로 더 늦게
# 끝나는 활성 승인이 있으면(갱신됨) 만료 알림 대상이 아니다.
RENEWED = (
    " AND NOT EXISTS (SELECT 1 FROM mint.approvals n WHERE n.instance_id = t.instance_id"
    "  AND n.relation_id = t.relation_id AND n.scope_type = t.scope_type"
    "  AND n.scope_id = t.scope_id AND n.tools = t.tools AND n.status = 'active'"
    "  AND n.valid_until > t.valid_until)"
)
_SOURCES = (
    ("call_approval", "call_approvals", ("pending", "approved"), "expires_at", ""),
    ("self_confirmation", "self_confirmations", ("pending", "confirmed"), "expires_at", ""),
    ("approval", "approvals", ("active",), "valid_until", RENEWED),
)
# 수명이 분 단위인 호출별 승인·본인 확인은 늘 만료 7일 안이라 열자마자 경보가 되므로 경보를 열지
# 않는다(이미 열린 경보를 닫는 데에만 쓴다). 갱신이 필요한 것은 기간이 긴 승인뿐이다.
_WARNED = {"approval"}


def warn_expiring(conn: psycopg.Connection, instance_id: str) -> int:
    """7일 안에 만료될 승인마다 경보 ``approval_expiring``을 하나 연다(기간이 길면 열지 않는다).

    한 번 연 건은 이후 해결돼도 다시 열지 않는다(운영자가 닫은 경보가 매분 되살아나지 않게).
    대기·확정 상태를 벗어난 건의 경보는 해결됨으로 닫는다. 새로 연 경보 수를 돌려준다.
    """
    opened = 0
    with conn.transaction():
        for source, table, statuses, column, extra in _SOURCES:
            if source not in _WARNED:
                continue
            rows = conn.execute(
                f"SELECT t.id, t.{column} FROM mint.{table} t"
                f" WHERE t.instance_id = %s AND t.status = ANY(%s)"
                f" AND t.{column} > now() AND t.{column} <= now() + %s{extra}"
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
        for source, table, statuses, column, extra in _SOURCES:
            closed = conn.execute(
                "UPDATE mint.alerts a SET status = 'resolved', resolved_at = now()"
                " WHERE a.instance_id = %s AND a.kind = 'approval_expiring'"
                " AND a.status <> 'resolved' AND a.subject->>'source' = %s"
                f" AND NOT EXISTS (SELECT 1 FROM mint.{table} t WHERE t.instance_id = a.instance_id"
                f"  AND t.id::text = a.subject->>'id' AND t.status = ANY(%s)"
                f"  AND t.{column} > now(){extra})"
                " RETURNING a.id",
                (instance_id, source, list(statuses)),
            ).fetchall()
            for (alert_id,) in closed:
                alerts.record_resolved(
                    conn, instance_id, str(alert_id), "approval_expiring", alerts.AUTO_ACTOR
                )
    return opened


# 판정 프로세스가 막힌 호출에서 자동으로 연 호출별 승인 요청의 요청자 표시
AUTO_REQUESTER = "mint-auto"


def _preview(display: dict) -> str:
    """알림에 싣는 인자 미리보기. 저장된 표시 값에 남은 비밀도 한 번 더 가리고 길이를 줄인다."""
    text = mask_text(", ".join(f"{k}={v}" for k, v in display.items()))
    return text if len(text) <= 300 else text[:300] + "…"


def announce_requests(conn: psycopg.Connection, instance_id: str) -> int:
    """자동으로 열린 대기 요청마다 요청 사건과 경보 ``call_approval_requested``를 하나 남긴다.

    판정 프로세스는 경보나 원장을 쓸 수 없으므로 작업 실행기가 알린다. 새로 알린 수를 돌려준다.
    """
    announced = 0
    with conn.transaction():
        rows = conn.execute(
            "SELECT t.id, t.org_id, t.principal_type, t.principal_id, t.server_id, t.tool,"
            " t.policy_version_id, t.requested_by, t.state_version, t.target, t.action, t.display"
            " FROM mint.call_approvals t WHERE t.instance_id = %s AND t.requested_by = %s"
            " AND t.status = 'pending' AND t.expires_at > now()"
            " AND NOT EXISTS (SELECT 1 FROM mint.alerts a WHERE a.instance_id = t.instance_id"
            "  AND a.dedup_key = 'call_approval_requested:' || t.id::text)",
            (instance_id, AUTO_REQUESTER),
        ).fetchall()
        for (call_id, org_id, ptype, pid, server_id, tool, policy_id, requested_by, version,
             target, action, display) in rows:
            ledger.record(
                conn, instance_id, EventKind.CALL_APPROVAL_REQUESTED, entity_id=str(call_id),
                state_version=version, actor=alerts.AUTO_ACTOR,
                payload={"call_approval_id": str(call_id), "org_id": org_id,
                         "principal_type": ptype, "principal_id": pid, "server_id": server_id,
                         "tool": tool, "policy_version_id": policy_id,
                         "requested_by": requested_by,
                         **({"target": target, "action": action} if action is not None else {})},
            )
            announced += alerts.raise_alert(
                conn, instance_id, kind="call_approval_requested", severity="medium",
                dedup_key=f"call_approval_requested:{call_id}",
                subject={"id": str(call_id), "server_id": server_id, "tool": tool,
                         "principal_id": pid,
                         **({"action": action} if action else {}),
                         **({"preview": _preview(display)} if display else {})},
            )
    return announced
