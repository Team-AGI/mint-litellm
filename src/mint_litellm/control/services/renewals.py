"""만료가 가까운 승인의 갱신 후보: 계약과 등급이 승인 뒤로 그대로인 것과 바뀐 것을 가른다.

승인의 유효 기간은 고치지 못하므로 갱신은 같은 범위·도구의 새 승인을 만드는 일이다
(``console/api.py``의 일괄 갱신). 이 모듈은 대상만 가른다.
"""

from datetime import timedelta
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.services.expiry import RENEWED, WARN_WITHIN

# 승인을 준 뒤 이 사건이 있으면 그 서버의 계약이나 등급이 바뀐 것이다.
_CHANGE_EVENTS = (
    "contract_approved", "deployment_contract_approved", "contract_superseded",
    "contract_drift_detected", "deployment_drift_detected",
)


def _reason(conn: psycopg.Connection, instance_id: str, row: dict[str, Any]) -> str | None:
    """바뀌었으면 사유, 그대로면 None."""
    server = fetchone(
        conn,
        "SELECT s.status, s.deployment_drift FROM mint.servers s"
        " WHERE s.instance_id = %s AND s.server_id = %s",
        (instance_id, row["server_id"]),
    )
    if server is None or server["status"] != "approved":
        return "서버가 승인 상태가 아님"
    if row["recert_held_at"] is not None:
        return "재확인 보류"
    if server["deployment_drift"]:
        return "배포 계약 변경"
    drifted = fetchone(
        conn,
        "SELECT 1 AS x FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status = 'approved' AND drift <> 'none' AND tool = ANY(%s)",
        (instance_id, row["server_id"], row["tools"]),
    )
    if drifted:
        return "도구 계약 변경"
    pending = fetchone(
        conn,
        "SELECT 1 AS x WHERE EXISTS (SELECT 1 FROM mint.tool_contracts WHERE instance_id = %s"
        " AND server_id = %s AND status = 'candidate' AND tool = ANY(%s))"
        " OR EXISTS (SELECT 1 FROM mint.deployment_contracts WHERE instance_id = %s"
        " AND server_id = %s AND status = 'candidate')",
        (instance_id, row["server_id"], row["tools"], instance_id, row["server_id"]),
    )
    if pending:
        return "재승인 대기 중인 변경"
    since = fetchone(
        conn,
        "SELECT 1 AS x FROM mint.events e WHERE e.instance_id = %s AND e.kind = ANY(%s)"
        " AND e.payload->>'server_id' = %s AND e.inserted_at > (SELECT g.inserted_at"
        " FROM mint.events g WHERE g.instance_id = %s AND g.kind = 'approval_granted'"
        " AND g.payload->>'approval_id' = %s LIMIT 1)",
        (instance_id, list(_CHANGE_EVENTS), row["server_id"], instance_id, str(row["id"])),
    )
    return "승인 뒤 계약·등급 변경" if since else None


def candidates(
    conn: psycopg.Connection, instance_id: str, within: timedelta = WARN_WITHIN
) -> dict[str, list[dict]]:
    """만료가 ``within`` 안인 활성 승인(이미 갱신된 것 제외)을 그대로인 것과 바뀐 것으로 가른다."""
    rows = fetchall(
        conn,
        "SELECT t.* FROM mint.approvals t WHERE t.instance_id = %s AND t.status = 'active'"
        f" AND t.valid_until > now() AND t.valid_until <= now() + %s{RENEWED}"
        " ORDER BY t.valid_until, t.id",
        (instance_id, within),
    )
    result: dict[str, list[dict]] = {"unchanged": [], "changed": []}
    for row in rows:
        reason = _reason(conn, instance_id, row)
        if reason is None:
            result["unchanged"].append(row)
        else:
            result["changed"].append({**row, "reason": reason})
    return result
