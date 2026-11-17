"""검사용 승인: 단말이 도구 목록을 대신 받아 올리게 하는 별도 권한의 발급·철회·조회.

승인이 아니다. 신청에 기록된 설치 키 하나, 지금의 묶음·계약 하나, 1회로 묶이고 서버 상태·승인·
호출 허가에는 들어가지 않는다. 단말이 올린 결과의 처리는 작업(``endpoint_inspections``)이 한다.
"""

import os
from datetime import UTC, datetime
from typing import Any

from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, conflict, not_found
from mint_litellm.control.services import intakes
from mint_litellm.control.services.base import require_role, transact

MINUTES_ENV = "MINT_INSPECTION_APPROVAL_MINUTES"
DEFAULT_MINUTES = 60
MAX_MINUTES = 24 * 60
OPEN = ("issued", "consumed")

# 계약 해시는 DB 함수와 같은 식이다(권한이 지금 후보와 같은지 함수가 다시 계산한다).
CONTRACT_HASH_SQL = "encode(sha256(convert_to(d.exec_contract::text, 'UTF8')), 'hex')"


def minutes() -> int:
    """발급 후 유효 시간(분). 환경 변수가 없거나 잘못되면 기본값."""
    text = os.environ.get(MINUTES_ENV, "")
    return min(int(text), MAX_MINUTES) if text.isdigit() and int(text) > 0 else DEFAULT_MINUTES


def effective_status(row: dict, now: datetime | None = None) -> str:
    """열린 권한이 기간을 넘겼으면 만료로 본다(표시용)."""
    if row["status"] in OPEN and row["expires_at"] <= (now or datetime.now(UTC)):
        return "expired"
    return str(row["status"])


def issue(ctx: Context, intake_id: str) -> str:
    """판별 불가인 단말 신청에 검사 권한을 발급한다. 권한 식별자를 돌려준다."""
    require_role(ctx, "intake inspect")
    with transact(ctx):
        row = intakes.get(ctx, intake_id, lock=True)
        if row["source"] != "endpoint":
            raise ControlError("단말에서 올린 신청만 검사용 승인을 줄 수 있습니다.")
        if row["status"] != "indeterminate":
            raise conflict(f"{row['status']} 상태의 신청에는 검사용 승인을 줄 수 없습니다.")
        deployment = intakes.deployment_candidate(ctx.conn, ctx.instance_id, row["server_id"])
        if (deployment is None or not deployment["pack_sha256"]
                or not isinstance(deployment["exec_contract"], dict)):
            raise ControlError("실행 묶음이 준비되지 않았습니다. 재검사한 뒤 시도하십시오.")
        key = fetchone(
            ctx.conn,
            "SELECT 1 AS ok FROM mint.endpoint_installs WHERE instance_id = %s AND key_token = %s"
            " AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
            (ctx.instance_id, row["endpoint_key_token"]),
        )
        if key is None:
            raise ControlError("신청자의 설치 키가 만료됐거나 해제됐습니다.")
        ctx.conn.execute(
            "UPDATE mint.endpoint_inspections SET status = 'expired' WHERE instance_id = %s"
            " AND intake_id = %s AND status IN ('issued', 'consumed') AND expires_at <= now()",
            (ctx.instance_id, row["id"]),
        )
        if fetchone(ctx.conn, "SELECT 1 AS x FROM mint.endpoint_inspections WHERE intake_id = %s"
                    " AND status IN ('issued', 'consumed')", (row["id"],)):
            raise conflict("이 신청에는 이미 열려 있는 검사용 승인이 있습니다.")
        made = fetchone(
            ctx.conn,
            "INSERT INTO mint.endpoint_inspections (instance_id, intake_id, server_id, key_token,"
            " pack_sha256, contract_sha256, issued_by, expires_at)"
            " SELECT %s, %s, %s, k.key_token, d.pack_sha256, " + CONTRACT_HASH_SQL + ", %s,"
            " least(clock_timestamp() + make_interval(mins => %s),"
            "       coalesce(k.expires_at, 'infinity'::timestamptz))"
            " FROM mint.deployment_contracts d, mint.endpoint_installs k"
            " WHERE d.id = %s AND k.instance_id = %s AND k.key_token = %s RETURNING id",
            (ctx.instance_id, row["id"], row["server_id"], ctx.operator.name, minutes(),
             deployment["id"], ctx.instance_id, row["endpoint_key_token"]),
        )
        return str(made["id"])


def revoke(ctx: Context, inspection_id: str) -> None:
    """열려 있거나 처리를 기다리는 검사 권한을 철회한다."""
    require_role(ctx, "intake inspect-revoke")
    with transact(ctx):
        row = fetchone(
            ctx.conn,
            "SELECT * FROM mint.endpoint_inspections WHERE instance_id = %s AND id = %s"
            " FOR UPDATE", (ctx.instance_id, inspection_id))
        if row is None:
            raise not_found(f"검사용 승인 {inspection_id}이(가) 없습니다.")
        if row["status"] not in (*OPEN, "submitted"):
            raise conflict(f"{effective_status(row)} 상태의 검사용 승인은 철회할 수 없습니다.")
        ctx.conn.execute(
            "UPDATE mint.endpoint_inspections SET status = 'revoked', revoked_at = now(),"
            " revoked_by = %s WHERE id = %s", (ctx.operator.name, row["id"]))


def for_intake(conn: Any, instance_id: str, intake_id: Any, limit: int = 5) -> list[dict]:
    """신청의 최근 검사 권한(최신순). 결과 본문은 싣지 않는다."""
    rows = fetchall(
        conn,
        "SELECT id, status, issued_by, issued_at, expires_at, consumed_at, submitted_at,"
        " verified_at, revoked_at, revoked_by, outcome FROM mint.endpoint_inspections"
        " WHERE instance_id = %s AND intake_id = %s ORDER BY issued_at DESC LIMIT %s",
        (instance_id, intake_id, limit),
    )
    now = datetime.now(UTC)
    return [{**r, "status": effective_status(r, now)} for r in rows]


def invalidate_changed(conn: Any, instance_id: str, deployment_id: Any) -> None:
    """후보 묶음·계약이 바뀌었으면 그 서버의 열린 검사 권한을 무효로 한다."""
    conn.execute(
        "UPDATE mint.endpoint_inspections i SET status = 'invalid' WHERE i.instance_id = %s"
        " AND i.server_id = (SELECT server_id FROM mint.deployment_contracts WHERE id = %s)"
        " AND i.status IN ('issued', 'consumed', 'submitted')"
        " AND NOT EXISTS (SELECT 1 FROM mint.deployment_contracts d WHERE d.id = %s"
        " AND d.pack_sha256 = i.pack_sha256 AND " + CONTRACT_HASH_SQL + " = i.contract_sha256)",
        (instance_id, deployment_id, deployment_id),
    )
