"""승인의 필요성 재확인: 기한 계산, 요청·보류를 여는 주기 검사, 운영자의 재확인.

기준 시각은 마지막 재확인(없으면 승인의 유효 시작)이다. 기준 + 주기에 요청을 열고 경보를 올리며,
기준 + 주기 + 유예가 지나도록 확인이 없으면 승인을 보류한다. 보류된 승인은 판정이 쓰지 않아
그 범위의 호출이 ``APPROVAL_RECERT_REQUIRED``로 막힌다. 보류를 풀 수 있는 것은 재확인뿐이다.
"""

from datetime import datetime, timedelta
from typing import Any

import psycopg

from mint_litellm.control import alerts, ledger
from mint_litellm.control.context import Context
from mint_litellm.control.errors import forbidden, not_found
from mint_litellm.control.services.base import lock_version, transact
from mint_litellm.types.events import EventKind

DUE_ALERT = "approval_recert_due"
HELD_ALERT = "approval_recert_held"

# 기준 시각 식(SQL). 주기 작업의 질의가 이 정의를 쓴다.
_BASE = "COALESCE(recert_confirmed_at, valid_from)"


def due_at(row: dict[str, Any], period: timedelta) -> datetime:
    """재확인 기한. 마지막 재확인(없으면 유효 시작)에 주기를 더한다."""
    return (row.get("recert_confirmed_at") or row["valid_from"]) + period


def state(row: dict[str, Any], now: datetime, period: timedelta, grace: timedelta) -> str | None:
    """활성 승인의 재확인 상태: ``ok``·``due``·``overdue``·``held``. 활성이 아니면 None."""
    if row["status"] != "active":
        return None
    if row.get("recert_held_at") is not None:
        return "held"
    due = due_at(row, period)
    if now < due:
        return "ok"
    return "overdue" if now >= due + grace else "due"


def scan(
    conn: psycopg.Connection, instance_id: str, period: timedelta, grace: timedelta
) -> dict[str, int]:
    """기한이 된 승인에 요청을 열고, 유예가 지난 승인을 보류한다. 연 요청·보류 수를 돌려준다."""
    held = requested = 0
    with conn.transaction():
        # 먼저 보류한다. 작업이 오래 멈췄다면 요청 없이 곧바로 보류되므로 요청 시각도 채운다.
        for approval_id, server_id, scope_type, scope_id, version in conn.execute(
            "UPDATE mint.approvals SET recert_held_at = now(),"
            " recert_requested_at = COALESCE(recert_requested_at, now())"
            " WHERE instance_id = %s AND status = 'active' AND recert_held_at IS NULL"
            f" AND valid_until > now() AND {_BASE} + %s + %s <= now()"
            " RETURNING id, server_id, scope_type, scope_id, state_version",
            (instance_id, period, grace),
        ).fetchall():
            held += 1
            subject = {"approval_id": str(approval_id), "server_id": server_id}
            ledger.record(
                conn, instance_id, EventKind.APPROVAL_HELD, entity_id=str(approval_id),
                state_version=version, actor=alerts.AUTO_ACTOR,
                payload={**subject, "scope_type": scope_type, "scope_id": scope_id},
            )
            alerts.raise_alert(
                conn, instance_id, kind=HELD_ALERT, severity="high",
                dedup_key=f"{HELD_ALERT}:{approval_id}", subject=subject,
            )
            alerts.resolve(conn, instance_id, f"{DUE_ALERT}:{approval_id}")
        for approval_id, server_id, version in conn.execute(
            "UPDATE mint.approvals SET recert_requested_at = now()"
            " WHERE instance_id = %s AND status = 'active' AND recert_held_at IS NULL"
            f" AND recert_requested_at IS NULL AND valid_until > now() AND {_BASE} + %s <= now()"
            " RETURNING id, server_id, state_version",
            (instance_id, period),
        ).fetchall():
            requested += 1
            subject = {"approval_id": str(approval_id), "server_id": server_id}
            ledger.record(
                conn, instance_id, EventKind.APPROVAL_RECERT_REQUESTED,
                entity_id=str(approval_id), state_version=version, actor=alerts.AUTO_ACTOR,
                payload=subject,
            )
            alerts.raise_alert(
                conn, instance_id, kind=DUE_ALERT, severity="medium",
                dedup_key=f"{DUE_ALERT}:{approval_id}", subject=subject,
            )
        # 철회·만료로 활성이 아니게 된 승인의 열린 경보는 닫는다.
        for kind in (DUE_ALERT, HELD_ALERT):
            for (dedup_key,) in conn.execute(
                "SELECT a.dedup_key FROM mint.alerts a WHERE a.instance_id = %s AND a.kind = %s"
                " AND a.status <> 'resolved' AND NOT EXISTS (SELECT 1 FROM mint.approvals p"
                "  WHERE p.instance_id = a.instance_id AND p.id::text = a.subject->>'approval_id'"
                "  AND p.status = 'active')",
                (instance_id, kind),
            ).fetchall():
                alerts.resolve(conn, instance_id, dedup_key)
    return {"requested": requested, "held": held}


def confirm(ctx: Context, approval_id: str, *, expected_version: int | None = None) -> None:
    """관리자가 승인이 여전히 업무에 필요함을 확인한다. 주기를 새로 시작하고 보류를 푼다."""
    if ctx.operator.role != "admin":
        raise forbidden(
            f"승인 재확인은 {ctx.operator.role} 역할로 실행할 수 없습니다.", exit_code=4
        )
    with transact(ctx):
        lock_version(ctx, "approvals", approval_id, expected_version)
        row = ctx.conn.execute(
            "UPDATE mint.approvals SET recert_confirmed_at = now(), recert_confirmed_by = %s,"
            " recert_requested_at = NULL, recert_held_at = NULL"
            " WHERE instance_id = %s AND id = %s AND status = 'active'"
            " RETURNING state_version, server_id",
            (ctx.operator.name, ctx.instance_id, approval_id),
        ).fetchone()
        if row is None:
            raise not_found(f"활성 상태의 승인 {approval_id}이(가) 없습니다.")
        ctx.emit(
            EventKind.APPROVAL_RECERT_CONFIRMED, approval_id, row[0],
            {"approval_id": approval_id, "server_id": row[1]},
        )
        for kind in (DUE_ALERT, HELD_ALERT):
            alerts.resolve(ctx.conn, ctx.instance_id, f"{kind}:{approval_id}")
