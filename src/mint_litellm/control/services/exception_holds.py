"""예외 승인의 두 번째 승인 대기: 첫 승인자가 요청하고, 다른 승인자가 화면에서 확인한다."""

import json
from datetime import timedelta

from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, conflict, not_found
from mint_litellm.control.services import intakes
from mint_litellm.control.services.base import require_role, transact
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

HOLD_HOURS = 24
PENDING_SQL = (
    " FROM mint.exception_holds h"
    " JOIN mint.intakes i ON i.instance_id = h.instance_id AND i.id = h.intake_id"
    " WHERE h.instance_id = %(instance)s AND h.status = 'pending'"
    " AND h.expires_at > statement_timestamp()"
    " AND i.status = 'indeterminate' AND h.params->'state_version' = to_jsonb(i.state_version)"
)


def pending(conn, instance: str, intake_id: str | None = None) -> list[dict]:
    extra = " AND h.intake_id = %(intake_id)s" if intake_id else ""
    return fetchall(
        conn,
        "SELECT h.id, h.intake_id, h.first_name, h.first_user_id, h.params, h.expires_at,"
        " h.created_at, i.server_id, i.requested_by, i.purpose"
        + PENDING_SQL + extra + " ORDER BY h.created_at",
        {"instance": instance, "intake_id": intake_id},
    )


def count(conn, instance: str) -> int:
    return len(pending(conn, instance))


def _close(ctx: Context, hold: dict, status: str, reason: str) -> None:
    ctx.conn.execute(
        "UPDATE mint.exception_holds SET status = %s, closed_by = %s, closed_at = clock_timestamp()"
        " WHERE id = %s", (status, ctx.operator.name, hold["id"]))
    ctx.emit(EventKind.INTAKE_EXCEPTION_CANCELLED, hold["id"], 1,
             {"intake_id": str(hold["intake_id"]), "hold_id": str(hold["id"]),
              "reason": reason, "first_approver": hold["first_name"]})


def _lock_pending(ctx: Context, hold_id: str) -> tuple[dict, dict]:
    # Always lock the intake before the hold, as request() does when replacing a hold.
    args = (ctx.instance_id, hold_id)
    intake = fetchone(
        ctx.conn,
        "SELECT i.status, i.state_version FROM mint.intakes i JOIN mint.exception_holds h"
        " ON i.instance_id = h.instance_id AND i.id = h.intake_id"
        " WHERE h.instance_id = %s AND h.id = %s FOR UPDATE OF i",
        args,
    )
    if intake is None:
        raise not_found("두 번째 승인 요청이 없습니다.")
    hold = fetchone(ctx.conn, "SELECT * FROM mint.exception_holds"
                    " WHERE instance_id = %s AND id = %s FOR UPDATE",
                    args)
    if hold is None:
        raise not_found("두 번째 승인 요청이 없습니다.")
    if hold["status"] != "pending":
        raise conflict("이미 처리된 요청입니다.")
    return intake, hold


def _require_current(intake: dict, hold: dict) -> None:
    if (intake["status"] != "indeterminate"
            or intake["state_version"] != hold["params"].get("state_version")):
        raise conflict("신청 상태가 변경되어 이 두 번째 승인 요청을 처리할 수 없습니다.")


def _close_if_expired(ctx: Context, hold: dict) -> bool:
    # Read the database clock after any wait for the intake and hold locks.
    expired = fetchone(ctx.conn, "SELECT %s <= clock_timestamp() AS expired",
                       (hold["expires_at"],))["expired"]
    if expired:
        _close(ctx, hold, "expired", "expired")
    return expired


def request(ctx: Context, intake_id: str, params: dict, *, expected_version: int | None) -> dict:
    """결정자(첫 승인자)가 예외 승인을 요청한다. 승인 처리는 하지 않는다."""
    require_role(ctx, "intake except")
    reason = (params.get("reason") or "").strip()
    if not reason:
        raise ControlError("사유가 필요합니다(--reason).")
    with transact(ctx):
        row = intakes.get(ctx, intake_id, lock=True)
        if expected_version is not None and row["state_version"] != expected_version:
            raise conflict(f"신청의 상태 버전이 요청({expected_version})과 다릅니다"
                           f"(현재 {row['state_version']}).")
        if row["status"] != "indeterminate":
            raise conflict(f"{row['status']} 상태의 신청은 except할 수 없습니다.")
        intakes._require_separation(ctx, row, None, False)
        intakes._require_fresh_evidence(ctx, row)
        now = fetchone(ctx.conn, "SELECT clock_timestamp() AS t")["t"]
        for old in fetchall(  # 열린 요청은 새 요청이 대체한다(만료된 것은 만료로 닫는다)
                ctx.conn, "SELECT * FROM mint.exception_holds WHERE instance_id = %s"
                " AND intake_id = %s AND status = 'pending'", (ctx.instance_id, row["id"])):
            expired = old["expires_at"] <= now
            _close(ctx, old, "expired" if expired else "superseded",
                   "expired" if expired else "superseded")
        hold = fetchone(
            ctx.conn,
            "INSERT INTO mint.exception_holds (id, instance_id, intake_id, first_name, first_role,"
            " first_user_id, params, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)"
            " RETURNING *",
            (new_uuid7(), ctx.instance_id, row["id"], ctx.operator.name, ctx.operator.role,
             ctx.operator.user_id, json.dumps({**params, "state_version": row["state_version"]},
                                              ensure_ascii=False),
             now + timedelta(hours=HOLD_HOURS)))
        ctx.emit(EventKind.INTAKE_EXCEPTION_REQUESTED, hold["id"], 1,
                 {"intake_id": str(row["id"]), "hold_id": str(hold["id"]),
                  "server_id": row["server_id"], "first_approver": ctx.operator.name,
                  "reason": reason, "expires_at": hold["expires_at"].isoformat()})
        return hold


def reject(ctx: Context, hold_id: str) -> dict | None:
    """승인자(첫 승인자 본인 포함)가 요청을 거절·취소한다."""
    require_role(ctx, "intake except")
    with transact(ctx):
        intake, hold = _lock_pending(ctx, hold_id)
        if _close_if_expired(ctx, hold):
            return {"expired": True}
        _require_current(intake, hold)
        _close(ctx, hold, "rejected", "rejected")


def confirm(ctx: Context, hold_id: str, run) -> dict:
    """다른 승인자가 확인하면 첫 승인자 이름으로 기존 예외 승인을 같은 트랜잭션에서 처리한다.

    ``run(hold)``는 두 번째 승인자를 ``ctx.operator``로 넘겨 승인 처리를 한다.
    """
    require_role(ctx, "intake except")
    with transact(ctx):
        intake, hold = _lock_pending(ctx, hold_id)
        if _close_if_expired(ctx, hold):
            return {"expired": True}
        _require_current(intake, hold)
        result = run(hold)
        ctx.conn.execute(
            "UPDATE mint.exception_holds SET status = 'confirmed', closed_by = %s,"
            " closed_at = clock_timestamp() WHERE id = %s", (ctx.operator.name, hold["id"]))
        return result
