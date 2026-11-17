"""Requester-only withdrawal; no approvals, credentials, or evidence are removed."""

from uuid import UUID

import psycopg

from mint_litellm.control.context import Context
from mint_litellm.control.errors import ControlError, conflict, forbidden, not_found
from mint_litellm.control.services import staff, staff_intakes
from mint_litellm.control.services.base import transact
from mint_litellm.types.events import EventKind


def inputs(identifier: str, reason: str) -> tuple[UUID, str]:
    try:
        value = UUID(str(identifier))
    except (ValueError, TypeError):
        raise not_found("신청을 찾을 수 없습니다.") from None
    reason = reason.strip()
    if not 1 <= len(reason) <= 500:
        raise ControlError("철회 사유를 1자 이상 500자 이하로 입력하십시오.")
    return value, reason


def withdraw(ctx: Context, identifier: str, version: int, reason: str) -> dict:
    identifier, reason = inputs(identifier, reason)
    if not ctx.operator.user_id:
        raise forbidden("신청자 본인만 철회할 수 있습니다.")
    try:
        with transact(ctx):
            result = ctx.conn.execute(
                "SELECT mint.withdraw_intake_row(%s,%s,%s,%s,%s,%s)",
                (
                    ctx.instance_id,
                    identifier,
                    ctx.operator.user_id,
                    version,
                    reason,
                    ctx.operator.name,
                ),
            ).fetchone()[0]
            row = result["intake"]
            if result["changed"]:
                ctx.emit(
                    EventKind.INTAKE_DECIDED,
                    identifier,
                    row["state_version"],
                    {
                        "intake_id": str(identifier),
                        "server_id": row["server_id"],
                        "decision": "withdrawn",
                        "reason": reason,
                        "decided_by": ctx.operator.name,
                        "automatic": False,
                    },
                )
            return row
    except psycopg.errors.InsufficientPrivilege as error:
        if error.diag.message_primary == "only the requester may withdraw this application":
            raise forbidden("신청자 본인만 철회할 수 있습니다.") from None
        raise
    except psycopg.errors.CheckViolation:
        raise conflict(
            "신청 상태가 바뀌었거나 검사가 진행 중입니다. 새로고침 후 다시 확인하십시오. "
            "이미 승인·거절된 신청은 철회할 수 없습니다."
        ) from None


def staff_withdraw(
    sctx: staff.StaffContext, session_hash: str, identifier: str, version: int, reason: str
) -> dict:
    identifier, reason = inputs(identifier, reason)
    staff_intakes.detail(
        sctx, str(identifier)
    )  # Foreign IDs remain indistinguishable from missing IDs.
    staff._active_session(sctx, session_hash)
    try:
        with staff._staff_transaction(sctx, session_hash) as conn:
            result = conn.execute(
                "SELECT mint.staff_withdraw_intake(%s,%s,%s)", (identifier, version, reason)
            ).fetchone()[0]
            return result["intake"]
    except psycopg.errors.CheckViolation:
        raise conflict(
            "신청 상태가 바뀌었거나 검사가 진행 중입니다. 새로고침 후 다시 확인하십시오. "
            "이미 승인·거절된 신청은 철회할 수 없습니다."
        ) from None
