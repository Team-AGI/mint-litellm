"""운영자 등록 서비스."""

import psycopg

from mint_litellm.control import operators as domain
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, conflict, not_found, separation_of_duties
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.services import console_sessions
from mint_litellm.control.services.base import (
    Prefetched,
    lock_version,
    require_role,
    service,
    transact,
)
from mint_litellm.types.cli_commands import OperatorRole
from mint_litellm.types.events import EventKind


def add(
    ctx: Context,
    litellm: LiteLLMAdmin,
    name: str,
    role: OperatorRole,
    user_id: str | None,
    expires_in_days: int | None,
) -> str:
    """운영자를 등록하고 토큰(한 번만 표시)을 돌려준다."""
    require_role(ctx, "operator add")
    facts = Prefetched(litellm)
    if user_id:
        facts.prefetch("get_user", user_id)
    with transact(ctx):
        return domain.add(ctx, facts, name, role, user_id, expires_in_days)  # type: ignore[arg-type]


def bootstrap(
    conn: psycopg.Connection,
    instance_id: str,
    litellm: LiteLLMAdmin,
    name: str,
    user_id: str,
    emitted: list | None = None,
) -> str:
    """운영자가 하나도 없을 때만 토큰 없이 첫 admin을 만든다(토큰 없는 명령)."""
    facts = Prefetched(litellm).prefetch("get_user", user_id)
    mark = len(emitted) if emitted is not None else 0
    try:
        with conn.transaction():
            return domain.bootstrap(conn, instance_id, facts, name, user_id, emitted)  # type: ignore[arg-type]
    except BaseException:
        if emitted is not None:
            del emitted[mark:]
        raise


def _active(ctx: Context, name: str) -> dict:
    row = fetchone(
        ctx.conn,
        "SELECT name, role, user_id, state_version FROM mint.operators"
        " WHERE instance_id = %s AND name = %s AND (expires_at IS NULL OR expires_at > now())"
        " FOR UPDATE",
        (ctx.instance_id, name),
    )
    if row is None:
        gone = fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.operators WHERE instance_id = %s AND name = %s",
            (ctx.instance_id, name),
        )
        raise not_found(
            f"운영자 {name}은(는) 이미 삭제되었습니다."
            if gone
            else f"운영자 {name}이(가) 없습니다."
        )
    return row


def _serialize_admin_changes(ctx: Context) -> None:
    """관리자 수를 세기 전에 배치 공통 잠금을 건다(동시에 둘이 낮춰 0명이 되는 것을 막는다)."""
    ctx.conn.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mint-operators:{ctx.instance_id}",)
    )


def _require_another_admin(ctx: Context, name: str) -> None:
    other = fetchone(
        ctx.conn,
        "SELECT count(*) AS n FROM mint.operators WHERE instance_id = %s AND role = 'admin'"
        " AND name <> %s AND (expires_at IS NULL OR expires_at > now())",
        (ctx.instance_id, name),
    )
    if not other["n"]:
        raise conflict("마지막 관리자는 삭제하거나 역할을 낮출 수 없습니다.")


def _end_sessions(ctx: Context, user_id: str | None, reason: str) -> None:
    if user_id:
        console_sessions.revoke_user_sessions(
            ctx.conn, ctx.instance_id, user_id, actor=ctx.operator.name, reason=reason
        )


@service("operator remove")
def remove(ctx: Context, name: str, *, expected_version: int | None = None) -> None:
    """운영자를 삭제한다. 행은 남기고 만료시켜 토큰을 끝내며, 그 사용자의 콘솔 세션을 폐기한다."""
    _serialize_admin_changes(ctx)
    lock_version(ctx, "operators", name, expected_version)
    target = _active(ctx, name)
    if target["name"] == ctx.operator.name:
        raise separation_of_duties("본인은 삭제할 수 없습니다.")
    if target["role"] == "admin":
        _require_another_admin(ctx, name)
    row = fetchone(
        ctx.conn,
        "UPDATE mint.operators SET expires_at = now() WHERE instance_id = %s AND name = %s"
        " RETURNING state_version",
        (ctx.instance_id, name),
    )
    ctx.emit(EventKind.OPERATOR_REMOVED, name, row["state_version"],
             {"name": name, "role": target["role"], "user_id": target["user_id"]})
    _end_sessions(ctx, target["user_id"], "operator_changed")


@service("operator set-role")
def set_role(
    ctx: Context, name: str, role: OperatorRole, *, expected_version: int | None = None
) -> None:
    _serialize_admin_changes(ctx)
    lock_version(ctx, "operators", name, expected_version)
    target = _active(ctx, name)
    if target["role"] == role.value:
        raise conflict(f"운영자 {name}의 역할은 이미 {role.value}입니다.")
    if role is not OperatorRole.VIEWER and not target["user_id"]:
        raise ControlError(
            f"{role.value} 역할은 LiteLLM 사용자에 결속된 운영자만 받을 수 있습니다."
        )
    if target["role"] == "admin":
        _require_another_admin(ctx, name)
    row = fetchone(
        ctx.conn,
        "UPDATE mint.operators SET role = %s WHERE instance_id = %s AND name = %s"
        " RETURNING state_version",
        (role.value, ctx.instance_id, name),
    )
    ctx.emit(EventKind.OPERATOR_ROLE_CHANGED, name, row["state_version"],
             {"name": name, "from": target["role"], "to": role.value,
              "user_id": target["user_id"]})
    _end_sessions(ctx, target["user_id"], "operator_changed")
