"""권한 요청(FM-60): 직원이 막힌 도구·서버를 요청하고 승인자가 기존 조치로 처리한다.

새 판정 규칙은 없다. 처리는 차단 해제(denials), 승인 부여(approvals), 호출별 승인 규칙
(call approval rules) 중 하나를 부르고, 요청 행에는 무엇으로 풀었는지만 남긴다.
"""

import uuid
from datetime import UTC, datetime, timedelta

import psycopg

from mint_litellm.control import approvals as approval_domain
from mint_litellm.control import call_approval_rules as rule_domain
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, conflict, not_found
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.services import approvals as approval_service
from mint_litellm.control.services import staff
from mint_litellm.control.services.base import lock_version, require_role, transact
from mint_litellm.types.contracts import ALL_TOOLS
from mint_litellm.types.events import EventKind

# 거부 사유 → 기본 처리. 화면은 이 값을 주 단추로 보인다.
SUGGESTED = {
    "DENIED": "lift",
    "TOOL_NOT_IN_APPROVAL": "grant",
    "APPROVAL_ABSENT": "grant",
    "APPROVAL_EXPIRED": "grant",
    "APPROVAL_REVOKED": "grant",
    "CALL_APPROVAL_REQUIRED": "temp",
    "CALL_APPROVAL_DENIED": "temp",
}
TEMP_MINUTES = 30
GRANT_DAYS = (7, 30, 90)
_COLUMNS = (
    "id, requested_by, server_id, tool, reason_code, note, status, resolution, resolution_ref,"
    " decided_by, decision_note, created_at, decided_at, state_version"
)


def _request_id(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise not_found("권한 요청을 찾을 수 없습니다.") from None


# --- 직원 쪽 ---------------------------------------------------------------------------


def staff_open(
    sctx: staff.StaffContext,
    session_hash: str,
    *,
    server_id: str,
    tool: str | None,
    reason_code: str,
    note: str,
) -> str:
    """요청을 연다. 같은 서버·도구의 대기 요청이 있으면 그 요청 번호를 돌려준다."""
    reason_code = (reason_code or "APPROVAL_ABSENT").strip().upper()
    if reason_code not in SUGGESTED:
        raise ControlError("이 사유로는 권한을 요청할 수 없습니다. 관리자에게 문의하십시오.")
    if len(note or "") > 500:
        raise ControlError("요청 사유는 500자 이하로 적으십시오.")
    staff._active_session(sctx, session_hash)
    try:
        with staff._staff_transaction(sctx, session_hash) as conn:
            row = conn.execute(
                "SELECT mint.staff_open_access_request(%s, %s, %s, %s, %s)",
                (uuid.uuid4(), server_id, tool or "", reason_code, note or ""),
            ).fetchone()
    except psycopg.errors.NoDataFound:
        raise not_found("그런 서버가 없습니다.") from None
    return str(row[0])


def staff_cancel(sctx: staff.StaffContext, session_hash: str, request_id: str) -> bool:
    staff._active_session(sctx, session_hash)
    with staff._staff_transaction(sctx, session_hash) as conn:
        row = conn.execute(
            "SELECT mint.staff_cancel_access_request(%s)", (_request_id(request_id),)
        ).fetchone()
    return bool(row[0])


def mine(sctx: staff.StaffContext, limit: int = 100) -> list[dict]:
    return fetchall(
        sctx.control,
        f"SELECT {_COLUMNS} FROM mint.access_requests WHERE instance_id = %s"
        " AND requested_by = %s ORDER BY created_at DESC LIMIT %s",
        (sctx.instance_id, sctx.user_id, limit),
    )


# --- 승인자 쪽 ---------------------------------------------------------------------------


def pending(conn: psycopg.Connection, instance_id: str) -> list[dict]:
    """대기 요청(오래된 순)과 요청자 이름, 처리에 쓸 후보(풀 차단·이용 관계)."""
    rows = fetchall(
        conn,
        f"SELECT r.{_COLUMNS.replace(', ', ', r.')},"
        " coalesce(u.email, r.requested_by) AS requester,"
        " coalesce(u.team_ids, '[]'::jsonb) AS team_ids"
        " FROM mint.access_requests r LEFT JOIN mint.directory_users u"
        " ON u.instance_id = r.instance_id AND u.user_id = r.requested_by"
        " WHERE r.instance_id = %s AND r.status = 'open' ORDER BY r.created_at",
        (instance_id,),
    )
    for row in rows:
        row["suggested"] = SUGGESTED.get(row["reason_code"], "grant")
        row["denials"] = blocking_denials(conn, instance_id, row)
    return rows


def blocking_denials(conn: psycopg.Connection, instance_id: str, req: dict) -> list[dict]:
    """요청자에게 걸리는 활성 차단 중 이 서버·도구에 닿는 것."""
    teams = [str(t) for t in (req.get("team_ids") or [])]
    return fetchall(
        conn,
        "SELECT id, scope_type, scope_id, server_id, tools, reason, state_version"
        " FROM mint.denials WHERE instance_id = %s AND lifted_at IS NULL"
        " AND (server_id IS NULL OR server_id = %s)"
        " AND (tools IS NULL OR %s::text IS NULL OR %s::text = ANY(tools))"
        " AND ((scope_type = 'user' AND scope_id = %s)"
        " OR (scope_type = 'team' AND scope_id = ANY(%s)) OR scope_type IN ('org', 'server'))"
        " ORDER BY scope_type, id",
        (
            instance_id,
            req["server_id"],
            req.get("tool"),
            req.get("tool"),
            req["requested_by"],
            teams,
        ),
    )


def _load(ctx: Context, request_id: str, expected_version: int | None) -> dict:
    rid = _request_id(request_id)
    lock_version(ctx, "access_requests", str(rid), expected_version)
    row = fetchone(
        ctx.conn,
        f"SELECT {_COLUMNS} FROM mint.access_requests"
        " WHERE instance_id = %s AND id = %s FOR UPDATE",
        (ctx.instance_id, rid),
    )
    if row is None:
        raise not_found("권한 요청을 찾을 수 없습니다.")
    if row["status"] != "open":
        raise conflict("이미 처리된 요청입니다. 새로고침하십시오.")
    return row


def _close(
    ctx: Context,
    row: dict,
    status: str,
    kind: EventKind,
    *,
    resolution: str | None = None,
    ref: str | None = None,
    note: str | None = None,
) -> None:
    updated = fetchone(
        ctx.conn,
        "UPDATE mint.access_requests SET status = %s, resolution = %s, resolution_ref = %s,"
        " decided_by = %s, decision_note = %s, decided_at = now()"
        " WHERE instance_id = %s AND id = %s RETURNING state_version",
        (status, resolution, ref, ctx.operator.name, note, ctx.instance_id, row["id"]),
    )
    ctx.emit(
        kind,
        str(row["id"]),
        updated["state_version"],
        {
            "request_id": str(row["id"]),
            "server_id": row["server_id"],
            "tool": row["tool"],
            "requested_by": row["requested_by"],
            "resolution": resolution,
            "ref": ref,
        },
    )


def resolve_lift(
    ctx: Context, request_id: str, denial_ids: list[str], *, expected_version: int | None = None
) -> list[str]:
    """요청자에게 걸린 차단을 푼다. ``denial_ids``가 비면 닿는 차단을 모두 푼다."""
    require_role(ctx, "denial lift")
    with transact(ctx):
        row = _load(ctx, request_id, expected_version)
        team_row = fetchone(
            ctx.conn,
            "SELECT team_ids FROM mint.directory_users WHERE instance_id = %s AND user_id = %s",
            (ctx.instance_id, row["requested_by"]),
        )
        candidates = blocking_denials(
            ctx.conn, ctx.instance_id, {**row, "team_ids": (team_row or {}).get("team_ids")}
        )
        chosen = [d for d in candidates if not denial_ids or str(d["id"]) in set(denial_ids)]
        if not chosen:
            raise conflict("요청자에게 걸린 차단이 없습니다. 이미 풀렸는지 확인하십시오.")
        for denial in chosen:
            approval_domain.lift_denial(ctx, str(denial["id"]))
        ids = [str(d["id"]) for d in chosen]
        _close(
            ctx,
            row,
            "resolved",
            EventKind.ACCESS_REQUEST_RESOLVED,
            resolution="lift",
            ref=",".join(ids),
        )
        return ids


def resolve_grant(
    ctx: Context,
    litellm: LiteLLMAdmin,
    request_id: str,
    *,
    valid_days: int,
    expected_version: int | None = None,
) -> str:
    """요청자에게 이 서버(또는 그 도구)의 승인을 준다. 서버의 활성 이용 관계에 붙인다."""
    if valid_days not in GRANT_DAYS:
        raise ControlError("기간은 7일, 30일, 90일 중에서 고르십시오.")
    require_role(ctx, "approve")
    row = fetchone(
        ctx.conn,
        f"SELECT {_COLUMNS} FROM mint.access_requests WHERE instance_id = %s AND id = %s",
        (ctx.instance_id, _request_id(request_id)),
    )
    if row is None:
        raise not_found("권한 요청을 찾을 수 없습니다.")
    if row["status"] != "open":
        raise conflict("이미 처리된 요청입니다. 새로고침하십시오.")
    relation = fetchone(
        ctx.conn,
        "SELECT id, state_version FROM mint.usage_relations"
        " WHERE instance_id = %s AND server_id = %s AND status = 'active'"
        " ORDER BY id DESC LIMIT 1",
        (ctx.instance_id, row["server_id"]),
    )
    if relation is None:
        raise conflict("이 서버에는 이용 관계가 없습니다. 먼저 도입 신청을 승인하십시오.")
    now = datetime.now(UTC)
    approval_id, _ = approval_service.approve(
        ctx,
        litellm,
        relation_id=str(relation["id"]),
        scope_type="user",
        scope_id=row["requested_by"],
        tools=[row["tool"]] if row["tool"] else [ALL_TOOLS],
        valid_from=now,
        valid_until=now + timedelta(days=valid_days),
        approval_class="standard",
        basis_text=f"권한 요청 {row['id']}: {row['note'] or row['reason_code']}"[:500],
        requested_by=row["requested_by"],
        allowlist_ids=[],
        second=None,
    )
    with transact(ctx):
        current = _load(ctx, request_id, expected_version)
        _close(
            ctx,
            current,
            "resolved",
            EventKind.ACCESS_REQUEST_RESOLVED,
            resolution="grant",
            ref=str(approval_id),
        )
    return str(approval_id)


def resolve_temp(ctx: Context, request_id: str, *, expected_version: int | None = None) -> str:
    """호출별 승인이 필요한 도구를 요청자에게 30분 동안 허용한다(상시 승인 규칙)."""
    require_role(ctx, "call-approval-rule add")
    with transact(ctx):
        row = _load(ctx, request_id, expected_version)
        org = fetchone(
            ctx.conn,
            "SELECT org_id FROM mint.usage_relations WHERE instance_id = %s"
            " AND server_id = %s AND status = 'active' ORDER BY id DESC LIMIT 1",
            (ctx.instance_id, row["server_id"]),
        )
        if org is None:
            raise conflict("이 서버에는 이용 관계가 없습니다. 먼저 도입 신청을 승인하십시오.")
        # 규칙은 도구 계약의 동작 종류(읽기·쓰기)가 같아야 맞는다. 그 도구의 종류마다 하나씩 둔다.
        classes = [
            r["action_type"]
            for r in fetchall(
                ctx.conn,
                "SELECT DISTINCT action_type FROM mint.tool_contracts WHERE instance_id = %s"
                " AND server_id = %s AND status = 'approved' AND action_type IN ('read', 'write')"
                " AND (%s::text IS NULL OR tool = %s)",
                (ctx.instance_id, row["server_id"], row["tool"], row["tool"]),
            )
        ] or ["write"]
        until = datetime.now(UTC) + timedelta(minutes=TEMP_MINUTES)
        rule_ids = [
            str(
                rule_domain.add(
                    ctx,
                    org_id=org["org_id"],
                    action_class=action_class,
                    window_minutes=TEMP_MINUTES,
                    principal_type="user",
                    principal_id=row["requested_by"],
                    server_id=row["server_id"],
                    tool_pattern=row["tool"] or "*",
                    valid_until=until,
                )
            )
            for action_class in sorted(classes)
        ]
        _close(
            ctx,
            row,
            "resolved",
            EventKind.ACCESS_REQUEST_RESOLVED,
            resolution="temp",
            ref=",".join(rule_ids),
        )
        return ",".join(rule_ids)


def reject(
    ctx: Context, request_id: str, note: str, *, expected_version: int | None = None
) -> None:
    note = (note or "").strip()
    if not note:
        raise ControlError("거절 사유를 적으십시오. 요청자에게 보입니다.")
    if len(note) > 500:
        raise ControlError("거절 사유는 500자 이하로 적으십시오.")
    require_role(ctx, "approve")
    with transact(ctx):
        row = _load(ctx, request_id, expected_version)
        _close(ctx, row, "rejected", EventKind.ACCESS_REQUEST_REJECTED, note=note)
