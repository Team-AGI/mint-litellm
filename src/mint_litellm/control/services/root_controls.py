"""Root 통제(FM-55~59): 전역 정지, 강제 반려, 서버 강제 중지·재개·폐기, 사람 전체 차단.

새 판정 로직은 없다. 기존 서비스(설정, 신청 결정, 서버 상태, denials, 단말 키 해제, 세션 폐기)를
부르고 강제 조치 기록 한 행과 사건을 남긴다. 전파는 기록 시각 뒤의 반영 시각으로 확인한다.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from mint_litellm.control import approvals as approval_domain
from mint_litellm.control import endpoint_kits
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError, ControlError, conflict, not_found
from mint_litellm.control.services import console_sessions, intakes, servers
from mint_litellm.control.services.base import enqueue_job, require_role, transact
from mint_litellm.types.events import EventKind

HALT_SCOPES = {
    "all": "모든 MCP 호출",
    "local": "PC에서 실행하는 로컬 MCP 호출",
    "freeze": "새 승인·배포 동결(기존 사용은 유지)",
}
LOCKOUT_REASON_PREFIX = "전체 차단: "


def root_names(conn, instance_id: str) -> list[str]:
    row = fetchone(
        conn, "SELECT root_operators FROM mint.settings WHERE instance_id = %s", (instance_id,)
    )
    return list(row["root_operators"]) if row else ["root"]


def is_root(ctx: Context) -> bool:
    """Root 표지가 있는 관리자(기본 계정 root는 항상 Root)."""
    if ctx.operator.role != "admin":
        return False
    return ctx.operator.name == "root" or ctx.operator.name in root_names(ctx.conn, ctx.instance_id)


def require_root(ctx: Context) -> None:
    if not is_root(ctx):
        raise AdminError(AdminCode.FORBIDDEN, "이 조치는 Root만 할 수 있습니다.")


def _reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise ControlError("사유를 적으십시오. 강제 조치 기록에 남습니다.")
    if len(reason) > 500:
        raise ControlError("사유는 500자 이하로 적으십시오.")
    return reason


def record(
    ctx: Context,
    action: str,
    target: str,
    reason: str,
    *,
    impact: dict | None = None,
    refs: dict | None = None,
    undoes: str | None = None,
) -> str:
    """강제 조치 기록 한 행과 사건 한 건. 기록 시각이 전파 확인의 기준이다."""
    action_id = str(uuid.uuid4())
    ctx.conn.execute(
        "INSERT INTO mint.forced_actions (id, instance_id, action, target, reason, actor, impact,"
        " refs) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)",
        (
            action_id,
            ctx.instance_id,
            action,
            target,
            reason,
            ctx.operator.name,
            json.dumps(impact or {}, ensure_ascii=False, default=str),
            json.dumps(refs or {}, ensure_ascii=False, default=str),
        ),
    )
    if undoes:
        ctx.conn.execute(
            "UPDATE mint.forced_actions SET undone_by = %s WHERE instance_id = %s AND id = %s",
            (action_id, ctx.instance_id, undoes),
        )
    ctx.emit(
        EventKind.FORCED_ACTION_RECORDED,
        action_id,
        1,
        {
            "action_id": action_id,
            "action": action,
            "target": target,
            "reason": reason,
            "impact": impact or {},
            "refs": refs or {},
        },
    )
    return action_id


# --- 전역 정지 ------------------------------------------------------------------------------


def halt_state(conn, instance_id: str) -> dict | None:
    row = fetchone(
        conn,
        "SELECT halt_scope, halt_reason, halt_by, halt_at FROM mint.settings"
        " WHERE instance_id = %s",
        (instance_id,),
    )
    return row if row and row["halt_scope"] else None


def set_halt(ctx: Context, scope: str, reason: str) -> str:
    require_root(ctx)
    if scope not in HALT_SCOPES:
        raise ControlError("정지 범위는 모든 호출, 로컬만, 새 승인·배포 동결 중에서 고르십시오.")
    reason = _reason(reason)
    with transact(ctx):
        current = halt_state(ctx.conn, ctx.instance_id)
        if current and current["halt_scope"] == scope:
            raise conflict("이미 같은 범위로 정지 중입니다.")
        row = fetchone(
            ctx.conn,
            "UPDATE mint.settings SET halt_scope = %s, halt_reason = %s, halt_by = %s,"
            " halt_at = now() WHERE instance_id = %s RETURNING settings_version",
            (scope, reason, ctx.operator.name, ctx.instance_id),
        )
        ctx.emit(
            EventKind.GLOBAL_HALT_SET,
            ctx.instance_id,
            row["settings_version"],
            {"scope": scope, "reason": reason},
        )
        impact = _halt_impact(ctx, scope)
        if scope in ("all", "local"):
            enqueue_job(ctx, "kit_key_sync", "all")  # PC가 다음 보고 때 정지 지시를 받는다
        return record(ctx, "halt", HALT_SCOPES[scope], reason, impact=impact)


def lift_halt(ctx: Context, reason: str) -> str:
    require_root(ctx)
    reason = _reason(reason)
    with transact(ctx):
        current = halt_state(ctx.conn, ctx.instance_id)
        if current is None:
            raise conflict("전역 정지 중이 아닙니다.")
        row = fetchone(
            ctx.conn,
            "UPDATE mint.settings SET halt_scope = NULL, halt_reason = NULL, halt_by = NULL,"
            " halt_at = NULL WHERE instance_id = %s RETURNING settings_version",
            (ctx.instance_id,),
        )
        ctx.emit(
            EventKind.GLOBAL_HALT_LIFTED,
            ctx.instance_id,
            row["settings_version"],
            {"scope": current["halt_scope"], "reason": reason},
        )
        last = fetchone(
            ctx.conn,
            "SELECT id FROM mint.forced_actions WHERE instance_id = %s"
            " AND action = 'halt' AND undone_by IS NULL ORDER BY created_at DESC"
            " LIMIT 1",
            (ctx.instance_id,),
        )
        enqueue_job(ctx, "kit_key_sync", "all")
        return record(
            ctx,
            "halt_lift",
            HALT_SCOPES[current["halt_scope"]],
            reason,
            undoes=str(last["id"]) if last else None,
        )


def _halt_impact(ctx: Context, scope: str) -> dict:
    counts = fetchone(
        ctx.conn,
        "SELECT (SELECT count(*) FROM mint.servers WHERE instance_id = %(i)s"
        "        AND status = 'approved') AS servers,"
        " (SELECT count(*) FROM mint.endpoint_installs WHERE instance_id = %(i)s"
        "        AND revoked_at IS NULL) AS pcs,"
        " (SELECT count(*) FROM mint.intakes WHERE instance_id = %(i)s"
        "        AND status <> 'decided') AS open_intakes",
        {"i": ctx.instance_id},
    )
    return {"scope": scope, **counts}


# --- 신청·서버 ------------------------------------------------------------------------------


def force_reject(ctx: Context, intake_id: str, reason: str) -> str:
    """접수·검사 중을 포함해 어느 단계의 신청이든 반려한다."""
    require_root(ctx)
    reason = _reason(reason)
    row = intakes.decide(ctx, intake_id, "reject", reason=reason, early=True)
    with transact(ctx):
        return record(
            ctx, "intake_reject", row["server_id"], reason, refs={"intake_id": str(intake_id)}
        )


FORCE_EXCEPT_DAYS = 30


def force_except(ctx: Context, intake_id: str, reason: str) -> str:
    """검사 생략 승인: 접수·검사 중을 포함해 예외 승인(기본 30일)으로 결정한다."""
    require_root(ctx)
    reason = _reason(reason)
    until = datetime.now(UTC) + timedelta(days=FORCE_EXCEPT_DAYS)
    row = intakes.decide(ctx, intake_id, "except", reason=reason, early=True, valid_until=until)
    with transact(ctx):
        return record(
            ctx, "intake_except", row["server_id"], reason,
            impact={"valid_days": FORCE_EXCEPT_DAYS}, refs={"intake_id": str(intake_id)},
        )


def cancel_runs(ctx: Context, kind: str, target: str, reason: str) -> str:
    """진행 중 실행 취소: 그 서버나 사람의 승인 대기·미사용 호출별 승인을 취소한다.

    이미 원격 서버로 보낸 호출은 취소할 수 없다. PC 로컬 서버를 멈추려면 서버 중지를 쓴다.
    """
    require_root(ctx)
    reason = _reason(reason)
    column = {"server": "server_id", "person": "principal_id"}.get(kind)
    if column is None:
        raise ControlError("취소 대상은 서버나 사람이어야 합니다.")
    with transact(ctx):
        calls = fetchall(
            ctx.conn,
            f"SELECT id FROM mint.call_approvals WHERE instance_id = %s AND {column} = %s"
            " AND status IN ('pending', 'approved') ORDER BY id",
            (ctx.instance_id, target),
        )
        for call in calls:
            approval_domain.call_cancel(ctx, str(call["id"]))
        return record(
            ctx, "run_cancel", f"{kind}:{target}", reason,
            impact={"call_approvals": len(calls),
                    "not_cancellable": "이미 원격 서버로 보낸 호출"},  # fmt: skip
        )


def server_action(ctx: Context, server_id: str, action: str, reason: str) -> str:
    """서버 강제 중지·재개·폐기. 중지·폐기는 MINT 판정이 다음 호출부터 거부한다."""
    if action not in ("suspend", "resume", "terminate"):
        raise ValueError(action)
    require_root(ctx)
    reason = _reason(reason)
    impact = fetchone(
        ctx.conn,
        "SELECT (SELECT count(*) FROM mint.approvals WHERE instance_id = %(i)s"
        "        AND server_id = %(s)s AND status = 'active') AS approvals,"
        " (SELECT count(DISTINCT scope_id) FROM mint.approvals WHERE instance_id = %(i)s"
        "        AND server_id = %(s)s AND status = 'active' AND scope_type = 'user') AS users",
        {"i": ctx.instance_id, "s": server_id},
    )
    {"suspend": servers.suspend, "resume": servers.resume, "terminate": servers.terminate}[action](
        ctx, server_id, reason=reason
    )
    with transact(ctx):
        return record(ctx, f"server_{action}", server_id, reason, impact=impact)


# --- 사람 ----------------------------------------------------------------------------------


def _person_version(ctx: Context, user_id: str) -> int:
    """사람 차단·해제 사건의 판본: 그 사람에 대한 강제 조치 기록 수 + 1(같은 초에도 겹치지 않음)."""
    row = fetchone(
        ctx.conn,
        "SELECT count(*) AS n FROM mint.forced_actions WHERE instance_id = %s AND target = %s"
        " AND action IN ('person_lockout', 'person_unlock')",
        (ctx.instance_id, user_id),
    )
    return row["n"] + 1


def end_sessions(ctx: Context, user_id: str, reason: str) -> str:
    """사람의 콘솔·직원 세션을 모두 끝낸다. 키와 MCP 호출은 그대로다."""
    require_role(ctx, "deny")
    if ctx.operator.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 세션을 종료할 수 있습니다.")
    reason = _reason(reason)
    with transact(ctx):
        sessions = fetchall(
            ctx.conn,
            "SELECT id_hash FROM mint.console_sessions"
            " WHERE instance_id = %s AND user_id = %s AND revoked_at IS NULL",
            (ctx.instance_id, user_id),
        )
        if not sessions:
            raise ControlError("끝낼 활성 세션이 없습니다.")
        ended = sum(
            console_sessions.revoke(
                ctx.conn, ctx.instance_id, s["id_hash"], actor=ctx.operator.name, reason=reason
            )
            for s in sessions
        )
        return record(ctx, "sessions_end", user_id, reason, impact={"sessions": ended})


def lockout(ctx: Context, issuer: Any, user_id: str, reason: str) -> str:
    """사람 전체 차단: 모든 MCP 호출 거부(denial), PC 키·앱 자격 해제, 콘솔 세션 종료.

    관리자도 쓸 수 있지만 본인과 Root는 대상으로 삼을 수 없다(Root는 Root만).
    """
    require_role(ctx, "deny")
    if ctx.operator.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 사람 전체를 차단할 수 있습니다.")
    reason = _reason(reason)
    if user_id == ctx.operator.user_id:
        raise ControlError("본인은 차단할 수 없습니다.")
    target_root = fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.operators o JOIN mint.settings s USING (instance_id)"
        " WHERE o.instance_id = %s AND o.user_id = %s AND (o.name = 'root'"
        " OR o.name = ANY(s.root_operators))",
        (ctx.instance_id, user_id),
    )
    if target_root and not is_root(ctx):
        raise AdminError(AdminCode.FORBIDDEN, "Root는 Root만 차단할 수 있습니다.")
    results: dict[str, Any] = {}
    with transact(ctx):
        existing = fetchone(
            ctx.conn,
            "SELECT id FROM mint.denials WHERE instance_id = %s AND scope_type = 'user'"
            " AND scope_id = %s AND server_id IS NULL AND tools IS NULL AND lifted_at IS NULL"
            " AND reason LIKE %s",  # 「MCP 차단」 같은 다른 차단은 해제가 따로라 재사용하지 않는다
            (ctx.instance_id, user_id, LOCKOUT_REASON_PREFIX + "%"),
        )
        results["denial"] = (
            str(existing["id"])
            if existing
            else approval_domain.create_denial(
                ctx,
                scope_type="user",
                scope_id=user_id,
                server_id=None,
                tools=None,
                reason=LOCKOUT_REASON_PREFIX + reason,
                org_id=None,
            )
        )
        results["pcs"] = 0
        if issuer is not None:
            try:
                results["pcs"] = endpoint_kits.revoke_keys(
                    ctx.conn, issuer, ctx.instance_id, user_id, ctx.operator.name
                )
            except ControlError:
                results["pcs"] = 0  # 연결된 PC가 없다
        sessions = fetchall(
            ctx.conn,
            "SELECT id_hash FROM mint.console_sessions"
            " WHERE instance_id = %s AND user_id = %s AND revoked_at IS NULL",
            (ctx.instance_id, user_id),
        )
        results["sessions"] = sum(
            console_sessions.revoke(
                ctx.conn, ctx.instance_id, s["id_hash"], actor=ctx.operator.name, reason="전체 차단"
            )
            for s in sessions
        )
        ctx.emit(
            EventKind.PERSON_LOCKOUT,
            user_id,
            _person_version(ctx, user_id),
            {"user_id": user_id, "reason": reason, **results},
        )
        enqueue_job(ctx, "kit_key_sync", "all")
        return record(
            ctx,
            "person_lockout",
            user_id,
            reason,
            impact=results,
            refs={"denial_id": results["denial"]},
        )


def unlock(ctx: Context, user_id: str, reason: str) -> str:
    """전체 차단을 푼다. 해제된 PC 키는 돌아오지 않는다(다시 설치해야 한다)."""
    require_role(ctx, "denial lift")
    if ctx.operator.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 전체 차단을 풀 수 있습니다.")
    reason = _reason(reason)
    with transact(ctx):
        rows = fetchall(
            ctx.conn,
            "SELECT id FROM mint.denials WHERE instance_id = %s AND scope_type = 'user'"
            " AND scope_id = %s AND server_id IS NULL AND tools IS NULL AND lifted_at IS NULL"
            " AND reason LIKE %s",
            (ctx.instance_id, user_id, LOCKOUT_REASON_PREFIX + "%"),
        )
        if not rows:
            raise not_found("이 사람에게 걸린 전체 차단이 없습니다.")
        for row in rows:
            approval_domain.lift_denial(ctx, str(row["id"]))
        ctx.emit(
            EventKind.PERSON_UNLOCKED,
            user_id,
            _person_version(ctx, user_id),
            {"user_id": user_id, "reason": reason},
        )
        last = fetchone(
            ctx.conn,
            "SELECT id FROM mint.forced_actions WHERE instance_id = %s"
            " AND action = 'person_lockout' AND target = %s AND undone_by IS NULL"
            " ORDER BY created_at DESC LIMIT 1",
            (ctx.instance_id, user_id),
        )
        return record(
            ctx,
            "person_unlock",
            user_id,
            reason,
            refs={"denials": [str(r["id"]) for r in rows]},
            undoes=str(last["id"]) if last else None,
        )


# --- 기록·전파 ------------------------------------------------------------------------------


def recent(conn, instance_id: str, limit: int = 100) -> list[dict]:
    rows = fetchall(
        conn,
        "SELECT * FROM mint.forced_actions WHERE instance_id = %s"
        " ORDER BY created_at DESC LIMIT %s",
        (instance_id, limit),
    )
    return [{**row, "points": propagation(conn, instance_id, row)} for row in rows]


def propagation(conn, instance_id: str, action: dict) -> list[dict]:
    """지점별 반영 상태. 확인할 수 없는 지점은 「확인 못 함」으로 둔다."""
    since: datetime = action["created_at"]
    sync = fetchone(
        conn,
        "SELECT max(updated_at) AS at FROM mint.jobs WHERE instance_id = %s"
        " AND kind = 'kit_key_sync' AND status = 'done' AND created_at >= %s",
        (instance_id, since),
    )
    pcs = fetchone(
        conn,
        "SELECT count(*) AS total, count(*) FILTER (WHERE reported_at >= %s) AS reported"
        " FROM mint.endpoint_installs WHERE instance_id = %s AND revoked_at IS NULL",
        (since, instance_id),
    )
    return [
        {"point": "MINT 판정", "state": "반영", "at": since},
        {
            "point": "LiteLLM 키 권한",
            "state": "반영" if sync and sync["at"] else "대기",
            "at": sync["at"] if sync else None,
            "limit": "60초",
        },
        {
            "point": "PC 수신",
            "state": f"{pcs['reported']}/{pcs['total']}대",
            "at": None,
            "limit": "다음 보고(약 20초)",
        },
        {"point": "관리 밖 경로", "state": "확인되지 않음", "at": None},
    ]


def verify(ctx: Context, action_id: str) -> list[dict]:
    require_role(ctx, "deny")
    with transact(ctx):
        row = fetchone(
            ctx.conn,
            "SELECT * FROM mint.forced_actions WHERE instance_id = %s AND id = %s FOR UPDATE",
            (ctx.instance_id, action_id),
        )
        if row is None:
            raise not_found("강제 조치 기록을 찾을 수 없습니다.")
        points = propagation(ctx.conn, ctx.instance_id, row)
        ctx.conn.execute(
            "UPDATE mint.forced_actions SET verified_at = now(), propagation = %s::jsonb"
            " WHERE instance_id = %s AND id = %s",
            (json.dumps(points, ensure_ascii=False, default=str), ctx.instance_id, action_id),
        )
        return points


# --- Root 표지 ------------------------------------------------------------------------------


def set_root_operator(ctx: Context, name: str, on: bool, reason: str) -> str:
    """운영자에게 Root 표지를 주거나 푼다. Root만 할 수 있다(감사 사건은 운영자 역할 변경 사건)."""
    require_root(ctx)
    reason = _reason(reason)
    with transact(ctx):
        target = fetchone(
            ctx.conn,
            "SELECT role FROM mint.operators WHERE instance_id = %s AND name = %s"
            " AND (expires_at IS NULL OR expires_at > now())",
            (ctx.instance_id, name),
        )
        if target is None:
            raise not_found(f"운영자 {name}이(가) 없습니다.")
        settings = fetchone(
            ctx.conn,
            "SELECT root_operators, settings_version FROM mint.settings"
            " WHERE instance_id = %s FOR UPDATE",
            (ctx.instance_id,),
        )
        marked = list(settings["root_operators"])
        is_marked = name == "root" or name in marked
        if on:
            if target["role"] != "admin":
                raise ControlError("관리자 역할인 운영자만 Root로 지정할 수 있습니다.")
            if is_marked:
                raise conflict(f"{name}은(는) 이미 Root입니다.")
            marked.append(name)
        else:
            if name == "root":
                raise ControlError("기본 계정 root는 항상 Root이고 마지막 Root입니다.")
            if name == ctx.operator.name:
                raise ControlError("본인의 Root 표지는 풀 수 없습니다.")
            if not is_marked:
                raise conflict(f"{name}은(는) Root가 아닙니다.")
            marked.remove(name)
        row = fetchone(
            ctx.conn,
            "UPDATE mint.settings SET root_operators = %s WHERE instance_id = %s"
            " AND settings_version = %s RETURNING settings_version",
            (marked, ctx.instance_id, settings["settings_version"]),
        )
        if row is None:
            raise conflict("그 사이 설정이 바뀌었습니다. 새로 고침한 뒤 다시 시도하십시오.")
        ctx.emit(
            EventKind.OPERATOR_ROLE_CHANGED,
            f"root.{name}",
            row["settings_version"],
            {"name": name, "root": on, "reason": reason},
        )
        record(ctx, "root_set" if on else "root_unset", name, reason)
        return name

