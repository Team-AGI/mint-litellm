"""권한 동기화 조회와 재개 서비스."""

from mint_litellm.control import sync_state
from mint_litellm.control.alerts import resolve as resolve_alert
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.control.services.base import enqueue_job, lock_version, service
from mint_litellm.types.events import EventKind


@service("sync status")
def status(ctx: Context, *, held_only: bool = False) -> list[dict]:
    """LiteLLM 반영 상태. MINT가 관리하는 항목(철회로 거둔 행 제외)만 돌려준다."""
    return fetchall(
        ctx.conn,
        "SELECT id, target_type, target_id, item, server_id, tools, preexisting, observed,"
        " observed_at, missing_count, missing_window_start, held, held_at, last_applied_at,"
        " state_version FROM mint.litellm_grants WHERE instance_id = %s"
        " AND observed IS NOT NULL AND (NOT %s OR held)"
        " ORDER BY target_type, target_id, server_id, item",
        (ctx.instance_id, held_only),
    )


@service("sync resume")
def resume(ctx: Context, grant_id: str, *, expected_version: int | None = None) -> None:
    """보류된 항목을 풀고 카운터를 지운 뒤 그 대상의 동기화를 등록한다."""
    lock_version(ctx, "litellm_grants", grant_id, expected_version)
    row = fetchone(
        ctx.conn,
        "SELECT * FROM mint.litellm_grants WHERE instance_id = %s AND id = %s FOR UPDATE",
        (ctx.instance_id, grant_id),
    )
    if row is None:
        raise not_found(f"동기화 항목 {grant_id}이(가) 없습니다.")
    if not row["held"]:
        raise ControlError(f"동기화 항목 {grant_id}은(는) 보류 상태가 아닙니다.")
    updated = fetchone(
        ctx.conn,
        "UPDATE mint.litellm_grants SET held = false, held_at = NULL, missing_count = 0,"
        " missing_window_start = NULL WHERE id = %s RETURNING state_version",
        (grant_id,),
    )
    ctx.emit(
        EventKind.SYNC_APPLIED,
        grant_id,
        updated["state_version"],
        {"target_type": row["target_type"], "target_id": row["target_id"], "item": row["item"],
         "server_id": row["server_id"], "action": "resume"},
    )
    resolve_alert(ctx.conn, ctx.instance_id, f"sync_divergence:held:{grant_id}")
    if row["target_type"] in sync_state.SYNC_SCOPES:
        enqueue_job(ctx, "sync_target", sync_state.target_ref(row["target_type"], row["target_id"]))
    else:
        enqueue_job(ctx, "sync_server", row["server_id"])
