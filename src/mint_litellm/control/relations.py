"""이용 관계."""

from mint_litellm.control import approvals, orgs
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.control.services import base
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7


def add(ctx: Context, org_id: str, server_id: str, purpose: str, team_id: str | None) -> str:
    orgs.require_active(ctx, org_id)
    server = fetchone(
        ctx.conn,
        "SELECT status FROM mint.servers WHERE instance_id = %s AND server_id = %s",
        (ctx.instance_id, server_id),
    )
    if server is None:
        raise ControlError(
            f"등록되지 않은 서버입니다: {server_id}. server register를 먼저 실행하십시오."
        )
    if server["status"] in ("rejected", "terminating", "terminated"):
        raise ControlError(f"서버 {server_id}는 {server['status']} 상태라 관계를 만들 수 없습니다.")
    if fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.usage_relations WHERE instance_id = %s AND org_id = %s"
        " AND server_id = %s AND purpose = %s AND team_id IS NOT DISTINCT FROM %s",
        (ctx.instance_id, org_id, server_id, purpose, team_id),
    ):
        raise ControlError("같은 조직·팀·목적·서버의 이용 관계가 이미 있습니다.")
    relation_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.usage_relations (id, instance_id, org_id, team_id, purpose, server_id)"
        " VALUES (%s, %s, %s, %s, %s, %s) RETURNING state_version",
        (relation_id, ctx.instance_id, org_id, team_id, purpose, server_id),
    )
    ctx.emit(
        EventKind.RELATION_CREATED,
        relation_id,
        row["state_version"],
        {
            "relation_id": str(relation_id),
            "org_id": org_id,
            "team_id": team_id,
            "purpose": purpose,
            "server_id": server_id,
        },
    )
    return str(relation_id)


def terminate(ctx: Context, relation_id: str) -> None:
    """관계를 종료 중으로 바꾸고, 그 관계의 활성 승인을 바로 철회한다.

    LiteLLM의 권한을 거둔 것을 읽어 확인하고 ``terminated``로 마무리하는 일은
    ``relation_finalize`` 작업이 한다(``sync_jobs``).
    """
    row = fetchone(
        ctx.conn,
        "UPDATE mint.usage_relations SET status = 'terminating' WHERE instance_id = %s"
        " AND id = %s AND status = 'active' RETURNING state_version, org_id, server_id",
        (ctx.instance_id, relation_id),
    )
    if row is None:
        raise not_found(f"활성 상태의 이용 관계 {relation_id}이(가) 없습니다.")
    ctx.emit(
        EventKind.RELATION_TERMINATING,
        relation_id,
        row["state_version"],
        {
            "relation_id": relation_id,
            "org_id": row["org_id"],
            "server_id": row["server_id"],
            "phase": "started",
        },
    )
    for approval in fetchall(
        ctx.conn,
        "SELECT id FROM mint.approvals WHERE instance_id = %s AND relation_id = %s"
        " AND status = 'active' ORDER BY id",
        (ctx.instance_id, relation_id),
    ):
        approvals.revoke(ctx, str(approval["id"]), "이용 관계 종료", False)
    base.enqueue_job(ctx, "relation_finalize", relation_id)
