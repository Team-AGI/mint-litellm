"""도구별 「호출별 검토」 지정. 지정한 도구만 호출마다 승인을 받고, 기본은 모두 꺼짐이다."""

from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.services.base import service


def marked(conn, instance: str, server_id: str) -> set[str]:
    rows = fetchall(
        conn,
        "SELECT tool FROM mint.call_review_tools WHERE instance_id = %s AND server_id = %s",
        (instance, server_id),
    )
    return {r["tool"] for r in rows}


@service("call-approval-rule add")
def set_tool(ctx: Context, server_id: str, tool: str, on: bool) -> None:
    if on:
        ctx.conn.execute(
            "INSERT INTO mint.call_review_tools (instance_id, server_id, tool, created_by)"
            " VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (ctx.instance_id, server_id, tool, ctx.operator.name),
        )
    else:
        ctx.conn.execute(
            "DELETE FROM mint.call_review_tools WHERE instance_id = %s AND server_id = %s"
            " AND tool = %s",
            (ctx.instance_id, server_id, tool),
        )
