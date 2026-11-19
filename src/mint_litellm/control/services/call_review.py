"""도구별 「호출별 검토」 지정. 유효한 이용 승인의 high_risk_tools 조건에 도구를 넣고 뺀다."""

import json

from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.services.base import service


def marked(conn, instance: str, server_id: str) -> set[str]:
    rows = fetchall(
        conn,
        "SELECT conditions -> 'high_risk_tools' AS tools FROM mint.approvals"
        " WHERE instance_id = %s AND server_id = %s AND status = 'active'",
        (instance, server_id),
    )
    return {t for r in rows for t in (r["tools"] or [])}


@service("call-approval-rule add")
def set_tool(ctx: Context, server_id: str, tool: str, on: bool) -> int:
    """서버의 유효 승인 전부에 반영하고 바꾼 승인 수를 돌려준다."""
    rows = fetchall(
        ctx.conn,
        "SELECT id, conditions FROM mint.approvals WHERE instance_id = %s AND server_id = %s"
        " AND status = 'active' FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    changed = 0
    for r in rows:
        conditions = dict(r["conditions"] or {})
        tools = set(conditions.get("high_risk_tools") or [])
        if (tool in tools) == on:
            continue
        tools = tools | {tool} if on else tools - {tool}
        if tools:
            conditions["high_risk_tools"] = sorted(tools)
        else:
            conditions.pop("high_risk_tools", None)
        ctx.conn.execute(
            "UPDATE mint.approvals SET conditions = %s::jsonb, state_version = state_version + 1"
            " WHERE instance_id = %s AND id = %s",
            (json.dumps(conditions), ctx.instance_id, r["id"]),
        )
        changed += 1
    return changed
