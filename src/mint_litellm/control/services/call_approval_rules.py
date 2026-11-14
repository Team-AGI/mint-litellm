"""상시 승인 규칙 서비스."""

from datetime import datetime, timedelta

import psycopg

from mint_litellm.control import call_approval_rules as domain
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.services.base import lock_version, service


@service("call-approval-rule add")
def add(
    ctx: Context,
    *,
    org_id: str,
    action_class: str,
    window_minutes: int,
    principal_type: str | None = None,
    principal_id: str | None = None,
    server_id: str | None = None,
    tool_pattern: str | None = None,
    valid_until: datetime | None = None,
) -> str:
    return domain.add(
        ctx, org_id=org_id, action_class=action_class, window_minutes=window_minutes,
        principal_type=principal_type, principal_id=principal_id, server_id=server_id,
        tool_pattern=tool_pattern, valid_until=valid_until,
    )


@service("call-approval-rule disable")
def disable(ctx: Context, rule_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "call_approval_rules", rule_id, expected_version)
    domain.disable(ctx, rule_id)


def impact(
    conn: psycopg.Connection,
    instance_id: str,
    *,
    org_id: str,
    action_class: str,
    principal_type: str | None = None,
    principal_id: str | None = None,
    server_id: str | None = None,
    tool_pattern: str | None = None,
    days: int = 7,
) -> dict[str, int]:
    """이 조건의 규칙이 있었다면 최근 ``days``일 호출 중 자동 승인됐을 건수(조회만).

    맞춤 기준은 요청을 열 때 쓰는 데이터베이스 함수와 같다: 호출이 계약에 묶여 있고 계약의
    행위 분류가 규칙과 같아야 한다. ``matched``는 해당 건수, ``by_person``은 그중 규칙이 아닌
    방식으로 처리된 건수다.
    """
    row = fetchone(
        conn,
        "SELECT count(*) AS matched, count(*) FILTER (WHERE c.approved_by IS NULL"
        " OR c.approved_by NOT LIKE 'rule:%%') AS by_person"
        " FROM mint.call_approvals c JOIN mint.tool_contracts t ON t.instance_id = c.instance_id"
        " AND t.id = c.contract_id AND t.server_id = c.server_id AND t.tool = c.tool"
        " WHERE c.instance_id = %s AND c.org_id = %s AND c.requested_at > now() - %s"
        " AND t.action_type = %s"
        " AND (%s::text IS NULL OR (c.principal_type = %s AND c.principal_id = %s))"
        " AND (%s::text IS NULL OR c.server_id = %s)"
        " AND (%s::text IS NULL"
        "  OR c.tool LIKE replace(replace(%s, '_', '\\_'), '*', '%%'))",
        (instance_id, org_id, timedelta(days=days), action_class, principal_type, principal_type,
         principal_id, server_id, server_id, tool_pattern, tool_pattern),
    )
    return {"matched": row["matched"], "by_person": row["by_person"]}
