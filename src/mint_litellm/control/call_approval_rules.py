"""상시 승인 규칙. 규칙에 맞는 호출은 사람 승인 없이 규칙이 정한 기간의 승인이 자동으로 열린다.

삭제·외부 전송·자격 접근은 규칙을 만들 수 없고, 승인된 도구 계약이 없어 행위 분류를 모르는 호출은
규칙에 맞지 않는다. 맞춤은 판정 프로세스가 요청을 열 때 데이터베이스 함수가 한다.
"""

import re
from datetime import datetime

from mint_litellm.control import orgs
from mint_litellm.control.approvals import PRINCIPAL_TYPES
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

ACTION_CLASSES = ("read", "write")
WINDOWS = (10, 30)
SCOPES = ("org", "principal")
_TOOL_PATTERN = re.compile(r"[A-Za-z0-9_.:*-]{1,128}")


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
    if action_class not in ACTION_CLASSES:
        raise ControlError(
            f"행위 분류는 {', '.join(ACTION_CLASSES)} 중 하나여야 합니다. "
            "삭제·외부 전송·자격 접근은 상시 승인 규칙을 만들 수 없습니다."
        )
    if window_minutes not in WINDOWS:
        raise ControlError("사용 기간은 10분 또는 30분이어야 합니다.")
    if (principal_type is None) != (principal_id is None):
        raise ControlError("주체 종류와 주체 식별자는 함께 주어야 합니다.")
    if principal_type is not None and principal_type not in PRINCIPAL_TYPES:
        raise ControlError(f"주체 종류는 {', '.join(PRINCIPAL_TYPES)} 중 하나여야 합니다.")
    if tool_pattern is not None and not _TOOL_PATTERN.fullmatch(tool_pattern):
        raise ControlError("도구 패턴은 영문·숫자, _ . : - 및 *만 쓸 수 있습니다(128자 이내).")
    orgs.require_active(ctx, org_id)
    if server_id is not None and fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.servers WHERE instance_id = %s AND server_id = %s"
        " AND contract_status = 'managed'",
        (ctx.instance_id, server_id),
    ) is None:
        raise ControlError(f"서버 {server_id}은(는) 계약 관리 서버가 아닙니다.")
    rule_id = new_uuid7()
    scope = "principal" if principal_type else "org"
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.call_approval_rules (id, instance_id, org_id, scope_type,"
        " principal_type, scope_id, server_id, action_class, tool_pattern, window_minutes,"
        " valid_until, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " RETURNING state_version",
        (rule_id, ctx.instance_id, org_id, scope, principal_type, principal_id, server_id,
         action_class, tool_pattern, window_minutes, valid_until, ctx.operator.name),
    )
    ctx.emit(
        EventKind.CALL_APPROVAL_RULE_CREATED, rule_id, row["state_version"],
        {"rule_id": str(rule_id), "org_id": org_id, "scope_type": scope,
         "principal_type": principal_type, "principal_id": principal_id, "server_id": server_id,
         "action_class": action_class, "tool_pattern": tool_pattern,
         "window_minutes": window_minutes,
         "valid_until": valid_until.isoformat() if valid_until else None},
    )
    return str(rule_id)


def disable(ctx: Context, rule_id: str) -> None:
    row = fetchone(
        ctx.conn,
        "UPDATE mint.call_approval_rules SET status = 'disabled', disabled_by = %s,"
        " disabled_at = clock_timestamp() WHERE instance_id = %s AND id = %s"
        " AND status = 'active' RETURNING state_version, org_id, server_id, action_class",
        (ctx.operator.name, ctx.instance_id, rule_id),
    )
    if row is None:
        raise not_found(f"사용 중인 상시 승인 규칙 {rule_id}이(가) 없습니다.")
    ctx.emit(
        EventKind.CALL_APPROVAL_RULE_DISABLED, rule_id, row["state_version"],
        {"rule_id": rule_id, "org_id": row["org_id"], "server_id": row["server_id"],
         "action_class": row["action_class"]},
    )
