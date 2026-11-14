"""상시 승인 규칙 서비스."""

from datetime import datetime

from mint_litellm.control import call_approval_rules as domain
from mint_litellm.control.context import Context
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
