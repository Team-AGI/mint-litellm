"""승인과 철회 서비스."""

from datetime import datetime

from mint_litellm.control import approvals as domain
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.services.base import (
    Prefetched,
    lock_version,
    require_not_frozen,
    require_role,
    service,
    transact,
)

_LITELLM_READ = {"key": "get_key", "team": "get_team", "user": "get_user"}


def approve(
    ctx: Context,
    litellm: LiteLLMAdmin,
    *,
    relation_id: str,
    scope_type: str,
    scope_id: str,
    tools: list[str],
    valid_from: datetime,
    valid_until: datetime,
    approval_class: str,
    basis_text: str,
    requested_by: str,
    allowlist_ids: list[str],
    second: Operator | None,
    conditions: dict | None = None,
    expected_version: int | None = None,
) -> tuple[str, list[str]]:
    """승인을 만든다. ``expected_version``은 이용 관계의 ``state_version``이다."""
    require_role(ctx, "approve")
    require_not_frozen(ctx)
    facts = Prefetched(litellm)
    if scope_type in _LITELLM_READ:
        facts.prefetch(_LITELLM_READ[scope_type], scope_id).prefetch("list_servers")
    with transact(ctx):
        lock_version(ctx, "usage_relations", relation_id, expected_version)
        return domain.approve(
            ctx,
            facts,  # type: ignore[arg-type]
            relation_id=relation_id,
            scope_type=scope_type,
            scope_id=scope_id,
            tools=tools,
            valid_from=valid_from,
            valid_until=valid_until,
            approval_class=approval_class,
            basis_text=basis_text,
            requested_by=requested_by,
            allowlist_ids=allowlist_ids,
            second=second,
            conditions=conditions,
        )


@service("revoke")
def revoke(
    ctx: Context,
    approval_id: str,
    reason: str,
    deny: bool,
    *,
    expected_version: int | None = None,
) -> None:
    lock_version(ctx, "approvals", approval_id, expected_version)
    domain.revoke(ctx, approval_id, reason, deny)
