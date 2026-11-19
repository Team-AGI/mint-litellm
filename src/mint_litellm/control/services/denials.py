"""거부 서비스."""

from mint_litellm.control import approvals as domain
from mint_litellm.control.context import Context
from mint_litellm.control.services.base import lock_version, service


@service("deny")
def deny(
    ctx: Context,
    *,
    scope_type: str,
    scope_id: str,
    server_id: str | None,
    tools: list[str] | None,
    reason: str,
    org_id: str | None,
    action_types: list[str] | None = None,
) -> str:
    return domain.create_denial(
        ctx, scope_type=scope_type, scope_id=scope_id, server_id=server_id, tools=tools,
        reason=reason, org_id=org_id, action_types=action_types,
    )


@service("denial lift")
def lift(ctx: Context, denial_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "denials", denial_id, expected_version)
    domain.lift_denial(ctx, denial_id)
