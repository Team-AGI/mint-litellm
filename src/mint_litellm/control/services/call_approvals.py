"""호출별 승인 서비스."""

from mint_litellm.control import approvals as domain
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.services.base import lock_version, service


@service("call-approval request")
def request(
    ctx: Context,
    *,
    org_id: str,
    principal_type: str,
    principal_id: str,
    server_id: str,
    tool: str,
    args_fp: str,
    fp_key_version: int,
    policy_version_id: str | None,
    expires_in_minutes: int,
    requested_by: str,
    target: str | None = None,
    action: str | None = None,
) -> str:
    return domain.call_request(
        ctx,
        org_id=org_id,
        principal_type=principal_type,
        principal_id=principal_id,
        server_id=server_id,
        tool=tool,
        args_fp=args_fp,
        fp_key_version=fp_key_version,
        policy_version_id=policy_version_id,
        expires_in_minutes=expires_in_minutes,
        requested_by=requested_by,
        target=target,
        action=action,
    )


@service("call-approval approve")
def approve(
    ctx: Context,
    call_id: str,
    second: Operator | None,
    *,
    expected_version: int | None = None,
    window_minutes: int | None = None,
) -> None:
    lock_version(ctx, "call_approvals", call_id, expected_version)
    domain.call_approve(ctx, call_id, second, window_minutes)


@service("call-approval reject")
def reject(
    ctx: Context, call_id: str, *, expected_version: int | None = None, reason: str | None = None
) -> None:
    lock_version(ctx, "call_approvals", call_id, expected_version)
    domain.call_reject(ctx, call_id, reason)


@service("call-approval cancel")
def cancel(ctx: Context, call_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "call_approvals", call_id, expected_version)
    domain.call_cancel(ctx, call_id)
