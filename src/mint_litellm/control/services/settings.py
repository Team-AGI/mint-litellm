"""저장된 설정 서비스."""

from mint_litellm.control import orgs as org_domain
from mint_litellm.control import settings_store as domain
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.services.base import lock_version, service
from mint_litellm.types.events import EventKind
from mint_litellm.types.settings import Mode


@service("init")
def initialize(
    ctx: Context, org_id: str, org_name: str, control_key: str | None = None
) -> str | None:
    """설정 행이 없을 때만 만들고 기본 조직을 정한다. 다시 실행해도 바꾼 값을 건드리지 않는다.

    ``control_key``(제어 평면 LiteLLM 키)가 주어지면 저장된 값이 없을 때 그 토큰을 저장한다.
    """
    version = domain.ensure(ctx.conn, ctx.instance_id)
    if version is not None:
        ctx.emit(
            EventKind.SETTINGS_CHANGED,
            ctx.instance_id,
            version,
            {"created": True, "observable_policy_ids": list(domain.DEFAULT_OBSERVABLE_POLICY_IDS)},
        )
        if not fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.orgs WHERE instance_id = %s AND org_id = %s",
            (ctx.instance_id, org_id),
        ):
            org_domain.add(ctx, org_id, org_name)
        domain.set_default_org(ctx, org_id)
    if control_key:
        return domain.set_control_key(ctx, control_key, keep_existing=True)
    return None


@service("settings default-org")
def set_default_org(
    ctx: Context, org_id: str | None, *, expected_version: int | None = None
) -> None:
    lock_version(ctx, "settings", ctx.instance_id, expected_version)
    domain.set_default_org(ctx, org_id)


@service("settings mode")
def set_mode(
    ctx: Context, mode: Mode, ceiling: Mode, *, expected_version: int | None = None
) -> None:
    lock_version(ctx, "settings", ctx.instance_id, expected_version)
    domain.set_mode(ctx, mode, ceiling)


@service("settings observable")
def set_observable(
    ctx: Context,
    reasons: list[str] | None,
    policy_ids: list[str] | None,
    *,
    expected_version: int | None = None,
) -> None:
    lock_version(ctx, "settings", ctx.instance_id, expected_version)
    domain.set_observable(ctx, reasons, policy_ids)


@service("settings control-key")
def set_control_key(
    ctx: Context,
    key: str | None,
    *,
    keep_existing: bool = False,
    expected_version: int | None = None,
) -> str:
    """제어 평면 LiteLLM 키의 토큰을 저장한다. 도구 목록 면제(pin)가 이 키를 알아보는 데 쓴다."""
    lock_version(ctx, "settings", ctx.instance_id, expected_version)
    return domain.set_control_key(ctx, key, keep_existing=keep_existing)
