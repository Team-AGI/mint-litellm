"""서버 등록과 중지·재개 서비스."""

from collections.abc import Mapping
from typing import Any

from mint_litellm.control import servers as domain
from mint_litellm.control.context import Context
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.services.base import (
    Prefetched,
    enqueue_job,
    lock_version,
    require_role,
    service,
    transact,
)
from mint_litellm.types.exec_contract import ExecContract


def register(
    ctx: Context,
    litellm: LiteLLMAdmin,
    server_id: str,
    url: str | None = None,
    config: Mapping[str, Any] | None = None,
) -> None:
    require_role(ctx, "server register")
    facts = Prefetched(litellm).prefetch("get_server", server_id)
    with transact(ctx):
        domain.register(ctx, facts, server_id, url, config)  # type: ignore[arg-type]


def register_local(ctx: Context, server_id: str, contract: ExecContract) -> None:
    require_role(ctx, "server register-local")
    with transact(ctx):
        domain.register_local(ctx, server_id, contract)


@service("server suspend")
def suspend(ctx: Context, server_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "servers", server_id, expected_version)
    domain.suspend(ctx, server_id)


@service("server resume")
def resume(ctx: Context, server_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "servers", server_id, expected_version)
    domain.resume(ctx, server_id)


@service("server terminate")
def terminate(ctx: Context, server_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "servers", server_id, expected_version)
    domain.terminate(ctx, server_id)
    enqueue_job(ctx, "server_finalize", server_id)
