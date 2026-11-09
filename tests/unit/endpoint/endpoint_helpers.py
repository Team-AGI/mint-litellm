"""결정 경로·훅 시험이 함께 쓰는 값 생성기."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugin"))

from plugin_helpers import (  # noqa: E402
    INSTANCE,
    KEY,
    approval,
    harness,
    server_row,
    snapshot,
)

from mint_litellm.compat import litellm_1_106 as compat  # noqa: E402
from mint_litellm.endpoint.contract import LocalExecContract  # noqa: E402
from mint_litellm.endpoint.decide import (  # noqa: E402
    ContractRegistry,
    LocalServer,
    stdio_identity_hash,
)

SERVER_ID = "srv-local"
HASH_A = "a" * 64
HASH_B = "b" * 64


def contract(**override: Any) -> LocalExecContract:
    args: dict[str, Any] = {
        "executable": "/usr/bin/python3",
        "argv": ("/opt/mcp/count_mcp.py", "/var/log/count.log"),
        "cwd": "/work",
        "executable_sha256": HASH_A,
        "script_sha256": HASH_B,
        "env": {"MODE": "test"},
        "secret_refs": {},
    }
    args.update(override)
    return LocalExecContract(**args)


def registry(**override: Any) -> ContractRegistry:
    return ContractRegistry({"cnt": LocalServer(SERVER_ID, contract(**override))})


def body(**override: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "server": "cnt",
        "tool": "echo",
        "arguments": {"text": "hi"},
        "contract": contract().model_dump(mode="json"),
        "tool_use_id": "toolu_1",
    }
    data.update(override)
    return data


def auth(**override: Any) -> SimpleNamespace:
    args: dict[str, Any] = {
        "token": KEY,
        "api_key": "sk-user",
        "user_id": "u1",
        "team_id": "t1",
        "metadata": None,
        "end_user_id": None,
    }
    args.update(override)
    return SimpleNamespace(**args)


def principal_of(a: Any, *, instance_id: str):
    return compat.principal_from_auth(a, instance_id=instance_id, master_alias="master-alias")


def local_snapshot(**override: Any):
    args: dict[str, Any] = {
        "server": server_row(
            server_id=SERVER_ID, url_sha256=stdio_identity_hash(SERVER_ID), transport="stdio"
        ),
        "approvals": (approval(tools=("echo",)),),
    }
    args.update(override)
    return snapshot(**args)


def runtime(tmp_path, **override: Any):
    h = harness(tmp_path, local_snapshot(), **override)
    return h, SimpleNamespace(config=h.deps.config, deps=h.deps)


__all__ = ["INSTANCE", "KEY"]
