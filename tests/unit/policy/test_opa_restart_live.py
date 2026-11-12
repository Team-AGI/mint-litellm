import asyncio
import os
import shlex
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from mint_litellm.plugin.policy.bundle import prepare_bundle, publish_bundle
from mint_litellm.plugin.policy.opa_client import OPAClient
from mint_litellm.types.reason_codes import Reason

ROOT = Path(__file__).resolve().parents[3]
IMAGE = (
    "openpolicyagent/opa:1.21.4@sha256:"
    "12420358d3f22a0cd2424ddc44a16e292ecb42825d3dfbca779986006822a3f6"
)
REQUIRED_ENV = ("MINT_TEST_OPA_URL", "MINT_TEST_OPA_BUNDLE_DIR", "MINT_TEST_OPA_CONTAINER")

POLICY_INPUT = {
    "principal": {
        "type": "user", "id": "u", "key_id": "k", "org_id": "o", "org_source": "user",
        "team_id": None, "claimed_end_user_id": None,
    },
    "server": {
        "id": "s", "status": "approved", "transport": "http", "auth_type": "none",
        "provider_allowed": True, "auth_server_allowed": True, "contract_status": "none",
    },
    "tool": {"name": "read"},
    "arguments": {"keys": [], "sizes": {}},
    "approval": {
        "present": True, "id": "a", "class": "standard", "scope_type": "user",
        "expires_in_days": 1, "conditions": {},
    },
    "consent": {"status": "not_applicable", "source": None},
    "time": {"iso": "instant", "ns": 345600000000000},
    "settings": {"high_risk_tools": []},
    "mode": "enforce",
    "operation": "tool_call",
}


def docker(*arguments: str) -> None:
    command = [*shlex.split(os.environ.get("MINT_TEST_DOCKER", "docker")), *arguments]
    subprocess.run(command, check=True, capture_output=True)


def test_connection_lost_on_opa_restart_blocks_then_reconnects():
    if not all(os.environ.get(key) for key in REQUIRED_ENV):
        pytest.skip("live OPA URL, bundle directory and container name are required")
    opa_url = os.environ["MINT_TEST_OPA_URL"].rstrip("/")
    container = os.environ["MINT_TEST_OPA_CONTAINER"]
    mount = os.environ.get("MINT_TEST_DOCKER_SOURCE", str(ROOT.resolve()))
    opa = [*shlex.split(os.environ.get("MINT_TEST_DOCKER", "docker")),
           "run", "--rm", "-v", f"{mount}:/work:ro", IMAGE]
    bundle = prepare_bundle(ROOT, "restart", opa=opa, opa_policy_path="/work/policy")
    publish_bundle(Path(os.environ["MINT_TEST_OPA_BUNDLE_DIR"]) / "mint.tar.gz", bundle.archive)

    async def evaluate(client, budget=2.0):
        return await client.evaluate(
            POLICY_INPUT, policy_version_id="restart", bundle_sha256=bundle.bundle_sha256,
            budget_seconds=budget,
        )

    async def wait_loaded():
        async with httpx.AsyncClient(trust_env=False) as http:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    reply = await http.get(f"{opa_url}/v1/data/mint/meta")
                    if reply.json().get("result", {}).get("policy_version_id") == "restart":
                        return
                except (httpx.HTTPError, ValueError):
                    pass
                await asyncio.sleep(0.2)
        raise AssertionError("bundle was not loaded")

    async def run():
        client = OPAClient(opa_url, 2)
        try:
            await wait_loaded()
            assert (await evaluate(client)).output is not None
            assert (await evaluate(client)).output is not None
            docker("stop", container)
            for _ in range(2):
                down = await evaluate(client)
                assert down.output is None
                assert down.failure.reason_code == Reason.DEPENDENCY_FAILURE
            docker("start", container)
            recovered = None
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                result = await evaluate(client)
                if result.output is not None:
                    recovered = result
                    break
                assert result.failure.reason_code == Reason.DEPENDENCY_FAILURE
                await asyncio.sleep(0.3)
            assert recovered is not None
            assert recovered.output.decision == "Allow"
        finally:
            await client.aclose()

    asyncio.run(run())
