"""큰 인자에서도 판정 한 건이 처리 흐름을 오래 잡지 않는다.

네트워크 없이 훅 데이터 해석부터 판정(스냅숏·정책·선기록 대역)까지 한 호출의 CPU 시간을 잰다.
기준은 같은 실행에서 잰 작은 인자의 값에 대한 배수와, 정상 구현이 한참 못 미치는 넉넉한 절대
상한뿐이라 느린 장비에서도 흔들리지 않는다.
"""

import asyncio
import statistics
import time

import pytest
from plugin_helpers import (
    NOW,
    approval,
    evaluator,
    harness,
    resolved_server,
    server_row,
    snapshot,
    user_principal,
)

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.plugin.pipeline import build_request, evaluate_request
from mint_litellm.plugin.snapshot import ToolContractRow
from mint_litellm.types.decision import OperationType

SERVER = server_row(contract_status="managed", last_observed_at=NOW)
CONTRACTS = (ToolContractRow("c1", "server", "search", "none", 1),)
PROSE = "The quick brown fox: see https://example.com/a?b=c and /var/log/x.txt, key=value\n"
KIB = 1024


def arguments_of(kind: str) -> dict:
    if kind == "small":
        return {"q": "hello world"}
    if kind == "string_64k":
        return {"q": "a" * 64 * KIB}
    if kind == "string_128k":
        return {"q": "a" * 128 * KIB}
    if kind == "text_64k":
        return {f"k{i}": (PROSE * 60)[:4000] for i in range(16)}
    if kind == "text_128k":
        return {f"k{i}": (PROSE * 60)[:4000] for i in range(32)}
    if kind == "address_dense_64k":
        return {f"k{i}": "ab://" * 800 for i in range(16)}
    raise AssertionError(kind)


def median_cost(tmp_path, kind: str, runs: int) -> float:
    h = harness(
        tmp_path / kind,
        snapshot(server=SERVER, tool_contracts=CONTRACTS, approvals=(approval(),)),
        evaluate=evaluator(),
    )
    arguments = arguments_of(kind)
    data = {
        "mcp_server_name": "mslearn",
        "mcp_tool_name": "search",
        "mcp_arguments": arguments,
        "messages": [{"role": "user", "content": f"call\nArguments: {arguments}"}],
    }

    async def once() -> float:
        h.store.events.clear()
        started = time.perf_counter()
        request = build_request(
            data,
            None,
            operation=OperationType.TOOL_CALL,
            instance_id="inst",
            hook_parser=compat.parse_hook_data,
            resolver=lambda hook: resolved_server(),
            principal_factory=lambda auth, instance_id: user_principal(),
        )
        outcome = await evaluate_request(request, h.deps)
        elapsed = time.perf_counter() - started
        assert outcome.allowed, outcome.error
        return elapsed

    async def go() -> list[float]:
        await once()
        return [await once() for _ in range(runs)]

    return statistics.median(asyncio.run(go()))


@pytest.fixture(scope="module")
def small(tmp_path_factory) -> float:
    return median_cost(tmp_path_factory.mktemp("small"), "small", 15)


@pytest.mark.parametrize("kind", ["string_64k", "string_128k"])
def test_a_large_string_costs_little_more_than_a_small_argument(tmp_path, small, kind):
    assert median_cost(tmp_path, kind, 15) <= max(10 * small, 0.005)


def test_an_argument_over_the_size_limit_is_not_scanned(tmp_path, small):
    assert median_cost(tmp_path, "text_128k", 15) <= max(10 * small, 0.005)


def test_a_full_size_text_argument_stays_far_under_the_decision_limit(tmp_path):
    assert median_cost(tmp_path, "text_64k", 9) < 0.1


def test_an_argument_made_only_of_addresses_does_not_stall_the_loop(tmp_path):
    assert median_cost(tmp_path, "address_dense_64k", 5) < 0.4
