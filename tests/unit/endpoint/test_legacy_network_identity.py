"""옛 신청의 network none 승인 계약과 그 값을 뺀 단말 계약이 같은 서버로 맞는다."""

import asyncio
from types import SimpleNamespace

from mint_litellm.endpoint.decide import DecideBody, _legacy_network
from mint_litellm.types.exec_contract import ExecContract

CONTRACT = {"executable": "/usr/bin/python3", "executable_sha256": "a" * 64}


def _run(stored: str | None, body: DecideBody) -> DecideBody:
    async def rows(_instance):
        return [SimpleNamespace(server_id="s1", exec_contract_sha256=stored)]

    runtime = SimpleNamespace(
        config=SimpleNamespace(instance_id="i"), database=SimpleNamespace(registered_servers=rows)
    )
    return asyncio.run(_legacy_network(body, runtime))


def test_stripped_contract_matches_stored_network_none():
    stored = ExecContract.model_validate({**CONTRACT, "network": "none"}).sha256()
    body = DecideBody(server="s1", tool="t", contract=ExecContract.model_validate(CONTRACT))
    assert _run(stored, body).contract.sha256() == stored


def test_other_mismatch_stays_mismatched():
    body = DecideBody(server="s1", tool="t", contract=ExecContract.model_validate(CONTRACT))
    assert _run("b" * 64, body) is body
