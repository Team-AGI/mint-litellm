"""치명 취약점 조치 기한이 지난 서버의 호출을 막는다(관측 모드로도 풀리지 않는다)."""

import asyncio
from dataclasses import replace

import pytest
from plugin_helpers import approval, evaluator, harness, request, server_row, snapshot

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.snapshot import SettingsRow
from mint_litellm.types.settings import Mode


def decide(tmp_path, *, blocked, observe=False):
    extra = {"settings": SettingsRow(mode=Mode.OBSERVE)} if observe else {}
    snap = snapshot(server=server_row(vuln_blocked=blocked), approvals=(approval(),), **extra)
    h = harness(tmp_path, snap, evaluate=evaluator())
    if observe:
        h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    return asyncio.run(evaluate_request(request(), h.deps))


@pytest.mark.parametrize("observe", [False, True])
def test_a_server_past_its_deadline_is_blocked(tmp_path, observe):
    out = decide(tmp_path, blocked=True, observe=observe)
    assert not out.allowed
    assert out.error.code == "MINT-CONTRACT-DRIFT-vuln-overdue"
    assert "CONTRACT_DRIFT_vuln_overdue" in [f.reason_code for f in out.snapshot.findings]


def test_without_the_mark_the_call_is_unaffected(tmp_path):
    assert decide(tmp_path, blocked=False).allowed
