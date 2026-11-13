"""설치된 LiteLLM의 훅 지점 모양을 확인한다. 새 LiteLLM 판본은 여기서 먼저 깨진다.

야간 워크플로가 PyPI의 최신 판본으로 이 모듈을 돌린다.
"""

import pytest

pytest.importorskip("litellm")

from mint_litellm.compat import capabilities  # noqa: E402
from mint_litellm.compat import litellm_1_106 as compat  # noqa: E402


def test_every_capability_is_detected_on_the_installed_litellm():
    found = capabilities.assess(compat.SUPPORTED_LITELLM_VERSIONS)
    assert found.missing == ()
    assert found.grade == "A"


def test_required_symbols_exist_on_the_installed_litellm():
    assert compat.missing_symbols(env={"MINT_ALLOW_UNTESTED_LITELLM": "true"}) == []


def test_pre_call_hook_receives_the_call_types_mint_branches_on():
    from litellm.types.utils import CallTypes

    assert CallTypes.call_mcp_tool.value == compat.CALL_TOOL
    assert CallTypes.list_mcp_tools.value == compat.LIST_TOOLS


def test_guardrail_event_names_match_the_configured_modes():
    from litellm.types.guardrails import GuardrailEventHooks

    from mint_litellm.plugin.selfcheck import REQUIRED_MODES

    assert {GuardrailEventHooks(mode).value for mode in REQUIRED_MODES} == set(REQUIRED_MODES)


def test_grade_follows_detected_capabilities():
    names = {name: tier for name, tier, _ in capabilities.CAPABILITIES}
    everything = dict.fromkeys(names, True)
    assert capabilities.grade_of(everything) == "A"
    assert capabilities.grade_of({**everything, "list_hook": False}) == "B"
    no_result = {**everything, "list_hook": False, "result_guardrail_mode": False}
    assert capabilities.grade_of(no_result) == "C"
    assert capabilities.grade_of({**everything, "server_resolution": False}) == "D"
    # 아래 층이 깨지면 위 층이 모두 있어도 성립하지 않는다.
    assert capabilities.grade_of({**everything, "pre_call_hook": False}) == "D"


def test_untested_version_needs_an_explicit_opt_in():
    from unittest import mock

    with mock.patch.object(compat, "installed_litellm_version", return_value="9.9.9"):
        assert any("untested" in m for m in compat.missing_symbols(env={}))
        assert compat.missing_symbols(env={"MINT_ALLOW_UNTESTED_LITELLM": "true"}) == []
        assert not compat.litellm_assessment().tested


def test_lower_grade_is_refused_naming_the_missing_capability():
    def importer(name):
        if name == "litellm.types.guardrails":
            raise ImportError(name)
        import importlib

        return importlib.import_module(name)

    missing = compat.missing_symbols(importer=importer, env={"MINT_ALLOW_UNTESTED_LITELLM": "true"})
    assert any("missing capability" in m and "call_guardrail_mode" in m for m in missing)
