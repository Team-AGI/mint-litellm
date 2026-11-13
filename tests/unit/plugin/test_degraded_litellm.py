"""LiteLLM 등급 B·C의 저하 운용: 켜진 기능, 잃는 보장의 보고, 결과의 관측 전용 경로."""

import json
from pathlib import Path

import pytest

pytest.importorskip("litellm")

from litellm.types.mcp import MCPPostCallResponseObject  # noqa: E402
from mcp.types import TextContent  # noqa: E402
from test_plugin_hooks import build_runtime, make_logger, pre, run, synthesized  # noqa: E402

from mint_litellm.compat import capabilities  # noqa: E402
from mint_litellm.compat import litellm_1_106 as compat  # noqa: E402
from mint_litellm.control import status  # noqa: E402
from mint_litellm.plugin.selfcheck import LiteLLMView  # noqa: E402
from mint_litellm.types.decision import MINT_CTX_KEY  # noqa: E402
from mint_litellm.types.events import ResponseObservation  # noqa: E402

CATALOG = Path(__file__).parents[3] / "policy" / "catalog.json"


def assessment(grade):
    return capabilities.Assessment("1.0.0", grade, (), False)


@pytest.mark.parametrize(
    ("grade", "listing", "result"),
    [("A", True, True), ("B", False, True), ("C", False, False)],
)
def test_grade_decides_which_features_are_enforced(grade, listing, result):
    assert capabilities.list_enforced(grade) is listing
    assert capabilities.result_enforced(grade) is result


def test_only_b_and_c_have_losses_and_c_has_more():
    assert capabilities.degraded_findings(assessment("A")) == []
    assert capabilities.degraded_findings(assessment("D")) == []
    b, c = (capabilities.degraded_findings(assessment(g)) for g in ("B", "C"))
    assert b and set(b) < set(c)
    assert capabilities.affected_policies("A") == ()
    assert capabilities.affected_policies("B") == ("POL-O-02",)
    assert capabilities.affected_policies("C") == ("POL-E-04", "POL-E-05", "POL-E-16", "POL-O-02")


def test_affected_policies_exist_in_the_catalog_and_rest_on_the_degraded_code():
    catalog = {p["id"]: p for p in json.loads(CATALOG.read_text(encoding="utf-8"))["policies"]}
    for grade in ("B", "C"):
        for policy_id in capabilities.affected_policies(grade):
            assert policy_id in catalog
    refs = {
        pid: " ".join(catalog[pid]["enforced_by"]) for pid in capabilities.affected_policies("C")
    }
    assert "discovery.py" in refs["POL-O-02"]
    assert all("result" in refs[p] or "logger" in refs[p] or "sensitive" in refs[p]
               for p in ("POL-E-04", "POL-E-05", "POL-E-16"))


def test_degraded_opt_in_defaults_off():
    assert not capabilities.allow_degraded({})
    assert capabilities.allow_degraded({"MINT_ALLOW_DEGRADED_LITELLM": "true"})


@pytest.mark.parametrize("grade", ["B", "C"])
def test_b_and_c_start_only_with_the_opt_in(grade, monkeypatch):
    monkeypatch.setattr(compat, "installed_litellm_version", lambda: "1.0.0")
    found = capabilities.Assessment("1.0.0", grade, ("x",), False)
    monkeypatch.setattr(capabilities, "assess", lambda *a, **k: found)
    refused = compat.missing_symbols(env={})
    assert any(f"grade {grade}" in m and "MINT_ALLOW_DEGRADED_LITELLM" in m for m in refused)
    assert compat.missing_symbols(env={"MINT_ALLOW_DEGRADED_LITELLM": "true"}) == []


def test_grade_d_is_refused_even_with_the_opt_in(monkeypatch):
    monkeypatch.setattr(
        capabilities, "assess", lambda *a, **k: capabilities.Assessment("1.0.0", "D", ("x",), False)
    )
    env = {"MINT_ALLOW_DEGRADED_LITELLM": "true", "MINT_ALLOW_UNTESTED_LITELLM": "true"}
    assert any("grade D" in m for m in compat.missing_symbols(env=env))


def test_the_view_carries_the_degraded_findings(monkeypatch):
    from mint_litellm.plugin import selfcheck

    monkeypatch.setattr(
        compat, "litellm_assessment", lambda: capabilities.Assessment("1.0.0", "C", (), False)
    )
    monkeypatch.setattr(compat, "missing_symbols", lambda env=None: [])
    monkeypatch.setattr(compat, "arguments_witness_problem", lambda: None)
    view = selfcheck.collect_view({})
    assert isinstance(view, LiteLLMView)
    assert view.result_guardrail is False
    assert any("result checks run observe-only" in f for f in view.degraded)


def test_status_names_what_is_not_guaranteed():
    found = {
        "version": "1.0.0", "grade": "C", "tested": False, "missing": ["result_guardrail_mode"],
        "degraded": capabilities.degraded_findings(assessment("C")),
        "affected_policies": list(capabilities.affected_policies("C")),
    }
    text = "\n".join([status._compat_line(found), *status._degraded_lines(found)])
    assert "MINT_ALLOW_DEGRADED_LITELLM" in text and "observe-only" in text and "POL-E-04" in text


def runtime_with(tmp_path, grade):
    runtime, store, _ = build_runtime(tmp_path)
    runtime._grade = grade
    return runtime, store


def test_a_litellm_without_the_result_mode_registers_two_modes(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from mint_litellm.plugin import guardrail as guardrail_module

    runtime, _ = runtime_with(tmp_path, "C")
    hooks = SimpleNamespace(pre_call="pre_call", pre_mcp_call="pre_mcp_call")
    monkeypatch.setattr(guardrail_module, "GuardrailEventHooks", hooks)
    assert runtime.guardrail.get_supported_event_hooks() == ["pre_call", "pre_mcp_call"]


def test_a_degraded_grade_skips_list_judgment_and_events(tmp_path):
    runtime, store = runtime_with(tmp_path, "B")
    assert pre(runtime.guardrail, synthesized(None), "list_mcp_tools") is None
    assert store.of_kind("discovery_evaluated") == []


def result_call(tmp_path, grade, policy):
    runtime, store = runtime_with(tmp_path, grade)
    logger = make_logger(runtime)
    ctx = {
        "invocation_id": "0192f7a0-7c1e-7a10-8000-0123456789ab", "attempt_id": 1,
        "decision_ref": "0192f7a0-7c1e-7a10-8000-0123456789ab:1", "allowed": True,
        "state_epoch": 7, "server_id": "srv-1", "tool": "search", "result_policy": policy,
    }
    text = "x" * 50
    response = MCPPostCallResponseObject(
        mcp_tool_call_response=[TextContent(type="text", text=text)], hidden_params={}
    )
    details = {MINT_CTX_KEY: ctx}
    run(logger.async_post_mcp_tool_call_hook(details, response, None, None))
    run(logger.async_log_success_event(details, response, None, None))
    (event,) = store.of_kind("call_response_received")
    return response.mcp_tool_call_response[0].text, event.payload


def test_grade_c_records_a_finding_without_blocking_the_result(tmp_path):
    policy = {"max_result_bytes": 10, "scan": False, "enforce": True}
    text, payload = result_call(tmp_path, "C", policy)
    assert text == "x" * 50
    assert payload["output_findings"] == ["POL-E-16"]
    assert payload["output_blocked"] is False and payload["result_unenforced"] is True


def test_grades_a_and_b_still_block_the_same_result(tmp_path):
    policy = {"max_result_bytes": 10, "scan": False, "enforce": True}
    for grade in ("A", "B"):
        text, payload = result_call(tmp_path, grade, policy)
        assert "MINT-OUTPUT-BLOCKED" in text
        assert payload["output_blocked"] is True and payload["result_unenforced"] is False


def test_the_response_event_defaults_to_enforced():
    fields = ResponseObservation.model_fields
    assert fields["result_unenforced"].default is False
