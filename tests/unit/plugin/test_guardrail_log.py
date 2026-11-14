"""MINT 판정을 LiteLLM 표준 가드레일 기록으로 남기는지 실제 기반 클래스로 시험한다."""

import inspect
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("litellm")
pytest.importorskip("fastapi")

import test_plugin_hooks as hooks  # noqa: E402
from litellm.integrations.custom_guardrail import CustomGuardrail  # noqa: E402
from plugin_helpers import snapshot  # noqa: E402

from mint_litellm.plugin import guardrail_log  # noqa: E402
from mint_litellm.types.decision import MINT_CTX_KEY, StageResult  # noqa: E402
from mint_litellm.types.outcome import Outcome  # noqa: E402
from mint_litellm.types.reason_codes import Reason  # noqa: E402

blocked, build_runtime, logging_obj = hooks.blocked, hooks.build_runtime, hooks.logging_obj
make_logger, pre, synthesized = hooks.make_logger, hooks.pre, hooks.synthesized
# 기존 시험의 고정 장치를 그대로 쓴다.
isolated_callbacks, registry, contract_snapshot = (
    hooks.isolated_callbacks,
    hooks.registry,
    hooks.contract_snapshot,
)

SECRET_ARGUMENT = "ARGUMENT-VALUE-must-not-be-logged"
RESPONSE_FIELDS = {
    "mint_outcome",
    "decision_ref",
    "reason_code",
    "reason_label",
    "policy_ids",
    "approval_request_id",
}


def records(data):
    return data["metadata"]["standard_logging_guardrail_information"]


def assert_clean(record, *, reference=None):
    assert record["guardrail_provider"] == "mint"
    assert record["guardrail_name"] == "mint"
    response = record["guardrail_response"]
    assert set(response) <= RESPONSE_FIELDS
    assert record["guardrail_id"] == response["decision_ref"]
    assert record["guardrail_action"] == response["mint_outcome"]
    assert record["duration"] >= 0
    assert SECRET_ARGUMENT not in json.dumps(record, default=str)
    if reference is not None:
        assert response["decision_ref"] == reference


class TestDecisionRecords:
    def test_an_allowed_call_is_recorded_as_success(self, tmp_path, contract_snapshot):
        runtime, _, _ = build_runtime(tmp_path, contract_snapshot)
        obj = logging_obj()
        data = synthesized(obj, mcp_arguments={"q": SECRET_ARGUMENT})
        assert pre(runtime.guardrail, data) is None
        (record,) = records(data)
        reference = obj.model_call_details[MINT_CTX_KEY]["decision_ref"]
        assert_clean(record, reference=reference)
        assert record["guardrail_status"] == "success"
        assert record["guardrail_response"]["mint_outcome"] == "allowed"
        assert "reason_code" not in record["guardrail_response"]
        assert "pre_mcp_call" in str(record["guardrail_mode"])

    def test_a_denied_call_is_recorded_as_intervened_with_the_reason_and_the_body_reference(
        self, tmp_path, contract_snapshot
    ):
        runtime, _, _ = build_runtime(
            tmp_path, snapshot(server=contract_snapshot.server, approvals=())
        )
        obj = logging_obj()
        data = synthesized(obj, mcp_arguments={"q": SECRET_ARGUMENT})
        error = blocked(lambda: pre(runtime.guardrail, data))
        (record,) = records(data)
        assert_clean(record, reference=error.reference)
        assert record["guardrail_status"] == "guardrail_intervened"
        response = record["guardrail_response"]
        assert response["mint_outcome"] == "policy_denied"
        assert response["reason_code"] == "APPROVAL_ABSENT"
        assert response["reason_label"] == "승인 없음"
        assert record["guardrail_name"] == "mint"

    def test_an_internal_failure_is_recorded_as_a_dependency_error(
        self, tmp_path, contract_snapshot
    ):
        runtime, _, _ = build_runtime(tmp_path, contract_snapshot)

        async def broken(*args, **kwargs):
            raise RuntimeError("boom")

        runtime.judge_call = broken
        data = synthesized(logging_obj(), mcp_arguments={"q": SECRET_ARGUMENT})
        error = blocked(lambda: pre(runtime.guardrail, data))
        (record,) = records(data)
        assert_clean(record, reference=error.reference)
        assert record["guardrail_status"] == "guardrail_failed_to_respond"
        assert record["guardrail_response"]["mint_outcome"] == "dependency_error"

    @pytest.mark.parametrize(
        ("outcome", "reason", "status", "name"),
        [
            (
                Outcome.PENDING_APPROVAL,
                Reason.CALL_APPROVAL_REQUIRED,
                "guardrail_intervened",
                "approval_pending",
            ),
            (Outcome.CONTRACT_DRIFT, Reason.UNSUPPORTED, "guardrail_intervened", "policy_denied"),
            (
                Outcome.DEPENDENCY_FAILURE,
                Reason.DEPENDENCY_FAILURE,
                "guardrail_failed_to_respond",
                "dependency_error",
            ),
            (Outcome.OBSERVED, Reason.APPROVAL_ABSENT, "guardrail_flagged", "observed"),
        ],
    )
    def test_each_outcome_maps_to_its_status(self, outcome, reason, status, name):
        stop = StageResult.stop(reason) if reason.value not in ("APPROVAL_ABSENT",) else None
        finding = StageResult.finding(reason) if stop is None else None
        fake = SimpleNamespace(
            allowed=outcome is Outcome.OBSERVED,
            approval_request_id="req-1" if outcome is Outcome.PENDING_APPROVAL else None,
            snapshot=SimpleNamespace(
                outcome=outcome,
                stop=stop,
                findings=(finding,) if finding else (),
                decision_ref="ref:1",
                policy_ids=("POL-E-07",),
            ),
        )
        data = {"metadata": {}}
        guardrail = CustomGuardrail(guardrail_name="mint", event_hook="pre_mcp_call")
        guardrail_log.record_decision(
            guardrail, data, fake, guardrail_log.clock(), event="pre_mcp_call"
        )
        (record,) = records(data)
        assert_clean(record, reference="ref:1")
        assert record["guardrail_status"] == status
        response = record["guardrail_response"]
        assert response["mint_outcome"] == name
        assert response["policy_ids"] == ["POL-E-07"]
        assert record["violation_categories"] == ["POL-E-07"]
        assert response.get("approval_request_id") == fake.approval_request_id or (
            fake.approval_request_id is None and "approval_request_id" not in response
        )

    def test_a_recording_failure_never_changes_the_decision(self, tmp_path, contract_snapshot):
        runtime, _, _ = build_runtime(tmp_path, contract_snapshot)

        def broken(**kwargs):
            raise RuntimeError("boom")

        runtime.guardrail.add_standard_logging_guardrail_information_to_request_data = broken
        assert pre(runtime.guardrail, synthesized(logging_obj())) is None


class TestOutputRecords:
    def ctx(self, **override):
        base = {
            "decision_ref": "ref:2",
            "output_findings": ["POL-R-01"],
            "output_blocked": False,
            "output_masked": False,
        }
        return {**base, **override}

    def test_a_blocked_result_is_recorded_into_the_spend_log_metadata(self, tmp_path):
        runtime, _, _ = build_runtime(tmp_path)
        details = {"litellm_params": {"metadata": {}}}
        guardrail_log.record_output(
            runtime.guardrail, details, self.ctx(output_blocked=True), guardrail_log.clock()
        )
        (record,) = details["litellm_params"]["metadata"]["standard_logging_guardrail_information"]
        assert_clean(record, reference="ref:2")
        assert record["guardrail_status"] == "guardrail_intervened"
        assert record["guardrail_response"]["mint_outcome"] == "output_blocked"
        assert record["guardrail_response"]["reason_code"] == "OUTPUT_SCAN"
        assert "post_mcp_call" in str(record["guardrail_mode"])

    def test_a_masked_result_carries_only_counts(self, tmp_path):
        runtime, _, _ = build_runtime(tmp_path)
        details = {}
        guardrail_log.record_output(
            runtime.guardrail,
            details,
            self.ctx(output_masked=True, sensitive_findings={"email": 2}),
            guardrail_log.clock(),
        )
        (record,) = details["litellm_params"]["metadata"]["standard_logging_guardrail_information"]
        assert_clean(record)
        assert record["guardrail_status"] == "guardrail_flagged"
        assert record["guardrail_response"]["mint_outcome"] == "masked"
        assert record["masked_entity_count"] == {"email": 2}

    def test_a_result_delivered_as_is_is_not_recorded(self, tmp_path):
        runtime, _, _ = build_runtime(tmp_path)
        details = {"litellm_params": {"metadata": {}}}
        guardrail_log.record_output(runtime.guardrail, details, self.ctx(), guardrail_log.clock())
        assert details["litellm_params"]["metadata"] == {}


class TestResponseHeader:
    def test_the_header_carries_the_decision_reference_of_the_same_request(self, tmp_path):
        runtime, _, _ = build_runtime(tmp_path)
        logger = make_logger(runtime)
        obj = SimpleNamespace(model_call_details={MINT_CTX_KEY: {"decision_ref": "ref:3"}})
        import asyncio

        got = asyncio.run(
            logger.async_post_call_response_headers_hook({"litellm_logging_obj": obj}, None, None)
        )
        assert got == {"x-mint-decision-ref": "ref:3"}
        none = asyncio.run(logger.async_post_call_response_headers_hook({}, None, None))
        assert none is None


def test_litellm_still_exposes_the_recording_interface():
    names = inspect.signature(
        CustomGuardrail.add_standard_logging_guardrail_information_to_request_data
    ).parameters
    for name in (
        "guardrail_json_response",
        "request_data",
        "guardrail_status",
        "start_time",
        "end_time",
        "duration",
        "masked_entity_count",
        "guardrail_provider",
        "event_type",
        "tracing_detail",
    ):
        assert name in names


def test_a_spend_log_without_stored_prompts_keeps_the_correlation_fields(tmp_path, monkeypatch):
    """프롬프트 저장이 꺼진 지출 기록은 응답 본문을 지운다. 판정 참조·결과 구분은 남아야 한다."""
    spend = pytest.importorskip("litellm.proxy.spend_tracking.spend_tracking_utils")
    monkeypatch.setattr(spend, "should_store_prompts_and_responses_in_spend_logs", lambda: False)
    runtime, _, _ = build_runtime(tmp_path)
    details = {"litellm_params": {"metadata": {}}}
    guardrail_log.record_output(
        runtime.guardrail,
        details,
        {**TestOutputRecords().ctx(), "output_blocked": True},
        guardrail_log.clock(),
    )
    raw = details["litellm_params"]["metadata"]["standard_logging_guardrail_information"]
    (kept,) = spend._sanitize_guardrail_information_for_spend_logs(raw)
    assert kept["guardrail_response"] != raw[0]["guardrail_response"]
    assert kept["guardrail_id"] == "ref:2" and kept["guardrail_action"] == "output_blocked"
    assert kept["violation_categories"] == ["POL-R-01"]


def test_the_spend_lookup_reads_only_the_mint_entries(monkeypatch):
    from mint_litellm.control.litellm_admin import LiteLLMAdmin

    admin = LiteLLMAdmin("http://localhost:9", "key")
    row = {
        "messages": "SECRET",
        "metadata": {
            "guardrail_information": [
                {"guardrail_provider": "other", "guardrail_id": "x"},
                {
                    "guardrail_provider": "mint",
                    "guardrail_status": "success",
                    "guardrail_action": "allowed",
                    "guardrail_id": "ref:1",
                    "duration": 0.01,
                },
            ]
        },
    }
    seen = {}

    def fake_get(path, params=None):
        seen.update(path=path, params=params)
        return 200, [row]

    monkeypatch.setattr(admin, "_get", fake_get)
    assert admin.spend_guardrail("call-1") == [
        {"status": "success", "outcome": "allowed", "decision_ref": "ref:1", "seconds": 0.01}
    ]
    assert seen == {"path": "/spend/logs", "params": {"request_id": "call-1"}}


def test_the_ledger_drawer_looks_up_the_spend_log_only_when_enabled():
    from mint_litellm.console.pages.dashboard import _spend_records

    admin = SimpleNamespace(
        spend_guardrail=lambda call_id: [{"outcome": "policy_denied", "status": "x"}]
    )
    payload = {"litellm_call_id": "call-1"}
    on = SimpleNamespace(spend_lookup=True, litellm_admin=admin)
    off = SimpleNamespace(spend_lookup=False, litellm_admin=admin)
    assert _spend_records(on, payload) == [{"label": "정책 차단"}]
    assert _spend_records(off, payload) == []
    assert _spend_records(on, {}) == []

    def broken(call_id):
        raise RuntimeError("boom")

    assert (
        _spend_records(
            SimpleNamespace(
                spend_lookup=True, litellm_admin=SimpleNamespace(spend_guardrail=broken)
            ),
            payload,
        )
        == []
    )
