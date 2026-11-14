"""MINT 판정을 LiteLLM의 표준 가드레일 기록으로 남긴다.

LiteLLM 화면의 가드레일 열, 지출 기록(spend logs), OpenTelemetry 구간, 가드레일 지표는 모두
``CustomGuardrail.add_standard_logging_guardrail_information_to_request_data``가 쓰는 기록에서
나온다. 이 모듈은 판정마다 그 기록을 한 건 남기며, 기록 실패가 판정을 바꾸지 않도록 모든 오류를
삼킨다.

기록의 응답 본문에는 허용 목록의 값(결과 구분, 사유 코드·이름, 판정 참조, 정책 식별자, 승인 요청
식별자)만 담고 인자·결과·비밀은 담지 않는다. 지출 기록은 프롬프트 저장이 꺼져 있으면 응답 본문을
지우므로, 그때도 남는 필드(``guardrail_id``=판정 참조, ``guardrail_action``=결과 구분,
``violation_categories``=정책 식별자)에 같은 값을 싣는다.

LiteLLM 상태값은 다섯 가지뿐이라 결과 구분은 ``mint_outcome``이 나눈다.

==================  ======================  =========================
결과 구분            LiteLLM 상태            비고
==================  ======================  =========================
allowed             success
observed            guardrail_flagged       관측 모드로 통과
policy_denied       guardrail_intervened    정책·계약 차단
approval_pending    guardrail_intervened    승인·본인 확인 대기
dependency_error    guardrail_failed_...    판정 부품 실패(차단)
output_blocked      guardrail_intervened    실행된 뒤 결과를 막음
masked              guardrail_flagged       결과의 값을 가려서 줌
==================  ======================  =========================
"""

from __future__ import annotations

import json
import logging
import time
from types import SimpleNamespace
from typing import Any

from mint_litellm.console.labels import outcome_reason
from mint_litellm.types.outcome import Outcome

log = logging.getLogger("mint_litellm.guardrail_log")

PROVIDER = "mint"

_SUCCESS = "success"
_FLAGGED = "guardrail_flagged"
_INTERVENED = "guardrail_intervened"
_FAILED = "guardrail_failed_to_respond"

# 판정 사건의 네 부분 요약 → (LiteLLM 상태, 결과 구분)
_DECISION = {
    Outcome.ALLOWED: (_SUCCESS, "allowed"),
    Outcome.OBSERVED: (_FLAGGED, "observed"),
    Outcome.BLOCKED: (_INTERVENED, "policy_denied"),
    Outcome.CONTRACT_DRIFT: (_INTERVENED, "policy_denied"),
    Outcome.PENDING_APPROVAL: (_INTERVENED, "approval_pending"),
    Outcome.DEPENDENCY_FAILURE: (_FAILED, "dependency_error"),
}


def clock() -> tuple[float, int]:
    """(기록용 시각, 단조 시계 나노초). 걸린 시간은 단조 시계로 잰다."""
    return time.time(), time.perf_counter_ns()


def _event(name: str) -> Any:
    from litellm.types.guardrails import GuardrailEventHooks

    return getattr(GuardrailEventHooks, name, None)


def _emit(
    guardrail: Any,
    request_data: Any,
    *,
    status: str,
    outcome: str,
    reference: str,
    event: str,
    began: tuple[float, int],
    reason: str | None = None,
    policy_ids: tuple[str, ...] | list[str] = (),
    approval_request_id: str | None = None,
    masked: dict[str, int] | None = None,
) -> None:
    try:
        if guardrail is None or not isinstance(request_data, dict):
            return
        started, mono = began
        duration = (time.perf_counter_ns() - mono) / 1e9
        body: dict[str, Any] = {"mint_outcome": outcome, "decision_ref": reference}
        if reason:
            body["reason_code"] = reason
            body["reason_label"] = outcome_reason(reason)
        if policy_ids:
            body["policy_ids"] = [str(i) for i in policy_ids]
        if approval_request_id:
            body["approval_request_id"] = str(approval_request_id)
        tracing: dict[str, Any] = {"guardrail_id": reference, "guardrail_action": outcome}
        if policy_ids:
            tracing["violation_categories"] = [str(i) for i in policy_ids]
        guardrail.add_standard_logging_guardrail_information_to_request_data(
            guardrail_json_response=body,
            request_data=request_data,
            guardrail_status=status,
            start_time=started,
            end_time=started + duration,
            duration=duration,
            masked_entity_count=dict(masked) if masked else None,
            guardrail_provider=PROVIDER,
            event_type=_event(event),
            tracing_detail=tracing,
        )
    except Exception as exc:
        log.error("가드레일 기록 오류: %s", type(exc).__name__)


def error_reference(error: Any) -> str:
    """``internal_block()`` 예외 본문의 판정 참조. 읽지 못하면 빈 문자열."""
    try:
        return str(json.loads(error.detail)["reference"])
    except Exception:
        return ""


def record_decision(
    guardrail: Any, data: Any, outcome: Any, began: tuple[float, int], *, event: str
) -> None:
    """호출 전 판정 결과를 기록한다. ``event``는 ``pre_mcp_call`` 또는 ``pre_call``."""
    try:
        snapshot = outcome.snapshot
        status, name = _DECISION.get(snapshot.outcome, (None, None))
        if status is None:
            status, name = (
                (_SUCCESS, "allowed") if outcome.allowed else (_INTERVENED, "policy_denied")
            )
        first = snapshot.stop or (snapshot.findings[0] if snapshot.findings else None)
        reason = first.reason_code if first is not None else None
        reference, policy_ids = snapshot.decision_ref, snapshot.policy_ids
        approval = outcome.approval_request_id
    except Exception as exc:
        log.error("가드레일 기록 오류: %s", type(exc).__name__)
        return
    _emit(
        guardrail,
        data,
        status=status,
        outcome=name,
        reference=reference,
        event=event,
        began=began,
        reason=reason,
        policy_ids=policy_ids,
        approval_request_id=approval,
    )


def record_internal_error(
    guardrail: Any, data: Any, reference: str, began: tuple[float, int], *, event: str
) -> None:
    """판정 코드 자체의 오류로 막은 호출. 사유는 형식 오류이다."""
    _emit(
        guardrail,
        data,
        status=_FAILED,
        outcome="dependency_error",
        reference=reference,
        event=event,
        began=began,
        reason="SCHEMA_ERROR",
    )


def record_output(
    guardrail: Any, details: Any, ctx: dict[str, Any], began: tuple[float, int]
) -> None:
    """결과 검사에서 막거나 가린 호출을 기록한다. 결과가 그대로 나간 호출은 기록하지 않는다.

    ``details``는 호출 로깅 객체의 ``model_call_details``이다. 결과 단계에는 요청 데이터가 없어
    지출 기록이 읽는 ``litellm_params``의 metadata로 바로 옮길 수 있는 임시 요청 데이터를 쓴다.
    """
    try:
        blocked, masked = bool(ctx.get("output_blocked")), bool(ctx.get("output_masked"))
        if not (blocked or masked) or not isinstance(details, dict):
            return
        findings = [str(i) for i in ctx.get("output_findings") or ()]
        counts = ctx.get("sensitive_findings")
        if not isinstance(details.get("litellm_params"), dict):
            details["litellm_params"] = {}
        request_data = {
            "metadata": {},
            "litellm_logging_obj": SimpleNamespace(
                litellm_params=details.get("litellm_params"), model_call_details=details
            ),
        }
    except Exception as exc:
        log.error("가드레일 기록 오류: %s", type(exc).__name__)
        return
    _emit(
        guardrail,
        request_data,
        status=_INTERVENED if blocked else _FLAGGED,
        outcome="output_blocked" if blocked else "masked",
        reference=str(ctx.get("decision_ref")),
        event="post_mcp_call",
        began=began,
        reason="OUTPUT_SCAN",
        policy_ids=findings,
        masked={k: int(v) for k, v in counts.items()}
        if masked and isinstance(counts, dict)
        else None,
    )
