"""도구 결과를 LiteLLM의 표준 결과 단계(``post_mcp_call``)에서 통제하는 출력 전용 가드레일.

``MintGuardrail``에 ``apply_guardrail``을 더하면 모델 요청 사전 단계가 LiteLLM의 통합 경로로 바뀌고,
``use_native_lifecycle_hooks``를 켜면 이번에는 결과 단계가 건너뛰어진다. 그래서 결과 통제는 이 별도
클래스가 맡는다. ``MintGuardrail``의 생성자가 이 가드레일을 ``post_mcp_call`` 하나로 등록하며, 다른
이벤트에서는 어떤 경우에도 돌지 않는다(``should_run_guardrail``을 재정의해 키·팀 설정과 무관하다).

LiteLLM은 결과의 텍스트 블록과 구조화된 결과의 문자열(키와 숫자 값 포함)을 한 목록으로 넘기고,
돌려받은 목록을 같은 자리에 되쓴다. 구조화된 결과의 문자열도 제자리에서 가려진다. 막을 때는
예외를 던져 결과가 호출자에게 가지 않게 한다. 도구는 이미 실행됐으므로 오류 본문이 그렇게 밝힌다.
이 단계는 결과 객체를 받지 못하므로 크기·항목 수 상한과 내장 리소스 텍스트는 보지 못한다. 그 둘은
``MintLogger``의 결과 훅이 같은 호출 컨텍스트(``output_adapter``)에 합쳐서 본다. 이 가드레일이
이미 본문을 본 호출은 로거가 다시 보지 않는다.

호출 컨텍스트는 요청 데이터(LiteLLM이 호출 로깅 객체의 상세를 그대로 넘긴다)에서 읽고, 없으면 같이
넘어온 로깅 객체에서 읽는다. 둘 다 없으면 판정을 거치지 않은 호출이다. 정책과 모드를 알 수 없어
결과를 검사하지 못하므로 막고, 이유(``missing_context``)를 가드레일 기록에 남긴다.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.types.guardrails import GuardrailEventHooks

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.plugin import guardrail_log
from mint_litellm.plugin.policy.sensitive_scan import mask_text
from mint_litellm.plugin.result import (
    POL_RESULT_SCAN_ERROR,
    blocked_output_detail,
    observe_response,
    screen_result,
)
from mint_litellm.plugin.selfcheck import PluginRuntime, get_runtime
from mint_litellm.types.decision import MINT_CTX_KEY, MintContext
from mint_litellm.types.errors import output_blocked_error
from mint_litellm.types.ids import new_uuid7

log = logging.getLogger("mint_litellm.output_guardrail")

POST_MCP_CALL = "post_mcp_call"


def _should_run_guardrail(self: Any, data: Any, event_type: Any) -> bool:
    """결과 단계에서만, 키·팀 metadata와 요청 본문에 관계없이 항상 돈다."""
    return str(getattr(event_type, "value", event_type)) == POST_MCP_CALL


class MintOutputGuardrail(CustomGuardrail):
    should_run_guardrail = _should_run_guardrail
    # 자가 점검이 재정의가 그대로인지 비교하는 기준
    mint_should_run_guardrail = _should_run_guardrail

    def __init__(self, runtime: PluginRuntime | None = None, **kwargs: Any) -> None:
        kwargs.setdefault("guardrail_name", "mint-output")
        super().__init__(event_hook=[POST_MCP_CALL], default_on=True, **kwargs)
        self._runtime = runtime if runtime is not None else get_runtime()
        self._runtime.output_guardrail = self

    def get_supported_event_hooks(self):
        return [GuardrailEventHooks.post_mcp_call]

    async def apply_guardrail(self, inputs, request_data, input_type, logging_obj=None):
        """도구 결과의 문자열을 검사한다. 가릴 값은 가려서 돌려주고, 막을 결과는 예외로 막는다."""
        if input_type != "response":
            return inputs
        began = guardrail_log.clock()
        details = compat.logging_details(logging_obj)
        if details is None and isinstance(request_data, dict):
            details = request_data
        ctx = _context(request_data, details)
        if ctx is None:
            self._without_context(request_data, began)
        ctx["output_adapter"] = True
        texts = list(inputs.get("texts") or ())
        masked: list[str] | None = None
        try:
            blocked = screen_result(
                ctx,
                size=None,
                items=0,
                texts=texts,
                max_chars=self._runtime.result_deps.config.scan_max_chars,
                limits=False,
            )
            if not blocked and ctx.get("output_masked"):
                masked = [mask_text(text) for text in texts]
        except Exception as exc:
            log.error("결과 검사 오류: %s", type(exc).__name__)
            blocked = _block_on_scan_error(ctx)
        if blocked:
            raise await self._block(ctx, details, began)
        if masked is not None:
            guardrail_log.record_output(self, details, ctx, began)
            return {**inputs, "texts": masked}
        return inputs

    async def _block(self, ctx: dict[str, Any], details: Any, began) -> HTTPException:
        """막은 결과의 응답 사건과 가드레일 기록을 남기고 호출자에게 갈 오류를 만든다.

        결과를 막으면 LiteLLM은 호출을 실패로 끝내므로 응답 사건은 여기서 남기고, 같은 호출의
        실패 관측이 판정 불명 사건을 또 남기지 않게 표시한다.
        """
        try:
            deps = self._runtime.result_deps
            await observe_response(ctx, is_error=False, size_bytes=None, deps=deps)
        except Exception as exc:
            log.error("응답 관측 오류: %s", type(exc).__name__)
        ctx["response_observed"] = True
        guardrail_log.record_output(self, details, ctx, began)
        return HTTPException(status_code=403, detail=blocked_output_detail(ctx))

    def _without_context(self, request_data, began):
        """MINT 판정 컨텍스트가 없는 호출의 결과. 정책도 모드도 몰라 검사하지 못하므로 막는다."""
        reference = MintContext(invocation_id=new_uuid7(), attempt_id=1).decision_ref
        log.error("결과를 검사할 호출 컨텍스트가 없어 막는다: %s", reference)
        guardrail_log.record_internal_error(
            self, request_data, reference, began, event=POST_MCP_CALL, cause="missing_context"
        )
        raise HTTPException(status_code=403, detail=output_blocked_error(reference).detail())


def _context(request_data: Any, details: Any) -> dict[str, Any] | None:
    for source in (request_data, details):
        ctx = source.get(MINT_CTX_KEY) if isinstance(source, Mapping) else None
        if isinstance(ctx, dict):
            return ctx
    return None


def _block_on_scan_error(ctx: dict[str, Any]) -> bool:
    """검사를 끝내지 못한 결과. 집행 모드이면 원문을 주지 않는다."""
    policy = ctx.get("result_policy")
    if not ctx.get("allowed") or not (isinstance(policy, dict) and policy.get("enforce")):
        return False
    ctx["output_findings"] = [POL_RESULT_SCAN_ERROR]
    ctx["output_blocked"], ctx["output_masked"] = True, False
    return True
