"""도구 호출의 응답·실패 관측을 맡는 ``CustomLogger``.

도구 호출 판정은 ``MintGuardrail``이 병렬 단계에서 한다. 로거는 판정이 호출 컨텍스트에 남긴
값을 읽어 응답(`call_response_received`)과 실패(`call_outcome_unknown`)를 기록한다. 로거는
``MintGuardrail``의 생성자가 등록한다. ``litellm_settings.callbacks``에 따로 적으면 두 번
등록되므로 기동을 거부한다.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.plugin import guardrail_log
from mint_litellm.plugin.policy.result_scan import walk_structured
from mint_litellm.plugin.policy.sensitive_scan import mask_text
from mint_litellm.plugin.result import (
    POL_RESULT_SCAN_ERROR,
    blocked_output_detail,
    observe_response,
    observe_unknown_outcome,
    screen_result,
)
from mint_litellm.plugin.selfcheck import PluginRuntime, get_runtime, leave_startup_failure_marker
from mint_litellm.types.decision import MINT_CTX_KEY, MintContext
from mint_litellm.types.errors import error_for_reason
from mint_litellm.types.ids import new_uuid7
from mint_litellm.types.reason_codes import Reason

log = logging.getLogger("mint_litellm.logger")


def internal_block() -> HTTPException:
    """판정 코드 자체의 오류. 판정할 수 없으므로 차단한다."""
    reference = MintContext(invocation_id=new_uuid7(), attempt_id=1).decision_ref
    error = error_for_reason(Reason.SCHEMA_ERROR.value, reference)
    return HTTPException(status_code=403, detail=error.detail())


class MintLogger(CustomLogger):
    registered_by_guardrail = False

    def __init__(self, runtime: PluginRuntime | None = None, **kwargs: Any) -> None:
        # LiteLLM은 생성자가 RuntimeError 밖의 예외를 던지면 기동을 계속하므로 모두 바꾼다.
        try:
            super().__init__(**kwargs)
            self._runtime = runtime if runtime is not None else get_runtime()
            self._runtime.logger = self
            self._runtime.ensure_started()
        except RuntimeError:
            leave_startup_failure_marker()
            raise
        except Exception as exc:
            leave_startup_failure_marker()
            raise RuntimeError(f"MintLogger could not start: {type(exc).__name__}") from exc

    async def async_post_mcp_tool_call_hook(
        self, kwargs, response_obj, start_time, end_time
    ):
        """허용된 호출의 결과를 호출자에게 주기 전에 검사한다.

        결과 본문의 검사와 가리기·막기는 ``MintOutputGuardrail``이 LiteLLM의 결과 단계
        가드레일 경로에서 먼저 하고(같은 호출 컨텍스트에 ``output_adapter`` 표시를 남긴다),
        이 훅은 그 단계가 보지 못하는 것만 본다: 결과 객체의 크기·항목 수 상한과 내장 리소스
        텍스트. 어댑터가 본문을 보지 않은 호출(본문에 텍스트가 없어 LiteLLM이 어댑터를 부르지
        않았거나 어댑터가 없는 LiteLLM)은 본문 전체와 구조화된 결과를 여기서 본다. 이미 본 본문은
        다시 보지 않는다.

        막아야 하면 결과 내용을 오류 본문으로 바꾸고, 가려야 하면 찾은 값만 바꾼다.

        LiteLLM은 이 훅의 예외를 삼키고 원래 결과를 그대로 내보낸다(litellm_logging.py의
        ``async_post_mcp_tool_call_hook`` 루프). 그래서 검사 오류는 던지지 않고 이 훅 안에서
        결과를 오류 본문으로 바꾼다(집행 모드일 때. 관측 모드는 결과를 건드리지 않는다).
        """
        ctx = kwargs.get(MINT_CTX_KEY)
        content = getattr(response_obj, "mcp_tool_call_response", None)
        if not isinstance(ctx, dict) or not isinstance(content, list):
            return None
        began = guardrail_log.clock()
        if not self._runtime.result_enforced:
            # 결과 단계 가드레일이 없는 LiteLLM: 걸린 것을 기록만 하고 결과는 건드리지 않는다.
            policy = ctx.get("result_policy")
            ctx["result_unenforced"] = True
            if isinstance(policy, dict):
                ctx["result_policy"] = {**policy, "enforce": False}
        try:
            limit = self._runtime.result_deps.config.scan_max_chars
            if ctx.get("output_adapter"):
                texts, structured, structured_cut = compat.resource_texts(content), [], False
            else:
                texts = compat.content_texts(content)
                structured, structured_cut = walk_structured(
                    compat.structured_root(kwargs.get("original_response")), limit
                )
            if screen_result(
                ctx,
                size=compat.content_size(content),
                items=len(content),
                texts=texts,
                structured=structured,
                structured_truncated=structured_cut,
                max_chars=limit,
            ):
                compat.replace_tool_content(response_obj, blocked_output_detail(ctx))
            elif ctx.get("output_masked"):
                self._mask_or_block(ctx, response_obj)
        except Exception as exc:
            log.error("결과 검사 오류: %s", type(exc).__name__)
            self._block_on_scan_error(ctx, response_obj)
        guardrail_log.record_output(
            self._runtime.output_guardrail or self._runtime.guardrail, kwargs, ctx, began
        )
        return None

    async def async_post_call_response_headers_hook(
        self, data, user_api_key_dict, response, request_headers=None, litellm_call_info=None
    ):
        """같은 요청의 로깅 객체에 판정 참조가 있으면 ``x-mint-decision-ref`` 헤더로 돌려준다."""
        ctx = (compat.logging_details(data.get("litellm_logging_obj")) or {}).get(MINT_CTX_KEY)
        reference = ctx.get("decision_ref") if isinstance(ctx, dict) else None
        return {"x-mint-decision-ref": reference} if isinstance(reference, str) else None

    @staticmethod
    def _block_on_scan_error(ctx: dict[str, Any], response_obj) -> None:
        """검사를 끝내지 못한 결과는 원문을 주지 않는다. 본문을 바꾸지 못하면 비운다."""
        policy = ctx.get("result_policy")
        if not ctx.get("allowed") or not (isinstance(policy, dict) and policy.get("enforce")):
            return
        try:
            compat.replace_tool_content(response_obj, blocked_output_detail(ctx))
        except Exception:
            response_obj.mcp_tool_call_response.clear()
        ctx["output_findings"] = [POL_RESULT_SCAN_ERROR]
        ctx["output_blocked"], ctx["output_masked"] = True, False

    @staticmethod
    def _mask_or_block(ctx, response_obj) -> None:
        """결과의 비밀·개인정보를 가린다. 가리지 못하면 원문을 주지 않고 막는다."""
        try:
            compat.mask_tool_content(response_obj, mask_text)
        except Exception as exc:
            log.error("결과 가리기 오류: %s", type(exc).__name__)
            compat.replace_tool_content(response_obj, blocked_output_detail(ctx))
            ctx["output_masked"], ctx["output_blocked"] = False, True

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        ctx = kwargs.get(MINT_CTX_KEY)
        if not isinstance(ctx, dict):
            return
        try:
            await observe_response(
                ctx,
                is_error=False,
                size_bytes=compat.tool_result_size(response_obj),
                deps=self._runtime.result_deps,
            )
        except Exception as exc:
            log.error("응답 관측 오류: %s", type(exc).__name__)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        ctx = kwargs.get(MINT_CTX_KEY)
        # 결과를 막은 호출은 출력 어댑터가 응답 사건을 이미 남겼다.
        if not isinstance(ctx, dict) or ctx.get("response_observed"):
            return
        exc = compat.failure_exception(kwargs)
        try:
            if compat.is_tool_result_error(exc):
                await observe_response(
                    ctx, is_error=True, size_bytes=None, deps=self._runtime.result_deps
                )
            else:
                await observe_unknown_outcome(
                    ctx,
                    exception_type=type(exc).__name__ if exc is not None else "unknown",
                    http_status=compat.exception_status(exc),
                    deps=self._runtime.result_deps,
                )
        except Exception as error:
            log.error("실패 관측 오류: %s", type(error).__name__)


_instance: MintLogger | None = None


def __getattr__(name: str) -> MintLogger:
    global _instance
    if name != "mint_logger":
        raise AttributeError(name)
    if _instance is None:
        _instance = MintLogger()
    return _instance
