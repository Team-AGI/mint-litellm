"""MINT의 판정 지점인 병렬 ``CustomGuardrail``.

``guardrails`` 설정에서 ``pre_call``·``pre_mcp_call``·``post_mcp_call`` 세 모드,
``default_on: true``로 등록한다. ``pre_call``은 모델 요청의 사전 단계이며 공급자가 외부 MCP
서버를 직접 부르게 하는 항목(``provider_mcp``)이 있으면 막는다. 패스스루 경로도 같은 사전
단계를 지난다. 생성자가 병렬 실행(``run_in_parallel``)을 켜고 요청 원문 검사
(``scan_raw_request``)를 끈다. LiteLLM은 병렬 가드레일을 순차 훅이 모두 끝난 뒤의 최종
``data``로 돌리고, 차단 예외가 나면 업스트림에 닿기 전에 요청을 거부한다. 판정하는 인자는
전송부가 고르는 인자(참인 수정본, 없으면 훅에 들어오기 전의 원래 인자)이다. 앞선 순차
가드레일이 수정본 없이 ``mcp_arguments``만 바꾸면 원래 인자와 같다고 확인되지 않아 차단한다.
다만 ``mcp_arguments``와 첫 메시지를 함께 바꾸고 수정본을 만들지 않는 가드레일은 이 확인을
통과하며, 그 경우 판정한 인자와 전송되는 인자가 갈린다(보장과-한계에 적은 지원 범위 밖의
구성이다). ``should_run_guardrail``을 재정의해 도구 호출과 모델 요청 사전 이벤트에서는 키·팀
메타데이터의 가드레일 제외 설정과 무관하게 항상 판정한다. 도구 목록은 도구마다 이 훅이 불리고,
예외를 던진 도구는 목록에서 빠진다. 응답·실패 관측용 로거는 이 생성자가 등록한다.
``litellm_settings.callbacks``에 따로 적으면 두 번 등록되므로 기동을 거부한다.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.types.guardrails import GuardrailEventHooks

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.endpoint.wiring import install_from_env
from mint_litellm.plugin.logger import MintLogger, internal_block
from mint_litellm.plugin.provider_mcp import external_mcp, is_realtime
from mint_litellm.plugin.selfcheck import (
    PluginRuntime,
    get_runtime,
    leave_startup_failure_marker,
)
from mint_litellm.types.decision import MINT_CTX_KEY
from mint_litellm.types.reason_codes import Reason

log = logging.getLogger("mint_litellm.guardrail")

_TOOL_EVENTS = frozenset({"pre_call", "pre_mcp_call", "post_mcp_call"})


def _should_run_guardrail(self: Any, data: Any, event_type: Any) -> bool:
    """도구 호출과 모델 요청 사전 이벤트에서는 키·팀 metadata와 요청 본문에 관계없이 항상 돈다."""
    return str(getattr(event_type, "value", event_type)) in _TOOL_EVENTS


class MintGuardrail(CustomGuardrail):
    should_run_guardrail = _should_run_guardrail
    # 자가 점검이 재정의가 그대로인지 비교하는 기준
    mint_should_run_guardrail = _should_run_guardrail

    def __init__(self, runtime: PluginRuntime | None = None, **kwargs: Any) -> None:
        # LiteLLM은 생성자가 RuntimeError 밖의 예외를 던지면 가드레일 없이 기동하므로 모두 바꾼다.
        try:
            super().__init__(**kwargs)
            self.run_in_parallel = True
            self.scan_raw_request = False
            self._runtime = runtime if runtime is not None else get_runtime()
            self._runtime.guardrail = self
            self._register_logger()
            self._runtime.ensure_started()
            install_from_env(os.environ)
        except RuntimeError:
            leave_startup_failure_marker()
            raise
        except Exception as exc:
            leave_startup_failure_marker()
            raise RuntimeError(f"MintGuardrail could not start: {type(exc).__name__}") from exc

    def _register_logger(self) -> None:
        """응답·실패 관측용 MINT 로거를 등록한다.

        설정의 ``callbacks``에 로거가 따로 적혀 있으면 두 곳에 등록되므로 기동을 거부한다.
        """
        for existing in compat.litellm_callbacks():
            if not isinstance(existing, MintLogger):
                continue
            if not existing.registered_by_guardrail:
                raise RuntimeError(
                    "the MINT logger must not be listed in litellm_settings.callbacks; "
                    "the MINT guardrail registers it"
                )
            # 가드레일을 다시 만드는 경우: 이전 등록을 지우고 다시 올린다.
            compat.unregister_callback(existing)
        logger = self._runtime.logger
        if not isinstance(logger, MintLogger):
            logger = MintLogger(runtime=self._runtime)
        logger.registered_by_guardrail = True
        compat.register_callback(logger)

    def get_supported_event_hooks(self):
        return [
            GuardrailEventHooks.pre_call,
            GuardrailEventHooks.pre_mcp_call,
            GuardrailEventHooks.post_mcp_call,
        ]

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if call_type == compat.LIST_TOOLS:
            return await self._discover(user_api_key_dict, data)
        if call_type == compat.CALL_TOOL:
            # 가드레일이 도는 단계의 호출 데이터는 서버·도구 이름이 있는 객체여야 한다. 아니면
            # 판정 없이 통과시키지 않고 차단한다. REST 요청 본문 단계는 LiteLLM이 건너뛴다.
            await self._judge(user_api_key_dict, data if isinstance(data, dict) else {})
        else:
            await self._screen_provider_mcp(user_api_key_dict, data, call_type)
        return None

    async def _screen_provider_mcp(self, user_api_key_dict, data, call_type):
        """모델 요청(패스스루 포함)을 거른다. 공급자 쪽 MCP와 허용되지 않은 실시간 경로를 막고,
        판정 불능도 차단한다."""
        try:
            if is_realtime(call_type) and not self._runtime.config.allow_realtime:
                reason, kind = Reason.REALTIME_FORBIDDEN, "realtime"
            else:
                reason, kind = Reason.EXTERNAL_MCP_FORBIDDEN, external_mcp(data, call_type)
                if kind is None:
                    return
            outcome = await self._runtime.judge_refused_request(
                data, user_api_key_dict, reason, kind
            )
        except Exception as exc:
            log.error("모델 요청 판정 오류: %s", type(exc).__name__)
            raise internal_block() from exc
        if outcome.error is None:
            raise internal_block()
        raise HTTPException(status_code=403, detail=outcome.error.detail())

    async def _discover(self, user_api_key_dict, data):
        try:
            result = await self._runtime.judge_listed_tool(data, user_api_key_dict)
        except Exception as exc:
            log.error("도구 목록 판정 오류: %s", type(exc).__name__)
            raise internal_block() from exc
        if not result.show:
            assert result.error is not None
            raise HTTPException(status_code=403, detail=result.error.detail())
        return None

    async def _judge(self, user_api_key_dict, data):
        """도구 호출을 판정한다. 차단은 예외이고, 병렬 단계가 돌려주는 값은 버려진다.

        DEBUG 로그가 켜져 있을 때만 판정 진입부터 반환까지의 시간(선기록 포함)을 재서 한 줄 남긴다.
        꺼져 있으면 시간을 재지 않는다.
        """
        timed = log.isEnabledFor(logging.DEBUG)
        started = time.perf_counter() if timed else 0.0
        reference = None
        allowed = False
        try:
            hook = compat.parse_hook_data(data)
            try:
                outcome = await self._runtime.judge_call(data, user_api_key_dict)
            except Exception as exc:
                log.error("도구 호출 판정 오류: %s", type(exc).__name__)
                raise internal_block() from exc
            reference, allowed = outcome.snapshot.decision_ref, outcome.allowed
            details = compat.logging_details(hook.logging_obj)
            if details is not None:
                details[MINT_CTX_KEY] = outcome.context
            if not outcome.allowed:
                assert outcome.error is not None
                raise HTTPException(status_code=403, detail=outcome.error.detail())
        finally:
            if timed:
                log.debug(
                    "decision_ms=%.3f ref=%s allowed=%s",
                    (time.perf_counter() - started) * 1000,
                    reference,
                    str(allowed).lower(),
                )
