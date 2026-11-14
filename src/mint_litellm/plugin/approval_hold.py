"""호출별 승인을 기다리는 동안 호출을 붙잡아 두고, 승인되면 같은 호출로 결과를 돌려준다.

막힌 호출이 호출별 승인 요청을 열었거나 같은 호출의 대기 요청을 다시 쓰면(``approval_request_id``),
최대 ``MINT_APPROVAL_HOLD_SECONDS`` 동안 그 요청의 상태만 짧은 간격으로 읽는다. 기다리는 동안 잠금도
트랜잭션도 잡지 않는다(읽을 때마다 연결을 빌렸다가 돌려준다). 결정이 나거나 시간이 다 되면 판정을
처음부터 다시 돌린다. 승인이어도 모든 검사를 다시 거치고 승인은 평소처럼 소비되므로, 이 모듈은 어떤
검사도 건너뛰지 않는다. 호출자가 끊겨 취소되면 기다림만 멈추고 요청은 대기로 남는다.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from mint_litellm.plugin.pipeline import Outcome

log = logging.getLogger("mint_litellm.approval_hold")

FIRST_POLL_SECONDS = 0.25
MAX_POLL_SECONDS = 2.0
_APPROVED = frozenset({"approved", "consumed"})


async def hold_for_decision(
    request_id: str,
    seconds: float,
    status: Callable[[str], Awaitable[str | None]],
    *,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[str, int]:
    """결정을 기다린다. (``approved``·``denied``·``expired``·``timed_out``, 걸린 밀리초)를 돌려준다.

    ``status``는 요청의 현재 상태(없거나 만료면 None)를 읽는다. 읽기 실패는 기다림을 이어 간다.
    """
    started = clock()
    delay = FIRST_POLL_SECONDS
    result = "timed_out"
    try:
        while (left := seconds - (clock() - started)) > 0:
            await sleep(min(delay, left))
            delay = min(delay * 1.5, MAX_POLL_SECONDS)
            try:
                state = await status(request_id)
            except Exception as exc:
                log.debug("승인 대기 상태 읽기 실패: %s", type(exc).__name__)
                continue
            if state == "pending":
                continue
            result = (
                "approved"
                if state in _APPROVED
                else ("expired" if state in (None, "expired") else "denied")
            )
            break
    except asyncio.CancelledError:
        log.info("승인 대기 중 호출이 취소되어 요청은 대기로 남긴다")
        raise
    return result, int((clock() - started) * 1000)


async def hold_if_pending(
    outcome: Outcome,
    seconds: float,
    status: Callable[[str], Awaitable[str | None]],
    rejudge: Callable[[tuple[str, int]], Awaitable[Outcome]],
    **clock: Any,
) -> Outcome:
    """승인 대기 요청이 있는 거절이면 결정을 기다린 뒤 판정을 처음부터 다시 돌려 그 결과를 쓴다."""
    if outcome.allowed or outcome.approval_request_id is None or seconds <= 0:
        return outcome
    held = await hold_for_decision(outcome.approval_request_id, seconds, status, **clock)
    return await rejudge(held)
