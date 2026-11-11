"""판정 한 건의 단계별 걸린 시간.

각 단계의 벽시계 시간(초)을 모으고, 입출력 대기 횟수를 센다. 모으는 비용은 단계마다 시계 읽기
두 번과 딕셔너리 갱신 한 번이다. 꺼진 시계(``OFF``)는 시계를 읽지 않는다.
입출력 단계(``snapshot``, ``markers``, ``policy``, ``event``)의 시간에는 이벤트 루프가 다른 호출을
처리하느라 기다린 시간이 들어 있다. 계산 단계(``hook``, ``input``, ``patterns``,
``fingerprint``)는 순수한 처리 시간이다.
"""

from __future__ import annotations

import time
from collections.abc import Mapping

# 로그 줄에 이 순서로 남는 단계. 해당하지 않은 단계는 0이다.
STAGES = ("hook", "snapshot", "markers", "input", "patterns", "fingerprint", "policy", "event")


class StageClock:
    __slots__ = ("on", "seconds", "awaits")

    def __init__(self, on: bool = True) -> None:
        self.on = on
        self.seconds: dict[str, float] = {}
        self.awaits = 0

    def now(self) -> float:
        return time.perf_counter() if self.on else 0.0

    def since(self, stage: str, started: float) -> None:
        """``now()``가 돌려준 시각 이후 걸린 시간을 단계에 더한다."""
        if self.on:
            self.seconds[stage] = self.seconds.get(stage, 0.0) + (time.perf_counter() - started)

    def wait(self) -> None:
        """입출력 대기를 한 번 센다."""
        if self.on:
            self.awaits += 1


OFF = StageClock(on=False)


def stage_fields(seconds: Mapping[str, float], awaits: int) -> str:
    """``hook_ms=0.050 snapshot_ms=3.100 ... awaits=4`` 형식의 줄 조각."""
    parts = [f"{stage}_ms={seconds.get(stage, 0.0) * 1000:.3f}" for stage in STAGES]
    parts.append(f"awaits={awaits}")
    return " ".join(parts)
