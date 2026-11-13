"""정책 시험 적용: 후보 판본을 같은 입력으로 따로 평가해 판정이 달라지는 호출만 센다.

호출 판정(핫패스)은 ``submit``만 부른다. ``submit``은 메모리 값만 읽고 평가를 별도 작업으로 넘기며
어떤 경우에도 예외를 내지 않는다. 평가 결과는 호출의 실제 판정에 쓰이지 않는다. 시험 판본은 주기
작업이 DB에서 읽고, 센 값도 주기 작업이 모아서 쓴다. 부하는 세 가지로 막는다. 표본 비율, 초당 평가
상한, 동시에 진행하는 평가 수이며 어느 하나에 걸리면 그 호출은 평가하지 않고 건너뛴 수로만 센다.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

log = logging.getLogger("mint_litellm.plugin.shadow")

SAMPLES = 5
MAX_KEYS = 500
MAX_INFLIGHT = 16
REASON_LIMIT = 256

_STATS_SQL = (
    "INSERT INTO mint.policy_shadow_stats AS s"
    " (instance_id, version_id, evaluated, same, errors, skipped)"
    " VALUES (%s, %s, %s, %s, %s, %s)"
    " ON CONFLICT (instance_id, version_id) DO UPDATE SET"
    " evaluated = s.evaluated + EXCLUDED.evaluated, same = s.same + EXCLUDED.same,"
    " errors = s.errors + EXCLUDED.errors, skipped = s.skipped + EXCLUDED.skipped,"
    " updated_at = now()"
)
_RESULT_SQL = (
    "INSERT INTO mint.policy_shadow_results AS r (instance_id, version_id, server_id, tool,"
    " active_result, shadow_result, active_reason, shadow_reason, calls, samples)"
    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    " ON CONFLICT (instance_id, version_id, server_id, tool, active_result, shadow_result,"
    " active_reason, shadow_reason) DO UPDATE SET calls = r.calls + EXCLUDED.calls,"
    " last_seen_at = now(), samples = (SELECT coalesce(array_agg(u.s ORDER BY u.o), '{}')"
    " FROM (SELECT s, o FROM unnest(r.samples || EXCLUDED.samples) WITH ORDINALITY AS x(s, o)"
    " ORDER BY o LIMIT 5) u)"
)

Key = tuple[str, str, str, str, str, str]


@dataclass(frozen=True)
class ShadowTarget:
    version_id: str
    bundle_sha256: str


@dataclass
class Bucket:
    """한 시험 판본에 대해 아직 DB에 쓰지 않은 값."""

    evaluated: int = 0
    same: int = 0
    errors: int = 0
    skipped: int = 0
    results: dict[Key, tuple[int, list[str]]] = field(default_factory=dict)

    def differ(self, key: Key, invocation_id: str) -> None:
        count, samples = self.results.get(key, (0, []))
        if not count and len(self.results) >= MAX_KEYS:
            self.skipped += 1
            return
        if len(samples) < SAMPLES:
            samples = [*samples, invocation_id]
        self.results[key] = (count + 1, samples)

    def merge(self, other: Bucket) -> None:
        self.evaluated += other.evaluated
        self.same += other.same
        self.errors += other.errors
        self.skipped += other.skipped
        for key, (count, samples) in other.results.items():
            mine = self.results.get(key)
            if mine is None and len(self.results) >= MAX_KEYS:
                self.skipped += count
            elif mine is None:
                self.results[key] = (count, samples[:SAMPLES])
            else:
                self.results[key] = (mine[0] + count, (mine[1] + samples)[:SAMPLES])


def reason_text(policy_ids: Any) -> str:
    return ",".join(sorted(policy_ids))[:REASON_LIMIT]


@dataclass
class ShadowWatch:
    instance_id: str
    database: Any
    evaluate: Callable[..., Any]
    sample_percent: int = 100
    max_per_second: int = 50
    refresh_seconds: float = 5.0
    flush_seconds: float = 10.0
    clock: Callable[[], float] = time.monotonic
    rand: Callable[[], float] = random.random
    target: ShadowTarget | None = None
    pending: dict[str, Bucket] = field(default_factory=dict)
    _second: int = field(default=0, repr=False)
    _used: int = field(default=0, repr=False)
    _tasks: set[asyncio.Task[None]] = field(default_factory=set, repr=False)
    _flushed_at: float = field(default=0.0, repr=False)

    def _bucket(self, version_id: str) -> Bucket:
        return self.pending.setdefault(version_id, Bucket())

    def submit(
        self,
        policy_input: dict[str, Any],
        *,
        invocation_id: UUID | str,
        server_id: str,
        tool: str,
        decision: str,
        policy_ids: Any,
    ) -> None:
        """호출의 실제 판정이 정해진 뒤 부른다. 평가는 기다리지 않고 오류는 밖으로 내지 않는다."""
        target = self.target
        if target is None:
            return
        try:
            bucket = self._bucket(target.version_id)
            second = int(self.clock())
            if second != self._second:
                self._second, self._used = second, 0
            if (
                self.rand() * 100 >= self.sample_percent
                or self._used >= self.max_per_second
                or len(self._tasks) >= MAX_INFLIGHT
            ):
                bucket.skipped += 1
                return
            self._used += 1
            task = asyncio.get_running_loop().create_task(
                self._run(
                    target, policy_input, str(invocation_id), server_id, tool,
                    decision, reason_text(policy_ids),
                )
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        except Exception:
            self._bucket(target.version_id).errors += 1

    async def _run(
        self,
        target: ShadowTarget,
        policy_input: dict[str, Any],
        invocation_id: str,
        server_id: str,
        tool: str,
        decision: str,
        reasons: str,
    ) -> None:
        bucket = self._bucket(target.version_id)
        try:
            evaluation = await self.evaluate(
                policy_input,
                policy_version_id=target.version_id,
                bundle_sha256=target.bundle_sha256,
            )
            output = evaluation.output
            if output is None:
                bucket.errors += 1
                return
            shadow, shadow_reasons = output.decision, reason_text(output.policy_ids)
        except Exception:
            bucket.errors += 1
            return
        bucket.evaluated += 1
        if (shadow, shadow_reasons) == (decision, reasons):
            bucket.same += 1
            return
        bucket.differ(
            (server_id[:256], tool[:256], decision, shadow, reasons, shadow_reasons), invocation_id
        )

    async def refresh(self) -> None:
        """시험 판본을 읽는다. 읽지 못하면 이전 값을 그대로 둔다."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT version_id, bundle_sha256 FROM mint.policy_shadow WHERE instance_id = %s",
                (self.instance_id,),
            )
            return await cursor.fetchone()

        try:
            row = await self.database._run(read)
        except Exception as exc:
            log.debug("정책 시험 판본 조회 실패: %s", type(exc).__name__)
            return
        self.target = None if row is None or row[0] is None else ShadowTarget(row[0], row[1])

    async def flush(self) -> None:
        """모은 값을 DB에 더한다. 쓰지 못하면 다음 주기에 다시 쓰도록 되돌려 둔다."""
        batch, self.pending = self.pending, {}
        batch = {v: b for v, b in batch.items() if b.evaluated or b.errors or b.skipped}
        if not batch:
            return

        async def write(conn: Any) -> None:
            async with conn.transaction():
                for version, bucket in batch.items():
                    await conn.execute(
                        _STATS_SQL,
                        (self.instance_id, version, bucket.evaluated, bucket.same,
                         bucket.errors, bucket.skipped),
                    )
                    for key, (count, samples) in bucket.results.items():
                        await conn.execute(
                            _RESULT_SQL, (self.instance_id, version, *key, count, samples)
                        )

        try:
            await self.database._run(write)
        except Exception as exc:
            log.debug("정책 시험 결과 기록 실패: %s", type(exc).__name__)
            for version, bucket in batch.items():
                self._bucket(version).merge(bucket)

    async def run(self) -> None:
        while True:
            await self.refresh()
            if self.clock() - self._flushed_at >= self.flush_seconds:
                self._flushed_at = self.clock()
                await self.flush()
            await asyncio.sleep(self.refresh_seconds)
