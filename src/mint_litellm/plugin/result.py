"""도구 호출 응답·실패 관측과 결과 검사.

응답 본문과 결과 값은 기록하지 않는다. 허용된 호출만 관측하며, 차단된 호출의 실패 이벤트는
이미 판정 사건으로 기록되어 있어 무시한다. 결과 검사는 크기·항목 수 상한과 지시문 표지를 보고,
걸린 정책 식별자만 응답 사건에 남긴다.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from mint_litellm.plugin.buffer import EvidenceRecorder
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.policy.result_scan import scan_instructions
from mint_litellm.plugin.policy.sensitive_scan import SCAN_LIMIT, scan_sensitive
from mint_litellm.plugin.snapshot import NegativeStateQuery
from mint_litellm.types.decision import RevocationCheck
from mint_litellm.types.errors import output_blocked_error
from mint_litellm.types.events import (
    Event,
    EventKind,
    ResponseObservation,
    call_source_key,
)
from mint_litellm.types.outcome import Outcome, response_outcome

log = logging.getLogger("mint_litellm.result")


POL_RESULT_LIMIT = "POL-E-16"
POL_RESULT_INSTRUCTION = "POL-E-04"
POL_RESULT_SENSITIVE = "POL-E-05"
# 결과 검사 코드 자체의 오류. 검사하지 못한 결과는 막는다.
POL_RESULT_SCAN_ERROR = "MINT-RESULT-SCAN-ERROR"


class RevocationSource(Protocol):
    async def read_epoch(self, instance_id: str) -> int | None: ...

    async def has_negative_state(self, query: NegativeStateQuery) -> bool: ...


@dataclass
class ResultDeps:
    config: PluginConfig
    database: RevocationSource
    recorder: EvidenceRecorder
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)


def _event(ctx: Mapping[str, Any], kind: EventKind, payload: dict[str, Any], deps: ResultDeps):
    invocation_id = UUID(ctx["invocation_id"])
    attempt_id = int(ctx["attempt_id"])
    return Event(
        instance_id=deps.config.instance_id,
        inserted_at=deps.clock(),
        kind=kind,
        source_key=call_source_key(invocation_id, attempt_id, kind),
        invocation_id=invocation_id,
        attempt_id=attempt_id,
        payload={"decision_ref": ctx["decision_ref"], **payload},
    )


async def check_revocation(
    ctx: Mapping[str, Any], deps: ResultDeps
) -> tuple[RevocationCheck, int | None, bool | None]:
    """판정 스냅숏 이후 선택된 승인·거부·관계·서버가 부정 상태로 바뀌었는지.

    세대가 같으면 바뀐 것이 없다. 세대가 다르면 부정 상태를 다시 조회하고, DB를 읽지 못하면
    ``unavailable``로 남긴다.
    """
    snapshot_epoch = ctx.get("state_epoch")
    try:
        async with asyncio.timeout(deps.config.decision_budget_seconds):
            current = await deps.database.read_epoch(deps.config.instance_id)
            if current == snapshot_epoch:
                return RevocationCheck.UNCHANGED, current, False
            changed = await deps.database.has_negative_state(
                NegativeStateQuery(
                    instance_id=deps.config.instance_id,
                    server_id=ctx["server_id"],
                    tool=ctx["tool"],
                    key_id=ctx.get("key_id"),
                    user_id=ctx.get("user_id"),
                    team_id=ctx.get("team_id"),
                    org_id=ctx.get("org_id"),
                    approval_id=ctx.get("approval_id"),
                    relation_id=ctx.get("relation_id"),
                )
            )
    except Exception:
        return RevocationCheck.UNAVAILABLE, None, None
    return RevocationCheck.CHANGED, current, changed


def inspect_result(
    policy: Mapping[str, Any] | None, *, size: int | None, items: int, texts: Sequence[str]
) -> list[str]:
    """결과 한 건이 걸린 정책 식별자. 크기·항목 수 상한(E-16), 지시문 표지(E-04) 순으로 본다."""
    if not policy:
        return []
    findings: list[str] = []
    max_bytes, max_items = policy.get("max_result_bytes"), policy.get("max_result_items")
    # 크기를 잴 수 없는 결과는 상한이 있을 때 넘은 것으로 본다.
    if (max_bytes is not None and (size is None or size > max_bytes)) or (
        max_items is not None and items > max_items
    ):
        findings.append(POL_RESULT_LIMIT)
    if policy.get("scan") and scan_instructions(texts):
        findings.append(POL_RESULT_INSTRUCTION)
    return findings


def screen_result(
    ctx: dict[str, Any],
    *,
    size: int | None,
    items: int,
    texts: Sequence[str],
    structured: Sequence[str] = (),
) -> bool:
    """결과를 검사해 호출 컨텍스트에 걸린 정책을 남긴다. 호출자에게 주지 않고 막아야 하면 참.

    허용된 호출만 본다. 남긴 값은 같은 호출의 응답 관측 사건이 읽는다. 비밀·개인정보는
    탐지 종류와 건수만 남기고, 가리기(``output_masked``)는 호출한 쪽이 결과 본문에 적용한다.
    ``structured``(구조화된 결과의 문자열)는 지시문 표지 검사에만 더한다. 계약 관리가 아닌 서버의
    지시문 표지는 설정이 enforce일 때만 막고, 아니면 걸린 사실만 ``unmanaged_findings``에 남긴다.
    """
    if not ctx.get("allowed"):
        return False
    policy = ctx.get("result_policy")
    findings = inspect_result(policy, size=size, items=items, texts=[*texts, *structured])
    watched: list[str] = []
    if (
        policy
        and policy.get("unmanaged")
        and not policy.get("scan_enforce")
        and POL_RESULT_INSTRUCTION in findings
    ):
        findings.remove(POL_RESULT_INSTRUCTION)
        watched.append(POL_RESULT_INSTRUCTION)
    mode = (policy or {}).get("response_scan")
    sensitive = scan_sensitive(texts) if mode else {}
    if sensitive:
        findings.append(POL_RESULT_SENSITIVE)
        ctx["sensitive_findings"] = sensitive
    if watched:
        ctx["unmanaged_findings"] = sorted({*(ctx.get("unmanaged_findings") or ()), *watched})
    if not findings and not watched:
        return False
    ctx["output_findings"] = [*findings, *watched]
    enforce = bool(policy and policy.get("enforce"))
    # 한도·지시문 표지는 늘 막고, 비밀·개인정보는 승인 조건대로 한다. 끝까지 볼 수 없었던
    # 결과(scan_limit)는 가릴 수 없으므로 관측이 아니면 막는다.
    others = any(f != POL_RESULT_SENSITIVE for f in findings)
    block = others or mode == "block" or (mode == "mask" and SCAN_LIMIT in sensitive)
    ctx["output_blocked"] = bool(findings) and enforce and block
    ctx["output_masked"] = bool(findings) and enforce and not block and mode == "mask"
    return ctx["output_blocked"]


def blocked_output_detail(ctx: Mapping[str, Any]) -> str:
    """막힌 결과 대신 호출자에게 가는 오류 본문."""
    return output_blocked_error(ctx["decision_ref"]).detail()


async def observe_response(
    ctx: Mapping[str, Any], *, is_error: bool, size_bytes: int | None, deps: ResultDeps
) -> None:
    if not ctx.get("allowed"):
        return
    timed = log.isEnabledFor(logging.DEBUG)
    started = time.perf_counter() if timed else 0.0
    check, current, revoked = await check_revocation(ctx, deps)
    checked = time.perf_counter() if timed else 0.0
    observation = ResponseObservation(
        is_error=is_error,
        size_bytes=size_bytes,
        snapshot_state_epoch=ctx.get("state_epoch"),
        current_state_epoch=current,
        revocation_check=check,
        revoked_after_snapshot=revoked,
        output_findings=tuple(ctx.get("output_findings") or ()),
        output_blocked=bool(ctx.get("output_blocked")),
        output_masked=bool(ctx.get("output_masked")),
        result_unenforced=bool(ctx.get("result_unenforced")),
        sensitive_findings=dict(ctx.get("sensitive_findings") or {}),
        unmanaged_findings=tuple(ctx.get("unmanaged_findings") or ()),
        server_id=ctx.get("server_id") if ctx.get("unmanaged_findings") else None,
        outcome=response_outcome(
            is_error=is_error, output_blocked=bool(ctx.get("output_blocked"))
        ),
    )
    event = _event(ctx, EventKind.CALL_RESPONSE_RECEIVED, observation.model_dump(mode="json"), deps)
    await deps.recorder.record(event)
    if timed:
        done = time.perf_counter()
        log.debug(
            "response_ms=%.3f ref=%s revocation_ms=%.3f event_ms=%.3f",
            (done - started) * 1000,
            ctx.get("decision_ref"),
            (checked - started) * 1000,
            (done - checked) * 1000,
        )


async def observe_unknown_outcome(
    ctx: Mapping[str, Any], *, exception_type: str, http_status: int | None, deps: ResultDeps
) -> None:
    """응답이 오지 않은 허용 호출. 시간 초과와 연결 단절은 실패 이벤트로만 관측된다."""
    if not ctx.get("allowed"):
        return
    cause = "timeout" if http_status == 504 else "failure"
    payload: dict[str, Any] = {
        "cause": cause,
        "exception_type": exception_type,
        "http_status": http_status,
        "outcome": Outcome.UNKNOWN.value,
    }
    if ctx.get("unmanaged_findings"):
        payload["unmanaged_findings"] = list(ctx["unmanaged_findings"])
        payload["server_id"] = ctx.get("server_id")
    consumed = ctx.get("consumed_call_approval")
    if isinstance(consumed, Mapping):
        # 판정 뒤 다른 병렬 가드레일이 막은 호출도 여기에 닿는다. 소비된 승인을 사건에 묶어 둔다.
        payload["call_approval_id"] = consumed["id"]
    event = _event(ctx, EventKind.CALL_OUTCOME_UNKNOWN, payload, deps)
    await deps.recorder.record(event)
