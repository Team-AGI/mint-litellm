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
from mint_litellm.plugin.policy.result_scan import DEFAULT_MAX_SCAN_CHARS, scan_instructions
from mint_litellm.plugin.policy.sensitive_scan import (
    HIGH_ENTROPY,
    SCAN_LIMIT,
    SECRET_KINDS,
    locate_sensitive,
    scan_sensitive,
)
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
# 결과가 검사 상한을 넘어 끝까지 보지 못했다. 집행 모드는 막고, 관측은 응답 사건에 남긴다.
POL_RESULT_SCAN_LIMIT = "MINT-RESULT-SCAN-LIMIT"
MAX_FINDING_PATHS = 20


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
    policy: Mapping[str, Any] | None,
    *,
    size: int | None,
    items: int,
    texts: Sequence[str],
    max_chars: int = DEFAULT_MAX_SCAN_CHARS,
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
    if policy.get("scan") and scan_instructions(texts, max_chars):
        findings.append(POL_RESULT_INSTRUCTION)
    return findings


def _clip(texts: Sequence[str], budget: int) -> list[str]:
    """합쳐서 ``budget`` 글자까지만 남긴 본문 목록."""
    out: list[str] = []
    for text in texts:
        if budget <= 0:
            break
        out.append(text[:budget])
        budget -= len(text)
    return out


def screen_result(
    ctx: dict[str, Any],
    *,
    size: int | None,
    items: int,
    texts: Sequence[str],
    structured: Sequence[tuple[str, str]] = (),
    structured_truncated: bool = False,
    max_chars: int = DEFAULT_MAX_SCAN_CHARS,
) -> bool:
    """결과를 검사해 호출 컨텍스트에 걸린 정책을 남긴다. 호출자에게 주지 않고 막아야 하면 참.

    허용된 호출만 본다. 남긴 값은 같은 호출의 응답 관측 사건이 읽는다. 비밀·개인정보는
    탐지 종류와 건수만 남기고, 가리기(``output_masked``)는 호출한 쪽이 결과 본문에 적용한다.
    ``structured``(구조화된 결과의 ``(JSON 경로, 문자열)``)는 본문과 같은 검사를 받고, 걸리면 경로를
    ``finding_paths``에 남긴다. 구조화된 결과의 개인정보는 경로만 남기고 통과시키며, 알려진 형식의
    비밀은 가릴 수 없으므로 가리기 모드에서도 막는다. 고엔트로피 문자열은 건수만 남기고
    막지 않는다. 본문과 구조화된 문자열이 합쳐 ``max_chars``를 넘으면 앞쪽만 보고
    ``scan_truncated``를 남기며 집행 모드는 막는다.
    계약 관리가 아닌 서버의 지시문 표지·상한 초과는 설정이 enforce일 때만 막고, 아니면 걸린 사실만
    ``unmanaged_findings``에 남긴다.
    """
    if not ctx.get("allowed"):
        return False
    ctx["result_items"] = items
    policy = ctx.get("result_policy")
    mode = (policy or {}).get("response_scan")
    truncated = (
        structured_truncated
        or sum(map(len, texts)) + sum(len(t) for _, t in structured) > max_chars
    )
    body = _clip(texts, max_chars)
    pairs = _clip([t for _, t in structured], max_chars - sum(map(len, body)))
    structured = [(p, t) for (p, _), t in zip(structured, pairs, strict=False)]
    findings = inspect_result(
        policy, size=size, items=items, texts=[*body, *pairs], max_chars=max_chars
    )
    if truncated and policy and policy.get("scan"):
        findings.append(POL_RESULT_SCAN_LIMIT)
    if truncated and (mode or (policy or {}).get("scan")):
        ctx["scan_truncated"] = True
    watched: list[str] = []
    watching = bool(policy and policy.get("unmanaged") and not policy.get("scan_enforce"))
    if watching:
        for code in (POL_RESULT_INSTRUCTION, POL_RESULT_SCAN_LIMIT):
            if code in findings:
                findings.remove(code)
                watched.append(code)
    sensitive: dict[str, int] = {}
    entropy = 0
    structured_secret = False
    if mode:
        sensitive = scan_sensitive(body, max_chars, entropy=True)
        entropy = sensitive.pop(HIGH_ENTROPY, 0)
        paths: list[str] = []
        for path, kinds in locate_sensitive(structured):
            paths.append(path)
            entropy += kinds.pop(HIGH_ENTROPY, 0)
            for kind, count in kinds.items():
                # 구조화된 결과의 개인정보는 경로만 남기고 통과시킨다. 알려진 형식의 비밀만 센다.
                if kind in SECRET_KINDS:
                    sensitive[kind] = sensitive.get(kind, 0) + count
                    structured_secret = True
        if paths:
            ctx["finding_paths"] = paths[:MAX_FINDING_PATHS]
        if truncated and not watching:
            sensitive[SCAN_LIMIT] = 1
    if sensitive:
        findings.append(POL_RESULT_SENSITIVE)
    if sensitive or entropy:
        # 비밀처럼 보이는 긴 문자열은 오탐이 있어 기록과 경보에만 쓰고 막거나 가리지 않는다.
        recorded = {**sensitive, HIGH_ENTROPY: entropy} if entropy else sensitive
        ctx["sensitive_findings"] = dict(sorted(recorded.items()))
    if entropy and policy and policy.get("unmanaged"):
        ctx["unmanaged_findings"] = sorted({*(ctx.get("unmanaged_findings") or ()), HIGH_ENTROPY})
    if watched:
        ctx["unmanaged_findings"] = sorted({*(ctx.get("unmanaged_findings") or ()), *watched})
    if not findings and not watched:
        return False
    ctx["output_findings"] = [*findings, *watched]
    enforce = bool(policy and policy.get("enforce"))
    # 한도·지시문 표지·상한 초과는 늘 막고, 비밀·개인정보는 승인 조건대로 한다. 끝까지 볼 수
    # 없었거나(scan_limit) 구조화된 결과에서 걸려 가릴 수 없는 결과는 관측이 아니면 막는다.
    others = any(f != POL_RESULT_SENSITIVE for f in findings)
    unmaskable = SCAN_LIMIT in sensitive or structured_secret
    block = others or mode == "block" or (mode == "mask" and unmaskable)
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
        items=ctx.get("result_items"),
        server_id=ctx.get("server_id"),
        snapshot_state_epoch=ctx.get("state_epoch"),
        current_state_epoch=current,
        revocation_check=check,
        revoked_after_snapshot=revoked,
        output_findings=tuple(ctx.get("output_findings") or ()),
        output_blocked=bool(ctx.get("output_blocked")),
        output_masked=bool(ctx.get("output_masked")),
        result_unenforced=bool(ctx.get("result_unenforced")),
        aud_mismatch=bool(ctx.get("aud_mismatch")),
        aud_unchecked=bool(ctx.get("aud_unchecked")),
        aud_unchecked_reason=ctx.get("aud_unchecked_reason"),
        scope_exceeded=tuple(ctx.get("scope_exceeded") or ()),
        scope_unchecked_reason=ctx.get("scope_unchecked_reason"),
        sensitive_findings=dict(ctx.get("sensitive_findings") or {}),
        unmanaged_findings=tuple(ctx.get("unmanaged_findings") or ()),
        resolve_findings=tuple(ctx.get("resolve_findings") or ()),
        scan_truncated=bool(ctx.get("scan_truncated")),
        finding_paths=tuple(ctx.get("finding_paths") or ()),
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
    if ctx.get("resolve_findings"):
        payload["resolve_findings"] = list(ctx["resolve_findings"])
    if ctx.get("aud_mismatch"):
        payload["aud_mismatch"] = True
        payload["server_id"] = ctx.get("server_id")
    if ctx.get("scope_exceeded"):
        payload["scope_exceeded"] = list(ctx["scope_exceeded"])
        payload["server_id"] = ctx.get("server_id")
    consumed = ctx.get("consumed_call_approval")
    if isinstance(consumed, Mapping):
        # 판정 뒤 다른 병렬 가드레일이 막은 호출도 여기에 닿는다. 소비된 승인을 사건에 묶어 둔다.
        payload["call_approval_id"] = consumed["id"]
    event = _event(ctx, EventKind.CALL_OUTCOME_UNKNOWN, payload, deps)
    await deps.recorder.record(event)
