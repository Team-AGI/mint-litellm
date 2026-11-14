"""도구 호출·도구 발견 판정 파이프라인.

단계는 ``pass``·``finding``·``stop``을 돌려준다. 관측 모드로 전환될 수 있는 사유는
``finding``으로 쌓으며 끝까지 진행하고, 전환 불가 사유만 ``stop``이 되어 남은 단계를 건너뛴다.
모든 경로에서 종결자가 ``decision_evaluated`` 또는 ``discovery_evaluated``를 한 건 남긴다.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import posixpath
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID

from mint_litellm.compat.litellm_1_106 import HookData, ServerResolutionError
from mint_litellm.control import links
from mint_litellm.plugin.buffer import ConfirmationConsume, ConsumeRequest, EvidenceRecorder
from mint_litellm.plugin.call_display import call_display
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.list_seen import ListSeen, list_key
from mint_litellm.plugin.obligations import (
    AlertObligation,
    RequireCallApproval,
    RequireConsent,
    RequireUserConfirmation,
    normalize_policy_output,
)
from mint_litellm.plugin.policy.defaults import effective_conditions
from mint_litellm.plugin.policy.input import policy_input as make_policy_input
from mint_litellm.plugin.policy.opa_client import Evaluation
from mint_litellm.plugin.policy.patterns import compute_patterns
from mint_litellm.plugin.policy.sensitive_scan import INPUT_SECRET_KINDS, scan_arguments
from mint_litellm.plugin.resolve_guard import ResolveGuard
from mint_litellm.plugin.snapshot import (
    WINDOW_MAX_USES,
    ApprovalRow,
    CallApprovalRow,
    Snapshot,
    SnapshotQuery,
    ToolContractRow,
)
from mint_litellm.plugin.timing import OFF, StageClock
from mint_litellm.plugin.token_audience import MISMATCH, UNCHECKED, audience_verdict
from mint_litellm.plugin.token_scope import exceeded_scopes
from mint_litellm.types.canonical import credential_scope
from mint_litellm.types.contracts import ONE_SHOT_ACTIONS
from mint_litellm.types.decision import (
    UNSUPPORTED_STAGE,
    Action,
    Conclusion,
    DecisionSnapshot,
    MintContext,
    OperationType,
    PolicyDecision,
    ResolvedServer,
    SkippedStage,
    Stage,
    StageResult,
    StageStatus,
    apply_record_failure,
    conclude,
    entries_from_results,
    relation_state_result,
    server_state_result,
)
from mint_litellm.types.errors import Dependency, MintError, error_for_reason
from mint_litellm.types.events import Evidence, decision_event
from mint_litellm.types.fingerprint import argument_fingerprint
from mint_litellm.types.identity import (
    Principal,
    PrincipalType,
    derive_org,
    with_org,
)
from mint_litellm.types.ids import new_uuid7
from mint_litellm.types.outcome import Outcome as DecisionOutcome
from mint_litellm.types.outcome import decision_outcome
from mint_litellm.types.reason_codes import ContractDriftKind, Reason
from mint_litellm.types.reuse_policy import (
    ALLOW_INTERNAL_ADDRESS,
    ALLOW_TOKEN_FORWARD,
    FORWARDING_AUTH,
)
from mint_litellm.types.settings import Mode, ObservationSettings, effective_mode
from mint_litellm.types.target import (
    READ,
    Target,
    TargetUnresolved,
    bind_target,
    effective_profile,
)

log = logging.getLogger("mint_litellm.pipeline")

# 막힌 호출이 자동으로 여는 호출별 승인 요청의 요청자 표시와 유효 시간(분)
AUTO_REQUESTER = "mint-auto"
AUTO_REQUEST_MINUTES = 24 * 60

# 승인 범위는 좁은 쪽부터 본다.
_SCOPE_ORDER = ("key", "user", "team", "org")


PolicyEvaluate = Callable[..., Awaitable[Evaluation]]
"""``evaluate(policy_input, *, policy_version_id, bundle_sha256, budget_seconds)``."""


class Deadline:
    """한 판정의 단일 시간 예산. DB와 정책 엔진 호출은 남은 시간만큼만 기다린다."""

    def __init__(self, budget_seconds: float) -> None:
        self._end = time.monotonic() + budget_seconds

    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())


class SnapshotSource(Protocol):
    async def read_snapshot(self, query: SnapshotQuery) -> Snapshot: ...

    async def request_confirmation(self, params: Mapping[str, Any]) -> None: ...

    async def request_call_approval(self, params: Mapping[str, Any]) -> str | None: ...

    async def recent_call_outcome(
        self, params: Mapping[str, Any]
    ) -> tuple[str, str | None] | None: ...


@dataclass
class PipelineDeps:
    config: PluginConfig
    snapshots: SnapshotSource
    recorder: EvidenceRecorder
    evaluate: PolicyEvaluate | None
    verified: Callable[[], bool]
    # 호출을 막는 사유(되돌림 판정의 cause). 없으면 None. 메모리 값만 읽는다.
    unverified_cause: Callable[[], str | None] = lambda: None
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    secret_markers: Callable[..., Awaitable[tuple[str, ...] | None]] | None = None
    # 정책 시험 적용. 실제 판정이 정해진 뒤 같은 입력을 후보 판본에도 보내며 판정에는 영향이 없다.
    shadow: Callable[..., None] | None = None
    # 도구 목록의 「보임·통과」 반복을 거르는 기억. 없으면 걸러 내지 않는다.
    list_seen: ListSeen | None = None
    # 원격 서버 주소의 이름 조회 결과 재확인. 없으면 하지 않는다.
    resolve_guard: ResolveGuard | None = None


@dataclass(frozen=True)
class CallRequest:
    operation: OperationType
    principal: Principal
    hook: HookData
    resolved: ResolvedServer | None
    resolution_failure: StageResult | None
    invocation_id: UUID = field(default_factory=new_uuid7)
    attempt_id: int = 1
    # 승인 대기 보류 뒤 다시 하는 판정이면 (보류 결과, 걸린 밀리초)
    hold: tuple[str, int] | None = None


@dataclass(frozen=True)
class Outcome:
    allowed: bool
    snapshot: DecisionSnapshot
    error: MintError | None
    evidence: Evidence
    context: dict[str, Any]
    timing: StageClock = OFF
    # 호출별 승인 요청을 열었거나 다시 쓴 막힘이면 그 요청의 식별자. 승인 대기 보류가 쓴다.
    approval_request_id: str | None = None
    # 본인 확인 요청을 열어 둔 막힘이면 (주체, 서버, 도구, 인자 지문). 본인 확인 보류가 쓴다.
    confirmation_wait: tuple[str, str, str, str] | None = None


def scope_matches(scope_type: str, scope_id: str, principal: Principal, server_id: str) -> bool:
    if scope_type == "key":
        return principal.key_id == scope_id
    if scope_type == "user":
        return principal.user_id == scope_id
    if scope_type == "team":
        return principal.team_id == scope_id
    if scope_type == "org":
        return principal.org_id == scope_id
    return scope_type == "server" and server_id == scope_id


class _Stages:
    """단계 결과 누적. stop이 나오면 이후 결과를 받지 않는다."""

    def __init__(self) -> None:
        self.items: list[tuple[Stage, StageResult | SkippedStage]] = []
        self.stopped = False
        self.dependency: Dependency | None = None

    def add(self, stage: Stage, result: StageResult | SkippedStage) -> None:
        if self.stopped:
            return
        self.items.append((stage, result))
        if isinstance(result, StageResult) and result.status is StageStatus.STOP:
            self.stopped = True

    def results(self) -> list[StageResult]:
        return [r for _, r in self.items if isinstance(r, StageResult)]


def context_result(
    req: CallRequest, verified: bool, cause: str | None = None
) -> StageResult | None:
    if not verified:
        detail = None if cause is None else f"cause={cause}"
        return StageResult.stop(Reason.ENFORCEMENT_UNVERIFIED, detail=detail)
    # 모델 요청은 마스터 키로도 보낼 수 있으므로, 공급자 쪽 MCP 차단 사유를 그대로 돌려준다.
    master = req.principal.principal_type is PrincipalType.MASTER_KEY
    if master and req.operation is not OperationType.LLM_REQUEST:
        return StageResult.stop(Reason.MASTER_KEY_FORBIDDEN)
    if req.resolution_failure is not None:
        return req.resolution_failure
    resolved = req.resolved
    if resolved is not None and resolved.candidates_with_same_name >= 2:
        return StageResult.stop(Reason.SERVER_IDENTITY_AMBIGUOUS)
    return None


def derive_principal(snapshot: Snapshot, principal: Principal) -> Principal:
    derivation = derive_org(
        team_id=principal.team_id,
        user_id=principal.user_id,
        bindings=snapshot.bindings,
        default_org_id=snapshot.settings.default_org_id if snapshot.settings else None,
        org_status=snapshot.org_status,
    )
    return with_org(principal, derivation)


def state_results(
    snapshot: Snapshot, principal: Principal, resolved: ResolvedServer
) -> list[StageResult]:
    if principal.principal_type is PrincipalType.ANONYMOUS:
        return [StageResult.stop(Reason.ANONYMOUS)]
    if principal.org_id is None:
        return [StageResult.stop(Reason.ORG_BOUNDARY)]
    server = snapshot.server
    results = []
    state = server_state_result(server.status if server is not None else None)
    if state.status is not StageStatus.PASS:
        results.append(state)
    if server is not None and state.status is not StageStatus.STOP:
        if not resolved.matches_contract(
            url_sha256=server.url_sha256,
            transport=server.transport,
            auth_type=server.auth_type,
            identity_kind=server.identity_kind,
            exec_contract_sha256=server.exec_contract_sha256,
            exec_contract_version=server.exec_contract_version,
        ):
            results.append(StageResult.stop(Reason.SERVER_IDENTITY_MISMATCH))
    return results


@dataclass(frozen=True)
class ApprovalSelection:
    results: list[StageResult]
    selected: ApprovalRow | None


def _approval_expired(approval: ApprovalRow, now: datetime) -> bool:
    return approval.status == "expired" or (
        approval.status == "active" and approval.valid_until <= now
    )


def denial_and_approval(
    snapshot: Snapshot, principal: Principal, resolved: ResolvedServer, tool: str
) -> ApprovalSelection:
    now = snapshot.now
    for denial in snapshot.denials:
        applies = (
            scope_matches(denial.scope_type, denial.scope_id, principal, resolved.server_id)
            and (denial.server_id is None or denial.server_id == resolved.server_id)
            and (denial.tools is None or tool in denial.tools)
            and (denial.org_id is None or denial.org_id == principal.org_id)
        )
        if applies:
            return ApprovalSelection([StageResult.stop(Reason.DENIED)], None)

    matched = [
        a
        for a in snapshot.approvals
        if scope_matches(a.scope_type, a.scope_id, principal, resolved.server_id)
    ]
    in_org = [a for a in matched if a.org_id == principal.org_id]
    relation_status = {
        a.id: snapshot.relations[a.relation_id].status
        if a.relation_id in snapshot.relations
        else None
        for a in in_org
    }
    for approval in in_org:
        status = relation_status[approval.id]
        if status != "active" and status is not None:
            return ApprovalSelection([relation_state_result(status)], None)

    server = snapshot.server
    if server is not None:
        for allowlist_id in server.basis_allowlist_ids:
            entry = snapshot.allowlists.get(allowlist_id)
            if (
                entry is None
                or entry.status != "active"
                or not (entry.valid_from <= now < entry.valid_until)
            ):
                return ApprovalSelection([StageResult.stop(Reason.ALLOWLIST_EXPIRED)], None)

    valid = [
        a
        for a in in_org
        if a.status == "active"
        and not a.recert_held
        and a.valid_from <= now < a.valid_until
        and relation_status[a.id] == "active"
    ]
    # 유효 승인이 하나라도 있는 가장 좁은 범위 하나만 본다. 그 범위에 도구가 든 승인이 없으면
    # 더 넓은 범위에 있어도 선택하지 않는다.
    for scope in _SCOPE_ORDER:
        in_scope = [a for a in valid if a.scope_type == scope]
        if not in_scope:
            continue
        containing = [a for a in in_scope if tool in a.tools]
        if not containing:
            return ApprovalSelection([StageResult.finding(Reason.TOOL_NOT_IN_APPROVAL)], None)
        ordered = sorted(containing, key=lambda a: a.id)
        ordered.sort(key=lambda a: a.valid_from, reverse=True)
        return ApprovalSelection([], ordered[0])
    if not in_org:
        if matched:
            return ApprovalSelection([StageResult.stop(Reason.ORG_BOUNDARY)], None)
        return ApprovalSelection([StageResult.finding(Reason.APPROVAL_ABSENT)], None)
    if any(a.status == "revoked" for a in in_org):
        return ApprovalSelection([StageResult.stop(Reason.APPROVAL_REVOKED)], None)
    if any(a.status == "active" and a.recert_held for a in in_org):
        return ApprovalSelection([StageResult.stop(Reason.APPROVAL_RECERT_REQUIRED)], None)
    if any(_approval_expired(a, now) for a in in_org):
        return ApprovalSelection([StageResult.stop(Reason.APPROVAL_EXPIRED)], None)
    return ApprovalSelection([StageResult.finding(Reason.APPROVAL_ABSENT)], None)


def token_forward_result(
    resolved: ResolvedServer, selected: ApprovalRow | None
) -> StageResult | None:
    """호출자 토큰을 업스트림에 그대로 전달하는 서버(POL-R-06)는 선택된 승인이 조건
    ``allow_token_forward``를 true로 적었을 때만 호출을 보낸다. 아니면 닫는다."""
    if resolved.auth_type not in FORWARDING_AUTH:
        return None
    if selected is not None and selected.conditions.get(ALLOW_TOKEN_FORWARD) is True:
        return None
    return StageResult.stop(Reason.TOKEN_FORWARD_FORBIDDEN, detail=resolved.auth_type)


RESOLVE_OBSERVE_WAIT = 0.2  # 초
RESOLVE_ENFORCE_WAIT = 1.0  # 초


async def address_verdict(
    run: _Run, deps: PipelineDeps, resolved: ResolvedServer, selected: ApprovalRow | None
) -> StageResult | None:
    """원격 서버 URL의 호스트가 내부 주소로 풀리는지 호출 직전에 다시 본다(POL-R-12).

    승인 조건 ``allow_internal_address``를 true로 적은 서버는 보지 않는다. ``enforce``는 막고
    (관측 모드로 풀리지 않음), ``observe``는 호출을 통과시키되 걸린 종류를 ``resolve_findings``에
    남긴다. 조회 실패는 ``observe``에서 통과(기록만), ``enforce``에서 차단이다.
    """
    guard, mode = deps.resolve_guard, deps.config.resolve_check
    if guard is None or mode == "off" or not resolved.host:
        return None
    if selected is not None and selected.conditions.get(ALLOW_INTERNAL_ADDRESS) is True:
        return None
    verdict = guard.cached(resolved.host)
    if verdict is None:
        # 이름 조회가 판정 예산을 다 쓰면 승인 소비 등 뒤 단계가 시간 초과로 닫힌다. 관측은 짧게,
        # 집행은 남은 예산의 절반까지만 기다린다(늦게 끝난 조회는 캐시에 남아 다음 호출이 쓴다).
        enforce = mode == "enforce"
        share, cap = (0.5, RESOLVE_ENFORCE_WAIT) if enforce else (0.25, RESOLVE_OBSERVE_WAIT)
        verdict = await guard.check(resolved.host, min(run.deadline.remaining() * share, cap))
    if verdict.kind is None:
        return None
    if mode == "enforce":
        return StageResult.stop(Reason.RESOLVED_ADDRESS_FORBIDDEN, detail=verdict.detail())
    run.resolve_findings.append(verdict.kind)


def audience_result(
    bearer: str | None, resolved: ResolvedServer, mode: str, run: _Run
) -> StageResult | None:
    """업스트림에 전달되는 호출자 토큰(POL-R-05)의 aud가 서버 대상과 다르면 ``enforce``에서 닫는다.
    ``observe``는 호출을 보내고 사건에만 남긴다. 읽을 수 없는 토큰은 확인하지 않았다고 남긴다."""
    if resolved.auth_type not in FORWARDING_AUTH:
        return None
    if mode == "off":
        run.aud_unchecked, run.aud_unchecked_reason = True, "not_forwarded"
        return None
    if not bearer:
        return None
    verdict = audience_verdict(bearer, resolved.audiences)
    run.aud_unchecked = verdict == UNCHECKED
    run.aud_unchecked_reason = "opaque" if run.aud_unchecked else None
    run.aud_mismatch = verdict == MISMATCH
    if run.aud_mismatch and mode == "enforce":
        return StageResult.stop(Reason.TOKEN_AUDIENCE_MISMATCH, detail=resolved.auth_type)
    return None


def scope_result(
    bearer: str | None, resolved: ResolvedServer, snapshot: Snapshot, mode: str, run: _Run
) -> StageResult | None:
    """업스트림에 전달되는 호출자 토큰(POL-O-15)의 범위가 승인된 범위를 넘으면 ``enforce``에서
    닫는다. ``observe``는 호출을 보내고 사건에만 남긴다. 승인된 범위를 모르거나(없음·빈 목록) 토큰을
    읽을 수 없으면 확인하지 않았다고 이유와 함께 남긴다."""
    if resolved.auth_type not in FORWARDING_AUTH:
        return None
    if mode == "off":
        run.scope_unchecked_reason = "not_forwarded"
        return None
    if not bearer:
        return None
    server = snapshot.server
    approved = server.approved_oauth_scopes if server is not None else None
    if not approved:
        run.scope_unchecked_reason = "no_approved_scopes"
        return None
    extra = exceeded_scopes(bearer, approved)
    if extra is None:
        run.scope_unchecked_reason = "opaque"
        return None
    run.scope_exceeded = list(extra)
    if extra and mode == "enforce":
        return StageResult.stop(Reason.TOKEN_SCOPE_EXCEEDED, detail=resolved.auth_type)
    return None


def control_listing_negative(
    snapshot: Snapshot, principal: Principal, resolved: ResolvedServer, tool: str
) -> StageResult | None:
    if principal.principal_type is PrincipalType.ANONYMOUS:
        return StageResult.stop(Reason.ANONYMOUS)
    server = snapshot.server
    if server is not None and server.status in {
        "rejected",
        "suspended",
        "terminating",
        "terminated",
    }:
        return server_state_result(server.status)
    for denial in snapshot.denials:
        if (
            scope_matches(denial.scope_type, denial.scope_id, principal, resolved.server_id)
            and (denial.server_id is None or denial.server_id == resolved.server_id)
            and (denial.tools is None or tool in denial.tools)
            and (denial.org_id is None or denial.org_id == principal.org_id)
        ):
            return StageResult.stop(Reason.DENIED)
    if snapshot.negative_relation or any(
        r.status in {"terminating", "terminated"} for r in snapshot.relations.values()
    ):
        return StageResult.stop(Reason.RELATION_TERMINATED)
    return None


def current_contract(snapshot: Snapshot, tool: str) -> ToolContractRow | None:
    """계약 관리 서버에서 이 도구의 지금 승인된 계약(서버의 자격 범위 기준). 아니면 None."""
    server = snapshot.server
    if server is None or server.contract_status != "managed":
        return None
    scope = credential_scope(server.auth_type)
    return next(
        (c for c in snapshot.tool_contracts if c.credential_scope == scope and c.tool == tool), None
    )


def bound_to_current_contract(snapshot: Snapshot, tool: str, bound: str | None) -> bool:
    """승인이 받은 때의 계약이 지금 승인된 계약인가. 계약 관리 서버가 아니면 묶인 계약이 없다."""
    server = snapshot.server
    if server is None or server.contract_status != "managed":
        return bound is None
    contract = current_contract(snapshot, tool)
    return contract is not None and bound == contract.id


def vuln_result(snapshot: Snapshot) -> StageResult | None:
    """취약점 조치 기한이 지났거나 다른 인스턴스와 어긋난 서버의 호출을 막는다(닫힌 쪽)."""
    server = snapshot.server
    if server is not None and server.vuln_blocked:
        return StageResult.finding(Reason.CONTRACT_DRIFT, ContractDriftKind.VULN_OVERDUE.value)
    if server is not None and server.instance_mismatch:
        return StageResult.finding(
            Reason.CONTRACT_DRIFT, ContractDriftKind.INSTANCE_MISMATCH.value)
    return None


def contract_result(
    snapshot: Snapshot, tool: str, observe_seconds: int, resolved: ResolvedServer | None = None
) -> StageResult | SkippedStage:
    server = snapshot.server
    if server is None or server.contract_status != "managed":
        return UNSUPPORTED_STAGE
    if server.pin_blocked:
        return StageResult.finding(Reason.CONTRACT_DRIFT, "pin")
    if server.approved_contracts == 0:
        return StageResult.finding(Reason.CONTRACT_DRIFT, "no_contract")
    contract = current_contract(snapshot, tool)
    if contract is None:
        return StageResult.finding(Reason.CONTRACT_DRIFT, "unapproved_tool")
    if contract.drift == "input_schema":
        return StageResult.finding(Reason.CONTRACT_DRIFT, "input_schema")
    if server.deployment_drift:
        return StageResult.finding(Reason.CONTRACT_DRIFT, "deployment")
    if (
        resolved is not None
        and server.approved_oauth_scopes is not None
        and set(resolved.oauth_scopes) - set(server.approved_oauth_scopes)
    ):
        # 지금 서버 정의의 범위가 승인된 범위보다 넓다: 닫힌 쪽으로 막는다(좁아지거나 같으면 통과)
        return StageResult.finding(Reason.CONTRACT_DRIFT, "oauth_scope")
    if (
        server.last_observed_at is None
        or (snapshot.now - server.last_observed_at).total_seconds() > 2 * observe_seconds
    ):
        return StageResult.finding(Reason.CONTRACT_DRIFT, "unobserved")
    return StageResult.passed()


def input_keys_unknown(
    snapshot: Snapshot, tool: str, selected: ApprovalRow | None
) -> StageResult | None:
    """허용 인자 키를 채울 수 없는 호출. 계약의 입력 정의를 모르는데(NULL) 승인에도 키 목록이
    없으면 인자 키 판정이 건너뛰어지므로 막는다(닫힌 쪽). 승인에 목록이 있으면 그 값이 쓰인다."""
    contract = current_contract(snapshot, tool)
    if (
        selected is None
        or contract is None
        or contract.input_keys is not None
        or "allowed_arg_keys" in selected.conditions
    ):
        return None
    return StageResult.finding(Reason.CONTRACT_DRIFT, ContractDriftKind.INPUT_KEYS_UNKNOWN.value)


def consent_state(snapshot: Snapshot, principal: Principal, purpose: str) -> tuple[str, str | None]:
    """목적에 대한 동의 상태와 출처. 동의는 사람 사용자에게만 있다."""
    if principal.principal_type is not PrincipalType.USER:
        return "absent", None
    rows = [c for c in snapshot.consents if c.purpose == purpose and c.org_id == principal.org_id]
    if not rows:
        return "absent", None
    now = snapshot.now
    live = [c for c in rows if c.revoked_at is None and c.granted_at <= now < c.valid_until]
    if live:
        return "granted", max(live, key=lambda c: c.granted_at).source
    latest = max(rows, key=lambda c: c.granted_at)
    return ("revoked" if latest.revoked_at is not None else "expired"), None


class InputError(Exception):
    """정책 입력으로 만들 수 없는 승인 조건."""


# 결과 크기(바이트)와 결과 항목 수의 상한을 담는 승인 조건 이름
RESULT_LIMIT_KEYS = ("max_result_bytes", "max_result_items")

# 도구로 보내는 인자의 비밀 검사(POL-E-05). 운영자가 정한 비밀 표지에 걸린 경우의 탐지 종류 이름.
POL_INPUT_SENSITIVE = "POL-E-05"
CUSTOM_MARKER = "custom_marker"

# 결과의 비밀·개인정보 검사 방식 승인 조건. 지정하지 않으면 가린다(mask).
RESPONSE_SCAN_MODES = ("block", "mask", "observe")
DEFAULT_RESPONSE_SCAN = "mask"


def _argument_sizes(arguments: Mapping[str, Any]) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for key, value in arguments.items():
        raw = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        )
        sizes[str(key)] = len(raw.encode("utf-8"))
    return sizes


def _condition_list(conditions: Mapping[str, Any], key: str) -> list[str]:
    values = conditions.get(key, [])
    if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
        raise InputError(f"{key} must be a list of non-empty strings")
    return values


def _condition_limit(conditions: Mapping[str, Any], key: str) -> int | None:
    """승인 조건의 양의 정수 상한. 없으면 None, 정수가 아니거나 0 이하면 입력 오류."""
    value = conditions.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InputError(f"{key} must be a positive integer")
    return value


def _response_scan_mode(conditions: Mapping[str, Any]) -> str:
    """승인 조건 response_scan의 값. 없으면 기본값, 모르는 값이면 입력 오류."""
    value = conditions.get("response_scan", DEFAULT_RESPONSE_SCAN)
    if value not in RESPONSE_SCAN_MODES:
        raise InputError("response_scan must be one of block, mask, observe")
    return value


def _host_of(value: str) -> str:
    value = value.strip().lower()
    try:
        host = urlsplit(value if "://" in value else "//" + value).hostname or ""
    except ValueError:
        return ""
    return host.removeprefix("*.").rstrip(".")


def _argument_patterns(
    snapshot: Snapshot,
    principal: Principal,
    conditions: Mapping[str, Any],
    arguments: Mapping[str, Any],
    secret_markers: Sequence[str],
    timing: StageClock = OFF,
) -> dict[str, bool]:
    hosts = {_host_of(h) for h in _condition_list(conditions, "allowed_hosts")}
    hosts |= {_host_of(v) for v, org in snapshot.egress_targets if org in (None, principal.org_id)}
    raw_paths = _condition_list(conditions, "allowed_paths")
    paths = [posixpath.normpath(p.replace("\\", "/")) for p in raw_paths]
    started = timing.now()
    try:
        return compute_patterns(
            arguments,
            allowed_hosts={h for h in hosts if h},
            allowed_paths=paths,
            paths_unrestricted=conditions.get("allowed_paths_unrestricted") is True,
            secret_markers=secret_markers,
        )
    finally:
        timing.since("patterns", started)


def build_policy_input(
    *,
    snapshot: Snapshot,
    principal: Principal,
    resolved: ResolvedServer,
    tool: str,
    arguments: Mapping[str, Any],
    selected: ApprovalRow | None,
    mode: Mode,
    operation: OperationType,
    high_risk_tools: frozenset[str],
    secret_markers: Sequence[str] = (),
    timing: StageClock = OFF,
) -> dict[str, Any]:
    """정책 입력. 인자 원문은 넣지 않고(패턴 불리언만), 값이 없는 입력은 키를 만들지 않는다."""
    now = snapshot.now
    server = snapshot.server
    allowed_kinds = (
        {
            snapshot.allowlists[i].kind
            for i in server.basis_allowlist_ids
            if i in snapshot.allowlists and snapshot.allowlists[i].status == "active"
        }
        if server is not None
        else set()
    )
    # 서버 행이 없어도 server 객체를 빼지 않는다. 정책의 필수 입력 검사가 누락을 전환 불가 오류로
    # 바꾸면 관측 모드에서 미등록 서버를 허용으로 전환할 수 없다.
    server_doc: dict[str, Any] = {
        "id": resolved.server_id,
        "status": server.status if server is not None else "unregistered",
        "transport": resolved.transport,
        "auth_type": resolved.auth_type,
        "identity_kind": resolved.identity_kind,
        "provider_allowed": "provider" in allowed_kinds,
        "auth_server_allowed": "auth_server" in allowed_kinds,
    }
    if resolved.exec_contract_sha256 is not None:
        server_doc["exec_contract_sha256"] = resolved.exec_contract_sha256
        server_doc["exec_contract_version"] = resolved.exec_contract_version
    if server is not None and server.exec_contract_sha256 is not None:
        # 서버 행에 등록된 승인 대상 실행 계약. 보고된 계약과의 대조는 정책 규칙이 한다.
        server_doc["exec_approved_sha256"] = server.exec_contract_sha256
    managed = server is not None and server.contract_status == "managed"
    server_doc["contract_status"] = "managed" if managed else "none"
    # 승인된 계약의 위험 등급. 승인이 어떤 경로로 만들어졌든 정책이 같은 등급을 본다.
    tool_doc: dict[str, Any] = {"name": tool}
    contract = current_contract(snapshot, tool)
    if contract is not None:
        tool_doc["risk_grade"] = contract.risk_grade
        if contract.action_type is not None:
            tool_doc["action_type"] = contract.action_type

    if selected is None:
        approval: dict[str, Any] = {"present": False}
        consent: dict[str, Any] = {"status": "not_applicable", "source": None}
    else:
        approval = {
            "present": True,
            "id": selected.id,
            "class": selected.approval_class,
            "scope_type": selected.scope_type,
            "expires_in_days": max(0, (selected.valid_until - now).days),
            "conditions": effective_conditions(
                selected.conditions,
                tool=tool,
                action_type=None if contract is None else contract.action_type,
                input_keys=None if contract is None else contract.input_keys,
                data_grade=snapshot.data_grade,
                purpose=getattr(snapshot.relations.get(selected.relation_id), "purpose", None),
            ),
        }
        # 결과 상한은 호출 뒤에 쓰이지만 형식 오류는 호출 전에 막는다.
        for limit_key in RESULT_LIMIT_KEYS:
            _condition_limit(selected.conditions, limit_key)
        _response_scan_mode(selected.conditions)
        purpose = approval["conditions"].get("require_consent")
        if purpose is None:
            consent = {"status": "not_applicable", "source": None}
        elif isinstance(purpose, str) and purpose:
            status, source = consent_state(snapshot, principal, purpose)
            consent = {"status": status, "source": source}
        else:
            raise InputError("require_consent must be a purpose string")

    return make_policy_input(
        principal=principal,
        server=server_doc,
        tool=tool_doc,
        argument_keys=sorted(str(k) for k in arguments),
        argument_sizes=_argument_sizes(arguments),
        approval=approval,
        consent=consent,
        now=now,
        high_risk_tools=sorted(high_risk_tools),
        mode=mode.value,
        operation=operation.value,
        # 인자 패턴 정책은 계약 관리 서버에만 판정한다. 1단계 서버는 입력도 만들지 않는다.
        argument_patterns=(
            _argument_patterns(
                snapshot,
                principal,
                approval.get("conditions", {}),
                arguments,
                secret_markers,
                timing,
            )
            if managed
            else None
        ),
    )


def input_secret_result(
    snapshot: Snapshot,
    selected: ApprovalRow | None,
    arguments: Mapping[str, Any],
    policy_input: Mapping[str, Any],
    *,
    scan_unmanaged: str = "observe",
    observed: list[str] | None = None,
) -> StageResult | None:
    """호출 인자에 비밀이 있으면 막는 결과(POL-E-05, 도구로 보내기 전 입력).

    승인 조건 ``allow_input_secrets``에 적은 탐지 종류는 이 승인의 도구에 한해 허용한다. 사유에는
    탐지 종류와 건수만 남기고 값은 남기지 않는다. 운영자가 정한 비밀 표지(``secret_like``)도 본다.
    계약 관리가 아닌 서버는 ``scan_unmanaged``가 ``enforce``일 때만 막고, 아니면 막지 않고 정책
    식별자만 ``observed``에 더한다.
    """
    server = snapshot.server
    managed = server is not None and server.contract_status == "managed"
    watch_only = not managed and scan_unmanaged != "enforce"
    patterns = policy_input["arguments"].get("patterns") or {}
    # 크기·깊이 상한을 넘으면 네 패턴이 모두 참이 되어 다른 패턴 규칙이 이미 막는다. 훑지 않는다.
    if patterns and all(patterns.values()):
        return None
    allowed: set[str] = set()
    if selected is not None:
        allowed = set(_condition_list(selected.conditions, "allow_input_secrets"))
    found = {
        kind: count
        for kind, count in scan_arguments(arguments).items()
        if kind in INPUT_SECRET_KINDS and kind not in allowed
    }
    if patterns.get("secret_like") and CUSTOM_MARKER not in allowed:
        found[CUSTOM_MARKER] = 1
    if not found:
        return None
    if watch_only:
        if observed is not None:
            observed.append(POL_INPUT_SENSITIVE)
        return None
    detail = "input " + ",".join(f"{kind}={count}" for kind, count in sorted(found.items()))
    return StageResult.finding(Reason.POLICY_DETECT, POL_INPUT_SENSITIVE, detail)


@dataclass(frozen=True)
class PolicyStageResult:
    results: list[tuple[Stage, StageResult | SkippedStage]]
    observable: bool
    decision: PolicyDecision | None
    policy_ids: tuple[str, ...]
    obligations: tuple[Any, ...]
    version_id: str | None
    bundle_sha256: str | None
    dependency: Dependency | None = None


async def policy_stage(
    deps: PipelineDeps,
    snapshot: Snapshot,
    policy_input: dict[str, Any],
    timeout: float,
) -> PolicyStageResult:
    def stopped(result: StageResult, dependency: Dependency | None = None) -> PolicyStageResult:
        # 정책 엔진이 의무를 지원하지 못한다고 답한 경우는 의무 확인 단계의 중단이다.
        stage = Stage.OBLIGATIONS if result.reason_code == Reason.UNSUPPORTED else Stage.POLICY
        return PolicyStageResult([(stage, result)], False, None, (), (), None, None, dependency)

    version = snapshot.policy_version
    if version is None:
        return stopped(StageResult.stop(Reason.POLICY_VERSION_MISMATCH, detail="no active policy"))
    if deps.evaluate is None:
        return stopped(
            StageResult.stop(Reason.DEPENDENCY_FAILURE, detail="no policy engine"), Dependency.OPA
        )
    try:
        async with asyncio.timeout(timeout):
            evaluation = await deps.evaluate(
                policy_input,
                policy_version_id=version.id,
                bundle_sha256=version.bundle_sha256,
                budget_seconds=timeout,
            )
    except Exception:
        return stopped(StageResult.stop(Reason.DEPENDENCY_FAILURE), Dependency.OPA)
    if evaluation.failure is not None:
        dependency = (
            Dependency.OPA if evaluation.failure.reason_code == Reason.DEPENDENCY_FAILURE else None
        )
        return stopped(evaluation.failure, dependency)
    output = evaluation.output
    if output is None or output.missing_inputs:
        return stopped(StageResult.stop(Reason.SCHEMA_ERROR, detail="missing policy inputs"))
    if (output.policy_version_id, output.bundle_sha256) != (version.id, version.bundle_sha256):
        return stopped(StageResult.stop(Reason.POLICY_VERSION_MISMATCH))
    normalized = normalize_policy_output(output.decision, output.policy_ids, output.obligations)
    if normalized.failure is not None:
        stage = (
            Stage.POLICY
            if normalized.failure.reason_code == Reason.SCHEMA_ERROR
            else Stage.OBLIGATIONS
        )
        return PolicyStageResult(
            [(stage, normalized.failure)],
            False,
            None,
            (),
            (),
            version.id,
            version.bundle_sha256,
        )
    results: list[tuple[Stage, StageResult | SkippedStage]] = []
    for finding in normalized.findings:
        results.append((Stage.POLICY, finding))
    if not normalized.findings:
        results.append((Stage.POLICY, StageResult.passed()))
    return PolicyStageResult(
        results,
        bool(output.observable),
        normalized.decision,
        tuple(output.policy_ids),
        normalized.obligations,
        version.id,
        version.bundle_sha256,
    )


def target_binding(
    profile: str | None, resolved: ResolvedServer, tool: str, arguments: Mapping[str, Any]
) -> Target | StageResult | None:
    """프로필이 있는 서버 호출의 대상·행위. 프로필이 없으면 None, 정할 수 없으면 중단 결과.

    읽기가 아닌 효과를 정하지 못하는 호출(프로필에 없는 도구, 빠지거나 모호한 대상)은 승인으로
    풀 수 없으므로 업스트림으로 보내지 않는다.
    """
    if profile is None:
        return None
    try:
        return bind_target(profile, resolved.server_id, tool, arguments)
    except TargetUnresolved as exc:
        return StageResult.stop(Reason.CALL_APPROVAL_REQUIRED, detail=f"target: {exc}"[:200])


@dataclass(frozen=True)
class ObligationCheck:
    results: list[StageResult]
    consume: ConsumeRequest | None


def match_call_approval(
    snapshot: Snapshot,
    principal: Principal,
    resolved: ResolvedServer,
    tool: str,
    arguments: Mapping[str, Any],
    config: PluginConfig,
    invocation_id: UUID,
    binding: Target | None = None,
) -> tuple[StageResult | None, ConsumeRequest | None]:
    if config.fingerprint_key is None:
        return StageResult.stop(
            Reason.CALL_APPROVAL_REQUIRED, detail="fingerprint key not set"
        ), None
    bound_target = binding.target if binding is not None else None
    bound_action = binding.action if binding is not None else None
    version = snapshot.policy_version
    try:
        fingerprint = argument_fingerprint(arguments, config.fingerprint_key)
    except ValueError:
        return StageResult.stop(
            Reason.CALL_APPROVAL_REQUIRED, detail="arguments cannot be fingerprinted"
        ), None

    contract = current_contract(snapshot, tool)
    one_shot_only = contract is not None and contract.action_type in ONE_SHOT_ACTIONS

    def same_call(row: CallApprovalRow) -> bool:
        # 기간 승인은 인자 지문을 풀고 나머지 결속은 그대로 둔다. 1회 승인과 삭제·외부 전송·자격
        # 접근 도구는 지문까지 정확히 맞아야 한다. 기간 승인은 사용 횟수 상한이 있다.
        windowed = row.valid_until is not None
        fp_free = windowed and not one_shot_only
        return (
            row.org_id == principal.org_id
            and row.principal_type == principal.principal_type.value
            and row.principal_id == principal.principal_id
            and row.server_id == resolved.server_id
            and row.tool == tool
            and (fp_free or row.args_fp == fingerprint)
            and (not windowed or row.uses < WINDOW_MAX_USES)
            and row.fp_key_version == config.fingerprint_key_version
            and row.contract_version is None
            and bound_to_current_contract(snapshot, tool, row.contract_id)
            and row.target == bound_target
            and row.action == bound_action
            and row.exec_contract_sha256 == resolved.exec_contract_sha256
            and (row.valid_until or row.expires_at) > snapshot.now
        )

    candidates = [row for row in snapshot.call_approvals if same_call(row)]
    exact = sorted(
        (r for r in candidates if version is not None and r.policy_version_id == version.id),
        key=lambda r: str(r.id),
    )
    if exact:
        row = exact[0]
        return None, ConsumeRequest(
            call_approval_id=row.id,
            invocation_id=invocation_id,
            principal_type=row.principal_type,
            principal_id=row.principal_id,
            server_id=row.server_id,
            tool=row.tool,
            args_fp=row.args_fp,
            policy_version_id=row.policy_version_id,
            state_version=row.state_version,
            contract_id=row.contract_id,
            target=row.target,
            action=row.action,
            exec_contract_sha256=row.exec_contract_sha256,
            windowed=row.valid_until is not None,
        )
    if candidates:
        return StageResult.stop(Reason.CALL_APPROVAL_STALE), None
    return StageResult.stop(Reason.CALL_APPROVAL_REQUIRED), None


def obligation_check(
    snapshot: Snapshot,
    principal: Principal,
    resolved: ResolvedServer,
    tool: str,
    arguments: Mapping[str, Any],
    obligations: Sequence[Any],
    config: PluginConfig,
    invocation_id: UUID,
    binding: Target | None = None,
) -> ObligationCheck:
    consume: ConsumeRequest | None = None
    for obligation in obligations:
        if isinstance(obligation, RequireCallApproval):
            failure, consume = match_call_approval(
                snapshot, principal, resolved, tool, arguments, config, invocation_id, binding
            )
            if failure is not None:
                return ObligationCheck([failure], None)
        elif isinstance(obligation, RequireConsent):
            status, _ = consent_state(snapshot, principal, obligation.purpose)
            if status != "granted":
                reason = {
                    "absent": Reason.CONSENT_REQUIRED,
                    "expired": Reason.CONSENT_EXPIRED,
                    "revoked": Reason.CONSENT_REVOKED,
                }[status]
                return ObligationCheck([StageResult.stop(reason)], None)
        elif isinstance(obligation, RequireUserConfirmation):
            failure, confirmation = match_confirmation(
                snapshot, principal, resolved, tool, arguments, config, invocation_id
            )
            if failure is not None:
                return ObligationCheck([failure], None)
            assert confirmation is not None
            consume = (
                replace(consume, confirmation=confirmation.confirmation)
                if consume is not None else confirmation
            )
    return ObligationCheck([], consume)


def match_confirmation(
    snapshot: Snapshot, principal: Principal, resolved: ResolvedServer, tool: str,
    arguments: Mapping[str, Any], config: PluginConfig, invocation_id: UUID,
) -> tuple[StageResult | None, ConsumeRequest | None]:
    if principal.principal_type is not PrincipalType.USER or config.fingerprint_key is None:
        return StageResult.stop(Reason.CONFIRMATION_REQUIRED), None
    try:
        fingerprint = argument_fingerprint(arguments, config.fingerprint_key)
    except ValueError:
        return StageResult.stop(Reason.CONFIRMATION_REQUIRED), None
    candidates = [
        c for c in snapshot.self_confirmations
        if c.org_id == principal.org_id and c.principal_id == principal.principal_id
        and c.confirmed_by_user_id == principal.principal_id
        and c.server_id == resolved.server_id and c.tool == tool
        and c.args_fp == fingerprint and c.fp_key_version == config.fingerprint_key_version
        and bound_to_current_contract(snapshot, tool, c.contract_id)
        and c.exec_contract_sha256 == resolved.exec_contract_sha256
        and c.expires_at > snapshot.now
        and (snapshot.settings is not None and (
            not snapshot.settings.require_separate_confirm_key
            or c.confirmed_by_key_token != c.requested_by_key_token
        ))
    ]
    exact = sorted(
        (c for c in candidates if snapshot.policy_version is not None
         and c.policy_version_id == snapshot.policy_version.id), key=lambda c: str(c.id)
    )
    if exact:
        c = exact[0]
        return None, ConsumeRequest(
            call_approval_id=None, invocation_id=invocation_id, principal_type="user",
            principal_id=c.principal_id, server_id=c.server_id, tool=c.tool, args_fp=c.args_fp,
            policy_version_id=c.policy_version_id, state_version=c.state_version,
            confirmation=ConfirmationConsume(c.id, c.org_id, c.fp_key_version, c.state_version),
            contract_id=c.contract_id, exec_contract_sha256=c.exec_contract_sha256,
        )
    reason = Reason.CONFIRMATION_STALE if candidates else Reason.CONFIRMATION_REQUIRED
    return StageResult.stop(reason), None


def confirmation_display(
    arguments: Mapping[str, Any], fields: Sequence[str]
) -> dict[str, Any]:
    if not fields:
        return {"keys": sorted(arguments), "sizes": _argument_sizes(arguments)}
    return {
        name: (value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))[:256]
        for name in fields if name in arguments for value in (arguments[name],)
    }

# 본인 확인 링크는 요청의 유효 시간(10분)과 같이 만료된다.
CONFIRMATION_LINK_TTL = 600

_MISSING = {
    "litellm_call_id": "not_provided",
    "requested_server_name": "not_provided",
    "tool": "not_provided",
    "state_epoch": "snapshot_unavailable",
    "settings_version": "snapshot_unavailable",
    "policy_version_id": "policy_not_evaluated",
    "bundle_sha256": "policy_not_evaluated",
    "policy_decision": "policy_not_evaluated",
    "resolved_server_id": "server_unresolved",
    "resolved_url_sha256": "server_unresolved",
    "resolved_transport": "server_unresolved",
    "resolved_auth_type": "server_unresolved",
    "candidates_with_same_name": "server_unresolved",
    "selected_approval_id": "no_selected_approval",
    "consumed_call_approval_id": "not_consumed",
    "revoked_after_snapshot": "pending_response",
    "revocation_check": "pending_response",
}

_OBLIGATION_CLASSES = (
    AlertObligation, RequireCallApproval, RequireConsent, RequireUserConfirmation,
)


@dataclass
class _Run:
    req: CallRequest
    stages: _Stages
    principal: Principal
    mode: Mode
    evaluated_at: datetime
    deadline: Deadline
    current: Stage = Stage.CONTEXT
    snapshot: Snapshot | None = None
    selected: ApprovalRow | None = None
    consume: ConsumeRequest | None = None
    binding: Target | None = None
    # (프로필, 출처): 승인된 배포 계약에서 자동으로 골랐거나 환경 변수로 덮어쓴 결과.
    profile: tuple[str, str] | None = None
    policy: PolicyStageResult | None = None
    observation: ObservationSettings = field(default_factory=ObservationSettings)
    # 판정 사건의 기록이 시작됐는지(결과가 불명일 수 있다), 어느 위치든 남겨졌는지.
    event_started: bool = False
    event_written: bool = False
    # 이 호출에서 기록을 시작한 가장 큰 시도 번호. 취소 사건은 그보다 큰 번호를 쓴다.
    last_attempt: int = 0
    control_listing: bool = False
    timing: StageClock = OFF
    # 승인 조건에 상한이 없을 때 계약 관리 서버에 채우는 결과 상한(바이트, 항목 수).
    result_defaults: tuple[int | None, int | None] = (None, None)
    # 판정을 시작한 단조 시계 값(나노초). 판정 사건에 걸린 시간을 남기는 데 쓴다.
    started_at: int = field(default_factory=time.perf_counter_ns)
    # 막힌 호출이 연(또는 다시 쓴) 호출별 승인 요청의 식별자
    call_approval_request: str | None = None
    # 막힌 호출이 연 본인 확인 요청의 (식별자, 주체, 서버, 도구, 인자 지문)
    confirmation_request: tuple[str, str, str, str, str] | None = None
    # 같은 호출의 직전 요청이 거부된 사유(거부 기억 안의 재시도), 승인이 쓰이지 않고 만료됐는지
    denial_reason: str | None = None
    previous_expired: bool = False
    # 계약 관리가 아닌 서버에서 관측만 한 검사 결과의 정책 식별자(입력 쪽)와 검사 설정
    unmanaged_findings: list[str] = field(default_factory=list)
    scan_unmanaged: str = "observe"
    # 서버 주소 재확인(observe)에서 걸린 종류(private·rebind·unresolved). 막지 않고 기록만 한다.
    resolve_findings: list[str] = field(default_factory=list)
    # 전달되는 호출자 토큰의 aud 확인 결과(대상 불일치, 읽을 수 없어 확인하지 않음)
    aud_mismatch: bool = False
    aud_unchecked: bool = False
    aud_unchecked_reason: str | None = None
    # 전달되는 호출자 토큰이 승인된 범위를 넘은 범위 이름, 확인하지 않은 이유
    scope_exceeded: list[str] = field(default_factory=list)
    scope_unchecked_reason: str | None = None


def _decision_snapshot(
    run: _Run,
    conclusion: Conclusion,
    consumed: ConsumeRequest | None,
    *,
    attempt_id: int | None = None,
) -> DecisionSnapshot:
    """판정 사건의 본문. ``attempt_id``를 주면 그 시도의 사건이고 처음 시도를 원래 참조로 담는다."""
    req, snap, policy = run.req, run.snapshot, run.policy
    attempt = req.attempt_id if attempt_id is None else attempt_id
    resolved = req.resolved
    values: dict[str, Any] = {
        "litellm_call_id": req.hook.litellm_call_id,
        "requested_server_name": req.hook.server_name,
        "tool": req.hook.tool_name,
        "state_epoch": snap.epoch if snap else None,
        "settings_version": snap.settings.settings_version if snap and snap.settings else None,
        "policy_version_id": policy.version_id if policy else None,
        "bundle_sha256": policy.bundle_sha256 if policy else None,
        "policy_decision": policy.decision if policy else None,
        "resolved_server_id": resolved.server_id if resolved else None,
        "resolved_url_sha256": resolved.url_sha256 if resolved else None,
        "resolved_transport": resolved.transport if resolved else None,
        "resolved_auth_type": resolved.auth_type if resolved else None,
        "candidates_with_same_name": resolved.candidates_with_same_name if resolved else None,
        "selected_approval_id": run.selected.id if run.selected else None,
        "consumed_call_approval_id": (
            str(consumed.call_approval_id)
            if consumed is not None and consumed.call_approval_id is not None else None
        ),
    }
    reasons = {k: _MISSING[k] for k, v in values.items() if v is None}
    if resolved is not None and resolved.url_sha256 is None:
        reasons["resolved_url_sha256"] = "not_applicable"  # 로컬 실행 서버는 URL이 없다
    # 식별 방식과 실행 계약은 해석된 서버가 있을 때만 값이 있고, 없는 이유를 따로 적지 않는다.
    values["resolved_identity_kind"] = resolved.identity_kind if resolved else None
    values["resolved_exec_contract_sha256"] = resolved.exec_contract_sha256 if resolved else None
    values["resolved_exec_contract_version"] = resolved.exec_contract_version if resolved else None
    values["resolved_credential_ref"] = resolved.credential_ref if resolved else None
    values["target_profile"] = run.profile[0] if run.profile else None
    values["target_profile_source"] = run.profile[1] if run.profile else None
    values["bound_target"] = run.binding.target if run.binding else None
    values["bound_action"] = run.binding.action if run.binding else None
    reasons["revoked_after_snapshot"] = _MISSING["revoked_after_snapshot"]
    reasons["revocation_check"] = _MISSING["revocation_check"]
    if snap is not None:
        if snap.settings is None:
            reasons["settings_version"] = "no_settings_row"
        if snap.epoch is None:
            reasons["state_epoch"] = "no_epoch_row"
    if policy is not None:
        for name in ("policy_version_id", "bundle_sha256", "policy_decision"):
            if name in reasons:
                reasons[name] = "policy_stopped"
    ref = MintContext(invocation_id=req.invocation_id, attempt_id=attempt)
    original = MintContext(invocation_id=req.invocation_id, attempt_id=req.attempt_id)
    return DecisionSnapshot(
        invocation_id=req.invocation_id,
        attempt_id=attempt,
        decision_ref=ref.decision_ref,
        original_decision_ref=original.decision_ref if attempt != req.attempt_id else None,
        operation=req.operation,
        evaluated_at=run.evaluated_at,
        principal=run.principal,
        mode=run.mode,
        policy_ids=policy.policy_ids if policy else (),
        obligation_types=tuple(
            o.type
            for o in (policy.obligations if policy else ())
            if isinstance(o, _OBLIGATION_CLASSES)
        ),
        stages=entries_from_results(run.stages.items),
        findings=conclusion.findings,
        stop=conclusion.stop,
        evaluated_decision=conclusion.evaluated_decision,
        enforced_action=conclusion.enforced_action,
        missing_reasons=reasons,
        outcome=_outcome_of(conclusion),
        decision_us=(time.perf_counter_ns() - run.started_at) // 1000,
        approval_hold=req.hold[0] if req.hold else None,
        approval_hold_ms=req.hold[1] if req.hold else None,
        cause="control_key_call"
        if conclusion.stop is not None and conclusion.stop.detail == "control_key_call"
        else None,
        **{k: v for k, v in values.items() if v is not None},
    )


def _outcome_of(conclusion: Conclusion) -> DecisionOutcome:
    """사건에 남기는 결과 분류. 차단 사유는 stop, 없으면 첫 finding이다."""
    allowed = conclusion.enforced_action is Action.ALLOW
    first = conclusion.stop or (conclusion.findings[0] if conclusion.findings else None)
    return decision_outcome(
        allowed=allowed,
        reason_code=first.reason_code if first else None,
        has_findings=bool(conclusion.findings),
    )


def blocking_reason(
    conclusion: Conclusion,
    *,
    mode: Mode,
    observation: ObservationSettings,
    policy_observable: bool,
) -> str:
    """차단 응답의 오류 코드가 될 사유.

    stop이 있으면 그 사유이고, 없으면 관측 모드로 전환되지 않은 finding 중 파이프라인 순서상
    첫 사유이다.
    """
    if conclusion.stop is not None:
        assert conclusion.stop.reason_code is not None
        return conclusion.stop.reason_code
    for finding in conclusion.findings:
        single = conclude(
            [finding], mode=mode, observation=observation, policy_observable=policy_observable
        )
        if single.enforced_action is Action.BLOCK:
            assert finding.reason_code is not None
            return finding.reason_code
    raise ValueError("conclusion does not block")


async def _run_stages(run: _Run, deps: PipelineDeps) -> None:
    req, stages, config = run.req, run.stages, deps.config
    hook, principal = req.hook, req.principal
    run.current = Stage.CONTEXT
    early = context_result(req, deps.verified(), deps.unverified_cause())
    if early is not None:
        stages.add(Stage.CONTEXT, early)
        return
    stages.add(Stage.CONTEXT, StageResult.passed())
    resolved = req.resolved
    tool = hook.tool_name
    assert resolved is not None and tool is not None

    run.current = Stage.SNAPSHOT
    query = SnapshotQuery(
        instance_id=config.instance_id,
        server_id=resolved.server_id,
        tool=tool,
        principal_id=principal.principal_id,
        key_id=principal.key_id,
        user_id=principal.user_id,
        team_id=principal.team_id,
    )
    snapshot: Snapshot | None = None
    timing = run.timing
    for attempt in (1, 2):
        started = timing.now()
        timing.wait()
        try:
            try:
                async with asyncio.timeout(run.deadline.remaining()):
                    snapshot = await deps.snapshots.read_snapshot(query)
            finally:
                timing.since("snapshot", started)
            break
        except Exception as exc:
            log.debug(
                "스냅숏 조회 실패(%d): %s sqlstate=%s",
                attempt,
                type(exc).__name__,
                getattr(exc, "sqlstate", None),
            )
            # 조회는 읽기 전용이라 다시 읽어도 안전하다. 풀에서 나온 끊어진 연결 같은 일시 오류는
            # 같은 예산 안에서 한 번 흡수한다. 시간 초과나 남은 예산이 없으면 다시 읽지 않는다.
            if attempt == 2 or isinstance(exc, TimeoutError) or run.deadline.remaining() <= 0:
                stages.dependency = Dependency.DB
                stages.add(Stage.SNAPSHOT, StageResult.stop(Reason.DEPENDENCY_FAILURE))
                return
    assert snapshot is not None
    stages.add(Stage.SNAPSHOT, StageResult.passed())
    run.snapshot = snapshot
    run.evaluated_at = snapshot.now
    settings = snapshot.settings
    run.mode = effective_mode(config.mode_ceiling, settings.mode if settings else Mode.ENFORCE)
    if settings is not None:
        run.observation = ObservationSettings(
            observable_reasons=settings.observable_reasons,
            observable_policy_ids=settings.observable_policy_ids,
        )

    run.current = Stage.STATE
    run.principal = derive_principal(snapshot, principal)
    control_key = settings.control_key_token if settings else None
    is_control = (
        control_key is not None
        and principal.key_id is not None
        and hmac.compare_digest(control_key.encode(), principal.key_id.encode())
    )
    if is_control and req.operation is OperationType.TOOL_CALL:
        stages.add(
            Stage.STATE, StageResult.stop(Reason.ENFORCEMENT_UNVERIFIED, detail="control_key_call")
        )
        return
    if is_control and req.operation is OperationType.RUNTIME_DISCOVERY:
        negative = control_listing_negative(snapshot, run.principal, resolved, tool)
        if negative is not None:
            stages.add(Stage.STATE, negative)
        else:
            run.control_listing = True
            stages.add(Stage.STATE, StageResult.passed())
        return
    state = state_results(snapshot, run.principal, resolved)
    for result in state:
        stages.add(Stage.STATE, result)
    if not state:
        stages.add(Stage.STATE, StageResult.passed())
    if stages.stopped:
        return

    run.current = Stage.DENIAL_APPROVAL
    selection = denial_and_approval(snapshot, run.principal, resolved, tool)
    for result in selection.results:
        stages.add(Stage.DENIAL_APPROVAL, result)
    if not selection.results:
        stages.add(Stage.DENIAL_APPROVAL, StageResult.passed())
    run.selected = selection.selected
    if stages.stopped:
        return
    if req.operation is OperationType.TOOL_CALL:
        forward = token_forward_result(resolved, run.selected)
        if forward is not None:
            stages.add(Stage.DENIAL_APPROVAL, forward)
            return
        address = await address_verdict(run, deps, resolved, run.selected)
        if address is not None:
            stages.add(Stage.DENIAL_APPROVAL, address)
        audience = audience_result(req.hook.bearer, resolved, config.token_audience, run)
        if audience is not None:
            stages.add(Stage.DENIAL_APPROVAL, audience)
            return
        scope = scope_result(req.hook.bearer, resolved, snapshot, config.token_scope, run)
        if scope is not None:
            stages.add(Stage.DENIAL_APPROVAL, scope)
            return

    if req.operation is OperationType.RUNTIME_DISCOVERY and (
        snapshot.server is None or snapshot.server.contract_status != "managed"
    ):
        return
    run.current = Stage.CONTRACT
    stages.add(Stage.CONTRACT, contract_result(snapshot, tool, config.observe_seconds, resolved))
    overdue = vuln_result(snapshot)
    if overdue is not None:
        stages.add(Stage.CONTRACT, overdue)
    if req.operation is OperationType.RUNTIME_DISCOVERY:
        return
    unknown_keys = input_keys_unknown(snapshot, tool, run.selected)
    if unknown_keys is not None:
        stages.add(Stage.CONTRACT, unknown_keys)
    run.current = Stage.POLICY
    markers: Sequence[str] = ()
    if (
        deps.secret_markers is not None
        and snapshot.policy_version is not None
        and snapshot.server is not None
        and snapshot.server.contract_status == "managed"
    ):
        started = timing.now()
        timing.wait()
        try:
            fetched = await deps.secret_markers(
                policy_version_id=snapshot.policy_version.id,
                bundle_sha256=snapshot.policy_version.bundle_sha256,
                budget_seconds=run.deadline.remaining(),
            )
        except Exception:
            fetched = None
        timing.since("markers", started)
        if fetched is None:
            stages.add(Stage.POLICY, StageResult.stop(Reason.DEPENDENCY_FAILURE))
            stages.dependency = Dependency.OPA
            return
        markers = fetched
    started = timing.now()
    try:
        policy_input = build_policy_input(
            snapshot=snapshot,
            principal=run.principal,
            resolved=resolved,
            tool=tool,
            arguments=hook.arguments,
            selected=run.selected,
            mode=run.mode,
            operation=req.operation,
            high_risk_tools=config.high_risk_tools,
            secret_markers=markers,
            timing=timing,
        )
        secret = input_secret_result(
            snapshot, run.selected, hook.arguments, policy_input,
            scan_unmanaged=config.scan_unmanaged, observed=run.unmanaged_findings,
        )
    except InputError as exc:
        stages.add(Stage.POLICY, StageResult.stop(Reason.SCHEMA_ERROR, detail=str(exc)[:200]))
        return
    if secret is not None:
        stages.add(Stage.POLICY, secret)
    # 패턴 계산은 따로 재므로 입력 단계에서 뺀다.
    timing.since("input", started + timing.seconds.get("patterns", 0.0))
    started = timing.now()
    if snapshot.policy_version is not None and deps.evaluate is not None:
        timing.wait()
    run.policy = await policy_stage(deps, snapshot, policy_input, run.deadline.remaining())
    timing.since("policy", started)
    if deps.shadow is not None and run.policy.decision is not None:
        with contextlib.suppress(Exception):
            deps.shadow(
                policy_input, invocation_id=req.invocation_id, server_id=resolved.server_id,
                tool=tool, decision=run.policy.decision.value, policy_ids=run.policy.policy_ids,
            )
    stages.dependency = run.policy.dependency
    for stage, result in run.policy.results:
        stages.add(stage, result)
    if stages.stopped:
        return

    run.current = Stage.OBLIGATIONS
    run.profile = effective_profile(
        config.target_profiles, resolved.server_id, snapshot.auto_profile
    )
    binding = target_binding(
        run.profile[0] if run.profile else None, resolved, tool, hook.arguments
    )
    if isinstance(binding, StageResult):
        stages.add(Stage.OBLIGATIONS, binding)
        return
    run.binding = binding
    obligations = run.policy.obligations
    # 프로필이 있는 서버의 변경·실행 호출은 정책이 요구하지 않아도 대상에 묶인 승인이 있어야 한다.
    if (
        binding is not None
        and binding.effect != READ
        and not any(isinstance(o, RequireCallApproval) for o in obligations)
    ):
        obligations = (*obligations, RequireCallApproval())
    started = timing.now()
    check = obligation_check(
        snapshot,
        run.principal,
        resolved,
        tool,
        hook.arguments,
        obligations,
        config,
        req.invocation_id,
        binding,
    )
    timing.since("fingerprint", started)
    check = await _previous_outcome(run, deps, check, resolved, tool, hook.arguments)
    for result in check.results:
        stages.add(Stage.OBLIGATIONS, result)
    if not check.results:
        stages.add(Stage.OBLIGATIONS, StageResult.passed())
    run.consume = check.consume
    if (
        check.results and check.results[0].reason_code in (
            Reason.CONFIRMATION_REQUIRED, Reason.CONFIRMATION_STALE
        ) and run.principal.principal_type is PrincipalType.USER
        and run.principal.key_id and config.fingerprint_key is not None
    ):
        obligation = next(
            o for o in run.policy.obligations if isinstance(o, RequireUserConfirmation)
        )
        contract = current_contract(snapshot, tool)
        assert snapshot.policy_version is not None
        try:
            async with asyncio.timeout(run.deadline.remaining()):
                confirmation_id = new_uuid7()
                args_fp = argument_fingerprint(hook.arguments, config.fingerprint_key)
                await deps.snapshots.request_confirmation({
                    "id": confirmation_id, "iid": config.instance_id,
                    "org_id": run.principal.org_id, "principal_id": run.principal.principal_id,
                    "server_id": resolved.server_id, "tool": tool,
                    "args_fp": args_fp,
                    "fp_key_version": config.fingerprint_key_version,
                    "policy_version_id": snapshot.policy_version.id,
                    "purpose": obligation.purpose, "key_token": run.principal.key_id,
                    "display": confirmation_display(hook.arguments, obligation.display_fields),
                    "contract_id": contract.id if contract is not None else None,
                    "exec_contract_sha256": resolved.exec_contract_sha256,
                })
            run.confirmation_request = (
                str(confirmation_id), run.principal.principal_id, resolved.server_id, tool, args_fp
            )
        except Exception as exc:
            # 확인을 만들지 못해도 이미 stop이며, 표시 값은 다른 저장소로 보내지 않는다.
            log.debug("본인 확인 요청 실패: %s", type(exc).__name__)
    await _open_call_approval(run, deps, check, resolved, tool, hook.arguments, binding)


async def _previous_outcome(
    run: _Run, deps: PipelineDeps, check: ObligationCheck, resolved: ResolvedServer, tool: str,
    arguments: Mapping[str, Any],
) -> ObligationCheck:
    """승인이 없어 막힌 호출의 직전 요청이 거부됐으면 새 요청 없이 그 사유로 거절한다.

    거부는 그 요청 1건에 한정되고 ``call_denial_minutes`` 안에서만 기억한다. 직전 승인이 쓰이지
    않고 만료됐으면 막힘은 그대로 두고 그 사실만 호출자에게 알린다(새 요청은 평소처럼 열린다).
    """
    config, principal, snapshot = deps.config, run.principal, run.snapshot
    first = check.results[0] if check.results else None
    if (
        first is None or first.detail is not None
        or first.reason_code not in (Reason.CALL_APPROVAL_REQUIRED, Reason.CALL_APPROVAL_STALE)
        or config.call_denial_minutes <= 0 or config.fingerprint_key is None
        or principal.principal_type not in (
            PrincipalType.USER, PrincipalType.TEAM_KEY, PrincipalType.SERVICE_ACCOUNT)
        or not principal.principal_id or snapshot is None
    ):
        return check
    try:
        async with asyncio.timeout(run.deadline.remaining()):
            prior = await deps.snapshots.recent_call_outcome({
                "iid": config.instance_id, "principal_type": principal.principal_type.value,
                "principal_id": principal.principal_id, "server_id": resolved.server_id,
                "tool": tool, "args_fp": argument_fingerprint(arguments, config.fingerprint_key),
                "fp_key_version": config.fingerprint_key_version,
                "minutes": config.call_denial_minutes,
            })
    except Exception as exc:
        log.debug("직전 호출별 승인 결과 조회 실패: %s", type(exc).__name__)
        return check
    if prior is None:
        return check
    if prior[0] == "rejected":
        run.denial_reason = prior[1]
        return ObligationCheck([StageResult.stop(Reason.CALL_APPROVAL_DENIED)], None)
    run.previous_expired = True
    return check


async def _open_call_approval(
    run: _Run, deps: PipelineDeps, check: ObligationCheck, resolved: ResolvedServer, tool: str,
    arguments: Mapping[str, Any], binding: Target | None,
) -> None:
    """승인이 없어 막힌 호출의 호출별 승인 요청을 열거나 같은 호출의 대기 요청을 다시 쓴다.

    요청은 대기 상태로만 열리고 승인은 사람이 한다. 열지 못해도 이미 stop이다.
    """
    config, principal, snapshot = deps.config, run.principal, run.snapshot
    first = check.results[0] if check.results else None
    if (
        first is None or first.detail is not None
        or first.reason_code not in (Reason.CALL_APPROVAL_REQUIRED, Reason.CALL_APPROVAL_STALE)
        or principal.principal_type not in (
            PrincipalType.USER, PrincipalType.TEAM_KEY, PrincipalType.SERVICE_ACCOUNT)
        or not principal.principal_id or not principal.org_id
        or config.fingerprint_key is None or snapshot is None or snapshot.policy_version is None
    ):
        return
    contract = current_contract(snapshot, tool)
    try:
        async with asyncio.timeout(run.deadline.remaining()):
            run.call_approval_request = await deps.snapshots.request_call_approval({
                "id": new_uuid7(), "iid": config.instance_id, "org_id": principal.org_id,
                "principal_type": principal.principal_type.value,
                "principal_id": principal.principal_id, "server_id": resolved.server_id,
                "tool": tool, "args_fp": argument_fingerprint(arguments, config.fingerprint_key),
                "fp_key_version": config.fingerprint_key_version,
                "policy_version_id": snapshot.policy_version.id,
                "requested_by": AUTO_REQUESTER, "minutes": AUTO_REQUEST_MINUTES,
                "display": call_display(arguments),
                "contract_id": contract.id if contract is not None else None,
                "exec_contract_sha256": resolved.exec_contract_sha256,
                "target": binding.target if binding is not None else None,
                "action": binding.action if binding is not None else None,
            })
    except Exception as exc:
        log.warning("호출별 승인 요청을 열지 못했습니다: %s", type(exc).__name__)


def _mark_written(run: _Run) -> Callable[[], None]:
    def mark() -> None:
        run.event_written = True

    return mark


def _block_with(conclusion: Conclusion, stop: StageResult) -> Conclusion:
    return Conclusion(
        evaluated_decision=Action.BLOCK,
        enforced_action=Action.BLOCK,
        findings=conclusion.findings,
        stop=stop,
    )


async def evaluate_request(
    req: CallRequest, deps: PipelineDeps, timing: StageClock = OFF
) -> Outcome:
    """한 호출(또는 목록의 도구 하나)을 판정하고 증거를 남긴다.

    허용 경로에서 DB 선기록이 실패하면 호출은 ``AUDIT_FAILURE``로 차단된다. 차단 경로의 기록
    실패는 결과를 바꾸지 않고 버퍼(안 되면 표준 오류)에 남긴다. 도구 호출 판정이 외부 취소로
    끝나면 아직 기록하지 못한 판정을 ``CANCELLED`` 사건으로 남기고 취소를 다시 전파한다.
    """
    run = _Run(
        req=req,
        stages=_Stages(),
        principal=req.principal,
        mode=effective_mode(deps.config.mode_ceiling, Mode.ENFORCE),
        evaluated_at=deps.clock(),
        deadline=Deadline(deps.config.decision_budget_seconds),
        timing=timing,
        result_defaults=(
            deps.config.default_max_result_bytes or None,
            deps.config.default_max_result_items or None,
        ),
        scan_unmanaged=deps.config.scan_unmanaged,
    )
    try:
        return await _evaluate(run, deps)
    except asyncio.CancelledError:
        if req.operation is OperationType.TOOL_CALL and not run.event_written:
            await _shielded(_record_cancelled(run, deps))
        raise


async def _shielded(coro: Awaitable[None]) -> None:
    """취소가 한 번 더 와도 기록은 끝까지 가도록 별도 작업으로 돌린다."""
    task = asyncio.ensure_future(coro)
    await asyncio.shield(task)


async def _record_cancelled(run: _Run, deps: PipelineDeps) -> None:
    """남은 판정 예산 안에서 DB → 버퍼 → 표준 오류 순서로 ``CANCELLED`` 판정 사건을 남긴다.

    기록이 이미 시작됐다면 그 사건이 커밋됐는지 알 수 없으므로 같은 키를 쓰지 않고 다음 시도로
    남긴다. 버퍼 기록은 예산과 무관하게 한 번 시도한다.
    """
    try:
        kept = [(stage, result) for stage, result in run.stages.items if stage is not run.current]
        stages = _Stages()
        stages.items = kept
        stages.add(run.current, StageResult.stop(Reason.CANCELLED))
        run.stages = stages
        conclusion = Conclusion(
            evaluated_decision=Action.BLOCK,
            enforced_action=Action.BLOCK,
            findings=(),
            stop=StageResult.stop(Reason.CANCELLED),
        )
        attempt = run.last_attempt + 1 if run.event_started else None
        event = decision_event(_decision_snapshot(run, conclusion, None, attempt_id=attempt))
        stored = await deps.recorder.try_database(event, timeout=run.deadline.remaining())
        if not stored.stored:
            await deps.recorder.fallback(event)
    except Exception as exc:
        log.error("취소된 판정을 기록하지 못했습니다: %s", type(exc).__name__)


async def _evaluate(run: _Run, deps: PipelineDeps) -> Outcome:
    req = run.req
    try:
        await _run_stages(run, deps)
    except Exception as exc:
        log.error("판정 중 예기치 않은 오류: %s", type(exc).__name__)
        run.stages.add(
            run.current,
            StageResult.stop(Reason.SCHEMA_ERROR, detail=f"internal {type(exc).__name__}"[:200]),
        )

    observable = run.policy.observable if run.policy else False
    conclusion = conclude(
        run.stages.results(),
        mode=run.mode,
        observation=run.observation,
        policy_observable=observable,
    )
    consume = run.consume if conclusion.enforced_action is Action.ALLOW else None
    if run.control_listing:
        document = _decision_snapshot(run, conclusion, None)
        return Outcome(
            True,
            document,
            None,
            Evidence.DB,
            _context_document(run, document, True, None),
            run.timing,
        )
    list_key_value = _list_dedup_key(run, conclusion, deps)
    if list_key_value is not None and deps.list_seen and deps.list_seen.seen(list_key_value):
        document = _decision_snapshot(run, conclusion, None)
        return Outcome(
            True,
            document,
            None,
            Evidence.DB,
            _context_document(run, document, True, None),
            run.timing,
        )
    event = decision_event(_decision_snapshot(run, conclusion, consume))
    run.event_started = True
    run.last_attempt = req.attempt_id
    started = run.timing.now()
    run.timing.wait()
    stored = await deps.recorder.try_database(event, consume, timeout=run.deadline.remaining())
    run.timing.since("event", started)
    evidence = Evidence.DB
    attempt: int | None = None
    if stored.stored:
        run.event_written = True
        if list_key_value is not None and deps.list_seen:
            deps.list_seen.add(list_key_value)
    else:
        if stored.consumption_lost:
            reason = Reason(stored.consumption_reason)
            conclusion = _block_with(conclusion, StageResult.stop(reason))
            consume = None
            event = decision_event(_decision_snapshot(run, conclusion, None))
            retry = await deps.recorder.try_database(event, timeout=run.deadline.remaining())
            if retry.stored:
                run.event_written = True
            else:
                evidence = await deps.recorder.fallback(event, on_written=_mark_written(run))
        else:
            if conclusion.enforced_action is Action.ALLOW:
                # 허용 사건이 커밋됐는지 알 수 없다. 같은 키로 차단 사건을 쓰면 재적재가 그것을
                # 허용 사건의 중복으로 버리므로, 차단은 같은 호출의 다음 시도로 남긴다.
                conclusion = apply_record_failure(conclusion)
                consume = None
                attempt = req.attempt_id + 1
                run.last_attempt = attempt
                event = decision_event(
                    _decision_snapshot(run, conclusion, None, attempt_id=attempt)
                )
            evidence = await deps.recorder.fallback(event, on_written=_mark_written(run))

    snapshot_doc = _decision_snapshot(run, conclusion, consume, attempt_id=attempt)
    allowed = conclusion.enforced_action is Action.ALLOW
    error: MintError | None = None
    approval_request_id: str | None = None
    confirmation_wait: tuple[str, str, str, str] | None = None
    if not allowed:
        reason = blocking_reason(
            conclusion, mode=run.mode, observation=run.observation, policy_observable=observable
        )
        error = error_for_reason(
            reason,
            snapshot_doc.decision_ref,
            run.stages.dependency or Dependency.DB,
        )
        if run.call_approval_request is not None and reason in (
            Reason.CALL_APPROVAL_REQUIRED, Reason.CALL_APPROVAL_STALE
        ):
            error = error.model_copy(update={
                "approval_requested": True, "previous_expired": run.previous_expired,
            })
            approval_request_id = run.call_approval_request
        elif reason == Reason.CALL_APPROVAL_DENIED:
            error = error.model_copy(update={"denial_reason": run.denial_reason})
        elif run.confirmation_request is not None and reason in (
            Reason.CONFIRMATION_REQUIRED, Reason.CONFIRMATION_STALE
        ):
            request_id, *wait = run.confirmation_request
            confirmation_wait = (wait[0], wait[1], wait[2], wait[3])
            link = _confirmation_link(deps.config, request_id)
            if link is not None:
                error = error.model_copy(update={"confirm_link": link})
    return Outcome(
        allowed=allowed,
        snapshot=snapshot_doc,
        error=error,
        evidence=evidence,
        context=_context_document(run, snapshot_doc, allowed, consume),
        timing=run.timing,
        approval_request_id=approval_request_id,
        confirmation_wait=confirmation_wait,
    )


def _confirmation_link(config: PluginConfig, confirmation_id: str) -> str | None:
    """직원 화면의 본인 확인 링크. 주소나 서명 키가 없으면 None. 링크는 화면만 연다."""
    if config.console_url is None or config.link_key is None:
        return None
    token = links.make(config.link_key, "confirm", confirmation_id, ttl=CONFIRMATION_LINK_TTL)
    return f"{config.console_url.rstrip('/')}/staff/link/{token}"


def _list_dedup_key(run: _Run, conclusion: Conclusion, deps: PipelineDeps) -> tuple | None:
    """도구 목록에서 결과 없이 통과한 판정의 중복 판단 키. 숨김·발견·정지는 키가 없다."""
    if (
        deps.list_seen is None
        or run.req.operation is not OperationType.RUNTIME_DISCOVERY
        or conclusion.enforced_action is not Action.ALLOW
        or conclusion.evaluated_decision is not Action.ALLOW
        or conclusion.findings
        or conclusion.stop is not None
    ):
        return None
    snap = run.snapshot
    version = snap.policy_version if snap else None
    return list_key(_decision_snapshot(run, conclusion, None), version.id if version else None)


def _result_policy(run: _Run) -> dict[str, Any]:
    """결과 검사 입력. 승인 조건의 상한(없으면 기본 상한)과, 계약 관리 서버의 지시문 표지 검사 여부.

    관측 모드에서는 결과를 막지 않고 기록만 한다. 조건 형식이 틀린 호출은 이미 막혔으므로
    상한을 읽지 못하면 비운다.
    """
    conditions = run.selected.conditions if run.selected else {}
    if not isinstance(conditions, Mapping):
        conditions = {}
    server = run.snapshot.server if run.snapshot else None
    limits: dict[str, int | None] = {}
    for key in RESULT_LIMIT_KEYS:
        try:
            limits[key] = _condition_limit(conditions, key)
        except InputError:
            limits[key] = None
    managed = server is not None and server.contract_status == "managed"
    if managed:
        # 적은 값은 그대로 두고 빈 상한만 기본값으로 채운다(POL-E-16).
        for key, default in zip(RESULT_LIMIT_KEYS, run.result_defaults, strict=True):
            if limits[key] is None:
                limits[key] = default
    try:
        response_scan = _response_scan_mode(conditions)
    except InputError:
        response_scan = DEFAULT_RESPONSE_SCAN
    return {
        **limits,
        "response_scan": response_scan,
        "scan": conditions.get("scan_result") is not False,
        "enforce": run.mode is Mode.ENFORCE,
        # 계약 관리가 아닌 서버는 지시문 표지를 기본으로 기록만 하고, 설정이 enforce일 때 막는다.
        "unmanaged": not managed,
        "scan_enforce": run.scan_unmanaged == "enforce",
    }


def _context_document(
    run: _Run, snapshot: DecisionSnapshot, allowed: bool, consumed: ConsumeRequest | None
) -> dict[str, Any]:
    """응답·실패 이벤트가 읽는 호출 컨텍스트. JSON 값만 담고 인자·결과는 담지 않는다."""
    principal = run.principal
    return {
        "invocation_id": str(snapshot.invocation_id),
        "attempt_id": snapshot.attempt_id,
        "decision_ref": snapshot.decision_ref,
        "consumed_call_approval": (
            {"id": str(consumed.call_approval_id), "state_version": consumed.state_version}
            if allowed and consumed is not None and consumed.call_approval_id is not None
            else None
        ),
        "allowed": allowed,
        "state_epoch": snapshot.state_epoch,
        "server_id": snapshot.resolved_server_id,
        "tool": snapshot.tool,
        "approval_id": snapshot.selected_approval_id,
        "relation_id": run.selected.relation_id if run.selected else None,
        "key_id": principal.key_id,
        "user_id": principal.user_id,
        "team_id": principal.team_id,
        "org_id": principal.org_id,
        "result_policy": _result_policy(run),
        "unmanaged_findings": list(dict.fromkeys(run.unmanaged_findings)),
        "resolve_findings": list(dict.fromkeys(run.resolve_findings)),
        "aud_mismatch": run.aud_mismatch,
        "aud_unchecked": run.aud_unchecked,
        "aud_unchecked_reason": run.aud_unchecked_reason,
        "scope_exceeded": list(run.scope_exceeded),
        "scope_unchecked_reason": run.scope_unchecked_reason,
    }


def build_request(
    data: Mapping[str, Any],
    user_api_key_dict: Any,
    *,
    operation: OperationType,
    instance_id: str,
    hook_parser: Callable[[Mapping[str, Any]], HookData],
    resolver: Callable[[HookData], ResolvedServer],
    principal_factory: Callable[..., Principal],
) -> CallRequest:
    """사전 훅 ``data``와 인증 객체로 판정 요청을 만든다. LiteLLM 접점은 인자로 받는다."""
    hook = hook_parser(data)
    principal = principal_factory(user_api_key_dict, instance_id=instance_id)
    resolved: ResolvedServer | None = None
    failure: StageResult | None = None
    if hook.tool_name is None or hook.server_name is None:
        failure = StageResult.stop(Reason.SCHEMA_ERROR, detail="hook data has no server or tool")
    elif not hook.arguments_ok:
        failure = StageResult.stop(Reason.SCHEMA_ERROR, detail="arguments are not an object")
    elif not hook.arguments_confirmed:
        failure = StageResult.stop(
            Reason.SCHEMA_ERROR, detail="arguments cannot be matched with the original"
        )
    else:
        try:
            resolved = resolver(hook)
        except ServerResolutionError as exc:
            failure = StageResult.stop(exc.reason, detail=exc.detail[:200])
    return CallRequest(
        operation=operation,
        principal=principal,
        hook=hook,
        resolved=resolved,
        resolution_failure=failure,
    )
