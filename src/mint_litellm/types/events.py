"""원장 사건: 종류, 중복 제거 키, 증거 위치, 사건 JSON.

같은 사건이 DB, 로컬 버퍼, 표준 오류 중 둘 이상에 남을 수 있다(기록 결과가 불명인 경우).
DB의 ``source_key`` 유일성이 재적재 시 한 건으로 수렴시킨다.
"""

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from mint_litellm.types.decision import DecisionSnapshot, OperationType, RevocationCheck
from mint_litellm.types.frozen import json_value, no_floats
from mint_litellm.types.ids import new_uuid7
from mint_litellm.types.outcome import Outcome


class Evidence(StrEnum):
    DB = "db"
    BUFFER = "buffer"
    STDERR = "stderr"


class EventKind(StrEnum):
    # 호출 사건
    DECISION_EVALUATED = "decision_evaluated"
    DISCOVERY_EVALUATED = "discovery_evaluated"
    CALL_RESPONSE_RECEIVED = "call_response_received"
    CALL_OUTCOME_UNKNOWN = "call_outcome_unknown"
    # 시스템 사건
    ENFORCEMENT_UNVERIFIED = "enforcement_unverified"
    ENFORCEMENT_VERIFIED = "enforcement_verified"
    SERVER_IDENTITY_MISMATCH_OBSERVED = "server_identity_mismatch_observed"
    BUFFER_OVERFLOW = "buffer_overflow"
    BUFFER_REPLAYED = "buffer_replayed"
    # 제어 사건(사람의 행위)
    SERVER_REGISTERED = "server_registered"
    SERVER_APPROVED = "server_approved"
    SERVER_SUSPENDED = "server_suspended"
    SERVER_RESUMED = "server_resumed"
    SERVER_TERMINATING = "server_terminating"
    SERVER_TERMINATED = "server_terminated"
    RELATION_CREATED = "relation_created"
    RELATION_TERMINATING = "relation_terminating"
    RELATION_TERMINATED = "relation_terminated"
    EVIDENCE_ATTACHED = "evidence_attached"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REVOKED = "approval_revoked"
    DENIAL_CREATED = "denial_created"
    DENIAL_LIFTED = "denial_lifted"
    CALL_APPROVAL_REQUESTED = "call_approval_requested"
    CALL_APPROVAL_APPROVED = "call_approval_approved"
    CALL_APPROVAL_REJECTED = "call_approval_rejected"
    CALL_APPROVAL_CANCELLED = "call_approval_cancelled"
    CALL_APPROVAL_RULE_CREATED = "call_approval_rule_created"
    CALL_APPROVAL_RULE_DISABLED = "call_approval_rule_disabled"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    ALLOWLIST_ADDED = "allowlist_added"
    ALLOWLIST_LIFTED = "allowlist_lifted"
    ORG_CREATED = "org_created"
    ORG_CLOSED = "org_closed"
    ORG_BINDING_CREATED = "org_binding_created"
    ORG_BINDING_REMOVED = "org_binding_removed"
    POLICY_ACTIVATED = "policy_activated"
    SETTINGS_CHANGED = "settings_changed"
    OPERATOR_ADDED = "operator_added"
    OPERATOR_REMOVED = "operator_removed"
    OPERATOR_ROLE_CHANGED = "operator_role_changed"
    OPERATOR_CHAT_BOUND = "operator_chat_bound"
    # 2단계 제어 사건
    INTAKE_RECEIVED = "intake_received"
    INTAKE_REQUESTER_ASSIGNED = "intake_requester_assigned"
    INTAKE_CHECKED = "intake_checked"
    INTAKE_DECIDED = "intake_decided"
    CONTRACT_APPROVED = "contract_approved"
    CONTRACT_DRIFT_DETECTED = "contract_drift_detected"
    CONTRACT_SUPERSEDED = "contract_superseded"
    REAPPROVAL_REQUESTED = "reapproval_requested"
    SYNC_APPLIED = "sync_applied"
    SYNC_HELD = "sync_held"
    EXPORT_WRITTEN = "export_written"
    EXPORT_FAILED = "export_failed"
    RESTORE_BLOCKED = "restore_blocked"
    RESTORE_ATTESTED = "restore_attested"
    RESTORE_STALE_ACCEPTED = "restore_stale_accepted"
    ALERT_OPENED = "alert_opened"
    ALERT_ACKNOWLEDGED = "alert_acknowledged"
    ALERT_RESOLVED = "alert_resolved"
    CONSOLE_SESSION_STARTED = "console_session_started"
    CONSOLE_SESSION_ENDED = "console_session_ended"
    DEPLOYMENT_CONTRACT_APPROVED = "deployment_contract_approved"
    DEPLOYMENT_DRIFT_DETECTED = "deployment_drift_detected"
    DEPLOYMENT_CONTRACT_SUPERSEDED = "deployment_contract_superseded"
    APPROVAL_RECERT_REQUESTED = "approval_recert_requested"
    APPROVAL_HELD = "approval_held"
    APPROVAL_RECERT_CONFIRMED = "approval_recert_confirmed"
    POLICY_SHADOW_SET = "policy_shadow_set"
    POLICY_SHADOW_CLEARED = "policy_shadow_cleared"
    EVENT_PARTITION_EXPORTED = "event_partition_exported"
    EVENT_PARTITION_DROPPED = "event_partition_dropped"
    ENDPOINT_REMEDIATED = "endpoint_remediated"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    CONFIG_EXPORTED = "config_exported"
    CONFIG_IMPORTED = "config_imported"
    SIEM_TARGET_ADDED = "siem_target_added"
    SIEM_TARGET_REMOVED = "siem_target_removed"
    KEY_BLOCK_PROPOSED = "key_block_proposed"
    KEY_BLOCK_APPROVED = "key_block_approved"
    KEY_BLOCK_REJECTED = "key_block_rejected"
    KEY_BLOCK_EXPIRED = "key_block_expired"
    KEY_BLOCK_APPLIED = "key_block_applied"
    KEY_BLOCK_FAILED = "key_block_failed"
    KEY_BLOCK_UNBLOCK_REQUESTED = "key_block_unblock_requested"
    KEY_BLOCK_UNBLOCKED = "key_block_unblocked"


CALL_KINDS: frozenset[EventKind] = frozenset(
    {
        EventKind.DECISION_EVALUATED,
        EventKind.DISCOVERY_EVALUATED,
        EventKind.CALL_RESPONSE_RECEIVED,
        EventKind.CALL_OUTCOME_UNKNOWN,
    }
)

SYSTEM_KINDS: frozenset[EventKind] = frozenset(
    {
        EventKind.ENFORCEMENT_UNVERIFIED,
        EventKind.ENFORCEMENT_VERIFIED,
        EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED,
        EventKind.BUFFER_OVERFLOW,
        EventKind.BUFFER_REPLAYED,
    }
)

# 제어 사건의 source_key 첫 마디. ``<entity>:{id}:{state_version}:{kind}``
CONTROL_ENTITY: dict[EventKind, str] = {
    EventKind.ENFORCEMENT_UNVERIFIED: "selfcheck",
    EventKind.ENFORCEMENT_VERIFIED: "selfcheck",
    EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED: "selfcheck",
    EventKind.BUFFER_OVERFLOW: "buffer",
    EventKind.BUFFER_REPLAYED: "buffer",
    EventKind.SERVER_REGISTERED: "server",
    EventKind.SERVER_APPROVED: "server",
    EventKind.SERVER_SUSPENDED: "server",
    EventKind.SERVER_RESUMED: "server",
    EventKind.SERVER_TERMINATING: "server",
    EventKind.SERVER_TERMINATED: "server",
    EventKind.RELATION_CREATED: "relation",
    EventKind.RELATION_TERMINATING: "relation",
    EventKind.RELATION_TERMINATED: "relation",
    EventKind.EVIDENCE_ATTACHED: "evidence",
    EventKind.APPROVAL_GRANTED: "approval",
    EventKind.APPROVAL_REVOKED: "approval",
    EventKind.DENIAL_CREATED: "denial",
    EventKind.DENIAL_LIFTED: "denial",
    EventKind.CALL_APPROVAL_REQUESTED: "call_approval",
    EventKind.CALL_APPROVAL_APPROVED: "call_approval",
    EventKind.CALL_APPROVAL_REJECTED: "call_approval",
    EventKind.CALL_APPROVAL_CANCELLED: "call_approval",
    EventKind.CALL_APPROVAL_RULE_CREATED: "call_approval_rule",
    EventKind.CALL_APPROVAL_RULE_DISABLED: "call_approval_rule",
    EventKind.CONSENT_GRANTED: "consent",
    EventKind.CONSENT_REVOKED: "consent",
    EventKind.ALLOWLIST_ADDED: "allowlist",
    EventKind.ALLOWLIST_LIFTED: "allowlist",
    EventKind.ORG_CREATED: "org",
    EventKind.ORG_CLOSED: "org",
    EventKind.ORG_BINDING_CREATED: "org_binding",
    EventKind.ORG_BINDING_REMOVED: "org_binding",
    EventKind.POLICY_ACTIVATED: "policy_version",
    EventKind.SETTINGS_CHANGED: "settings",
    EventKind.OPERATOR_ADDED: "operator",
    EventKind.OPERATOR_REMOVED: "operator",
    EventKind.OPERATOR_ROLE_CHANGED: "operator",
    EventKind.OPERATOR_CHAT_BOUND: "operator",
    EventKind.INTAKE_RECEIVED: "intake",
    EventKind.INTAKE_REQUESTER_ASSIGNED: "intake",
    EventKind.INTAKE_CHECKED: "intake_check",
    EventKind.INTAKE_DECIDED: "intake",
    EventKind.CONTRACT_APPROVED: "tool_contract",
    EventKind.CONTRACT_DRIFT_DETECTED: "tool_contract",
    EventKind.CONTRACT_SUPERSEDED: "tool_contract",
    EventKind.REAPPROVAL_REQUESTED: "tool_contract",
    EventKind.SYNC_APPLIED: "litellm_grant",
    EventKind.SYNC_HELD: "litellm_grant",
    EventKind.EXPORT_WRITTEN: "export",
    EventKind.EXPORT_FAILED: "export",
    EventKind.RESTORE_BLOCKED: "restore",
    EventKind.RESTORE_ATTESTED: "restore",
    EventKind.RESTORE_STALE_ACCEPTED: "restore",
    EventKind.ALERT_OPENED: "alert",
    EventKind.ALERT_ACKNOWLEDGED: "alert",
    EventKind.ALERT_RESOLVED: "alert",
    EventKind.CONSOLE_SESSION_STARTED: "console_session",
    EventKind.CONSOLE_SESSION_ENDED: "console_session",
    EventKind.DEPLOYMENT_CONTRACT_APPROVED: "deployment_contract",
    EventKind.DEPLOYMENT_DRIFT_DETECTED: "deployment_contract",
    EventKind.DEPLOYMENT_CONTRACT_SUPERSEDED: "deployment_contract",
    EventKind.APPROVAL_RECERT_REQUESTED: "approval",
    EventKind.APPROVAL_HELD: "approval",
    EventKind.APPROVAL_RECERT_CONFIRMED: "approval",
    EventKind.POLICY_SHADOW_SET: "policy_shadow",
    EventKind.POLICY_SHADOW_CLEARED: "policy_shadow",
    EventKind.EVENT_PARTITION_EXPORTED: "event_partition",
    EventKind.EVENT_PARTITION_DROPPED: "event_partition",
    EventKind.ENDPOINT_REMEDIATED: "endpoint",
    EventKind.BACKUP_CREATED: "backup",
    EventKind.BACKUP_RESTORED: "backup",
    EventKind.CONFIG_EXPORTED: "config",
    EventKind.CONFIG_IMPORTED: "config",
    EventKind.SIEM_TARGET_ADDED: "siem_target",
    EventKind.SIEM_TARGET_REMOVED: "siem_target",
    EventKind.KEY_BLOCK_PROPOSED: "key_block",
    EventKind.KEY_BLOCK_APPROVED: "key_block",
    EventKind.KEY_BLOCK_REJECTED: "key_block",
    EventKind.KEY_BLOCK_EXPIRED: "key_block",
    EventKind.KEY_BLOCK_APPLIED: "key_block",
    EventKind.KEY_BLOCK_FAILED: "key_block",
    EventKind.KEY_BLOCK_UNBLOCK_REQUESTED: "key_block",
    EventKind.KEY_BLOCK_UNBLOCKED: "key_block",
}

_ENTITY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CONTROL_KEY = re.compile(
    r"(?P<entity>[a-z_]+):(?P<id>[A-Za-z0-9][A-Za-z0-9._-]{0,127}):"
    r"(?P<version>[0-9]+):(?P<kind>[a-z_]+)"
)


def call_source_key(invocation_id: UUID, attempt_id: int, kind: EventKind) -> str:
    if kind not in CALL_KINDS:
        raise ValueError(f"{kind.value} is not a call event")
    if attempt_id < 1:
        raise ValueError("attempt_id starts at 1")
    return f"call:{invocation_id}:{attempt_id}:{kind.value}"


def control_source_key(kind: EventKind, entity_id: str, state_version: int) -> str:
    entity = CONTROL_ENTITY.get(kind)
    if entity is None:
        raise ValueError(f"{kind.value} is not a control event")
    if not _ENTITY_ID.fullmatch(entity_id):
        raise ValueError(f"invalid entity id {entity_id!r}")
    if state_version < 0:
        raise ValueError("state_version must not be negative")
    return f"{entity}:{entity_id}:{state_version}:{kind.value}"


class Event(BaseModel):
    """DB 행, 버퍼 줄, 표준 오류 구조화 로그가 공유하는 사건 JSON.

    ``evidence``는 이 사본이 어느 위치에 남았는지를 나타내며 DB 열이 아니다.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: UUID = Field(default_factory=new_uuid7)
    instance_id: str
    inserted_at: AwareDatetime
    kind: EventKind
    source_key: str
    invocation_id: UUID | None = None
    attempt_id: int | None = Field(default=None, ge=1)
    actor: str | None = None
    subject: dict[str, Any] | None = None
    payload: dict[str, Any]
    evidence: Evidence = Evidence.DB

    @field_validator("subject", "payload", mode="after")
    @classmethod
    def _json_only(cls, value: dict[str, Any] | None) -> Any:
        if value is not None:
            no_floats(value)
        return None if value is None else json_value(value)

    @model_validator(mode="after")
    def _source_key_matches(self) -> Self:
        if self.kind in CALL_KINDS:
            if self.invocation_id is None or self.attempt_id is None:
                raise ValueError("call events require invocation_id and attempt_id")
            expected = call_source_key(self.invocation_id, self.attempt_id, self.kind)
            if self.source_key != expected:
                raise ValueError(f"source_key must be {expected}")
            return self
        match = _CONTROL_KEY.fullmatch(self.source_key)
        if (
            match is None
            or match["entity"] != CONTROL_ENTITY[self.kind]
            or match["kind"] != self.kind.value
        ):
            raise ValueError(f"source_key does not match the rule for {self.kind.value}")
        if self.kind not in SYSTEM_KINDS and not self.actor:
            raise ValueError("control events require actor")
        return self

    def with_evidence(self, evidence: Evidence) -> Self:
        return self.model_copy(update={"evidence": evidence})

    def to_json_line(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json_line(cls, line: str) -> Self:
        return cls.model_validate_json(line)


PAYLOAD_VERSION = 2
# 판정 사건에서 항상 같은 사유라 본문에 적지 않는 값 없음 사유(응답 사건이 실제 값을 남긴다).
_CONSTANT_MISSING = ("revoked_after_snapshot", "revocation_check")
# 필드가 없다는 사실만 되풀이하는 사유(값이 없으면 그 상태이다). 그 밖의 사유는 그대로 남긴다.
_RESTATING_REASONS = frozenset(
    {
        ("consumed_call_approval_id", "not_consumed"),
        ("selected_approval_id", "no_selected_approval"),
        ("policy_version_id", "policy_not_evaluated"),
        ("bundle_sha256", "policy_not_evaluated"),
        ("policy_decision", "policy_not_evaluated"),
    }
)
# 항상 같은 이유로 건너뛰는 단계(미지원 단계, 정지 뒤 남은 단계)는 다시 만들 수 있어 적지 않는다.
_DERIVED_SKIPS = ("unsupported_stage", "after_stop")
_PRINCIPAL_DROP = ("instance_id", "org_source", "provenance")


def encode_decision_v2(snapshot: DecisionSnapshot) -> dict[str, Any]:
    """판정 본문 2판. 빈 값·기본값, 모두 통과한 단계, 판본에서 다시 찾을 수 있는 값을 뺀다.

    ``stages``에는 통과하지 않은 단계(걸림·정지·그 밖의 건너뜀)만 남고, 주체는 식별자만 남는다. 값이
    비어 뺀 필드는 ``missing_reasons``가 사유를 말한다. 번들 해시는 ``policy_version_id``가 있으면
    그 판본 행에서 찾는다. 읽는 쪽은 1판(``v`` 없음)과 2판을 모두 받아야 한다.
    """
    full = snapshot.model_dump(mode="json")
    body: dict[str, Any] = {"v": PAYLOAD_VERSION}
    for key, value in full.items():
        if value is None or value == [] or value == {}:
            continue
        body[key] = value
    principal = {
        k: v for k, v in full["principal"].items() if v is not None and k not in _PRINCIPAL_DROP
    }
    body["principal"] = principal
    stages = [
        s
        for s in full["stages"]
        if s["status"] != "pass" and s.get("missing_reason") not in _DERIVED_SKIPS
    ]
    body.pop("stages", None)
    if stages:
        body["stages"] = [{k: v for k, v in s.items() if v is not None} for s in stages]
    if body.get("mode") == "enforce":
        del body["mode"]
    if body.get("evaluated_decision") == body.get("enforced_action"):
        del body["evaluated_decision"]
    if "policy_version_id" in body:
        body.pop("bundle_sha256", None)
    reasons = {
        k: v
        for k, v in full["missing_reasons"].items()
        if k not in _CONSTANT_MISSING and (k, v) not in _RESTATING_REASONS
    }
    body.pop("missing_reasons", None)
    if reasons:
        body["missing_reasons"] = reasons
    return body


def decoded_decision(payload: Mapping[str, Any]) -> dict[str, Any]:
    """1판·2판 판정 본문을 읽는 쪽이 같은 모양으로 보도록 뺀 값을 채운다."""
    out = dict(payload)
    if out.get("v", 1) < 2:
        return out
    out.setdefault("mode", "enforce")
    out.setdefault("evaluated_decision", out.get("enforced_action"))
    out.setdefault("stages", [])
    out.setdefault("findings", [])
    out.setdefault("policy_ids", [])
    out.setdefault("obligation_types", [])
    out.setdefault("missing_reasons", {})
    return out


def decision_event(
    snapshot: DecisionSnapshot, *, inserted_at: AwareDatetime | None = None
) -> Event:
    """판정 스냅숏을 사건으로 만든다.

    도구 목록 판정은 도구마다 새 호출 식별자로 시도 번호 1에서 시작하고, 호출과 같이 결과가
    불명인 기록 뒤의 차단은 다음 시도 번호로 남긴다.
    """
    if snapshot.operation is OperationType.RUNTIME_DISCOVERY:
        kind = EventKind.DISCOVERY_EVALUATED
    else:
        kind = EventKind.DECISION_EVALUATED
    principal = snapshot.principal
    payload = encode_decision_v2(snapshot)
    if snapshot.cause is not None:
        payload["cause"] = snapshot.cause
    return Event(
        instance_id=principal.instance_id,
        inserted_at=inserted_at or snapshot.evaluated_at,
        kind=kind,
        source_key=call_source_key(snapshot.invocation_id, snapshot.attempt_id, kind),
        invocation_id=snapshot.invocation_id,
        attempt_id=snapshot.attempt_id,
        subject={
            "principal_type": principal.principal_type.value,
            "principal_id": principal.principal_id,
            "org_id": principal.org_id,
        },
        payload=payload,
    )


class ResponseObservation(BaseModel):
    """``call_response_received`` 본문. 응답 본문은 담지 않는다.

    ``revoked_after_snapshot``은 판정 스냅숏을 읽은 뒤 선택된 승인·거부·관계가 부정 상태로
    바뀌었는지이다. 세대를 읽지 못하면 값을 비우고 ``revocation_check``를 ``unavailable``로 둔다.
    ``output_findings``는 결과 검사에서 걸린 정책 식별자이고, ``output_blocked``는 결과를 호출자에게
    주지 않고 막았는지이다(관측 모드는 걸려도 막지 않는다). ``sensitive_findings``는 결과에서 찾은
    비밀·개인정보의 탐지 종류별 건수(값은 남기지 않는다)이고, ``output_masked``는 그 값을 가려서
    주었는지이다.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_error: bool
    size_bytes: int | None = Field(default=None, ge=0)
    # 결과 항목 수와 호출한 서버(대량 추출 탐지가 읽는다). 새 행부터 남고 알 수 없으면 비운다.
    items: int | None = Field(default=None, ge=0)
    server_id: str | None = None
    snapshot_state_epoch: int | None = Field(default=None, ge=0)
    current_state_epoch: int | None = Field(default=None, ge=0)
    revocation_check: RevocationCheck
    revoked_after_snapshot: bool | None = None
    output_findings: tuple[str, ...] = ()
    output_blocked: bool = False
    output_masked: bool = False
    sensitive_findings: dict[str, int] = Field(default_factory=dict)
    # 계약 관리가 아닌 서버에서 막지 않고 관측만 한 검사 결과(결과 지시문 표지·인자 비밀).
    unmanaged_findings: tuple[str, ...] = ()
    # 서버 주소 재확인이 observe에서 막지 않고 관측만 한 종류(private·rebind·unresolved)
    resolve_findings: tuple[str, ...] = ()
    # 업스트림에 전달된 호출자 토큰의 aud가 서버 대상과 다름(관측 모드) / 읽을 수 없어 확인하지 않음
    aud_mismatch: bool = False
    aud_unchecked: bool = False
    aud_unchecked_reason: str | None = None  # opaque(불투명 토큰), not_forwarded(훅에 전달 안 됨)
    # 전달되는 호출자 토큰이 승인된 범위를 넘은 범위 이름(토큰은 담지 않음) / 확인하지 않은 이유
    # (opaque, not_forwarded, no_approved_scopes)
    scope_exceeded: tuple[str, ...] = ()
    scope_unchecked_reason: str | None = None
    # 결과가 검사 상한을 넘어 끝까지 보지 못했는지, 구조화된 결과에서 비밀·개인정보가 걸린 JSON 경로
    # (값은 남기지 않는다).
    scan_truncated: bool = False
    finding_paths: tuple[str, ...] = ()
    # 결과 단계 가드레일이 없는 LiteLLM(저하 운용): 걸려도 막지도 가리지도 못한 결과.
    result_unenforced: bool = False
    # 새 행부터 남는 결과 분류(success·tool_error·output_blocked).
    outcome: Outcome | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.output_blocked and not self.output_findings:
            raise ValueError("a blocked output needs at least one finding")
        if self.output_masked and (self.output_blocked or not self.sensitive_findings):
            raise ValueError("a masked output needs sensitive findings and cannot be blocked")
        unavailable = self.revocation_check is RevocationCheck.UNAVAILABLE
        if unavailable != (self.revoked_after_snapshot is None):
            raise ValueError("revoked_after_snapshot is null exactly when the check is unavailable")
        if self.revocation_check is RevocationCheck.UNCHANGED and self.revoked_after_snapshot:
            raise ValueError("an unchanged epoch cannot show a revocation")
        return self


class AlertKind(StrEnum):
    SERVER_IDENTITY_CONFLICT = "server_identity_conflict"
    APPROVAL_EXPIRING = "approval_expiring"
    ENDPOINT_STALE_SERVER = "endpoint_stale_server"
    ENDPOINT_UNMANAGED = "endpoint_unmanaged"
    ENDPOINT_STALE_PROCESS = "endpoint_stale_process"
    ENDPOINT_STALE_AUTOSTART = "endpoint_stale_autostart"
    ENDPOINT_OUTSIDE_RETIRED = "endpoint_outside_retired"
    ENDPOINT_OUTSIDE_UNAPPROVED = "endpoint_outside_unapproved"
    ENDPOINT_OUTSIDE_APPROVED = "endpoint_outside_approved"
    ENDPOINT_UNSANDBOXED = "endpoint_unsandboxed"
    ENDPOINT_EGRESS_REFUSED = "endpoint_egress_refused"
    ENDPOINT_EGRESS_UNFILTERED = "endpoint_egress_unfiltered"
    ENDPOINT_SILENT = "endpoint_silent"
    ENDPOINT_KEY_EXPIRING = "endpoint_key_expiring"
    CALL_SPIKE = "call_spike"
    BULK_EXTRACTION = "bulk_extraction"
    CONTENT_FINDING_UNMANAGED = "content_finding_unmanaged"
    SERVER_ADDRESS_INTERNAL = "server_address_internal"
    RESULT_UNENFORCED = "result_unenforced"
    CONFIG_PLAINTEXT_SECRET = "config_plaintext_secret"
    KEY_BLOCK_PROPOSED = "key_block_proposed"
