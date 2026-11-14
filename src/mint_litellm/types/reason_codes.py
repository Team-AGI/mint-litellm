"""사유 코드와 관측 모드 전환 가능 여부.

전환 가능 사유는 단계 결과에서 ``finding``으로 누적되고, 전환 불가 사유만 ``stop``이 된다.
``POLICY_DETECT``·``CONTRACT_DRIFT``·``OUTPUT_SCAN``은 뒤에 한정자가 붙는 계열이다
(예: ``POLICY_DETECT_POL-E-07``).
"""

import re
from enum import StrEnum


class Reason(StrEnum):
    # 관측 모드 전환 후보
    SERVER_UNREGISTERED = "SERVER_UNREGISTERED"
    SERVER_NOT_APPROVED = "SERVER_NOT_APPROVED"
    APPROVAL_ABSENT = "APPROVAL_ABSENT"
    TOOL_NOT_IN_APPROVAL = "TOOL_NOT_IN_APPROVAL"
    POLICY_DETECT = "POLICY_DETECT"
    CONTRACT_DRIFT = "CONTRACT_DRIFT"
    OUTPUT_SCAN = "OUTPUT_SCAN"
    # 전환 불가
    SERVER_REJECTED = "SERVER_REJECTED"
    SERVER_SUSPENDED = "SERVER_SUSPENDED"
    SERVER_TERMINATED = "SERVER_TERMINATED"
    RELATION_TERMINATED = "RELATION_TERMINATED"
    DENIED = "DENIED"
    APPROVAL_REVOKED = "APPROVAL_REVOKED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_RECERT_REQUIRED = "APPROVAL_RECERT_REQUIRED"
    CALL_APPROVAL_REQUIRED = "CALL_APPROVAL_REQUIRED"
    CALL_APPROVAL_STALE = "CALL_APPROVAL_STALE"
    CALL_APPROVAL_DENIED = "CALL_APPROVAL_DENIED"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    CONSENT_EXPIRED = "CONSENT_EXPIRED"
    CONSENT_REVOKED = "CONSENT_REVOKED"
    ALLOWLIST_EXPIRED = "ALLOWLIST_EXPIRED"
    SERVER_IDENTITY_MISMATCH = "SERVER_IDENTITY_MISMATCH"
    SERVER_IDENTITY_AMBIGUOUS = "SERVER_IDENTITY_AMBIGUOUS"
    SERVER_UNRESOLVED = "SERVER_UNRESOLVED"
    MASTER_KEY_FORBIDDEN = "MASTER_KEY_FORBIDDEN"
    EXTERNAL_MCP_FORBIDDEN = "EXTERNAL_MCP_FORBIDDEN"
    REALTIME_FORBIDDEN = "REALTIME_FORBIDDEN"
    CODE_EXECUTION_FORBIDDEN = "CODE_EXECUTION_FORBIDDEN"
    TOKEN_FORWARD_FORBIDDEN = "TOKEN_FORWARD_FORBIDDEN"
    RESOLVED_ADDRESS_FORBIDDEN = "RESOLVED_ADDRESS_FORBIDDEN"
    TOKEN_AUDIENCE_MISMATCH = "TOKEN_AUDIENCE_MISMATCH"
    TOKEN_SCOPE_EXCEEDED = "TOKEN_SCOPE_EXCEEDED"
    UNSUPPORTED = "UNSUPPORTED"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    POLICY_VERSION_MISMATCH = "POLICY_VERSION_MISMATCH"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    AUDIT_FAILURE = "AUDIT_FAILURE"
    ORG_BOUNDARY = "ORG_BOUNDARY"
    ANONYMOUS = "ANONYMOUS"
    ENFORCEMENT_UNVERIFIED = "ENFORCEMENT_UNVERIFIED"
    CANCELLED = "CANCELLED"
    CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"
    CONFIRMATION_STALE = "CONFIRMATION_STALE"


class ContractDriftKind(StrEnum):
    """``CONTRACT_DRIFT_<kind>``의 한정자. 경보형 변경(설명·출력 스키마)은 사유가 되지 않는다."""

    INPUT_SCHEMA = "input_schema"
    DEPLOYMENT = "deployment"
    UNOBSERVED = "unobserved"
    UNAPPROVED_TOOL = "unapproved_tool"
    PIN = "pin"  # 고정 불일치·고정 해제 미완료(재승인 차단 표지)
    NO_CONTRACT = "no_contract"  # 관리 서버인데 승인 계약이 하나도 없다
    INPUT_KEYS_UNKNOWN = "input_keys_unknown"  # 허용 인자 키를 알 수 없다
    VULN_OVERDUE = "vuln_overdue"  # 치명 취약점의 조치 기한(48시간)이 지났다
    INSTANCE_MISMATCH = "instance_mismatch"  # 같은 서버를 쓰는 다른 인스턴스와 계약·설정이 다르다


# 관측 모드로 완화할 수 없는 계약 차단(고정 안전 조건). 설정과 무관하게 호출을 막는다.
NON_OBSERVABLE_DRIFT: frozenset[str] = frozenset(
    {
        ContractDriftKind.PIN.value,
        ContractDriftKind.NO_CONTRACT.value,
        ContractDriftKind.INPUT_KEYS_UNKNOWN.value,
        ContractDriftKind.VULN_OVERDUE.value,
        ContractDriftKind.INSTANCE_MISMATCH.value,
    }
)


PARAMETERIZED_REASONS: frozenset[Reason] = frozenset(
    {Reason.POLICY_DETECT, Reason.CONTRACT_DRIFT, Reason.OUTPUT_SCAN}
)

OBSERVATION_CANDIDATES: frozenset[Reason] = frozenset(
    {
        Reason.SERVER_UNREGISTERED,
        Reason.SERVER_NOT_APPROVED,
        Reason.APPROVAL_ABSENT,
        Reason.TOOL_NOT_IN_APPROVAL,
        Reason.POLICY_DETECT,
        Reason.CONTRACT_DRIFT,
        Reason.OUTPUT_SCAN,
    }
)

NON_CONVERTIBLE_REASONS: frozenset[Reason] = frozenset(Reason) - OBSERVATION_CANDIDATES

_QUALIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def make_reason_code(reason: Reason, qualifier: str | None = None) -> str:
    """계열 사유와 한정자로 구체 사유 코드를 만든다. 고정 사유에는 한정자를 붙일 수 없다."""
    if reason in PARAMETERIZED_REASONS:
        if qualifier is None or not _QUALIFIER.fullmatch(qualifier):
            raise ValueError(f"{reason.value} requires a valid qualifier")
        return f"{reason.value}_{qualifier}"
    if qualifier is not None:
        raise ValueError(f"{reason.value} does not take a qualifier")
    return reason.value


def contract_drift_code(kind: ContractDriftKind) -> str:
    return make_reason_code(Reason.CONTRACT_DRIFT, ContractDriftKind(kind).value)


def parse_reason_code(code: str) -> tuple[Reason, str | None]:
    """구체 사유 코드를 (계열, 한정자)로 분해한다. 정의 밖의 코드는 ValueError."""
    try:
        reason = Reason(code)
    except ValueError:
        pass
    else:
        if reason in PARAMETERIZED_REASONS:
            raise ValueError(f"{code} requires a qualifier")
        return reason, None
    for family in PARAMETERIZED_REASONS:
        prefix = f"{family.value}_"
        if code.startswith(prefix):
            qualifier = code[len(prefix) :]
            if not _QUALIFIER.fullmatch(qualifier):
                raise ValueError(f"invalid qualifier in reason code {code!r}")
            return family, qualifier
    raise ValueError(f"unknown reason code {code!r}")


def is_observation_candidate(code: str) -> bool:
    """관측 모드로 전환될 수 있는 계열의 사유인지(설정과 무관한 분류)."""
    return parse_reason_code(code)[0] in OBSERVATION_CANDIDATES
