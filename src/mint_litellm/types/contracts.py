"""도구 계약의 위험 등급 값과 점수 규칙.

등급 점수 = max(자료 점수, 행위 점수) + (되돌릴 수 없으면 1). 0 low, 1 medium, 2 high,
3 이상 critical. high 이상 도구는 호출별 승인 대상이다.
"""

from enum import StrEnum


class DataGrade(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ActionType(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXTERNAL_SEND = "external_send"
    CREDENTIAL_ACCESS = "credential_access"


class RiskGrade(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


DATA_SCORE: dict[DataGrade, int] = {
    DataGrade.PUBLIC: 0,
    DataGrade.INTERNAL: 1,
    DataGrade.CONFIDENTIAL: 2,
    DataGrade.RESTRICTED: 3,
}

ACTION_SCORE: dict[ActionType, int] = {
    ActionType.READ: 0,
    ActionType.WRITE: 1,
    ActionType.EXTERNAL_SEND: 2,
    ActionType.DELETE: 2,
    ActionType.CREDENTIAL_ACCESS: 3,
}

# 기간 승인을 허용하지 않고 호출마다 정확한 1회 승인만 받는 행위. 삭제·외부 전송은 본인 확인
# 기본값(plugin/policy/defaults.CONFIRM_ACTIONS)과 같고, 자격 접근은 행위 점수가 가장 높다.
ONE_SHOT_ACTIONS: frozenset[str] = frozenset(
    {ActionType.DELETE, ActionType.EXTERNAL_SEND, ActionType.CREDENTIAL_ACCESS}
)

_BY_SCORE = (RiskGrade.LOW, RiskGrade.MEDIUM, RiskGrade.HIGH, RiskGrade.CRITICAL)

HIGH_RISK_GRADES: frozenset[RiskGrade] = frozenset({RiskGrade.HIGH, RiskGrade.CRITICAL})


def risk_grade(data: DataGrade, action: ActionType, *, irreversible: bool = False) -> RiskGrade:
    score = max(DATA_SCORE[data], ACTION_SCORE[action]) + (1 if irreversible else 0)
    return _BY_SCORE[min(score, 3)]
