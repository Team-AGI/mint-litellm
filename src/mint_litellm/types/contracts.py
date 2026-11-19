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
# 승인 도구 목록에 이 값이 있으면 서버의 모든 도구(앞으로 생기는 도구 포함)를 기본 허용한다.
ALL_TOOLS = "*"


def covers(tools, tool: str) -> bool:
    """승인의 도구 목록이 이 도구를 허용하는가."""
    return ALL_TOOLS in tools or tool in tools


# 거부의 도구 목록에서 ``action:<행위 유형>`` 항목은 그 행위 유형의 모든 도구를 막는다.
ACTION_DENIAL_PREFIX = "action:"
# 행위 유형 차단에 쓸 수 있는 값(계약의 행위 유형과 임시 계약의 실행 유형)
DENIABLE_ACTIONS = ("read", "write", "delete", "external_send", "credential_access", "exec")


def denial_hits_tool(tools, tool: str, action_type: str | None) -> bool:
    """거부가 이 도구 호출에 걸리는가(도구 목록 없음 = 서버 전체)."""
    if tools is None:
        return True
    return any(
        (action_type is not None and t == ACTION_DENIAL_PREFIX + action_type)
        if t.startswith(ACTION_DENIAL_PREFIX) else t == tool
        for t in tools
    )


ONE_SHOT_ACTIONS: frozenset[str] = frozenset(
    {ActionType.DELETE, ActionType.EXTERNAL_SEND, ActionType.CREDENTIAL_ACCESS}
)

_BY_SCORE = (RiskGrade.LOW, RiskGrade.MEDIUM, RiskGrade.HIGH, RiskGrade.CRITICAL)

HIGH_RISK_GRADES: frozenset[RiskGrade] = frozenset({RiskGrade.HIGH, RiskGrade.CRITICAL})


def risk_grade(data: DataGrade, action: ActionType, *, irreversible: bool = False) -> RiskGrade:
    score = max(DATA_SCORE[data], ACTION_SCORE[action]) + (1 if irreversible else 0)
    return _BY_SCORE[min(score, 3)]
