"""호출 결과를 네 부분으로 나눈 요약 값.

연결(응답이 왔는가), 정책 판정(막았는가), 도구 업무 성공(``isError``·JSON-RPC 오류가 아닌가),
독립 부수효과(응답이 없어 알 수 없는가)를 한 낱말로 줄인다. 판정 사건과 응답 사건에 새 행부터
``outcome``으로 남으며, 기존 행의 본문·봉인은 바뀌지 않는다.
"""

from enum import StrEnum

from mint_litellm.types.reason_codes import Reason, parse_reason_code


class Outcome(StrEnum):
    # 판정 사건: 호출을 보내기 전의 결과
    ALLOWED = "allowed"  # 정책이 허용
    OBSERVED = "observed"  # 걸렸지만 관측 모드라 통과
    BLOCKED = "blocked"  # 정책이 차단
    PENDING_APPROVAL = "pending_approval"  # 호출 승인·확인을 기다림
    CONTRACT_DRIFT = "contract_drift"  # 승인된 계약과 달라 차단
    DEPENDENCY_FAILURE = "dependency_failure"  # 판정·기록 부품이 실패해 차단
    # 응답 사건: 보낸 뒤의 결과
    SUCCESS = "success"  # 연결 정상, 도구 성공
    TOOL_ERROR = "tool_error"  # 연결 정상, 도구가 오류를 돌려줌
    OUTPUT_BLOCKED = "output_blocked"  # 도구는 실행됐고 결과를 MINT가 막음
    UNKNOWN = "unknown"  # 응답 없음. 부수효과를 알 수 없음


_PENDING = {
    Reason.CALL_APPROVAL_REQUIRED,
    Reason.CALL_APPROVAL_STALE,
    Reason.CONFIRMATION_REQUIRED,
    Reason.CONFIRMATION_STALE,
}
_DEPENDENCY = {
    Reason.DEPENDENCY_FAILURE,
    Reason.AUDIT_FAILURE,
    Reason.SCHEMA_ERROR,
    Reason.ENFORCEMENT_UNVERIFIED,
}


def decision_outcome(*, allowed: bool, reason_code: str | None, has_findings: bool) -> Outcome:
    """판정 결과의 분류. ``reason_code``는 차단 사유(없으면 허용)이다."""
    if allowed or reason_code is None:
        return Outcome.OBSERVED if has_findings else Outcome.ALLOWED
    family, _ = parse_reason_code(reason_code)
    if family in _PENDING:
        return Outcome.PENDING_APPROVAL
    if family is Reason.CONTRACT_DRIFT:
        return Outcome.CONTRACT_DRIFT
    if family in _DEPENDENCY:
        return Outcome.DEPENDENCY_FAILURE
    return Outcome.BLOCKED


def response_outcome(*, is_error: bool, output_blocked: bool) -> Outcome:
    if output_blocked:
        return Outcome.OUTPUT_BLOCKED
    return Outcome.TOOL_ERROR if is_error else Outcome.SUCCESS
