"""차단 응답의 오류 계약.

차단은 항상 ``HTTPException(status_code=403, detail=<JSON 문자열>)``로 전달된다. REST 경로는
403을 그대로 돌려주고 스트리머블 HTTP 경로는 같은 JSON을 오류 텍스트에 담아 돌려주므로,
클라이언트는 어느 경로에서든 ``code``를 파싱할 수 있다.
"""

import json
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, model_validator

from mint_litellm.types.reason_codes import Reason, parse_reason_code, policy_detect_name

BLOCK_STATUS_CODE = 403

# 호출별 승인 대기 오류가 에이전트에게 전하는 다음 행동. 승인 뒤 같은 작업을 다시 요청하면 된다.
# 에이전트가 읽고 행동하는 세 갈래: 승인 대기(재시도), 정책 차단(재시도 금지), 일시 오류(재시도).
APPROVAL_RETRY_AFTER = 30
TRANSIENT_RETRY_AFTER = 5
APPROVAL_GUIDANCE = (
    f"승인 대기 중입니다. 승인되면 같은 호출을 다시 하십시오(약 {APPROVAL_RETRY_AFTER}초 뒤 "
    "재시도). Approval pending: retry the same call after approval."
)
TRANSIENT_GUIDANCE = (
    f"일시 오류입니다. 잠시 뒤(약 {TRANSIENT_RETRY_AFTER}초) 같은 호출을 다시 하십시오. "
    "Temporary error: retry shortly."
)
BLOCKED_GUIDANCE = (
    "정책상 차단되었으니 같은 호출을 재시도하지 마십시오. 다른 방법을 쓰거나 관리자에게 "
    "요청하십시오. Blocked by policy: do not retry the same call."
)
# 사용자 본인 확인이 필요한 호출. 확인 링크를 연 사람이 본인일 때만 확인된다.
CONFIRMATION_GUIDANCE = (
    "본인 확인이 필요합니다. 링크에서 확인한 뒤 같은 작업을 다시 요청하십시오."
)
# 관리자가 거부한 호출의 재시도. 실행되지 않았고, 되풀이하지 말고 사용자에게 알려야 한다.
DENIAL_GUIDANCE = (
    "관리자가 이 호출을 거부해 실행되지 않았습니다. 같은 작업을 되풀이하지 말고 사용자에게 "
    "거부 사유를 알리십시오."
)
# 결과를 막은 오류. 도구는 이미 실행됐으므로 같은 작업을 되풀이하면 부작용이 겹친다.
OUTPUT_GUIDANCE = (
    "도구는 이미 실행되었고 결과만 막혔습니다. 같은 작업을 다시 요청하지 말고 사용자에게 "
    "결과가 정책에 막혔다고 알리십시오."
)

# 사유별 설명을 빠짐없이 유지한다. 공통 조치는 호출을 다시 실행하기 전에 관리자에게 확인하는 것이다.
REASON_EXPLANATIONS = {
    Reason.SERVER_UNREGISTERED: "등록되지 않은 서버의 호출이 막혔습니다",
    Reason.SERVER_NOT_APPROVED: "승인되지 않은 서버의 호출이 막혔습니다",
    Reason.APPROVAL_ABSENT: "이 서버에 대한 승인이 없어 호출이 막혔습니다",
    Reason.TOOL_NOT_IN_APPROVAL: "승인 범위에 없는 도구의 호출이 막혔습니다",
    Reason.POLICY_DETECT: "호출이 정책에 막혔습니다",
    Reason.CONTRACT_DRIFT: "서버 계약과 실제 상태가 달라 호출이 막혔습니다",
    Reason.OUTPUT_SCAN: "결과 검사 정책에 따라 호출이 막혔습니다",
    Reason.SERVER_REJECTED: "거부된 서버의 호출이 막혔습니다",
    Reason.SERVER_SUSPENDED: "중지된 서버의 호출이 막혔습니다",
    Reason.SERVER_TERMINATED: "폐기된 서버의 호출이 막혔습니다",
    Reason.RELATION_TERMINATED: "종료된 이용 관계의 호출이 막혔습니다",
    Reason.DENIED: "명시적 거부에 따라 호출이 막혔습니다",
    Reason.APPROVAL_REVOKED: "철회된 승인에 따른 호출이 막혔습니다",
    Reason.APPROVAL_EXPIRED: "승인이 만료되어 호출이 막혔습니다",
    Reason.APPROVAL_RECERT_REQUIRED: "승인 재확인이 필요해 호출이 막혔습니다",
    Reason.CALL_APPROVAL_REQUIRED: "호출별 승인이 필요합니다",
    Reason.CALL_APPROVAL_STALE: "호출별 승인을 다시 확인해야 합니다",
    Reason.CALL_APPROVAL_DENIED: "호출별 승인이 거부되었습니다",
    Reason.CONSENT_REQUIRED: "동의가 필요해 호출이 막혔습니다",
    Reason.CONSENT_EXPIRED: "동의가 만료되어 호출이 막혔습니다",
    Reason.CONSENT_REVOKED: "동의가 철회되어 호출이 막혔습니다",
    Reason.ALLOWLIST_EXPIRED: "허용 목록이 만료되어 호출이 막혔습니다",
    Reason.SERVER_IDENTITY_MISMATCH: "서버 식별 정보가 달라 호출이 막혔습니다",
    Reason.SERVER_IDENTITY_AMBIGUOUS: "서버 식별 정보가 모호해 호출이 막혔습니다",
    Reason.SERVER_UNRESOLVED: "서버를 식별하지 못해 호출이 막혔습니다",
    Reason.MASTER_KEY_FORBIDDEN: "마스터 키로 도구 호출을 할 수 없습니다",
    Reason.EXTERNAL_MCP_FORBIDDEN: "외부 MCP 호출이 허용되지 않습니다",
    Reason.REALTIME_FORBIDDEN: "실시간 호출이 허용되지 않습니다",
    Reason.CODE_EXECUTION_FORBIDDEN: "코드 실행이 허용되지 않습니다",
    Reason.TOKEN_FORWARD_FORBIDDEN: "토큰 전달이 허용되지 않습니다",
    Reason.RESOLVED_ADDRESS_FORBIDDEN: "서버 주소가 허용되지 않습니다",
    Reason.TOKEN_AUDIENCE_MISMATCH: "토큰의 대상이 맞지 않습니다",
    Reason.TOKEN_SCOPE_EXCEEDED: "토큰의 권한 범위가 허용 범위를 넘었습니다",
    Reason.UNSUPPORTED: "지원하지 않는 호출이 막혔습니다",
    Reason.SCHEMA_ERROR: "요청 형식 오류로 호출이 막혔습니다",
    Reason.POLICY_VERSION_MISMATCH: "정책 버전이 달라 호출이 막혔습니다",
    Reason.DEPENDENCY_FAILURE: "필요한 서비스에 연결하지 못했습니다",
    Reason.AUDIT_FAILURE: "감사 기록을 남기지 못해 호출이 막혔습니다",
    Reason.ORG_BOUNDARY: "조직 경계를 벗어난 호출이 막혔습니다",
    Reason.ANONYMOUS: "사용자를 식별하지 못해 호출이 막혔습니다",
    Reason.ENFORCEMENT_UNVERIFIED: "정책 적용 상태가 확인되지 않아 호출이 막혔습니다",
    Reason.CANCELLED: "호출이 취소되었습니다",
    Reason.CONFIRMATION_REQUIRED: "본인 확인이 필요합니다",
    Reason.CONFIRMATION_STALE: "본인 확인을 다시 해야 합니다",
}


class DispatchState(StrEnum):
    NOT_DISPATCHED = "not_dispatched"
    DISPATCHED_UNKNOWN = "dispatched_unknown"
    DISPATCHED_COMPLETED = "dispatched_completed"


class Dependency(StrEnum):
    DB = "db"
    OPA = "opa"


class MintError(BaseModel):
    """``retry_safe``는 업스트림 전송이 일어나지 않았음이 확인된 경우에만 참일 수 있다."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    dispatch_state: DispatchState
    retry_safe: bool
    reference: str
    # 막힌 호출의 호출별 승인 요청을 열었음(참조로 승인자가 찾는다)
    approval_requested: bool = False
    # 같은 호출의 직전 요청이 거부된 사유(거부 기억 시간 안의 재시도)와, 직전 승인이 쓰이지 않고
    # 만료됐다는 사실. 요청자(에이전트)가 같은 시도를 되풀이하지 않도록 돌려준다.
    denial_reason: str | None = None
    previous_expired: bool = False
    # 호출자(에이전트)가 취할 다음 행동 안내. 승인 대기·거부·결과 차단 오류에만 있다.
    guidance: str | None = None
    # 다시 시도하기까지 기다릴 초. 승인 대기와 일시 오류에만 있다.
    retry_after: int | None = None
    # 본인 확인 화면으로 가는 서명된 단기 링크. 본인 확인 요청을 열었을 때만 있다.
    confirm_link: str | None = None

    @model_validator(mode="after")
    def _retry_only_before_dispatch(self) -> Self:
        if not self.code.startswith("MINT-"):
            raise ValueError("code must start with MINT-")
        if self.retry_safe and self.dispatch_state is not DispatchState.NOT_DISPATCHED:
            raise ValueError("retry_safe requires dispatch_state=not_dispatched")
        return self

    def detail(self) -> str:
        """``HTTPException.detail``에 넣을 JSON 문자열. 키 순서가 고정되어 있다."""
        body = {
            "code": self.code,
            "dispatch_state": self.dispatch_state.value,
            "retry_safe": self.retry_safe,
            "reference": self.reference,
        }
        if self.approval_requested:
            body["approval_requested"] = True
        if self.denial_reason is not None:
            body["denial_reason"] = self.denial_reason
        if self.previous_expired:
            body["previous_expired"] = True
        if self.guidance is not None:
            body["guidance"] = self.guidance
        if self.retry_after is not None:
            body["retry_after"] = self.retry_after
        if self.confirm_link is not None:
            body["confirm_link"] = self.confirm_link
        return json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def from_detail(cls, detail: str) -> Self:
        return cls.model_validate_json(detail)

    def as_block(self) -> "BlockResponse":
        return BlockResponse(status_code=BLOCK_STATUS_CODE, detail=self.detail())


class BlockResponse(BaseModel):
    """``HTTPException(status_code, detail)``에 그대로 넘기는 값 객체."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status_code: int
    detail: str


def error_code(reason_code: str) -> str:
    """사유 코드에서 오류 코드를 만든다: ``MINT-`` + 밑줄을 하이픈으로 바꾼 사유 코드."""
    parse_reason_code(reason_code)
    return "MINT-" + reason_code.replace("_", "-")


def error_for_reason(
    reason_code: str, reference: str, dependency: Dependency | None = None
) -> MintError:
    """전송 전 차단의 오류. 의존 서비스 불능과 호출별 승인 대기만 재시도 안전이고, 나머지는
    동의·본인 확인 뒤 재제출이다."""
    family, _ = parse_reason_code(reason_code)
    if family is Reason.DEPENDENCY_FAILURE:
        if dependency is None:
            raise ValueError("DEPENDENCY_FAILURE requires the failed dependency")
        return MintError(
            code=f"MINT-DEPENDENCY-{dependency.value.upper()}",
            dispatch_state=DispatchState.NOT_DISPATCHED,
            retry_safe=True,
            reference=reference,
            guidance=TRANSIENT_GUIDANCE,
            retry_after=TRANSIENT_RETRY_AFTER,
        )
    if family is Reason.CANCELLED:
        return cancelled_error(reference, dispatched=False)
    if family in (Reason.CALL_APPROVAL_REQUIRED, Reason.CALL_APPROVAL_STALE):
        # 승인 대기는 업스트림 전송이 없었으므로 승인 뒤 같은 호출을 다시 보내도 안전하다.
        return MintError(
            code=error_code(reason_code),
            dispatch_state=DispatchState.NOT_DISPATCHED,
            retry_safe=True,
            reference=reference,
            guidance=APPROVAL_GUIDANCE,
            retry_after=APPROVAL_RETRY_AFTER,
        )
    name = policy_detect_name(reason_code)
    guidance = {
        Reason.POLICY_DETECT: (
            f"정책 위반({name or '정책 탐지'})으로 막혔습니다. 호출 인자를 승인된 범위에 맞게 "
            "고쳐 다시 요청하거나 관리자에게 승인 범위를 문의하십시오. 같은 인자로는 재시도하지 "
            "마십시오. Blocked by policy: do not retry the same call."
        ),
        Reason.CALL_APPROVAL_DENIED: DENIAL_GUIDANCE,
        Reason.CONFIRMATION_REQUIRED: CONFIRMATION_GUIDANCE,
        Reason.CONFIRMATION_STALE: CONFIRMATION_GUIDANCE,
        Reason.MASTER_KEY_FORBIDDEN: (
            "마스터 키로 도구를 호출할 수 없습니다. 관리자에게 "
            "본인에게 발급된 일반 키를 요청하십시오."
        ),
    }.get(family) or (
        REASON_EXPLANATIONS[family] + ". " + BLOCKED_GUIDANCE
    )
    return MintError(
        code=error_code(reason_code),
        dispatch_state=DispatchState.NOT_DISPATCHED,
        retry_safe=False,
        reference=reference,
        guidance=guidance,
    )


def record_failed_error(reference: str) -> MintError:
    """전송 뒤 기록에 실패한 경우."""
    # 도구 결과를 검사하는 전송 뒤 경로에서만 쓰며, 전송 전에 끝나는 호출 판정에서는 쓰지 않는다.
    return MintError(
        code="MINT-RECORD-FAILED",
        dispatch_state=DispatchState.DISPATCHED_UNKNOWN,
        retry_safe=False,
        reference=reference,
    )


def cancelled_error(reference: str, *, dispatched: bool) -> MintError:
    return MintError(
        code="MINT-CANCELLED",
        dispatch_state=(
            DispatchState.DISPATCHED_UNKNOWN if dispatched else DispatchState.NOT_DISPATCHED
        ),
        retry_safe=not dispatched,
        reference=reference,
        guidance=(
            "호출이 취소되었습니다. 관리자에게 취소 사유를 확인하십시오."
            if not dispatched
            else "호출이 취소되었으나 실행 여부를 확인하십시오."
        ),
    )


def output_blocked_error(reference: str) -> MintError:
    return MintError(
        code="MINT-OUTPUT-BLOCKED",
        dispatch_state=DispatchState.DISPATCHED_COMPLETED,
        retry_safe=False,
        reference=reference,
        guidance=OUTPUT_GUIDANCE,
    )
