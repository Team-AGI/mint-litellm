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
APPROVAL_GUIDANCE = (
    "관리자 승인이 필요합니다. 승인된 뒤 같은 작업을 다시 요청하십시오. "
    "승인 범위·기간 안에서 정책을 다시 검사합니다."
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
    # 호출자(에이전트)가 취할 다음 행동 안내. 승인 대기 오류에만 있다.
    guidance: str | None = None
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
        )
    name = policy_detect_name(reason_code)
    guidance = {
        Reason.POLICY_DETECT: (
            f"정책 위반({name or '정책 탐지'})으로 막혔습니다. 호출 인자를 승인된 범위에 맞게 "
            "고쳐 다시 요청하거나 관리자에게 승인 범위를 문의하십시오."
        ),
        Reason.CALL_APPROVAL_DENIED: DENIAL_GUIDANCE,
        Reason.CONFIRMATION_REQUIRED: CONFIRMATION_GUIDANCE,
        Reason.CONFIRMATION_STALE: CONFIRMATION_GUIDANCE,
    }.get(family)
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
    )


def output_blocked_error(reference: str) -> MintError:
    return MintError(
        code="MINT-OUTPUT-BLOCKED",
        dispatch_state=DispatchState.DISPATCHED_COMPLETED,
        retry_safe=False,
        reference=reference,
    )
