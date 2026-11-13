"""차단 응답의 오류 계약.

차단은 항상 ``HTTPException(status_code=403, detail=<JSON 문자열>)``로 전달된다. REST 경로는
403을 그대로 돌려주고 스트리머블 HTTP 경로는 같은 JSON을 오류 텍스트에 담아 돌려주므로,
클라이언트는 어느 경로에서든 ``code``를 파싱할 수 있다.
"""

import json
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, model_validator

from mint_litellm.types.reason_codes import Reason, parse_reason_code

BLOCK_STATUS_CODE = 403


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
    """전송 전 차단의 오류. 의존 서비스 불능만 재시도 안전이고 나머지는 승인·동의 뒤 재제출이다."""
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
    return MintError(
        code=error_code(reason_code),
        dispatch_state=DispatchState.NOT_DISPATCHED,
        retry_safe=False,
        reference=reference,
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
