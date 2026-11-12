"""승인 조건에 MINT가 기본값을 채운다. 사람이 따로 설정하지 않아도 정책이 집행되게 한다.

채운 조건은 정책 입력에만 들어가며 저장된 승인 행은 바뀌지 않는다. 승인에 이미 적힌 값은
그대로 존중한다(허용 인자 키, 본인 확인 대상 이외에는 더하기만 한다).
"""

from collections.abc import Mapping, Sequence
from typing import Any

# 삭제·외부 전송 도구는 호출마다 사용자 본인 확인을 받는다.
CONFIRM_ACTIONS = frozenset({"delete", "external_send"})
CONFIRM_PURPOSE = "삭제·공유·외부 전송 확인"
# 개인정보 등급 자료를 다루는 서버는 사용자 동의가 있어야 쓴다.
CONSENT_GRADES = frozenset({"confidential", "restricted"})
CONSENT_FALLBACK = "서버 이용 동의"


def effective_conditions(
    conditions: Mapping[str, Any],
    *,
    tool: str,
    action_type: str | None,
    input_keys: Sequence[str] | None,
    data_grade: str | None,
    purpose: str | None,
) -> dict[str, Any]:
    """승인 조건에 빠진 집행 조건을 채운 사본.

    - 허용 인자 키: 계약의 입력 정의에 있는 항목만(``input_keys``가 있을 때).
    - 본인 확인 대상: 삭제·외부 전송 도구는 항상 포함한다.
    - 사용자 동의: 기밀 이상 자료 서버는 이용 목적으로 동의를 요구한다.
    """
    result = dict(conditions)
    if input_keys is not None and "allowed_arg_keys" not in result:
        result["allowed_arg_keys"] = sorted(set(input_keys))
    if action_type in CONFIRM_ACTIONS:
        confirm = result.get("require_user_confirmation")
        if confirm is None:
            result["require_user_confirmation"] = {
                "tools": [tool], "purpose": CONFIRM_PURPOSE, "display_fields": [],
            }
        elif (
            isinstance(confirm, Mapping)
            and isinstance(confirm.get("tools"), list)
            and all(isinstance(name, str) for name in confirm["tools"])
            and tool not in confirm["tools"]
        ):
            result["require_user_confirmation"] = {
                **confirm, "tools": sorted({*confirm["tools"], tool}),
            }
    if data_grade in CONSENT_GRADES and "require_consent" not in result:
        result["require_consent"] = (purpose or "").strip()[:128] or CONSENT_FALLBACK
    return result
