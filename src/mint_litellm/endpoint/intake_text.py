"""직원 단말에 보이는 신청 진행 단계·사유·다음 할 일(사람이 읽는 한국어)."""

from __future__ import annotations

from typing import Any

REASON = {
    "NAME_INVALID": "패키지 이름 형식이 맞지 않습니다",
    "VERSION_INVALID": "판본 형식이 맞지 않습니다",
    "COMMAND_INVALID": "명령 이름 형식이 맞지 않습니다",
    "ARGV_TOO_MANY": "실행 인자가 너무 많습니다",
    "ARGV_INVALID": "실행 인자 형식이 맞지 않습니다",
    "SPEC_INVALID": "신청 명세 형식이 맞지 않습니다",
    "PACK_INDEX_NOT_ALLOWED": "이 패키지 저장소는 허용되지 않았습니다",
    "PACK_RESOLVE_FAILED": "패키지를 받지 못했습니다",
    "PACK_SDIST_ONLY": "소스 배포본만 있어 묶을 수 없습니다",
    "PACK_DIRECT_URL": "직접 주소 패키지는 묶을 수 없습니다",
    "PACK_DIGEST_MISMATCH": "받은 파일이 배포처 값과 다릅니다",
    "PACK_ENTRY_NOT_FOUND": "실행 진입점을 찾지 못했습니다",
    "PACK_TOO_LARGE": "묶음이 너무 큽니다",
    "PACK_UNAVAILABLE": "묶음이 없어 검사하지 못했습니다",
    "EXEC_CONTRACT_INVALID": "실행 계약을 만들 수 없습니다",
    "INSPECTION_FAILED": "검사 중 서버가 도구 목록을 내지 못했습니다",
    "INSPECTION_INCOMPLETE": "도구 목록을 끝까지 받지 못했습니다",
    "INSPECTION_UNAVAILABLE": "검사기가 응답하지 않았습니다",
    "TIMEOUT": "검사 시간이 지났습니다",
    "NO_DEFINITIONS": "도구 정보가 없어 설명을 검사하지 못했습니다",
    "INPUT_MISSING": "필수 입력이 없어 등급을 정하지 못했습니다",
    "LIMIT_EXCEEDED": "도구 정의가 상한을 넘었습니다",
    "COLLECTION_FAILED": "도구 정의를 모으지 못했습니다",
}
# 판본을 바꾸면 달라질 수 있는 사유
RETRY_VERSION = {
    "PACK_RESOLVE_FAILED", "PACK_SDIST_ONLY", "PACK_DIRECT_URL", "PACK_DIGEST_MISMATCH",
    "PACK_ENTRY_NOT_FOUND", "PACK_TOO_LARGE",
}
CHECK_FAILED = "check_failed:"
NEXT_WAIT = "검사가 끝나기를 기다림"
NEXT_REVIEW = "관리자 검토 중"
NEXT_VERSION = "판본을 바꿔 다시 신청"
NEXT_FIX = "신청 내용을 고쳐 다시 신청"
NEXT_NONE = "없음"
NEXT_INSPECT = "단말 검사 필요 · s로 시작"
REASON_INSPECT = "단말 검사가 필요합니다"
UNKNOWN = "자동 검사로 판별하지 못했습니다"


def stage_of(row: dict[str, Any]) -> str:
    """접수·묶음 준비·검사 중·검사 통과·판별 불가·검사 실패·승인·거절·철회."""
    decision, status = row.get("decision"), row.get("status")
    if decision in ("approved", "exception"):
        return "approved"
    if decision in ("rejected", "withdrawn"):
        return str(decision)
    if status == "checking":
        return "inspect" if row.get("pack_ready") else "pack"
    known = ("received", "passed", "indeterminate", "failed")
    return str(status) if status in known else "received"


def _code(row: dict[str, Any]) -> str | None:
    reason = row.get("reason") or ""
    if reason.startswith(CHECK_FAILED):
        return reason.rsplit(":", 1)[-1]
    return row.get("reason_code")


def reason_of(row: dict[str, Any]) -> str | None:
    code, stage = _code(row), stage_of(row)
    if row.get("inspect") and stage in ("passed", "indeterminate", "failed"):
        return REASON_INSPECT
    if stage in ("indeterminate", "failed", "rejected") and code:
        return REASON.get(code, UNKNOWN)
    if stage in ("approved", "rejected", "withdrawn"):
        return row.get("reason") or None
    return UNKNOWN if stage in ("indeterminate", "failed") else None


def next_of(row: dict[str, Any]) -> str:
    stage, code = stage_of(row), _code(row)
    if row.get("inspect") and stage in ("passed", "indeterminate", "failed"):
        return NEXT_INSPECT
    if stage in ("received", "pack", "inspect"):
        return NEXT_WAIT
    if stage in ("passed", "indeterminate"):
        return NEXT_VERSION if code in RETRY_VERSION else NEXT_REVIEW
    if stage == "failed":
        return NEXT_FIX
    if stage == "rejected":
        return NEXT_VERSION
    return NEXT_NONE
