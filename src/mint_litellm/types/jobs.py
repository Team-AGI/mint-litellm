"""작업 멱등 키 형식. 같은 키의 작업은 한 행으로 수렴한다.

수렴 작업(동기화·관측·활성화 완결)은 멱등 키가 없고 대상당 대기 행이 하나다.
"""

import re
from datetime import UTC, datetime
from uuid import UUID

_KIND = re.compile(r"[a-z][a-z_]*")


def scheduled_job_key(kind: str, period_start: datetime) -> str:
    """예약 작업: ``<kind>:<주기 시작 시각>``. 시각은 UTC 초 단위 ISO 8601이다."""
    if not _KIND.fullmatch(kind):
        raise ValueError(f"invalid job kind {kind!r}")
    if period_start.tzinfo is None:
        raise ValueError("period_start must be timezone-aware")
    return f"{kind}:{period_start.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}"


def export_negative_job_key(state_epoch: int) -> str:
    """부정 상태 내보내기: ``export_negative:<state_epoch>``."""
    if state_epoch < 0:
        raise ValueError("state_epoch must not be negative")
    return f"export_negative:{state_epoch}"


def alert_deliver_job_key(delivery_id: UUID) -> str:
    """경보 전송: ``alert_deliver:<delivery_id>``."""
    return f"alert_deliver:{delivery_id}"


def intake_run_job_key(intake_id: UUID, attempt: int) -> str:
    """수용검증: ``intake_run:<intake_id>:<attempt>``."""
    if attempt < 1:
        raise ValueError("attempt starts at 1")
    return f"intake_run:{intake_id}:{attempt}"


def intake_reject_job_key(intake_id: UUID) -> str:
    """LiteLLM 제출 거절 전달: ``intake_run:<intake_id>:reject``. 신청마다 한 작업으로 수렴한다."""
    return f"intake_run:{intake_id}:reject"
