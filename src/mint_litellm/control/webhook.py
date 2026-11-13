"""경보 웹훅: 주소 검사, 서명, 본문, 전송.

요청 헤더 ``X-MINT-Signature``는 ``t=<unix 초>,v1=<HMAC-SHA256 16진수>``이고, 서명 대상은
``<t>.`` 뒤에 본문 바이트를 붙인 값이다. 수신 쪽은 ``verify``로 시각 차이(5분)와 서명을 함께 본다.
``X-MINT-Delivery``는 전송 식별자로, 수신 쪽이 중복을 거를 때 쓴다. 응답 본문은 읽어서 버린다.
"""

import hashlib
import hmac
import json
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlsplit

import httpx

from mint_litellm.control.errors import ControlError

log = logging.getLogger("mint_litellm.webhook")

SIGNATURE_HEADER = "X-MINT-Signature"
DELIVERY_HEADER = "X-MINT-Delivery"
TOLERANCE_SECONDS = 300
ATTEMPTS = 3
TIMEOUT_SECONDS = 5.0
# 한 번의 요청 전체 상한(연결·쓰기·읽기 단계를 합친 값)
DEADLINE_SECONDS = 5.0
_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="mint-webhook")


def check_url(url: str, allowed_hosts: Sequence[str]) -> None:
    """``https`` 주소이고 호스트가 허용 목록에 있어야 한다. 아니면 ``ControlError``."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ControlError("웹훅 주소는 https만 받습니다.")
    if parts.hostname not in allowed_hosts:
        raise ControlError("웹훅 주소의 호스트가 허용 목록에 없습니다.")


def sign(key: bytes, body: bytes, timestamp: int) -> str:
    mac = hmac.new(key, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify(
    key: bytes,
    header: str,
    body: bytes,
    *,
    now: int | None = None,
    tolerance: int = TOLERANCE_SECONDS,
) -> bool:
    """수신 쪽 검증. 형식이 틀리거나, 시각 차이가 ``tolerance``를 넘거나, 서명이 다르면 거짓이다."""
    parts = header.split(",")
    stamps = [part[2:] for part in parts if part.startswith("t=")]
    signatures = [part[3:] for part in parts if part.startswith("v1=")]
    if len(stamps) != 1 or len(signatures) != 1:
        return False
    try:
        timestamp = int(stamps[0])
    except ValueError:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > tolerance:
        return False
    expected = sign(key, body, timestamp).rsplit("v1=", 1)[1]
    return hmac.compare_digest(expected, signatures[0])


# 경보 종류별 위험 요지와 조치 절차. 담당자가 이 본문만으로 중지, 조사, 복구를 판단하게 한다.
GUIDE: dict[str, tuple[str, str]] = {
    "contract_drift": (
        "승인된 도구 정의와 서버가 알리는 정의가 달라졌습니다. 바뀐 도구는 승인 범위를 벗어납니다.",
        "콘솔에서 서버를 열어 바뀐 항목을 확인합니다. 의도한 변경이면 다시 승인하고, "
        "아니면 서버를 중지합니다.",
    ),
    "call_spike": (
        "도구 호출이 평소보다 갑자기 늘었습니다. 오남용이나 반복 호출 오류일 수 있습니다.",
        "콘솔의 기록에서 호출한 사용자와 인자를 확인합니다. 의도한 사용이 아니면 "
        "해당 서버의 승인을 철회하거나 서버를 중지합니다.",
    ),
    "sync_divergence": (
        "MINT의 승인 상태와 LiteLLM의 실제 설정이 다릅니다. "
        "승인 없이 열린 접근이 있을 수 있습니다.",
        "콘솔에서 해당 대상의 차이를 확인하고 동기화를 다시 실행합니다. "
        "계속되면 대상 서버를 중지합니다.",
    ),
    "sync_foreign_change": (
        "MINT가 아닌 곳에서 LiteLLM 설정이 바뀌었습니다.",
        "변경한 사람과 시각을 확인합니다. 의도하지 않았으면 "
        "MINT 기준으로 되돌리고 접근 키를 점검합니다.",
    ),
    "approval_expiring": (
        "승인이 곧 만료되며 만료 뒤에는 해당 서버 호출이 모두 차단됩니다.",
        "콘솔의 승인 목록에서 계속 필요한지 확인합니다. 필요하면 다시 승인하고, 아니면 철회합니다.",
    ),
    "evidence_expiring": (
        "서버에 첨부한 증빙의 유효 기한이 곧 끝납니다. 기한이 지나면 승인이 제한됩니다.",
        "콘솔의 서버 상세에서 증빙을 새로 첨부합니다.",
    ),
    "job_failed": (
        "백그라운드 작업이 반복해서 실패했습니다. 승인, 철회, 동기화가 지연될 수 있습니다.",
        "콘솔의 작업 상태에서 실패 원인을 확인하고, 해결되면 작업을 다시 실행합니다.",
    ),
    "litellm_unreachable": (
        "LiteLLM에 연결할 수 없어 승인 상태를 반영하지 못합니다.",
        "LiteLLM 프로세스와 네트워크를 확인합니다. 복구 전에는 서버 변경을 보류합니다.",
    ),
    "restore_request_rejected": (
        "복원 요청이 거부되었습니다. 이전 판본으로의 복원이 정책에 맞지 않습니다.",
        "콘솔의 복원 요청에서 거부 사유를 확인하고, "
        "필요하면 정책 판본을 점검한 뒤 다시 요청합니다.",
    ),
    "export_failed": (
        "감사 기록 내보내기가 실패했습니다. 보존 기한 안에 기록을 옮기지 못할 수 있습니다.",
        "내보내기 대상 저장소의 연결과 권한을 확인하고 내보내기를 다시 실행합니다.",
    ),
    "enforcement_unverified": (
        "차단이 실제로 적용되는지 확인하지 못했습니다.",
        "콘솔의 점검 결과를 확인하고, 해결되기 전에는 고위험 서버를 중지합니다.",
    ),
}
DEFAULT_GUIDE = (
    "MINT가 통제 상태의 이상을 감지했습니다.",
    "콘솔에서 경보 내용을 확인하고, "
    "대상 서버나 도구가 의심되면 중지한 뒤 원인을 조사합니다.",
)


def build_body(row: Mapping[str, Any], console_url: str | None) -> bytes:
    summary, action = GUIDE.get(row["kind"], DEFAULT_GUIDE)
    payload = {
        "summary": summary,
        "action": action,
        "kind": row["kind"],
        "severity": row["severity"],
        "subject": row["subject"],
        "count": row["count"],
        "first_at": row["first_at"].isoformat(),
        "last_at": row["last_at"].isoformat(),
        "console_url": console_url,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _within(call: Callable[[], int], seconds: float) -> int:
    """호출을 상한 안에서 기다린다. 넘으면 ``TimeoutError``(남은 호출은 자체 제한으로 끝난다)."""
    return _POOL.submit(call).result(timeout=seconds)


def post(
    client: httpx.Client,
    url: str,
    key: bytes,
    delivery_id: str,
    body: bytes,
    deadline: float = DEADLINE_SECONDS,
) -> tuple[bool, int]:
    """최대 ``ATTEMPTS``번 보낸다. 2xx면 성공. (성공 여부, 보낸 횟수)를 돌려준다.

    한 번의 요청은 ``deadline`` 초를 넘기지 않는다.
    """
    for attempt in range(1, ATTEMPTS + 1):
        headers = {
            "Content-Type": "application/json",
            SIGNATURE_HEADER: sign(key, body, int(time.time())),
            DELIVERY_HEADER: delivery_id,
        }
        try:
            status = _within(
                lambda h=headers: client.post(url, content=body, headers=h).status_code,
                deadline,
            )
        except (httpx.HTTPError, TimeoutError) as error:
            log.warning("웹훅 전송 %d회째 실패: %s", attempt, type(error).__name__)
            continue
        if 200 <= status < 300:
            return True, attempt
        log.warning("웹훅 전송 %d회째 응답 상태 %d", attempt, status)
    return False, ATTEMPTS


def client(timeout: float = TIMEOUT_SECONDS) -> httpx.Client:
    """리다이렉트를 따르지 않고 요청마다 같은 제한 시간을 쓰는 클라이언트."""
    return httpx.Client(timeout=timeout, follow_redirects=False)
