"""콘솔과 LiteLLM 안의 화면 어댑터가 주고받는 서버 간 호출의 서명.

별도 비밀값 없이 내보내기 서명 키에서 유도한다.
"""

import hashlib
import hmac
import time

PURPOSE = b"mint-ui-handoff"
MAX_SKEW_SECONDS = 60
SIGNATURE_HEADER = "X-Mint-Signature"
TIMESTAMP_HEADER = "X-Mint-Timestamp"
REDEEM_PATH = "/internal/ui-grants/redeem"
REVOKE_PATH = "/mint-ui/revoke"
ENTER_PATH = "/mint-ui/enter"
# 인계 코드의 유효 시간(초). 한 번 쓰면 끝난다.
CODE_SECONDS = 60


def _mac(key: bytes, timestamp: str, path: str, body: bytes) -> str:
    derived = hmac.new(key, PURPOSE, hashlib.sha256).digest()
    return hmac.new(derived, f"{timestamp}\n{path}\n".encode() + body, hashlib.sha256).hexdigest()


def sign(key: bytes, path: str, body: bytes, now: float | None = None) -> dict[str, str]:
    stamp = str(int(time.time() if now is None else now))
    return {TIMESTAMP_HEADER: stamp, SIGNATURE_HEADER: _mac(key, stamp, path, body)}


def verify(
    key: bytes, path: str, body: bytes, headers: dict[str, str], now: float | None = None
) -> bool:
    lowered = {k.lower(): v for k, v in headers.items()}
    stamp = lowered.get(TIMESTAMP_HEADER.lower(), "")
    signature = lowered.get(SIGNATURE_HEADER.lower(), "")
    if not stamp.isdigit():
        return False
    current = time.time() if now is None else now
    if abs(current - int(stamp)) > MAX_SKEW_SECONDS:
        return False
    return hmac.compare_digest(signature, _mac(key, stamp, path, body))
