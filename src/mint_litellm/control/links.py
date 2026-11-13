"""콘솔 바로가기 링크: 알림에서 해당 화면의 해당 항목으로 가는 서명된 단기 토큰.

토큰은 항목을 미리 골라 둘 뿐이다. 승인이나 철회는 하지 않으며, 링크를 연 사람은 콘솔에
로그인해 평소처럼 확인(CSRF 포함)해야 한다. 서명 키는 웹훅 서명 키에서 용도를 나눠 파생한다.
"""

import base64
import hashlib
import hmac
import json
import time

DEFAULT_TTL_SECONDS = 86400

# 토큰 종류 -> 알림 부속 항목 이름(subject의 키)
ALERT_LINKS: dict[str, tuple[str, str]] = {
    "call_approval_requested": ("call", "id"),
    "approval_recert_due": ("recert", "approval_id"),
    "approval_recert_held": ("recert", "approval_id"),
    "intake_pending": ("intake", "intake_id"),
    "approval_dormant": ("dormant", "server_id"),
}


def _mac(key: bytes, payload: bytes) -> str:
    derived = hmac.new(key, b"mint-console-link-v1", hashlib.sha256).digest()
    return hmac.new(derived, payload, hashlib.sha256).hexdigest()[:32]


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make(key: bytes, kind: str, ref: str, *, ttl: int = DEFAULT_TTL_SECONDS,
         now: int | None = None) -> str:
    current = int(time.time()) if now is None else now
    payload = _b64(json.dumps([kind, ref, current + ttl], separators=(",", ":")).encode("utf-8"))
    return f"{payload}.{_mac(key, payload.encode('ascii'))}"


def parse(key: bytes, token: str, *, now: int | None = None) -> tuple[str, str] | None:
    """서명이 맞고 기한 안이면 (종류, 항목)을, 아니면 None을 돌려준다."""
    payload, _, mac = token.partition(".")
    if not payload or not hmac.compare_digest(_mac(key, payload.encode("ascii", "ignore")), mac):
        return None
    try:
        padded = payload + "=" * (-len(payload) % 4)
        kind, ref, expires = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return None
    current = int(time.time()) if now is None else now
    if not (isinstance(kind, str) and isinstance(ref, str) and isinstance(expires, int)):
        return None
    return (kind, ref) if current <= expires else None


def for_alert(row: dict, console_url: str | None, key: bytes | None, ttl: int) -> str | None:
    """경보 한 건의 콘솔 링크. 대상이 아닌 종류이거나 콘솔 주소가 없으면 None."""
    spec = ALERT_LINKS.get(row["kind"])
    ref = (row.get("subject") or {}).get(spec[1]) if spec else None
    if not (spec and ref and console_url and key):
        return None
    return f"{console_url.rstrip('/')}/link/{make(key, spec[0], str(ref), ttl=ttl)}"
