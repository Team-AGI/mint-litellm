"""2단계 프로세스(콘솔·작업 실행기)가 읽는 환경 변수 설정.

필수 값이 없거나 잘못되면 ``ControlError``로 거부한다. 두 프로세스는 기동할 때
``Stage2Settings.from_env``를 부르고 실패하면 기동을 멈춘다.
"""

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from mint_litellm.control.errors import ControlError
from mint_litellm.types.fingerprint import MIN_KEY_BYTES, decode_fingerprint_key


def _key(env: Mapping[str, str], name: str, *, required: bool) -> bytes | None:
    raw = env.get(name)
    if raw is None or not raw.strip():
        if required:
            raise ControlError(f"{name}이(가) 설정되어 있지 않습니다.")
        return None
    try:
        return decode_fingerprint_key(raw)
    except ValueError:
        raise ControlError(
            f"{name}은(는) 디코딩하면 {MIN_KEY_BYTES}바이트 이상인 base64url 문자열이어야 합니다."
        ) from None


def _required_key(env: Mapping[str, str], name: str) -> bytes:
    key = _key(env, name, required=True)
    assert key is not None
    return key


def _seconds(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise ControlError(f"{name}은(는) 양의 정수여야 합니다: {raw!r}") from None
    if value < minimum:
        raise ControlError(f"{name}은(는) {minimum} 이상이어야 합니다: {value}")
    return value


def _days(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    value = _seconds(env, name, default, minimum)
    if value > 365:
        raise ControlError(f"{name}은(는) 365 이하여야 합니다: {value}")
    return value


def _ports(raw: str | None) -> tuple[int, ...]:
    if raw is None or not raw.strip():
        return (443, 8443)
    try:
        ports = tuple(int(part) for part in raw.split(",") if part.strip())
    except ValueError:
        ports = ()
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ControlError(
            f"MINT_INTAKE_ALLOWED_PORTS는 쉼표로 구분한 포트 목록이어야 합니다: {raw!r}"
        )
    return ports
def _refuse_internal_host(url: str, host: str) -> None:
    """리터럴 사설·루프백·링크로컬 주소와 localhost를 거부한다(이름 해석 결과는 보지 않는다)."""
    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith(".localhost"):
        raise ControlError(f"MINT_WEBHOOK_URLS에 localhost를 쓸 수 없습니다: {url}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise ControlError(f"MINT_WEBHOOK_URLS에 내부 주소를 쓸 수 없습니다: {url}")


def _webhook_urls(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return ()
    urls = tuple(part.strip() for part in raw.split(",") if part.strip())
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ControlError(f"MINT_WEBHOOK_URLS는 https 주소만 받습니다: {url}")
        _refuse_internal_host(url, parts.hostname)
    return urls


def _feed_url(raw: str | None) -> str:
    """취약점 조회 주소. 비우면 공개 OSV이고, 내부 미러를 쓰려면 http(s) 주소를 준다."""
    if raw is None or not raw.strip():
        return "https://api.osv.dev"
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ControlError(f"MINT_VULN_FEED_URL은 http 또는 https 주소여야 합니다: {raw!r}")
    return raw.strip().rstrip("/")


@dataclass(frozen=True)
class Stage2Settings:
    export_dir: Path
    export_hmac_key: bytes
    export_hmac_key_previous: bytes | None = None
    sync_hold_window_seconds: int = 3600
    webhook_urls: tuple[str, ...] = ()
    webhook_hmac_key: bytes | None = None
    worker_lease_seconds: int = 60
    reconcile_seconds: int = 300
    observe_seconds: int = 3600
    submission_poll_seconds: int = 60
    checkpoint_seconds: int = 600
    session_idle_seconds: int = 1800
    session_absolute_seconds: int = 28800
    session_verify_seconds: int = 300

    @property
    def session_verify_window_seconds(self) -> int:
        """마지막 성공 확인 뒤 요청을 받아 주는 시간(확인 주기 두 번). 넘으면 요청마다 거부한다."""
        return 2 * self.session_verify_seconds

    staff_consent_max_days: int = 90
    # 승인 필요성 재확인 주기와 유예(일). 기본값은 MINT가 채우며 운영자 설정이 필요 없다.
    recert_days: int = 90
    recert_grace_days: int = 14
    # 단말 설치 보고가 이 시간(시) 넘게 없으면 경보. 기본값은 MINT가 채운다(묶음은 6시간마다 보고).
    endpoint_silent_hours: int = 24
    # 새로 발급하는 단말 설치 묶음 키의 유효 기간(일, 30~365). 만료 전 14일 안의 보고가 늘려 준다.
    endpoint_key_days: int = 90
    intake_allowed_ports: tuple[int, ...] = (443, 8443)
    console_url: str | None = None
    # 호출량 급증: 최근 구간, 지난 기간(평균을 내는 기간), 평균의 몇 배, 최소 호출 수
    spike_window_seconds: int = 300
    spike_baseline_seconds: int = 86400
    spike_factor: int = 3
    spike_min_calls: int = 50
    # 알려진 취약점 조회(OSV 형식 API): 주소, 조회 주기, 요청 제한 시간(초). 기본값은 MINT가 채운다.
    vuln_feed_url: str = "https://api.osv.dev"
    vuln_scan_seconds: int = 900
    vuln_feed_timeout_seconds: int = 15

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Stage2Settings":
        export_dir = (env.get("MINT_EXPORT_DIR") or "").strip()
        if not export_dir:
            raise ControlError("MINT_EXPORT_DIR이(가) 설정되어 있지 않습니다.")
        urls = _webhook_urls(env.get("MINT_WEBHOOK_URLS"))
        webhook_key = _key(env, "MINT_WEBHOOK_HMAC_KEY", required=bool(urls))
        settings = cls(
            export_dir=Path(export_dir),
            export_hmac_key=_required_key(env, "MINT_EXPORT_HMAC_KEY"),
            export_hmac_key_previous=_key(env, "MINT_EXPORT_HMAC_KEY_PREVIOUS", required=False),
            sync_hold_window_seconds=_seconds(env, "MINT_SYNC_HOLD_WINDOW_SECONDS", 3600),
            webhook_urls=urls,
            webhook_hmac_key=webhook_key,
            worker_lease_seconds=_seconds(env, "MINT_WORKER_LEASE_SECONDS", 60),
            reconcile_seconds=_seconds(env, "MINT_RECONCILE_SECONDS", 300),
            observe_seconds=_seconds(env, "MINT_OBSERVE_SECONDS", 3600, 20),
            submission_poll_seconds=_seconds(env, "MINT_SUBMISSION_POLL_SECONDS", 60),
            checkpoint_seconds=_seconds(env, "MINT_CHECKPOINT_SECONDS", 600),
            session_idle_seconds=_seconds(env, "MINT_SESSION_IDLE_SECONDS", 1800),
            session_absolute_seconds=_seconds(env, "MINT_SESSION_ABSOLUTE_SECONDS", 28800),
            session_verify_seconds=_seconds(env, "MINT_SESSION_VERIFY_SECONDS", 300),
            staff_consent_max_days=_days(env, "MINT_STAFF_CONSENT_MAX_DAYS", 90),
            recert_days=_days(env, "MINT_RECERT_DAYS", 90),
            recert_grace_days=_days(env, "MINT_RECERT_GRACE_DAYS", 14),
            endpoint_silent_hours=_seconds(env, "MINT_ENDPOINT_SILENT_HOURS", 24),
            endpoint_key_days=_days(env, "MINT_ENDPOINT_KEY_DAYS", 90, 30),
            intake_allowed_ports=_ports(env.get("MINT_INTAKE_ALLOWED_PORTS")),
            spike_window_seconds=_seconds(env, "MINT_SPIKE_WINDOW_SECONDS", 300),
            spike_baseline_seconds=_seconds(env, "MINT_SPIKE_BASELINE_SECONDS", 86400),
            spike_factor=_seconds(env, "MINT_SPIKE_FACTOR", 3),
            spike_min_calls=_seconds(env, "MINT_SPIKE_MIN_CALLS", 50),
            vuln_feed_url=_feed_url(env.get("MINT_VULN_FEED_URL")),
            vuln_scan_seconds=_seconds(env, "MINT_VULN_SCAN_SECONDS", 900, 60),
            vuln_feed_timeout_seconds=_seconds(env, "MINT_VULN_FEED_TIMEOUT_SECONDS", 15),
            console_url=(env.get("MINT_CONSOLE_URL") or "").strip() or None,
        )
        if settings.session_idle_seconds > settings.session_absolute_seconds:
            raise ControlError(
                "MINT_SESSION_IDLE_SECONDS는 MINT_SESSION_ABSOLUTE_SECONDS를 넘을 수 없습니다."
            )
        return settings
