"""플러그인 설정. 환경 변수에서만 읽고, 잘못된 값은 ``RuntimeError``로 알린다.

LiteLLM은 가드레일 생성자가 ``ValueError``·``TypeError``를 던지면 가드레일 없이 기동하므로
이 모듈의 모든 오류는 ``RuntimeError``이다.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from mint_litellm.types.fingerprint import decode_fingerprint_key
from mint_litellm.types.settings import Mode
from mint_litellm.types.target import parse_profile_map

_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})

DEFAULT_BUFFER_DIR = "/var/lib/mint/buffer"
DEFAULT_BUFFER_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_DECISION_BUDGET_MS = 300
DEFAULT_SELFCHECK_GRACE_SECONDS = 120.0
# 승인 조건에 결과 상한이 없을 때 계약 관리 서버에 채우는 기본 상한. 0이면 채우지 않는다.
DEFAULT_MAX_RESULT_BYTES = 1024 * 1024
DEFAULT_MAX_RESULT_ITEMS = 1000
SELFCHECK_GRACE_RANGE = (10, 600)
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


@dataclass(frozen=True)
class PluginConfig:
    instance_id: str
    database_url: str
    opa_url: str
    mode_ceiling: Mode = Mode.ENFORCE
    required: bool = True
    high_risk_tools: frozenset[str] = frozenset()
    # 서버 식별자 -> 대상·행위 프로필 이름. 여기 없는 서버는 대상을 따로 묶지 않는다.
    target_profiles: dict[str, str] = field(default_factory=dict)
    buffer_dir: Path = Path(DEFAULT_BUFFER_DIR)
    buffer_max_bytes: int = DEFAULT_BUFFER_MAX_BYTES
    db_pool_size: int = 8
    decision_budget_seconds: float = DEFAULT_DECISION_BUDGET_MS / 1000
    fingerprint_key: bytes | None = None
    fingerprint_key_version: int = 1
    readiness_url: str | None = None
    selfcheck_grace_seconds: float = DEFAULT_SELFCHECK_GRACE_SECONDS
    log_level: str | None = None
    observe_seconds: int = 3600
    # 실시간 경로의 연결 뒤 도구 추가는 사전 훅을 지나지 않으므로 기본으로 거부한다.
    allow_realtime: bool = False
    # 모델이 만든 코드를 LiteLLM 샌드박스에서 실행하는 경로(스킬·코드 인터프리터)는 MCP 훅을 지나지
    # 않으므로 기본으로 거부한다.
    allow_code_execution: bool = False
    # 자가 점검을 통과하면 그때까지 만들어진 객체를 가비지 수거 대상에서 뺀다(긴 정지를 막는다).
    gc_freeze: bool = True
    # 되돌림 탐지(2단계). 읽기 전용으로 마운트한 내보내기 디렉터리와 서명 키.
    export_dir: Path | None = None
    export_hmac_key: bytes | None = None
    export_hmac_key_previous: bytes | None = None
    restore_interval_seconds: float = 60.0
    default_max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES
    default_max_result_items: int = DEFAULT_MAX_RESULT_ITEMS
    # 정책 시험 적용(선택). 주소가 없으면 시험 판본을 읽지도 평가하지도 않는다.
    shadow_opa_url: str | None = None
    shadow_sample_percent: int = 100
    shadow_max_per_second: int = 50

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> PluginConfig:
        instance_id = _required(env, "MINT_INSTANCE_ID")
        if not _IDENT.fullmatch(instance_id):
            raise RuntimeError("MINT_INSTANCE_ID must be an identifier of letters, digits, . _ -")
        mode_text = env.get("MINT_MODE", Mode.ENFORCE.value).strip().lower()
        try:
            ceiling = Mode(mode_text)
        except ValueError:
            raise RuntimeError("MINT_MODE must be enforce or observe") from None
        key = _fingerprint_key(env.get("MINT_FINGERPRINT_KEY"))
        export_dir = env.get("MINT_EXPORT_DIR", "").strip()
        return cls(
            instance_id=instance_id,
            database_url=_required(env, "MINT_DATABASE_URL"),
            opa_url=_required(env, "MINT_OPA_URL"),
            mode_ceiling=ceiling,
            required=_boolean(env, "MINT_REQUIRED", True),
            high_risk_tools=frozenset(
                t.strip() for t in env.get("MINT_HIGH_RISK_TOOLS", "").split(",") if t.strip()
            ),
            target_profiles=_target_profiles(env.get("MINT_TARGET_PROFILES", "")),
            buffer_dir=Path(env.get("MINT_BUFFER_DIR", DEFAULT_BUFFER_DIR)),
            buffer_max_bytes=_integer(env, "MINT_BUFFER_MAX_BYTES", DEFAULT_BUFFER_MAX_BYTES, 1024),
            db_pool_size=_integer(env, "MINT_DB_POOL_SIZE", 8, 1),
            decision_budget_seconds=_integer(
                env, "MINT_DECISION_BUDGET_MS", DEFAULT_DECISION_BUDGET_MS, 10
            )
            / 1000,
            fingerprint_key=key,
            fingerprint_key_version=_integer(env, "MINT_FINGERPRINT_KEY_VERSION", 1, 1),
            readiness_url=env.get("MINT_READINESS_URL") or None,
            log_level=_log_level(env.get("MINT_LOG_LEVEL")),
            observe_seconds=_integer(env, "MINT_OBSERVE_SECONDS", 3600, 20),
            allow_realtime=_boolean(env, "MINT_ALLOW_REALTIME", False),
            allow_code_execution=_boolean(env, "MINT_ALLOW_CODE_EXECUTION", False),
            gc_freeze=_boolean(env, "MINT_GC_FREEZE", True),
            default_max_result_bytes=_integer(
                env, "MINT_DEFAULT_MAX_RESULT_BYTES", DEFAULT_MAX_RESULT_BYTES, 0
            ),
            default_max_result_items=_integer(
                env, "MINT_DEFAULT_MAX_RESULT_ITEMS", DEFAULT_MAX_RESULT_ITEMS, 0
            ),
            shadow_opa_url=(env.get("MINT_SHADOW_OPA_URL") or "").strip() or None,
            shadow_sample_percent=_integer(env, "MINT_SHADOW_SAMPLE_PERCENT", 100, 1, 100),
            shadow_max_per_second=_integer(env, "MINT_SHADOW_MAX_PER_SECOND", 50, 1, 1000),
            export_dir=Path(export_dir) if export_dir else None,
            export_hmac_key=_hmac_key(env, "MINT_EXPORT_HMAC_KEY"),
            export_hmac_key_previous=_hmac_key(env, "MINT_EXPORT_HMAC_KEY_PREVIOUS"),
            selfcheck_grace_seconds=float(
                _integer(
                    env,
                    "MINT_SELFCHECK_GRACE_SECONDS",
                    int(DEFAULT_SELFCHECK_GRACE_SECONDS),
                    SELFCHECK_GRACE_RANGE[0],
                    SELFCHECK_GRACE_RANGE[1],
                )
            ),
        )


def _target_profiles(raw: str) -> dict[str, str]:
    try:
        return parse_profile_map(raw)
    except ValueError as exc:
        raise RuntimeError(f"MINT_TARGET_PROFILES is invalid: {exc}") from None


def _log_level(raw: str | None) -> str | None:
    if raw is None or not raw.strip():
        return None
    level = raw.strip().upper()
    if level not in LOG_LEVELS:
        raise RuntimeError(f"MINT_LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}")
    return level


def configure_logging(level: str | None) -> None:
    """``MINT_LOG_LEVEL``이 있으면 플러그인 로그의 수준을 정하고 표준 오류로 내보낸다."""
    if level is None:
        return
    logger = logging.getLogger("mint_litellm")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _fingerprint_key(raw: str | None) -> bytes | None:
    if raw is None:
        return None
    try:
        return decode_fingerprint_key(raw)
    except ValueError as exc:
        raise RuntimeError(f"MINT_FINGERPRINT_KEY is invalid: {exc}") from None


def _hmac_key(env: Mapping[str, str], name: str) -> bytes | None:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        return decode_fingerprint_key(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} is invalid: {exc}") from None


def _boolean(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    text = raw.strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise RuntimeError(f"{name} must be true or false")


def _integer(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int | None = None
) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer") from None
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise RuntimeError(f"{name} must be at most {maximum}")
    return value
