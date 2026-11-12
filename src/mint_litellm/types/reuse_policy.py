"""LiteLLM이 구현하는 정책을 MINT가 설정 값으로 강제하는 규칙.

기동 자가 점검(실행 중인 LiteLLM의 유효 값)과 배포 점검(설정 파일)이 같은 규칙을 쓰도록 값만
받아 판정한다. 위반의 ``key``는 설정 표(``SETTINGS_TABLE``)의 행 이름이다.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

# 도구 호출 제한 시간의 상한(초). 서버 설정이나 LiteLLM 기본값이 이를 넘으면 위반이다.
MAX_TOOL_TIMEOUT_SECONDS = 600.0
DEFAULT_TOOL_TIMEOUT_SECONDS = 60.0
# init이 서버마다 채우는 기본 한도: 분당 호출 수, 동시 실행 수
DEFAULT_SERVER_RPM = 600
DEFAULT_SERVER_CONCURRENCY = 8

# 인증 서버를 발견해 쓰는 인증 방식
DISCOVERY_AUTH = frozenset({"oauth2", "true_passthrough", "oauth_delegate"})

KEY_ENV_LOGIN = "disable_env_credential_login"
KEY_SSL = "ssl_verify"
KEY_URL_HOSTS = "user_url_allowed_hosts"
KEY_REDIRECT = "OAuth 리다이렉트 출처"
KEY_ISSUER = "mcp_servers.<이름>.issuer"
KEY_BINDING = "mcp_servers.<이름>.oauth_identity_binding.mode"
KEY_TIMEOUT = "mcp_servers.<이름>.timeout"
KEY_CREDENTIAL = "mcp_servers.<이름>.authentication_token"
KEY_RPM = "mcp_servers.<이름>.rpm"
KEY_CONCURRENCY = "mcp_servers.<이름>.max_concurrent_requests"


@dataclass(frozen=True)
class ServerFacts:
    """한 MCP 서버에서 규칙이 보는 값."""

    name: str
    discovery_oauth: bool  # 인증 서버를 발견해 쓰는 서버
    per_user_oauth: bool  # 게이트웨이가 사용자별 OAuth 토큰을 맡는 서버
    issuer: str | None
    binding_mode: str | None
    timeout: float | None
    credential: str | None  # 서버 고유 정적 자격의 해시. 없으면 None
    rpm: float | None = None
    max_concurrent: float | None = None
    # 정적 헤더에 실린 자격(Authorization 등)의 해시. 서버 사이에서 인증 토큰과 함께 비교한다.
    header_credentials: tuple[str, ...] = ()
    # LiteLLM DB에 등록된 서버. 한도는 MINT가 승인·동기화 때 채우므로 기동을 막지 않는다.
    in_database: bool = False


@dataclass(frozen=True)
class Violation:
    key: str
    message: str


def credential_digest(*parts: str | None) -> str | None:
    """정적 자격 값들의 해시. 값을 로그나 보고에 싣지 않고 서버 사이 중복만 비교한다."""
    values = [p for p in parts if p]
    if not values:
        return None
    return hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()


_CREDENTIAL_HEADER = ("auth", "token", "secret", "key", "cookie")


def header_credential_digests(headers: object) -> tuple[str, ...]:
    """정적 헤더 중 자격을 싣는 헤더(Authorization, X-API-Key 등)의 값 해시.

    LiteLLM은 ``static_headers``를 업스트림 요청에 그대로 붙이므로, 인증 토큰 대신 여기에 적은
    자격도 서버 사이 재사용 점검에 들어가야 한다. 문자열(JSON)이면 풀어서 본다.
    """
    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except ValueError:
            return ()
    if not isinstance(headers, Mapping):
        return ()
    found = (
        credential_digest(_strip_scheme(value))
        for name, value in headers.items()
        if isinstance(value, str) and any(w in str(name).lower() for w in _CREDENTIAL_HEADER)
    )
    return tuple(d for d in found if d)


def _strip_scheme(value: str) -> str:
    """``Bearer abc``와 ``abc``를 같은 자격으로 본다."""
    head, _, rest = value.strip().partition(" ")
    schemes = {"bearer", "basic", "token", "apikey"}
    return rest.strip() if rest and head.lower() in schemes else value


def ssl_verify_on(value: object) -> bool:
    """``ssl_verify`` 값이 인증서 검증을 끄지 않는지. CA 파일 경로 문자열은 켜진 것이다."""
    if isinstance(value, str):
        return value.strip().lower() != "false"
    return value is not False


def _origin_problem(entry: str) -> bool:
    """허용 출처 항목이 모든 주소(``*``)나 최상위 도메인 전체(``*.com``)를 여는 형태인지."""
    entry = entry.strip().lower()
    if "://" in entry:
        entry = entry.split("://", 1)[1]
    entry = entry.split("/", 1)[0]
    if entry == "*":
        return True
    return entry.startswith("*.") and "." not in entry[2:]


def reuse_violations(
    *,
    general: Mapping[str, object],
    allowed_hosts: Sequence[str],
    ssl_verify: bool,
    env: Mapping[str, str],
    servers: Sequence[ServerFacts],
    default_timeout: float | None,
) -> list[Violation]:
    """LiteLLM 재사용 정책의 설정 위반 목록. 비어 있으면 모두 충족이다."""
    found: list[Violation] = []

    def add(key: str, message: str) -> None:
        found.append(Violation(key, message))

    if general.get(KEY_ENV_LOGIN) is not True:
        add(KEY_ENV_LOGIN, "general_settings.disable_env_credential_login이 true가 아닙니다.")
    if allowed_hosts:
        add(KEY_URL_HOSTS, "litellm_settings.user_url_allowed_hosts가 비어 있지 않습니다.")
    if not ssl_verify:
        add(KEY_SSL, "TLS 인증서 검증이 꺼져 있습니다(ssl_verify 또는 SSL_VERIFY).")

    no_issuer = [s.name for s in servers if s.discovery_oauth and not s.issuer]
    if no_issuer:
        add(KEY_ISSUER, "issuer가 없는 발견형 인증 서버: " + ", ".join(no_issuer[:5]))
    unbound = [s.name for s in servers if s.per_user_oauth and s.binding_mode != "enforce"]
    if unbound:
        add(KEY_BINDING, "enforce가 아닌 사용자별 OAuth 서버: " + ", ".join(unbound[:5]))

    entries = [e for e in str(env.get("MCP_TRUSTED_REDIRECT_ORIGINS", "")).split(",") if e.strip()]
    wide = [e.strip() for e in entries if _origin_problem(e)]
    if wide:
        add(KEY_REDIRECT, "MCP_TRUSTED_REDIRECT_ORIGINS가 너무 넓습니다: " + ", ".join(wide[:5]))
    if any(s.discovery_oauth for s in servers) and not env.get("PROXY_BASE_URL"):
        add(KEY_REDIRECT, "OAuth 서버가 있으면 PROXY_BASE_URL을 설정하십시오.")

    unbounded = [
        s.name
        for s in servers
        if not 0 < (s.timeout if s.timeout is not None else (default_timeout or 0))
        <= MAX_TOOL_TIMEOUT_SECONDS
    ]
    if unbounded:
        add(KEY_TIMEOUT, "도구 호출 제한 시간이 없거나 너무 깁니다: " + ", ".join(unbounded[:5]))

    for key, label, values in (
        (KEY_RPM, "분당 호출 한도", [(s.name, s.rpm) for s in servers if not s.in_database]),
        (KEY_CONCURRENCY, "동시 실행 한도",
         [(s.name, s.max_concurrent) for s in servers if not s.in_database]),
    ):
        unset = [n for n, v in values if not isinstance(v, (int, float)) or v <= 0]
        if unset:
            add(key, f"{label}가 없거나 0 이하입니다: " + ", ".join(unset[:5]))

    owners: dict[str, list[str]] = {}
    for s in servers:
        for digest in dict.fromkeys((s.credential, *s.header_credentials)):
            if digest:
                owners.setdefault(digest, []).append(s.name)
    shared = sorted(", ".join(names[:5]) for names in owners.values() if len(names) > 1)
    if shared:
        add(KEY_CREDENTIAL, "한 정적 자격을 함께 쓰는 서버: " + "; ".join(shared[:3]))
    return found
