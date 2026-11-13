"""배포 점검. 설정 표(``SETTINGS_TABLE``)의 모든 행을 설정 파일·환경·관리 API로 검사한다.

필수 행의 위반은 실패, 권장 행의 위반은 경고이고, 관측 항목은 값만 보고한다. 보고의 항목 이름은
설정 표의 ``key``와 같다.
"""

import importlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mint_litellm.compat import capabilities
from mint_litellm.control import secrets_file
from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.litellm_config import GUARDRAIL_MODES, LOGGER_SUFFIXES
from mint_litellm.control.policy_check import PolicyState
from mint_litellm.types import fingerprint
from mint_litellm.types.decision import normalize_auth_type, url_sha256
from mint_litellm.types.reuse_policy import (
    DEFAULT_TOOL_TIMEOUT_SECONDS,
    DISCOVERY_AUTH,
    KEY_BINDING,
    KEY_CONCURRENCY,
    KEY_CREDENTIAL,
    KEY_ENV_LOGIN,
    KEY_FORWARD,
    KEY_ISSUER,
    KEY_REDIRECT,
    KEY_RESOURCE,
    KEY_RPM,
    KEY_SSL,
    KEY_TIMEOUT,
    KEY_URL_HOSTS,
    ServerFacts,
    credential_digest,
    forwarding_violation,
    forwards_client_token,
    reuse_violations,
    ssl_verify_on,
)
from mint_litellm.types.settings import (
    OBSERVATION_ITEMS,
    REUSE_POLICIES,
    SETTINGS_TABLE,
    SettingGrade,
)
from mint_litellm.types.target import effective_profile, parse_profile_map, select_profile

_REUSE_KEYS = (
    KEY_ENV_LOGIN, KEY_URL_HOSTS, KEY_SSL, KEY_REDIRECT, KEY_ISSUER, KEY_BINDING, KEY_TIMEOUT,
    KEY_CREDENTIAL, KEY_RPM, KEY_CONCURRENCY, KEY_RESOURCE, KEY_FORWARD,
)
_ROWS = {row.key: row for row in SETTINGS_TABLE}
_OPTOUT_KEYS = ("opted_out_global_guardrails", "disable_global_guardrails")

# 설정 표에는 없지만 필수로 취급하는 점검 항목
POLICY_ITEM = "정책 번들 내용"
FINGERPRINT_ITEM = "MINT_FINGERPRINT_KEY"
KEY_NAME_IN_FILE = "MINT_FINGERPRINT_KEY"
EXTRA_REQUIRED = frozenset({POLICY_ITEM, FINGERPRINT_ITEM})

# 호환 계층이 쓰는 LiteLLM 비공개 심볼: (모듈, 객체, 속성)
COMPAT_SYMBOLS: tuple[tuple[str, str | None, str | None], ...] = (
    ("litellm.proxy._experimental.mcp_server.mcp_server_manager", "global_mcp_server_manager",
     "_resolve_mcp_server_for_tool_call"),
    ("litellm.proxy._experimental.mcp_server.catalog", None, None),
    # 기동 전 검사가 설정을 읽는 로더(compat/litellm_config_loader.py)
    ("litellm.proxy.proxy_server", "ProxyConfig", "_get_config_from_file"),
)


class Level(StrEnum):
    OK = "통과"
    INFO = "정보"
    WARN = "경고"
    FAIL = "실패"
    SKIP = "확인 불가"


@dataclass(frozen=True)
class Finding:
    item: str
    level: Level
    message: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)

    def add(self, item: str, level: Level, message: str = "") -> None:
        self.findings.append(Finding(item, level, message))

    @property
    def failed(self) -> bool:
        return any(f.level is Level.FAIL for f in self.findings)

    @property
    def incomplete(self) -> list[str]:
        """확인하지 못한 필수 행. 실패는 아니지만 점검이 끝났다고 말할 수 없다."""
        return [
            f.item
            for f in self.findings
            if f.level is Level.SKIP
            and (f.item in EXTRA_REQUIRED
                 or (f.item in _ROWS and _ROWS[f.item].grade is SettingGrade.REQUIRED))
        ]

    def policy_status(self) -> dict[str, str]:
        """LiteLLM 재사용 정책별 충족 여부: 충족, 미충족, 확인 불가."""
        by_item: dict[str, list[Level]] = {}
        for f in self.findings:
            by_item.setdefault(f.item, []).append(f.level)
        status = {}
        for policy, keys in REUSE_POLICIES.items():
            levels = [level for key in keys for level in by_item.get(key, [Level.SKIP])]
            if any(level in (Level.FAIL, Level.WARN) for level in levels):
                status[policy] = "미충족"
            elif all(level in (Level.OK, Level.INFO) for level in levels):
                status[policy] = "충족"
            else:
                status[policy] = "확인 불가"
        return status

    def render(self) -> str:
        lines = [f"[{f.level.value}] {f.item}" + (f": {f.message}" if f.message else "")
                 for f in self.findings]
        lines.append("정책 이행(LiteLLM 재사용)")
        lines.extend(f"  {policy}: {state}" for policy, state in self.policy_status().items())
        lines.append("관측 항목")
        lines.extend(f"  {name}: {self.observations.get(name, '확인 불가')}"
                     for name in OBSERVATION_ITEMS)
        return "\n".join(lines)


def probe_compat_symbols() -> list[str] | None:
    """없는 심볼 이름 목록. LiteLLM을 불러올 수 없으면 None."""
    missing: list[str] = []
    for module_name, obj_name, attr in COMPAT_SYMBOLS:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            if _litellm_absent():
                return None
            missing.append(module_name)
            continue
        if obj_name is not None:
            target = getattr(module, obj_name, None)
            if target is None or not hasattr(target, attr or ""):
                missing.append(f"{module_name}.{obj_name}.{attr}")
    return missing


def _result_guardrail_exists() -> bool:
    return capabilities.assess(()).grade != "C"


def _litellm_absent() -> bool:
    try:
        importlib.import_module("litellm")
    except ImportError:
        return True
    return False


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def run_checks(
    config: Mapping[str, Any] | None,
    env: Mapping[str, str],
    litellm: LiteLLMAdmin | None,
    *,
    replicas: int = 1,
    registered_servers: list[dict] | None = None,
    policy_state: PolicyState | None = None,
    check_fingerprint: bool = False,
    env_file_keys: frozenset[str] = frozenset(),
    compat_probe: Callable[[], list[str] | None] = probe_compat_symbols,
) -> Report:
    report = Report()
    grade_fail = {SettingGrade.REQUIRED: Level.FAIL, SettingGrade.RECOMMENDED: Level.WARN}

    def judge(key: str, ok: bool, message: str) -> None:
        if ok:
            report.add(key, Level.OK)
        else:
            report.add(key, grade_fail[_ROWS[key].grade], message)

    file_missing = config is None
    if config is None:
        report.add("LiteLLM 설정 파일", Level.FAIL,
                   "MINT_LITELLM_CONFIG(또는 --config)로 설정 파일을 지정해야 검사할 수 있습니다.")
        config = {}
    general = config.get("general_settings") or {}
    lsettings = config.get("litellm_settings") or {}
    servers_cfg: dict[str, dict] = config.get("mcp_servers") or {}

    if not file_missing:
        _check_file_rows(judge, config, general, lsettings, servers_cfg, env, replicas)
        _check_env_rows(judge, general, env)

    # 관리 API 기반 행
    if litellm is not None:
        _check_registry_rows(report, judge, litellm, registered_servers or [], config)
        _check_keys_and_teams(report, judge, litellm, _mint_guardrail_names(config))
        if not file_missing:
            _check_guardrail_registered(report, litellm, config)
    else:
        for key in ("서버 이름·별칭 유일성", "사용자·팀에 결속되지 않은 키"):
            report.add(key, Level.SKIP, "LiteLLM 관리 API가 설정되어 있지 않습니다.")
        if not file_missing:
            report.add("guardrails[MINT]", Level.SKIP,
                       "실행 중인 LiteLLM의 가드레일 등록을 확인하지 못했습니다(관리 API 없음).")

    if policy_state is not None:
        _policy_finding(report, policy_state)
    if check_fingerprint:
        _fingerprint_finding(report, env, env_file_keys)
    missing = compat_probe()
    if missing is None:
        report.add("호환 계층 비공개 심볼", Level.SKIP,
                   "이 환경에 LiteLLM이 설치되어 있지 않습니다(플러그인 기동 점검이 확인합니다).")
    else:
        judge("호환 계층 비공개 심볼", not missing, "없는 심볼: " + ", ".join(missing))

    report.observations["spend_log_arguments_stored"] = (
        "확인 불가" if file_missing else str(not _truthy(general.get("disable_spend_logs"))).lower()
    )
    report.observations["auth_cache_shared"] = str(
        _truthy(lsettings.get("enable_redis_auth_cache"))
    ).lower()
    return report


def _check_file_rows(judge, config, general, lsettings, servers_cfg, env, replicas) -> None:
    # 가드레일 항목
    guardrails = config.get("guardrails") or []
    mint_index = next(
        (i for i, g in enumerate(guardrails)
         if str((g.get("litellm_params") or {}).get("guardrail", "")).endswith(".MintGuardrail")),
        None,
    )
    if mint_index is None:
        judge("guardrails[MINT]", False, "MINT 가드레일 항목이 없습니다.")
    else:
        params = guardrails[mint_index].get("litellm_params") or {}
        modes = params.get("mode")
        modes = [modes] if isinstance(modes, str) else list(modes or [])
        problems = []
        needed = [m for m in GUARDRAIL_MODES
                  if m != "post_mcp_call"
                  or not (capabilities.allow_degraded(env) and not _result_guardrail_exists())]
        if not set(needed) <= set(modes):  # 결과 단계 가드레일이 없는 LiteLLM(저하 운용)은 제외
            problems.append(f"mode에 {', '.join(needed)}이 모두 필요합니다")
        if params.get("default_on") is not True:
            problems.append("default_on이 true가 아닙니다")
        judge("guardrails[MINT]", not problems, "; ".join(problems))

    callbacks = lsettings.get("callbacks") or []
    callbacks = [callbacks] if isinstance(callbacks, str) else callbacks
    logged = [
        c for c in callbacks
        if isinstance(c, str) and c.endswith(LOGGER_SUFFIXES)
    ]
    judge("callbacks", not logged,
          "MINT 로거는 가드레일이 등록하므로 litellm_settings.callbacks에 적으면 안 됩니다: "
          + ", ".join(logged))

    open_servers = [n for n, s in servers_cfg.items() if _truthy((s or {}).get("allow_all_keys"))]
    judge("mcp_servers.<이름>.allow_all_keys", not open_servers,
          "allow_all_keys가 true인 서버: " + ", ".join(open_servers))
    unnamed = [n for n, s in servers_cfg.items() if not (s or {}).get("server_id")]
    judge("mcp_servers.<이름>.server_id", not unnamed,
          "server_id가 없는 설정 서버: " + ", ".join(unnamed))

    judge("require_key_mcp_access_defined", general.get("require_key_mcp_access_defined") is True,
          "general_settings.require_key_mcp_access_defined가 true가 아닙니다.")
    judge("store_prompts_in_spend_logs",
          not _truthy(general.get("store_prompts_in_spend_logs"))
          and not _truthy(env.get("STORE_PROMPTS_IN_SPEND_LOGS", "false")),
          "도구 결과 본문이 지출 로그에 저장됩니다.")
    judge("user_url_validation", lsettings.get("user_url_validation", True) is not False,
          "litellm_settings.user_url_validation이 false입니다.")
    objects = general.get("supported_db_objects")
    judge("supported_db_objects", objects is None or "mcp" in objects,
          "supported_db_objects에 mcp가 없습니다.")

    roles = (((lsettings.get("key_generation_settings") or {}).get("personal_key_generation")
              or {}).get("allowed_user_roles"))
    judge("key_generation_settings.personal_key_generation.allowed_user_roles",
          roles == ["proxy_admin"], 'allowed_user_roles를 ["proxy_admin"]으로 제한하십시오.')
    judge("mcp_allow_all_keys_respects_mcp_scope",
          general.get("mcp_allow_all_keys_respects_mcp_scope") is True,
          "general_settings.mcp_allow_all_keys_respects_mcp_scope를 true로 설정하십시오.")
    judge("enable_redis_auth_cache",
          replicas < 2 or _truthy(lsettings.get("enable_redis_auth_cache")),
          "복제본 × 워커가 둘 이상이면 enable_redis_auth_cache와 공유 Redis를 설정하십시오.")
    _check_reuse_rows(judge, general, lsettings, servers_cfg, env)


def _server_facts(name: str, cfg: Mapping[str, Any]) -> ServerFacts:
    auth = str(cfg.get("auth_type", "")).lower()
    m2m = cfg.get("oauth2_flow") == "client_credentials"
    timeout = cfg.get("timeout")
    delegate = _truthy(cfg.get("delegate_auth_to_upstream", False))
    return ServerFacts(
        name=name,
        gateway_oauth=auth == "oauth2" and not delegate,
        upstream_resource=cfg.get("upstream_resource"),
        forwards_token=forwards_client_token(auth, delegate, cfg.get("extra_headers")),
        discovery_oauth=auth in DISCOVERY_AUTH,
        per_user_oauth=auth == "oauth2" and not m2m and not _truthy(
            cfg.get("delegate_auth_to_upstream", False)),
        issuer=cfg.get("issuer"),
        binding_mode=(cfg.get("oauth_identity_binding") or {}).get("mode"),
        timeout=float(timeout) if isinstance(timeout, (int, float)) else None,
        rpm=cfg.get("rpm"),
        max_concurrent=cfg.get("max_concurrent_requests"),
        credential=(credential_digest(cfg.get("client_id"), cfg.get("client_secret")) if m2m
                    else credential_digest(cfg.get("authentication_token"))),
    )


def _check_reuse_rows(judge, general, lsettings, servers_cfg, env) -> None:
    """LiteLLM이 구현하는 정책의 설정 값. 기동 자가 점검과 같은 규칙이다."""
    try:
        default_timeout = float(env.get("LITELLM_MCP_CLIENT_TIMEOUT", DEFAULT_TOOL_TIMEOUT_SECONDS))
    except ValueError:
        default_timeout = None
    ssl_value = env.get("SSL_VERIFY", lsettings.get("ssl_verify", True))
    facts = [_server_facts(n, s or {}) for n, s in servers_cfg.items()]
    violations = reuse_violations(
        general=general,
        allowed_hosts=lsettings.get("user_url_allowed_hosts") or [],
        ssl_verify=ssl_verify_on(ssl_value),
        env=env,
        servers=facts,
        default_timeout=default_timeout,
    )
    forwarding = forwarding_violation(facts)
    violations = [*violations, *([forwarding] if forwarding else [])]
    for key in _REUSE_KEYS:
        messages = [v.message for v in violations if v.key == key]
        judge(key, not messages, " ".join(messages))


def _check_env_rows(judge, general, env) -> None:
    judge("LITELLM_STRICT_GUARDRAIL_MODES",
          str(env.get("LITELLM_STRICT_GUARDRAIL_MODES", "true")).lower() != "false",
          "LITELLM_STRICT_GUARDRAIL_MODES=false는 허용되지 않습니다.")
    judge("PROXY_BASE_URL", bool(env.get("PROXY_BASE_URL")), "PROXY_BASE_URL을 설정하십시오.")
    judge("MCP_TRUSTED_REDIRECT_ORIGINS", bool(env.get("MCP_TRUSTED_REDIRECT_ORIGINS")),
          "MCP_TRUSTED_REDIRECT_ORIGINS를 배치에 맞게 설정하십시오.")
    forwarded = _truthy(general.get("use_x_forwarded_for"))
    ranges = bool(general.get("mcp_trusted_proxy_ranges"))
    judge("use_x_forwarded_for, mcp_trusted_proxy_ranges", forwarded == ranges,
          "use_x_forwarded_for와 mcp_trusted_proxy_ranges는 함께 설정해야 합니다.")
    judge("LEGACY_MULTI_INSTANCE_RATE_LIMITING",
          not _truthy(env.get("LEGACY_MULTI_INSTANCE_RATE_LIMITING", "false")),
          "true이면 MCP 분당 호출 한도가 집행되지 않습니다.")


def _check_registry_rows(
    report, judge, litellm: LiteLLMAdmin, registered: list[dict], config: Mapping[str, Any]
) -> None:
    listing = litellm.list_servers()
    owners: dict[str, set[Any]] = {}
    for position, entry in enumerate(listing):
        owner = entry.get("server_id", position)
        for label in {entry.get("server_name"), entry.get("alias")} - {None, ""}:
            # 런타임 점검과 같은 정규화이다: 공백은 밑줄과 같은 이름으로 본다.
            owners.setdefault(str(label).replace(" ", "_"), set()).add(owner)
    duplicated = sorted(name for name, ids in owners.items() if len(ids) > 1)
    judge("서버 이름·별칭 유일성", not duplicated, "중복된 이름·별칭: " + ", ".join(duplicated))
    by_id = {e["server_id"]: e for e in listing}
    problems: list[str] = []
    unverified: list[str] = []
    open_servers: list[str] = []
    suspended_missing: list[str] = []
    for row in registered:
        entry = by_id.get(row["server_id"])
        if row.get("identity_kind", "remote") == "stdio":
            # 로컬 실행 서버는 레지스트리에 없어야 한다. 같은 식별자가 있으면 다른 서버로 오인된다.
            if entry is not None:
                problems.append(f"{row['server_id']}: 로컬 서버와 같은 식별자가 레지스트리에 있음")
            continue
        if entry is None:
            # 플러그인 자가 점검 5번과 같다: 승인된 서버만 기동을 막고, 중지된 서버는 알리기만 한다.
            status = row.get("status", "approved")
            if status == "approved":
                problems.append(f"{row['server_id']}: 레지스트리에 없음")
            elif status == "suspended":
                suspended_missing.append(row["server_id"])
            continue
        if _truthy(entry.get("allow_all_keys")):
            open_servers.append(row["server_id"])
        if (entry.get("transport"), normalize_auth_type(entry.get("auth_type"))) != (
            row["transport"], row["auth_type"]
        ):
            problems.append(f"{row['server_id']}: 전송·인증 방식 불일치")
            continue
        # 제어 평면 키에는 레지스트리 URL이 응답되지 않으므로 설정 파일의 URL로 대신 확인한다.
        url = entry.get("url") or _config_server_url(config, row["server_id"])
        if not url:
            unverified.append(row["server_id"])
        elif url_sha256(url) != row["url_sha256"]:
            problems.append(f"{row['server_id']}: URL 해시 불일치")
    if open_servers:
        report.add("mcp_servers.<이름>.allow_all_keys", Level.FAIL,
                   "allow_all_keys가 true인 등록 서버: " + ", ".join(open_servers))
    if suspended_missing:
        report.add("중지된 서버의 레지스트리 항목", Level.INFO,
                   "LiteLLM 레지스트리에 없는 중지 서버(기동을 막지 않고 플러그인이 "
                   "registry_missing 사건을 남깁니다): " + ", ".join(suspended_missing))
    if not registered:
        return
    if problems:
        report.add("등록 서버의 계약 값", Level.FAIL, "; ".join(problems))
    elif unverified:
        report.add("등록 서버의 계약 값", Level.SKIP,
                   "URL을 확인하지 못했습니다(제어 평면 키에는 레지스트리 URL이 응답되지 않고 설정 "
                   "파일에도 없음): " + ", ".join(unverified))
    else:
        report.add("등록 서버의 계약 값", Level.OK)


def _config_server_url(config: Mapping[str, Any], server_id: str) -> str | None:
    for server in (config.get("mcp_servers") or {}).values():
        if isinstance(server, Mapping) and server.get("server_id") == server_id:
            return server.get("url") or None
    return None


def _permission_of(litellm: LiteLLMAdmin, kind: str, obj: Mapping[str, Any]) -> Mapping[str, Any]:
    """목록 응답에 권한 객체가 생략된 키·팀은 상세 조회로 보충한다."""
    permission = obj.get("object_permission")
    if permission or not obj.get("object_permission_id"):
        return permission or {}
    detail = (
        litellm.get_team(obj["team_id"]) if kind == "team" else litellm.get_key(obj["token"])
    )
    return (detail or {}).get("object_permission") or {}


def _mint_guardrail_names(config: Mapping[str, Any]) -> frozenset[str]:
    """설정 파일에서 MINT 가드레일의 이름. 설정이 없거나 정의가 없으면 기본 이름을 쓴다."""
    names = {
        g.get("guardrail_name")
        for g in config.get("guardrails") or []
        if str((g.get("litellm_params") or {}).get("guardrail", "")).endswith(".MintGuardrail")
    } - {None}
    return frozenset(names or {"mint"})


def _check_keys_and_teams(
    report, judge, litellm: LiteLLMAdmin, mint_names: frozenset[str]
) -> None:
    keys = litellm.list_keys()
    teams = litellm.list_teams()
    registry_ids = {s["server_id"] for s in litellm.list_servers()}
    unbound = sum(1 for k in keys if not k.get("user_id") and not k.get("team_id"))
    judge("사용자·팀에 결속되지 않은 키", unbound == 0,
          f"사용자도 팀도 없는 키가 {unbound}개 있습니다.")
    report.observations["unbound_keys"] = unbound

    def optout(meta: Mapping[str, Any] | None) -> bool:
        """다른 가드레일을 끈 키·팀: MINT 외 이름이 목록에 있거나 전체 비활성이 ``True``일 때."""
        meta = meta or {}
        excluded = meta.get("opted_out_global_guardrails")
        if meta.get("disable_global_guardrails") is True:
            return True
        return isinstance(excluded, list) and any(
            isinstance(name, str) and name not in mint_names for name in excluded
        )

    subjects = sum(1 for k in keys if optout(k.get("metadata"))) + sum(
        1 for t in teams if optout(t.get("metadata"))
    )
    report.observations["guardrail_optout_subjects"] = subjects
    if subjects:
        report.add("가드레일 제외 대상", Level.INFO,
                   f"키·팀 metadata로 가드레일을 끈 키·팀이 {subjects}개 있습니다. "
                   "MINT 판정과 도구 목록 숨김은 그대로 적용되고, "
                   "꺼지는 것은 다른 가드레일뿐입니다.")
    bad: list[str] = []
    for owner, kind, objects in (("키", "key", keys), ("팀", "team", teams)):
        for obj in objects:
            for entry in _permission_of(litellm, kind, obj).get("mcp_servers") or []:
                if entry not in registry_ids:
                    label = obj.get("key_alias") or obj.get("team_alias") or obj.get("token") or ""
                    bad.append(f"{owner} {label}: {entry}")
    if bad:
        report.add("object_permission 서버 식별자 형식", Level.FAIL,
                   "서버 식별자가 아닌 항목(별칭·이름은 server_id로 교정): " + "; ".join(bad))
    else:
        report.add("object_permission 서버 식별자 형식", Level.OK)


def _check_guardrail_registered(report, litellm: LiteLLMAdmin, config: Mapping[str, Any]) -> None:
    """설정 파일의 MINT 가드레일이 실행 중인 LiteLLM에 같은 값으로 올라와 있는지 다시 확인한다."""
    declared = [
        g.get("guardrail_name")
        for g in config.get("guardrails") or []
        if str((g.get("litellm_params") or {}).get("guardrail", "")).endswith(".MintGuardrail")
    ]
    live = {
        g.get("guardrail_name"): g.get("litellm_params") or {} for g in litellm.list_guardrails()
    }
    problems: list[str] = []
    for name in declared:
        params = live.get(name)
        if params is None:
            problems.append(f"{name}: 실행 중인 LiteLLM에 등록되지 않았습니다")
            continue
        modes = params.get("mode")
        modes = [modes] if isinstance(modes, str) else list(modes or [])
        if not str(params.get("guardrail", "")).endswith(".MintGuardrail"):
            problems.append(f"{name}: 등록된 클래스가 MINT 가드레일이 아닙니다")
        if not set(GUARDRAIL_MODES) <= set(modes) or params.get("default_on") is not True:
            problems.append(f"{name}: 실행 중인 모드·default_on이 설정 파일과 다릅니다")
    if problems:
        report.add("guardrails[MINT]", Level.FAIL, "; ".join(problems))


def _policy_finding(report: Report, state: PolicyState) -> None:
    if state.state == "match":
        report.add(POLICY_ITEM, Level.OK, f"판본 {state.version}")
    elif state.state == "none":
        report.add(POLICY_ITEM, Level.WARN, state.detail)
    elif state.state == "mismatch":
        report.add(POLICY_ITEM, Level.FAIL, state.detail)
    else:
        report.add(POLICY_ITEM, Level.SKIP, state.detail)


def _fingerprint_finding(
    report: Report, env: Mapping[str, str], env_file_keys: frozenset[str]
) -> None:
    """검사에 쓰인 인자 지문 키와 키 판본이 있고 형식이 맞는지 본다.

    환경 변수에 없으면 서비스에 같은 값을 주는 비밀 파일을 본다. 읽을 수 없으면 확인 못한 것이다.
    출처를 함께 적는다: 실행 중인 LiteLLM 서비스가 실제로 받은 값과 대조하지는 않는다.
    """
    try:
        key, version, source = secrets_file.load_fingerprint_key_with_source(env)
    except ControlError as error:
        # 키가 없다는 것과 파일을 읽을 수 없다는 것을 구분한다.
        wrong = "찾을 수 없습니다" in str(error) or "정수가 아닙니다" in str(error)
        level = Level.FAIL if wrong else Level.SKIP
        report.add(FINGERPRINT_ITEM, level, str(error))
        return
    if source != "environment":
        origin = f"비밀 파일 {source}"
    elif KEY_NAME_IN_FILE in env_file_keys:
        origin = "--env-file"
    else:
        origin = "이 프로세스의 환경 변수"
    note = f" (검사 출처: {origin}; 실행 중인 LiteLLM 서비스가 받은 값과는 대조하지 않음)"
    try:
        fingerprint.decode_fingerprint_key(key)
    except ValueError as error:
        report.add(FINGERPRINT_ITEM, Level.FAIL, f"키 형식이 올바르지 않습니다: {error}{note}")
        return
    if version < 1:
        report.add(FINGERPRINT_ITEM, Level.FAIL, f"키 판본은 1 이상이어야 합니다.{note}")
        return
    report.add(FINGERPRINT_ITEM, Level.OK, f"키 판본 {version}{note}")


def target_profile_findings(
    report: Report, deployments: list[dict], env: Mapping[str, str]
) -> None:
    """서버마다 대상·행위 프로필을 무엇으로 쓰는지(자동 선택인지 환경 변수 덮어쓰기인지) 보인다.

    ``deployments``는 서버 식별자·승인된 배포 계약의 URL·승인된 도구 이름(``tools``)이다.
    """
    try:
        overrides = parse_profile_map(env.get("MINT_TARGET_PROFILES", ""))
    except ValueError as error:
        report.add("호출 대상 프로필", Level.FAIL, f"MINT_TARGET_PROFILES가 올바르지 않음: {error}")
        return
    auto = {d["server_id"]: select_profile(d["url"], d["tools"] or ()) for d in deployments}
    shown = []
    for server_id in sorted(auto.keys() | overrides.keys()):
        chosen = effective_profile(overrides, server_id, auto.get(server_id))
        if chosen is not None:
            shown.append(f"{server_id}={chosen[0]}({'자동' if chosen[1] == 'auto' else '덮어씀'})")
    report.add("호출 대상 프로필", Level.INFO, ", ".join(shown) if shown else "지정된 서버 없음")
