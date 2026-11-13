"""LiteLLM ``config.yaml`` 조각의 생성과 설정 파일·환경 파일 읽기."""

import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from mint_litellm.compat import litellm_config_loader
from mint_litellm.control.errors import ControlError
from mint_litellm.types.reuse_policy import DEFAULT_SERVER_CONCURRENCY, DEFAULT_SERVER_RPM

GUARDRAIL_CLASS = "mint_litellm.plugin.guardrail.MintGuardrail"
# 가드레일이 로거를 등록하므로 설정의 callbacks에는 적지 않는다. 적혀 있으면 거부한다.
LOGGER_SUFFIXES = (".MintLogger", ".mint_logger")
GUARDRAIL_MODES = ("pre_call", "pre_mcp_call", "post_mcp_call")
# 없으면 init --fix-config가 더하는 필수 설정: (섹션, 키)
REQUIRED_FLAGS = (("general_settings", "disable_env_credential_login"),)
# 서버마다 없으면 더하는 기본 한도(분당 호출 수, 동시 실행 수). 이미 적힌 값은 존중한다.
SERVER_LIMITS = {"rpm": DEFAULT_SERVER_RPM, "max_concurrent_requests": DEFAULT_SERVER_CONCURRENCY}

_HEADER = "# MINT 통제에 필요한 LiteLLM 설정 조각. 기존 config.yaml의 같은 키에 합친다.\n"


def snippet(servers: dict[str, tuple[str, str]], *, no_spend_logs: bool) -> str:
    """``servers``: 이름 -> (server_id, url)."""
    general: dict[str, Any] = {
        "require_key_mcp_access_defined": True,
        "mcp_allow_all_keys_respects_mcp_scope": True,
        "store_prompts_in_spend_logs": False,
        "disable_env_credential_login": True,
    }
    if no_spend_logs:
        general["disable_spend_logs"] = True
    document: dict[str, Any] = {
        "guardrails": [
            {
                "guardrail_name": "mint",
                "litellm_params": {
                    "guardrail": GUARDRAIL_CLASS,
                    "mode": list(GUARDRAIL_MODES),
                    "default_on": True,
                },
            }
        ],
        "litellm_settings": {
            "user_url_validation": True,
            "key_generation_settings": {
                "personal_key_generation": {"allowed_user_roles": ["proxy_admin"]}
            },
        },
        "general_settings": general,
    }
    if servers:
        document["mcp_servers"] = {
            name: {
                "server_id": server_id, "url": url, "transport": "http", "allow_all_keys": False,
                **SERVER_LIMITS,
            }
            for name, (server_id, url) in servers.items()
        }
    return _HEADER + yaml.safe_dump(document, sort_keys=False, allow_unicode=True)


def load_effective(path: Path | None, *, require_loader: bool = False) -> dict[str, Any] | None:
    """LiteLLM의 설정 로더로 ``include``까지 병합한 설정. 로더는 ``compat``에 격리되어 있다."""
    if path is None:
        return None
    return litellm_config_loader.load_effective_config(path, require_loader=require_loader)


def load_config(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ControlError(f"LiteLLM 설정 파일을 읽을 수 없습니다: {error}") from None
    if not isinstance(data, dict):
        raise ControlError("LiteLLM 설정 파일의 최상위가 매핑이 아닙니다.")
    return data


def load_env_file(path: Path) -> dict[str, str]:
    """``KEY=VALUE`` 줄만 읽는 환경 파일 해석. 주석과 빈 줄은 무시한다."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ControlError(f"환경 파일을 읽을 수 없습니다: {error}") from None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("\"'")
    return values


_MODE_LINE = re.compile(
    r"^(?P<head>\s*mode:\s*)(?:\[(?P<flow>[^\]#]*)\]|(?P<scalar>[A-Za-z_]+))(?P<tail>\s*(?:#.*)?)$"
)
_CLASS_LINE = re.compile(r"^(?P<indent>\s*)guardrail:\s*\S*\.MintGuardrail\s*(?:#.*)?$")


def _mint_item(document: Any) -> dict[str, Any] | None:
    for item in (document or {}).get("guardrails") or []:
        params = (item or {}).get("litellm_params") or {}
        if str(params.get("guardrail", "")).endswith(".MintGuardrail"):
            return params
    return None


def ensure_guardrail_modes(path: Path) -> list[str]:
    """운영자 설정의 MINT 가드레일 ``mode``에 빠진 모드를 더한다. 더한 모드를 돌려준다.

    한 줄 ``mode: [...]``나 ``mode: 이름`` 형태만 그 줄을 고친다(주석·다른 줄은 그대로). 바꾸기 전에
    ``<파일>.bak-<UTC 시각>`` 사본을 두고, 이미 모두 있거나 파일·MINT 가드레일이 없으면 아무것도
    하지 않는다. 안전하게 고칠 수 없는 모양이면 고칠 줄을 알리고 멈춘다.
    """
    if not path.is_file():
        return []
    raw = path.read_bytes().decode("utf-8")
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise ControlError(f"설정 파일을 읽을 수 없습니다({path}): {error}") from None
    params = _mint_item(document)
    if params is None:
        return []
    current = params.get("mode")
    modes = [current] if isinstance(current, str) else list(current or [])
    missing = [m for m in GUARDRAIL_MODES if m not in modes]
    if not missing:
        return []
    wanted = [*modes, *missing]
    fail = ControlError(
        f"MINT 가드레일 mode를 자동으로 고칠 수 없습니다. {path}의 mode를 "
        f"[{', '.join(GUARDRAIL_MODES)}]로 직접 고친 뒤 다시 실행하십시오."
    )
    lines = raw.split("\n")
    class_at = [i for i, ln in enumerate(lines) if _CLASS_LINE.match(ln)]
    if len(class_at) != 1:
        raise fail
    indent = _CLASS_LINE.match(lines[class_at[0]])["indent"]
    candidates = [
        i for i, ln in enumerate(lines)
        if (m := _MODE_LINE.match(ln)) and m["head"].startswith(indent + "mode")
        and len(m["head"]) - len(m["head"].lstrip()) == len(indent)
    ]
    if not candidates:
        raise fail
    at = min(candidates, key=lambda i: abs(i - class_at[0]))
    match = _MODE_LINE.match(lines[at])
    lines[at] = f"{match['head']}[{', '.join(wanted)}]{match['tail']}"
    edited = "\n".join(lines)
    expected = yaml.safe_load(raw)
    _mint_item(expected)["mode"] = wanted
    try:
        unchanged_elsewhere = yaml.safe_load(edited) == expected
    except yaml.YAMLError:
        unchanged_elsewhere = False
    if not unchanged_elsewhere:
        raise fail
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    shutil.copy2(path, path.with_name(f"{path.name}.bak-{stamp}"))
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(edited)
    return missing


def _server_defaults(cfg: object) -> dict[str, Any]:
    """서버마다 채우는 기본값: 기본 한도, 그리고 LiteLLM이 토큰을 받는 OAuth 서버의 RFC 8707
    resource(서버 주소). resource를 거부하는 인가 서버는 값을 빈 문자열로 적어 끈다."""
    if not isinstance(cfg, dict):
        return {}
    wanted: dict[str, Any] = dict(SERVER_LIMITS)
    if (str(cfg.get("auth_type", "")).lower() == "oauth2"
            and cfg.get("delegate_auth_to_upstream") is not True and cfg.get("url")):
        wanted["upstream_resource"] = "auto"
    return wanted


def _add_server_limits(
    lines: list[str], document: dict[str, Any], path: Path
) -> list[tuple[str, str]]:
    """``mcp_servers``의 각 서버 머리 줄 아래에 없는 기본 한도를 끼운다. 더한 (서버, 키) 목록."""
    fail = ControlError(
        f"{path}의 mcp_servers를 자동으로 고칠 수 없습니다. 서버마다 "
        + ", ".join(f"{k}: {v}" for k, v in SERVER_LIMITS.items())
        + "(OAuth 서버는 upstream_resource: auto도)를 직접 더하십시오."
    )
    added: list[tuple[str, str]] = []
    for name, cfg in (document.get("mcp_servers") or {}).items():
        wanted = {k: v for k, v in _server_defaults(cfg).items() if k not in cfg}
        if not wanted:
            continue
        top = next(
            (i for i, ln in enumerate(lines) if re.match(r"^mcp_servers:\s*(?:#.*)?$", ln)), -1
        )
        if top < 0:
            raise fail
        head = None
        for i in range(top + 1, len(lines)):
            if lines[i].strip() and not lines[i].startswith((" ", "#")):
                break  # 다음 최상위 키
            if re.match(rf"^\s+{re.escape(str(name))}:\s*(?:#.*)?$", lines[i]):
                head = i
                break
        if head is None:
            raise fail
        outer = len(lines[head]) - len(lines[head].lstrip())
        rest = lines[head + 1:]
        body = next((ln for ln in rest if ln.strip() and not ln.lstrip().startswith("#")), "")
        inner = len(body) - len(body.lstrip())
        if inner <= outer:
            raise fail
        lines[head + 1:head + 1] = [f"{' ' * inner}{k}: {v}" for k, v in wanted.items()]
        added += [(str(name), k) for k in wanted]
    return added


def ensure_required_flags(path: Path) -> list[str]:
    """운영자 설정에 없는 필수 설정을 더한다. 더한 키를 돌려준다.

    ``REQUIRED_FLAGS``는 true로, 서버마다 없는 ``SERVER_LIMITS``는 기본 한도로 더한다. 이미 적힌
    키는 값이 달라도 건드리지 않는다(기동 전 검사가 막는다). 섹션 머리 줄 바로 아래에 줄을 끼우고,
    섹션이 없으면 파일 끝에 덧붙인다. 바꾸기 전에 ``<파일>.bak-<UTC 시각>`` 사본을 두며, 다시 읽은
    결과가 기대와 다르면 아무것도 쓰지 않고 멈춘다.
    """
    if not path.is_file():
        return []
    raw = path.read_bytes().decode("utf-8")
    try:
        document = yaml.safe_load(raw) or {}
    except yaml.YAMLError as error:
        raise ControlError(f"설정 파일을 읽을 수 없습니다({path}): {error}") from None
    missing = [
        (section, key) for section, key in REQUIRED_FLAGS
        if key not in (document.get(section) or {})
    ]
    lines = raw.split("\n")
    expected = yaml.safe_load(raw) or {}
    for section, key in missing:
        head = [i for i, ln in enumerate(lines) if re.match(rf"^{section}:\s*(?:#.*)?$", ln)]
        if head:
            body = lines[head[0] + 1:]
            nxt = next((ln for ln in body if ln.strip() and not ln.lstrip().startswith("#")), "")
            indent = nxt[: len(nxt) - len(nxt.lstrip())] or "  "
            lines.insert(head[0] + 1, f"{indent}{key}: true")
        elif section in document and document[section] is not None:
            raise ControlError(
                f"{path}의 {section}을(를) 자동으로 고칠 수 없습니다. "
                f"{key}: true를 직접 더하십시오."
            )
        else:
            tail = [] if not lines or lines[-1] == "" else [""]
            lines += [*tail, f"{section}:", f"  {key}: true", ""]
        expected.setdefault(section, {})
        expected[section] = {**(expected[section] or {}), key: True}
    limits = _add_server_limits(lines, document, path)
    for name, key in limits:
        expected["mcp_servers"][name][key] = _server_defaults(expected["mcp_servers"][name])[key]
    added = [key for _, key in missing] + [f"mcp_servers.{n}.{k}" for n, k in limits]
    if not added:
        return []
    edited = "\n".join(lines)
    try:
        ok = yaml.safe_load(edited) == expected
    except yaml.YAMLError:
        ok = False
    if not ok:
        raise ControlError(
            f"필수 설정을 자동으로 더할 수 없습니다. {path}에 다음을 직접 더하십시오: "
            + ", ".join(added)
        )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    shutil.copy2(path, path.with_name(f"{path.name}.bak-{stamp}"))
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(edited)
    return added
