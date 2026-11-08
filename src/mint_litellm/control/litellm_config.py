"""LiteLLM ``config.yaml`` 조각의 생성과 설정 파일·환경 파일 읽기."""

from pathlib import Path
from typing import Any

import yaml

from mint_litellm.compat import litellm_config_loader
from mint_litellm.control.errors import ControlError

GUARDRAIL_CLASS = "mint_litellm.plugin.guardrail.MintGuardrail"
# 가드레일이 로거를 등록하므로 설정의 callbacks에는 적지 않는다. 적혀 있으면 거부한다.
LOGGER_SUFFIXES = (".MintLogger", ".mint_logger")
GUARDRAIL_MODES = ("pre_call", "pre_mcp_call", "post_mcp_call")

_HEADER = "# MINT 통제에 필요한 LiteLLM 설정 조각. 기존 config.yaml의 같은 키에 합친다.\n"


def snippet(servers: dict[str, tuple[str, str]], *, no_spend_logs: bool) -> str:
    """``servers``: 이름 -> (server_id, url)."""
    general: dict[str, Any] = {
        "require_key_mcp_access_defined": True,
        "mcp_allow_all_keys_respects_mcp_scope": True,
        "store_prompts_in_spend_logs": False,
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
            name: {"server_id": server_id, "url": url, "transport": "http", "allow_all_keys": False}
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
