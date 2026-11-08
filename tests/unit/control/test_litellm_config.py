"""init이 만드는 설정 조각과 설정·환경 파일 읽기."""

import pytest
import yaml

from mint_litellm.control import litellm_config
from mint_litellm.control.errors import ControlError


def test_snippet_has_the_required_guardrail_callback_and_server_entries():
    data = yaml.safe_load(
        litellm_config.snippet({"docs": ("docs-id", "http://u.test/mcp")}, no_spend_logs=False)
    )
    guardrail = data["guardrails"][0]["litellm_params"]
    assert guardrail["mode"] == ["pre_call", "pre_mcp_call", "post_mcp_call"]
    assert guardrail["default_on"]
    assert "callbacks" not in data["litellm_settings"]  # 로거는 가드레일이 등록한다
    assert data["guardrails"][-1]["litellm_params"]["guardrail"].endswith(".MintGuardrail")
    assert data["general_settings"]["require_key_mcp_access_defined"] is True
    assert data["general_settings"]["store_prompts_in_spend_logs"] is False
    assert "disable_spend_logs" not in data["general_settings"]
    roles = data["litellm_settings"]["key_generation_settings"]["personal_key_generation"]
    assert roles["allowed_user_roles"] == ["proxy_admin"]
    assert data["mcp_servers"]["docs"] == {
        "server_id": "docs-id", "url": "http://u.test/mcp", "transport": "http",
        "allow_all_keys": False,
    }


def test_disable_spend_logs_only_with_the_option_and_servers_are_optional():
    on = yaml.safe_load(litellm_config.snippet({}, no_spend_logs=True))
    assert on["general_settings"]["disable_spend_logs"] is True
    assert "mcp_servers" not in on


def test_load_config_and_env_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("general_settings:\n  a: 1\n", encoding="utf-8")
    assert litellm_config.load_config(path) == {"general_settings": {"a": 1}}
    assert litellm_config.load_config(None) is None
    path.write_text("- list\n", encoding="utf-8")
    with pytest.raises(ControlError, match="매핑"):
        litellm_config.load_config(path)
    with pytest.raises(ControlError, match="읽을 수 없습니다"):
        litellm_config.load_config(tmp_path / "missing.yaml")
    env = tmp_path / ".env"
    env.write_text("# 주석\nA=1\nB = \"two\"\n\nbroken\n", encoding="utf-8")
    assert litellm_config.load_env_file(env) == {"A": "1", "B": "two"}


def test_the_loader_reads_with_utf8_only_while_it_runs(monkeypatch, tmp_path):
    import sys
    import types

    from mint_litellm.compat import litellm_config_loader as compat

    module = types.ModuleType("fake_loader_module")
    source = (
        "async def loader(config_file_path):\n"
        "    with open(config_file_path) as handle:\n"
        "        return {'text': handle.read()}\n"
    )
    exec(source, module.__dict__)  # 로더의 전역이 이 모듈이라 open은 모듈 속성을 먼저 본다
    monkeypatch.setitem(sys.modules, "fake_loader_module", module)
    config = tmp_path / "c.yaml"
    config.write_text("# 한국어 설명\n", encoding="utf-8")
    seen = []
    real = compat._utf8_open
    monkeypatch.setattr(
        compat, "_utf8_open", lambda *a, **k: (seen.append(k), real(*a, **k))[1]
    )
    assert compat._run_loader(module.loader, config) == {"text": "# 한국어 설명\n"}
    assert seen  # 로더의 open이 UTF-8 고정 함수로 바뀌어 호출되었다
    assert "open" not in vars(module)


def test_the_loader_patch_is_removed_when_the_loader_fails(monkeypatch, tmp_path):
    import sys
    import types

    import pytest

    from mint_litellm.compat import litellm_config_loader as compat

    module = types.ModuleType("failing_loader_module")
    exec("async def loader(config_file_path):\n    raise RuntimeError('boom')\n", module.__dict__)
    monkeypatch.setitem(sys.modules, "failing_loader_module", module)
    with pytest.raises(RuntimeError):
        compat._run_loader(module.loader, tmp_path / "c.yaml")
    assert "open" not in vars(module)
