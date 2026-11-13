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
    assert data["general_settings"]["disable_env_credential_login"] is True
    assert "disable_spend_logs" not in data["general_settings"]
    roles = data["litellm_settings"]["key_generation_settings"]["personal_key_generation"]
    assert roles["allowed_user_roles"] == ["proxy_admin"]
    assert data["mcp_servers"]["docs"] == {
        "server_id": "docs-id", "url": "http://u.test/mcp", "transport": "http",
        "allow_all_keys": False, "rpm": 600, "max_concurrent_requests": 8,
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


OLD_CONFIG = """\
# 운영자 설정
guardrails:
  - guardrail_name: other
    litellm_params:
      guardrail: litellm_content_filter
      mode: [pre_call]
  - guardrail_name: mint
    litellm_params:
      guardrail: mint_litellm.plugin.guardrail.MintGuardrail
      mode: [pre_mcp_call, post_mcp_call]   # 옛 두 모드
      default_on: true
litellm_settings:
  telemetry: false
"""


def fix(tmp_path, text):
    path = tmp_path / "litellm.config.yaml"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path, litellm_config.ensure_guardrail_modes(path)


def test_an_old_two_mode_config_gets_the_missing_mode_with_a_copy_and_nothing_else_changes(
    tmp_path,
):
    path, added = fix(tmp_path, OLD_CONFIG)
    assert added == ["pre_call"]
    new = path.read_text(encoding="utf-8")
    assert yaml.safe_load(new)["guardrails"][1]["litellm_params"]["mode"] == [
        "pre_mcp_call", "post_mcp_call", "pre_call"]
    expected = yaml.safe_load(OLD_CONFIG)
    expected["guardrails"][1]["litellm_params"]["mode"] = [
        "pre_mcp_call", "post_mcp_call", "pre_call"]
    assert yaml.safe_load(new) == expected
    assert "# 운영자 설정" in new and "# 옛 두 모드" in new  # 주석 보존
    (backup,) = tmp_path.glob("litellm.config.yaml.bak-*")
    assert backup.read_text(encoding="utf-8") == OLD_CONFIG


def test_the_fix_is_idempotent_and_leaves_a_complete_config_untouched(tmp_path):
    path, added = fix(tmp_path, OLD_CONFIG)
    assert added == ["pre_call"]
    again = litellm_config.ensure_guardrail_modes(path)
    assert again == [] and len(list(tmp_path.glob("litellm.config.yaml.bak-*"))) == 1
    ok = tmp_path / "ok.yaml"
    ok.write_text(litellm_config.snippet({}, no_spend_logs=False), encoding="utf-8")
    before = ok.read_bytes()
    assert litellm_config.ensure_guardrail_modes(ok) == [] and ok.read_bytes() == before
    assert not list(tmp_path.glob("ok.yaml.bak-*"))


def test_a_scalar_mode_is_turned_into_a_list(tmp_path):
    text = OLD_CONFIG.replace("[pre_mcp_call, post_mcp_call]   # 옛 두 모드", "pre_mcp_call")
    path, added = fix(tmp_path, text)
    assert added == ["pre_call", "post_mcp_call"]
    modes = yaml.safe_load(path.read_text(encoding="utf-8"))["guardrails"][1]["litellm_params"]
    assert set(modes["mode"]) == set(litellm_config.GUARDRAIL_MODES)


def test_a_config_without_a_mint_guardrail_or_file_is_left_alone(tmp_path):
    path, added = fix(tmp_path, "litellm_settings:\n  telemetry: false\n")
    assert added == []
    assert litellm_config.ensure_guardrail_modes(tmp_path / "missing.yaml") == []


@pytest.mark.parametrize(
    "mode_lines",
    ["      mode:\n        - pre_mcp_call\n        - post_mcp_call\n", "      mode: *modes\n"],
    ids=["block-list", "alias"],
)
def test_a_shape_that_cannot_be_edited_safely_stops_with_the_line_to_fix(tmp_path, mode_lines):
    text = (
        "x-modes: &modes [pre_mcp_call, post_mcp_call]\nguardrails:\n  - guardrail_name: mint\n"
        "    litellm_params:\n      guardrail: mint_litellm.plugin.guardrail.MintGuardrail\n"
        + mode_lines + "      default_on: true\n"
    )
    path = tmp_path / "litellm.config.yaml"
    path.write_text(text, encoding="utf-8", newline="\n")
    with pytest.raises(ControlError) as raised:
        litellm_config.ensure_guardrail_modes(path)
    assert "pre_call, pre_mcp_call, post_mcp_call" in str(raised.value)
    assert path.read_text(encoding="utf-8") == text
    assert not list(tmp_path.glob("*.bak-*"))


FLAG = "disable_env_credential_login"


def test_a_missing_required_flag_is_added_under_its_section_with_a_copy(tmp_path):
    path = tmp_path / "litellm.config.yaml"
    text = "general_settings:\n    master_key: abc  # 주석\n\nlitellm_settings:\n  x: 1\n"
    path.write_text(text, encoding="utf-8", newline="")
    assert litellm_config.ensure_required_flags(path) == [FLAG]
    edited = path.read_text(encoding="utf-8")
    assert f"general_settings:\n    {FLAG}: true\n    master_key: abc  # 주석\n" in edited
    assert yaml.safe_load(edited)["litellm_settings"] == {"x": 1}
    (copy,) = tmp_path.glob("litellm.config.yaml.bak-*")
    assert copy.read_text(encoding="utf-8") == text
    assert litellm_config.ensure_required_flags(path) == []  # 두 번째는 아무것도 하지 않는다


def test_a_missing_section_is_appended_and_a_present_flag_is_never_touched(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("litellm_settings:\n  x: 1", encoding="utf-8", newline="")
    assert litellm_config.ensure_required_flags(path) == [FLAG]
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["general_settings"] == {FLAG: True}
    kept = tmp_path / "b.yaml"
    kept.write_text(f"general_settings:\n  {FLAG}: false\n", encoding="utf-8", newline="")
    assert litellm_config.ensure_required_flags(kept) == []
    assert not list(tmp_path.glob("b.yaml.bak-*"))
    assert litellm_config.ensure_required_flags(tmp_path / "missing.yaml") == []


def test_an_inline_section_cannot_be_edited_safely(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text("general_settings: {master_key: abc}\n", encoding="utf-8", newline="")
    with pytest.raises(ControlError, match=FLAG):
        litellm_config.ensure_required_flags(path)
    assert not list(tmp_path.glob("c.yaml.bak-*"))


def test_servers_without_limits_get_the_defaults_and_written_values_are_kept(tmp_path):
    path = tmp_path / "s.yaml"
    text = (
        "general_settings:\n  disable_env_credential_login: true\n"
        "mcp_servers:\n"
        "  docs:  # 문서 서버\n    server_id: docs\n    url: http://u.test/mcp\n"
        "  kept:\n    server_id: kept\n    rpm: 30\n    max_concurrent_requests: 2\n"
        "  half:\n    server_id: half\n    max_concurrent_requests: 3\n"
        "litellm_settings:\n  x: 1\n"
    )
    path.write_text(text, encoding="utf-8", newline="")
    assert litellm_config.ensure_required_flags(path) == [
        "mcp_servers.docs.rpm", "mcp_servers.docs.max_concurrent_requests", "mcp_servers.half.rpm",
    ]
    servers = yaml.safe_load(path.read_text(encoding="utf-8"))["mcp_servers"]
    assert servers["docs"]["rpm"] == 600 and servers["docs"]["max_concurrent_requests"] == 8
    assert servers["kept"] == {"server_id": "kept", "rpm": 30, "max_concurrent_requests": 2}
    assert servers["half"] == {"server_id": "half", "max_concurrent_requests": 3, "rpm": 600}
    (copy,) = tmp_path.glob("s.yaml.bak-*")
    assert copy.read_text(encoding="utf-8") == text
    assert litellm_config.ensure_required_flags(path) == []



def test_oauth_servers_that_hold_the_upstream_token_get_the_resource_default(tmp_path):
    path = tmp_path / "o.yaml"
    limits = "    rpm: 5\n    max_concurrent_requests: 1\n"
    path.write_text(
        "general_settings:\n  disable_env_credential_login: true\n"
        "mcp_servers:\n"
        f"  held:\n    url: http://u.test/a\n    auth_type: oauth2\n{limits}"
        "  optout:\n    url: http://u.test/b\n    auth_type: oauth2\n    upstream_resource: ''\n"
        f"{limits}"
        f"  forwarded:\n    url: http://u.test/c\n    auth_type: oauth_delegate\n{limits}",
        encoding="utf-8", newline="",
    )
    assert litellm_config.ensure_required_flags(path) == ["mcp_servers.held.upstream_resource"]
    servers = yaml.safe_load(path.read_text(encoding="utf-8"))["mcp_servers"]
    assert servers["held"]["upstream_resource"] == "auto"
    assert servers["optout"]["upstream_resource"] == ""
    assert "upstream_resource" not in servers["forwarded"]
