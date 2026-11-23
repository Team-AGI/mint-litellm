"""이미 설치된 PC도 보고 때 하네스 도구 확인 설정을 현재 판본으로 다시 맞춘다."""

import json
import tomllib

from test_kit_gateway import gateway_folder
from test_kit_install import make_kit


def old_install(tmp_path):
    """자동 허용이 없던 옛 판본 설치와 같은 파일 상태를 만든다."""
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=True)
    state = kit.install()
    root = tmp_path / "root"
    toml = root / "etc/codex/managed_config.toml"
    text = "".join(
        line for line in toml.read_text(encoding="utf-8").splitlines(keepends=True)
        if "default_tools_approval_mode" not in line
    )
    toml.write_text(
        text + '\n[mcp_servers."srv-1".tools.read]\napproval_mode = "prompt"\n', encoding="utf-8")
    settings = root / "etc/claude-code/managed-settings.json"
    data = json.loads(settings.read_text())
    data["permissions"]["allow"] = ["Bash(ls)"]
    settings.write_text(json.dumps(data))
    return kit, state, toml, settings


def test_report_time_refresh_restores_server_level_approval_and_is_idempotent(tmp_path, reports):
    kit, state, toml, settings = old_install(tmp_path)
    assert kit.refresh_approvals(state) is True
    parsed = tomllib.loads(toml.read_text(encoding="utf-8"))["mcp_servers"]
    for name in ("srv-1", "srv-2", "litellm_gateway"):
        assert parsed[name]["default_tools_approval_mode"] == "approve"
    assert parsed["srv-1"]["tools"]["read"]["approval_mode"] == "approve"
    allow = json.loads(settings.read_text())["permissions"]["allow"]
    assert allow[0] == "Bash(ls)" and "mcp__litellm_gateway__*" in allow
    once = toml.read_bytes()
    assert kit.refresh_approvals(state) is False and toml.read_bytes() == once


def test_user_config_keeps_other_settings(tmp_path):
    from mint_litellm.endpoint.kit import mint_kit as m

    text = (
        'model = "x"\n[mcp_servers.mine]\ncommand = "a"\n'
        '[mcp_servers.mine.tools.t]\napproval_mode = "prompt"\n'
        f'{m.BEGIN}\n[mcp_servers."srv-1"]\ncommand = "p"\n'
        '[mcp_servers."srv-1".tools.t]\napproval_mode = "prompt"\n'
        f'{m.END}\n'
    )
    new = m.approve_user_config(text, ["srv-1"])
    parsed = tomllib.loads(new)["mcp_servers"]
    assert parsed["mine"]["tools"]["t"]["approval_mode"] == "prompt"
    assert "default_tools_approval_mode" not in parsed["mine"]
    assert parsed["srv-1"]["default_tools_approval_mode"] == "approve"
    assert parsed["srv-1"]["tools"]["t"]["approval_mode"] == "approve"
    assert m.approve_user_config(new, ["srv-1"]) == new
