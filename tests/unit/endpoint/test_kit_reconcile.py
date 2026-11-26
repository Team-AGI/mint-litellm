"""자체 갱신만 거친 관리형 PC도 하네스 파일의 MINT 명령이 새 설치와 같아진다."""

import json
import re

import pytest
from test_kit_gateway import gateway_folder
from test_kit_install import make_kit

from mint_litellm.endpoint.kit import mint_kit


def managed_files(kit):
    found = [
        kit.managed_dir / "managed-settings.json", kit.managed_dir / "managed-mcp.json",
        kit.codex_managed_dir / "requirements.toml", kit.codex_managed_dir / "managed_config.toml",
    ]  # fmt: skip
    return [p for p in found if p.exists()]


def strip_isolation(path):
    """격리 실행(-I)이 없던 옛 형태로 되돌린다."""
    text = path.read_text(encoding="utf-8")
    old = re.sub(r"\s*\"-I\",|\"-I\", | -I |'-I' ", lambda m: " " if m[0] == " -I " else "", text)
    assert old != text
    path.write_text(old, encoding="utf-8")


@pytest.mark.parametrize("windows", [False, True])
def test_old_form_becomes_the_fresh_install_form_once(tmp_path, reports, windows):
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=True, windows=windows)
    state = kit.install()
    paths = managed_files(kit)
    fresh = {p: p.read_bytes() for p in paths}
    for path in paths:
        strip_isolation(path)
    assert kit.reconcile_commands(state) is True
    for path in paths:
        assert path.read_bytes() == fresh[path]
        assert mint_kit.sha256_bytes(fresh[path]) in state["files"].values()
    assert kit.check(state)[0]["files"] == state["files"]
    assert kit.reconcile_commands(state) is False
    assert {p: p.read_bytes() for p in paths} == fresh


def test_admin_content_is_kept(tmp_path, reports):
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=True)
    state = kit.install()
    paths = managed_files(kit)
    fresh = {p: p.read_bytes() for p in paths}
    settings, mcp, requirements, config = paths
    for path in paths:
        strip_isolation(path)
    extra = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/corp/audit"}]}
    data = json.loads(settings.read_text())
    data["permissions"]["deny"] = ["Bash(rm:*)"]
    data["hooks"]["PreToolUse"].insert(0, extra)
    settings.write_text(json.dumps(data, indent=2))
    data = json.loads(mcp.read_text())
    data["mcpServers"]["corp"] = {"command": "/opt/corp/srv", "args": ["x"]}
    mcp.write_text(json.dumps(data, indent=2))
    corp = '\n[mcp_servers."corp"]\ncommand = "/opt/corp/srv"\nargs = ["x"]\n'
    for path in (requirements, config):
        path.write_text(path.read_text(encoding="utf-8") + corp, encoding="utf-8")
    assert kit.reconcile_commands(state) is True
    data = json.loads(settings.read_text())
    assert data["hooks"]["PreToolUse"][0] == extra
    assert data["permissions"]["deny"] == ["Bash(rm:*)"]
    data["hooks"]["PreToolUse"].pop(0)
    del data["permissions"]["deny"]
    assert json.dumps(data, indent=2).encode() == fresh[settings]
    data = json.loads(mcp.read_text())
    assert data["mcpServers"].pop("corp") == {"command": "/opt/corp/srv", "args": ["x"]}
    assert json.dumps(data, indent=2).encode() == fresh[mcp]
    for path in (requirements, config):
        assert path.read_text(encoding="utf-8") == fresh[path].decode() + corp
    assert kit.reconcile_commands(state) is False
