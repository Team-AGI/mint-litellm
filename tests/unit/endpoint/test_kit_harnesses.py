"""Cursor·Grok Build CLI: 훅 파일·MCP 설정 설치와 제거, 훅 입력 변환."""

import json
import tomllib

import pytest
from kit_loader import load
from test_kit_install import kit_module, make_kit, unpack

agent = load("mint_agent")
KEY = "sk-mcp-only"
NEW = ("cursor", "grok")


def folder(tmp_path):
    return unpack(tmp_path, harnesses=NEW, gateway_key=KEY)


def test_a_managed_install_writes_a_fail_closed_cursor_hook_and_grok_files(tmp_path, reports):
    kit = make_kit(folder(tmp_path), tmp_path, managed=True)
    state = kit.install()
    root, home = tmp_path / "root", tmp_path / "home"
    hooks = json.loads((root / "etc/cursor/hooks.json").read_text())
    hook = hooks["hooks"]["beforeMCPExecution"][0]
    assert hooks["version"] == 1 and hook["failClosed"] is True and "cursor-pre" in hook["command"]
    mcp = json.loads((home / ".cursor/mcp.json").read_text())["mcpServers"]
    assert set(mcp) == {"srv-1", "srv-2", "litellm_gateway"}
    assert mcp["litellm_gateway"]["headers"] == {"Authorization": f"Bearer {KEY}"}
    grok = json.loads((home / ".grok/hooks/mint.json").read_text())
    assert "grok-pre" in grok["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    managed = tomllib.loads((root / "etc/grok/managed_config.toml").read_text(encoding="utf-8"))
    assert managed["mcp_servers"]["litellm_gateway"]["url"] == "https://mint.test/mcp"
    assert state["mcp_servers"] == ["srv-1", "srv-2"]
    assert kit.harness_problems(state) == []
    (root / "etc/cursor/hooks.json").write_text("{}")
    assert any("Cursor 훅 파일" in p for p in kit.check(state)[1])
    kept = kit.uninstall()["kept"]  # 바뀐 파일은 지우지 않는다
    left = [f for f in (tmp_path / "root").rglob("*") if f.is_file()]
    assert kept == ["/etc/cursor/hooks.json"] and len(left) == 1
    assert not (home / ".cursor/mcp.json").exists()
    assert not (home / ".grok/hooks/mint.json").exists()


def test_a_user_install_keeps_other_hooks_and_servers_and_restores_them(tmp_path, reports):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".grok").mkdir()
    mine = {"version": 1, "hooks": {"stop": [{"command": "./x.sh"}]}}
    (home / ".cursor/hooks.json").write_text(json.dumps(mine))
    (home / ".cursor/mcp.json").write_text(
        json.dumps({"mcpServers": {"own": {"url": "https://a"}}})
    )
    (home / ".grok/config.toml").write_text('[model."m"]\nbase_url = "https://x"\n')
    kit = make_kit(folder(tmp_path), tmp_path, managed=False)
    kit.install()
    hooks = json.loads((home / ".cursor/hooks.json").read_text())["hooks"]
    assert hooks["stop"] == [{"command": "./x.sh"}] and len(hooks["beforeMCPExecution"]) == 1
    assert "own" in json.loads((home / ".cursor/mcp.json").read_text())["mcpServers"]
    config = tomllib.loads((home / ".grok/config.toml").read_text())
    assert config["model"]["m"]["base_url"] == "https://x" and "srv-1" in config["mcp_servers"]
    kit.install()  # 재설치해도 훅은 하나
    again = json.loads((home / ".cursor/hooks.json").read_text())["hooks"]["beforeMCPExecution"]
    assert len(again) == 1
    kit.uninstall()
    assert json.loads((home / ".cursor/hooks.json").read_text()) == mine
    assert list(json.loads((home / ".cursor/mcp.json").read_text())["mcpServers"]) == ["own"]
    assert (home / ".grok/config.toml").read_text() == '[model."m"]\nbase_url = "https://x"\n'


def test_local_mcp_scan_reads_cursor_json_and_grok_toml(tmp_path):
    home = tmp_path
    (home / ".cursor").mkdir()
    (home / ".grok").mkdir()
    (home / ".cursor/mcp.json").write_text(
        json.dumps({"mcpServers": {"web": {"url": "https://u:p@docs.example.com/x?t=1"}}})
    )
    lines = ["[mcp_servers.git]", 'command = "uvx"', 'args = ["mcp-git"]']
    (home / ".grok/config.toml").write_text("\n".join(lines))
    found = {(i["harness"], i["name"], i["target"]) for i in kit_module.scan_local_mcp(home)}
    assert ("cursor", "web", "docs.example.com") in found and ("grok", "git", "uvx") in found


class Wire:
    def __init__(self, decision):
        self.decision = decision
        self.sent = []

    def __call__(self, url, headers, body, timeout):
        self.sent.append(json.loads(body))
        return 200, json.dumps({"decision": self.decision, "reference": "r1"}).encode()


def test_cursor_event_becomes_a_server_and_tool_decision(tmp_path):
    listing = tmp_path / "c.json"
    listing.write_text(json.dumps({"servers": {}}))
    cursor = {"mcp_server_name": "my-srv", "tool_name": "read", "tool_input": '{"a": 1}'}
    event = agent.adapt_event("cursor-pre", cursor)
    assert event["tool_name"] == "mcp__my_srv__read" and event["tool_input"] == {"a": 1}
    wire = Wire("deny")
    kwargs = {"url": "https://m", "key": "k", "contracts": str(listing), "state_dir": str(tmp_path),
              "post": wire}  # fmt: skip
    with pytest.raises(agent.Refuse):
        agent.decide(event, **kwargs)
    assert wire.sent == []  # 승인 목록에 없는 서버는 서버에 묻기 전에 막힌다
    listing.write_text(json.dumps({"servers": {}, "gateways": ["my-srv"]}))
    agent.decide(event, **kwargs)  # 게이트웨이 서버로 가는 호출은 게이트웨이 쪽 판정에 맡긴다
    with pytest.raises(agent.Refuse):
        agent.adapt_event("cursor-pre", {"tool_name": "x"})
    with pytest.raises(agent.Refuse):
        agent.adapt_event("cursor-pre", {**cursor, "tool_input": "{bad"})


def test_grok_non_mcp_tools_pass_and_mcp_names_are_judged(tmp_path):
    wire = Wire("deny")
    listing = tmp_path / "c.json"
    listing.write_text(json.dumps({"servers": {}}))
    kwargs = {"url": "https://m", "key": "k", "contracts": str(listing), "state_dir": str(tmp_path),
              "post": wire}  # fmt: skip
    agent.decide(agent.adapt_event("grok-pre", {"toolName": "Bash", "toolInput": {}}), **kwargs)
    assert wire.sent == []
    with pytest.raises(agent.Refuse):
        agent.decide(
            agent.adapt_event("grok-pre", {"toolName": "mcp__s__t", "toolInput": {"q": 1}}),
            **kwargs,
        )
