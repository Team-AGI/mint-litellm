"""단말 설정의 관리 대상이 아닌 MCP 항목: 실행 파일 이름·호스트만 남기고 비밀은 읽지 않는다."""

import json

import pytest
from kit_loader import load

from mint_litellm.endpoint.decide import LocalMcpItem, ReportBody

kit = load("mint_kit")

SECRETS = ("sk-live-123", "hunter2", "ghp_abcdef", "tok-987", "pa55word", "/private/path")


def claude_config():
    return {
        "mcpServers": {
            "files": {"command": "npx", "args": ["-y", "@scope/server-files@1.2.0", "--token",
                                                 "ghp_abcdef"],
                      "env": {"API_KEY": "sk-live-123"}},
            "docs": {"type": "http", "url": "https://user:hunter2@Docs.Example.com:8443/private/path"
                                            "?token=tok-987",
                     "headers": {"Authorization": "Bearer pa55word"}},
            "events": {"type": "sse", "url": "https://events.example.com/sse"},
            "winnode": {"command": "C:\\Program Files\\nodejs\\node.EXE", "args": ["srv.js"]},
            "weird": {"command": "/opt/my tool/run it", "args": []},
            "bare": {"type": "http", "url": "not a url"},
            "nothing": {"args": ["x"]},
            "managed-like": {"command": "/usr/bin/python3",
                             "args": ["/usr/local/lib/mint-endpoint/mint_agent.py", "run",
                                      "--server", "srv-1"]},
        },
        "projects": {
            "/work/a": {"mcpServers": {
                "files": {"command": "npx", "args": ["-y", "@scope/server-files@1.2.0"]},
                "local": {"command": "uvx", "args": ["mcp-server-git"]}}},
            "/work/b": "broken",
        },
    }


@pytest.fixture
def home(tmp_path):
    return tmp_path


def test_claude_entries_keep_only_the_name_the_kind_and_the_program_or_host(home):
    (home / ".claude.json").write_text(json.dumps(claude_config()))
    found = {(i["name"], i["kind"], i["target"], i["package"]) for i in kit.scan_local_mcp(home)}
    assert found == {
        ("files", "stdio", "npx", "@scope/server-files@1.2.0"),
        ("docs", "http", "docs.example.com", None),
        ("events", "sse", "events.example.com", None),
        ("winnode", "stdio", "node", None),
        ("weird", "stdio", "unknown", None),
        ("bare", "http", "unknown", None),
        ("local", "stdio", "uvx", "mcp-server-git"),
    }


def test_nothing_secret_survives_into_the_report_body(home):
    (home / ".claude.json").write_text(json.dumps(claude_config()))
    items = kit.scan_local_mcp(home)
    text = json.dumps(items)
    for secret in SECRETS:
        assert secret not in text
    for entry in items:
        LocalMcpItem.model_validate(entry)  # 서버가 받는 모양과 같다.
    body = {"kit_version": "k", "action": "installed", "mode": "managed", "local_mcp": items}
    assert ReportBody.model_validate(body).local_mcp is not None


def test_entries_that_start_through_the_kit_launcher_are_not_reported(home):
    (home / ".claude.json").write_text(json.dumps(claude_config()))
    assert "managed-like" not in {i["name"] for i in kit.scan_local_mcp(home)}


def test_codex_tables_are_read_but_the_kit_block_is_not(home):
    (home / ".codex").mkdir()
    (home / ".codex/config.toml").write_text(
        '[mcp_servers.own]\ncommand = "/usr/bin/node"\nargs = ["a.js", "--key", "sk-live-123"]\n'
        '[mcp_servers.own.env]\nTOKEN = "tok-987"\n\n'
        '[mcp_servers.remote]\nurl = "https://api.example.com/mcp"\n'
        'bearer_token_env_var = "TOKEN"\n\n'
        f'{kit.BEGIN}\n[mcp_servers."srv-1"]\ncommand = "/usr/bin/python3"\n'
        'args = ["/p/mint_agent.py", "run", "--server", "srv-1"]\n'
        f'{kit.END}\n',
        encoding="utf-8",
    )
    items = kit.scan_local_mcp(home)
    assert {(i["harness"], i["name"], i["kind"], i["target"]) for i in items} == {
        ("codex", "own", "stdio", "node"), ("codex", "remote", "http", "api.example.com")}
    assert "sk-live-123" not in json.dumps(items) and "tok-987" not in json.dumps(items)


@pytest.mark.parametrize("content", ["{not json", "[]", '{"mcpServers": []}', ""])
def test_a_broken_config_is_skipped_without_failing_the_report(home, content):
    (home / ".claude.json").write_text(content)
    assert kit.scan_local_mcp(home) == []


def test_an_oversized_config_is_not_read(home, monkeypatch):
    (home / ".claude.json").write_text(json.dumps(claude_config()))
    monkeypatch.setattr(kit, "MAX_CONFIG", 10)
    assert kit.scan_local_mcp(home) == []


def test_the_list_is_capped_to_what_the_server_accepts(home):
    servers = {f"s{i:03}": {"command": "node"} for i in range(100)}
    (home / ".claude.json").write_text(json.dumps({"mcpServers": servers}))
    assert len(kit.scan_local_mcp(home)) == kit.MAX_ITEMS == 64


def test_the_system_account_does_not_read_the_profile(tmp_path, monkeypatch, reports):
    (tmp_path / ".claude.json").write_text(json.dumps(claude_config()))
    folder = tmp_path / "f"
    folder.mkdir()
    (folder / "kit.json").write_text(json.dumps(
        {"kit_version": "k", "decide_url": "https://mint.test", "harnesses": ["claude"]}))
    account = kit.Account("tester", tmp_path, 0, 0)
    local = kit.Kit(folder, None, True, account, False, windows=False)
    assert {i["name"] for i in local.read_inventory()["local_mcp"]} >= {"files", "docs"}
    local.system_mode = True
    assert "local_mcp" not in local.read_inventory()
