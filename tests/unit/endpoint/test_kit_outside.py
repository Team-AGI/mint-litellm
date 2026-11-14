"""실행기 밖에서 직접 뜬 MCP 서버 패키지를 명령줄에서 알아보는 일과 보고 본문 모양."""

import pytest
from kit_loader import load

from mint_litellm.endpoint.decide import ReportBody

kit = load("mint_kit")

NODE = r'"C:\Program Files\nodejs\node.exe"'
RUN = "python3 /usr/local/lib/mint-endpoint/mint_agent.py run --contracts /c.json --server srv-1"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            "npx -y @modelcontextprotocol/server-filesystem /home/u",
            ("npm", "@modelcontextprotocol/server-filesystem"),
        ),
        ("npx --registry https://r.example -y mcp-remote@1.2.3 https://x", ("npm", "mcp-remote")),
        ("npx -p @Acme/mcp-x@latest run", ("npm", "@acme/mcp-x")),
        ("/usr/bin/env pnpm dlx mcp-foo --token s3cret", ("npm", "mcp-foo")),
        ("bunx mcp-bar", ("npm", "mcp-bar")),
        (r"cmd.exe /c npx -y mcp-foo", ("npm", "mcp-foo")),
        (r'cmd /c "npx.cmd -y @scope/mcp-baz"', ("npm", "@scope/mcp-baz")),
        (rf'{NODE} "C:\Users\u\AppData\npm\npx-cli.js" -y mcp-win', ("npm", "mcp-win")),
        ("uvx mcp-server-fetch", ("pypi", "mcp-server-fetch")),
        ("uvx --from mcp-server-git[x]==1.0 mcp-server-git", ("pypi", "mcp-server-git")),
        ("pipx run --spec mcp-pipx==2 mcp-pipx", ("pypi", "mcp-pipx")),
        ("uv tool run mcp-uv", ("pypi", "mcp-uv")),
        ("python3 -m mcp_server_x --a b", ("pypi", "mcp_server_x")),
        (r"C:\Python\python.exe -m mcp_server_y", ("pypi", "mcp_server_y")),
        (
            "docker run -i --rm -e K=v ghcr.io/acme/mcp-fetch:1.0 --x",
            ("container", "ghcr.io/acme/mcp-fetch"),
        ),
        ("podman run -i mcp/fetch@sha256:abc", ("container", "mcp/fetch")),
        ("bash -c 'uvx mcp-quoted'", ("pypi", "mcp-quoted")),
    ],
)
def test_a_direct_package_run_names_only_the_package(command, expected):
    assert kit.outside_package(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        "npx vite",
        "uvx ruff check",
        "python3 -m http.server",
        "docker run -i --rm alpine sh",
        "docker ps",
        "npx ./local/mcp-thing",
        "npx github:acme/mcp-x",
        "grep npx mcp.txt",
        RUN,
        "",
    ],
)
def test_other_commands_are_not_reported(command):
    assert kit.outside_package(command) is None


def test_arguments_and_secrets_never_reach_the_result():
    found = kit.outside_package("npx -y mcp-x --api-key sk-secret /home/someone/private")
    assert found == ("npm", "mcp-x")
    assert "sk-secret" not in repr(found) and "someone" not in repr(found)


def test_processes_under_the_launcher_are_inside_and_nested_matches_count_once(monkeypatch):
    entries = [
        (1, 0, RUN),
        (2, 1, "npx -y mcp-launched"),  # 실행기의 자식: 실행기 안
        (3, 2, "node /x/mcp-launched"),
        (10, 4, "cmd /c npx -y mcp-direct"),
        (11, 10, "node npx-cli.js -y mcp-direct"),  # 같은 패키지의 부모·자식은 하나
        (12, 4, "npx -y mcp-direct"),
        (13, 4, "uvx mcp-server-time"),
        (14, 4, "bash"),
    ]
    monkeypatch.setattr(kit, "process_entries", lambda windows: entries)
    assert kit.scan_outside(False) == [
        {"package": "mcp-direct", "ecosystem": "npm", "count": 2},
        {"package": "mcp-server-time", "ecosystem": "pypi", "count": 1},
    ]


def test_the_report_body_accepts_the_list_and_old_kits_omit_it():
    base = {"kit_version": "k", "action": "installed", "mode": "managed", "mcp_servers": []}
    assert ReportBody.model_validate(base).outside_processes is None
    parsed = ReportBody.model_validate(
        {**base, "outside_processes": [{"package": "@a/mcp-x", "ecosystem": "npm", "count": 1}]}
    )
    assert parsed.outside_processes[0].package == "@a/mcp-x"
    with pytest.raises(ValueError):
        ReportBody.model_validate(
            {
                **base,
                "outside_processes": [
                    {"package": "/home/u/x --k v", "ecosystem": "npm", "count": 1}
                ],
            }
        )
