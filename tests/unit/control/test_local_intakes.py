"""저장소 주소로 로컬 MCP 신청: 주소 해석(네트워크는 바꿔 끼움)과 신청 명세."""

import json

import pytest

from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import local_intakes

SHA = "c" * 40
PYPROJECT = b'[project]\nname = "ghidra-mcp"\n[project.scripts]\nghidra-mcp = "g.main:run"\n'


def fake(files):
    def fetch(url):
        return files.get(url)
    return fetch


def api(extra=None):
    base = "https://api.github.com/repos/o/ghidra-mcp"
    return {base: json.dumps({"default_branch": "main"}).encode(),
            base + "/commits/main": json.dumps({"sha": SHA}).encode(), **(extra or {})}


RAW = f"https://raw.githubusercontent.com/o/ghidra-mcp/{SHA}/"


def test_a_python_repo_gets_a_pinned_uvx_command():
    got = local_intakes.resolve("https://github.com/o/ghidra-mcp.git",
                                fake(api({RAW + "pyproject.toml": PYPROJECT})))
    assert got["commit"] == SHA and got["name"] == "ghidra_mcp" and not got["note"]
    assert got["command"] == f"uvx --from git+https://github.com/o/ghidra-mcp@{SHA} ghidra-mcp"


def test_a_node_repo_gets_an_npx_command_and_a_note():
    got = local_intakes.resolve("https://github.com/o/ghidra-mcp",
                                fake(api({RAW + "package.json": b'{"bin": {"g": "x.js"}}'})))
    assert got["command"] == f"npx -y github:o/ghidra-mcp#{SHA}"
    assert "관리자가 확인" in got["note"]


@pytest.mark.parametrize("files", [{}, api()])
def test_unresolved_input_falls_back_to_manual_fields(files):
    got = local_intakes.resolve("https://github.com/o/ghidra-mcp", fake(files))
    assert got["command"] == "" and got["note"]
    assert got["commit"] == (SHA if files else "")


def test_a_network_failure_is_shown_and_does_not_block():
    def down(url):
        raise OSError("down")

    got = local_intakes.resolve("https://github.com/o/ghidra-mcp", down)
    assert got["commit"] == "" and "직접 입력" in got["note"]


def test_other_code_hosts_are_manual_only():
    got = local_intakes.resolve("https://gitlab.com/o/r", fake({}))
    assert got["commit"] == "" and "GitHub" in got["note"]


def test_a_non_repo_address_is_refused():
    with pytest.raises(ControlError):
        local_intakes.resolve("https://mcp.example.com/mcp")


def form(**changes):
    return {"url": "https://github.com/o/ghidra-mcp", "purpose": "분석", "commit": SHA,
            "command": f"uvx --from git+https://github.com/o/ghidra-mcp@{SHA} ghidra-mcp --x 1",
            **changes}


def test_the_payload_pins_the_commit_in_the_spec():
    payload = local_intakes.build_payload(form())
    assert payload["server_id"] == "ghidra_mcp"
    assert payload["spec"] == {
        "index": "git", "git": "https://github.com/o/ghidra-mcp", "name": "ghidra-mcp",
        "version": SHA, "extras": [], "command": "ghidra-mcp", "argv": ["--x", "1"]}
    node = local_intakes.build_payload(form(command=f"npx -y github:o/ghidra-mcp#{SHA}"))
    assert node["spec"]["index"] == "npm" and node["spec"]["version"] == SHA


@pytest.mark.parametrize("changes", [
    {"commit": "main"}, {"commit": "a" * 40},  # 명령의 커밋과 다름
    {"command": "uvx other-package==1.0"}, {"command": ""},
    {"command": "uvx --from git+https://github.com/x/y@" + SHA + " c"},
    {"name": "-bad"}, {"purpose": ""},
])
def test_the_command_must_point_at_the_pinned_commit(changes):
    with pytest.raises(ControlError):
        local_intakes.build_payload(form(**changes))
