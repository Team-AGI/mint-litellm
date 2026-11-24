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
    assert node["spec"]["index"] == "git" and node["spec"]["version"] == SHA


@pytest.mark.parametrize("changes", [
    {"commit": "main"}, {"commit": "a" * 40},  # 명령의 커밋과 다름
    {"command": "uvx other-package==1.0"}, {"command": ""},
    {"command": "uvx --from git+https://github.com/x/y@" + SHA + " c"},
    {"name": "-bad"}, {"purpose": ""},
])
def test_the_command_must_point_at_the_pinned_commit(changes):
    with pytest.raises(ControlError):
        local_intakes.build_payload(form(**changes))


def test_package_forms_are_recognised():
    ref = local_intakes.package_refs.package_ref
    assert ref("uvx ghidra-mcp==1.2") == ("pypi", "ghidra-mcp", "1.2", [])
    assert ref("ghidra-mcp") == ("any", "ghidra-mcp", None, [])
    assert ref("npx -y @o/server@2.0.1 --flag") == ("npm", "@o/server", "2.0.1", ["--flag"])
    assert ref("https://github.com/o/r") is None and ref("uvx --from git+https://x") is None
    assert local_intakes.is_local("https://github.com/o/r") and local_intakes.is_local("pkg")
    assert not local_intakes.is_local("https://mcp.example.com/mcp")


def test_a_pypi_name_without_version_is_pinned_to_the_latest_release():
    url = "https://pypi.org/pypi/ghidra-mcp/json"
    got = local_intakes.resolve("uvx ghidra-mcp", fake(
        {url: json.dumps({"info": {"name": "ghidra-mcp", "version": "1.4.0"}}).encode()}))
    assert got["command"] == "uvx ghidra-mcp==1.4.0" and got["commit"] == "1.4.0"
    assert got["kind"] == "pypi" and got["name"] == "ghidra_mcp"
    payload = local_intakes.build_payload(
        form(url=got["url"], name=got["name"], commit=got["commit"], command=got["command"]))
    assert payload["spec"] == {"index": "pypi", "name": "ghidra-mcp", "version": "1.4.0",
                               "extras": [], "command": "ghidra-mcp", "argv": []}


def test_a_pypi_pin_must_match_the_version_field():
    with pytest.raises(ControlError):
        local_intakes.build_payload(form(commit="1.0", command="uvx ghidra-mcp==2.0"))


INTEGRITY = "sha512-" + "A" * 86 + "=="
SCOPED = {"version": "2.0.1", "gitHead": SHA, "bin": {"srv": "x.js"},
          "dist": {"integrity": INTEGRITY},
          "repository": {"type": "git", "url": "git+https://github.com/o/srv.git"}}
REGISTRY = "https://registry.npmjs.org/@o/srv/"


def test_an_npm_name_is_pinned_to_its_version_and_integrity():
    got = local_intakes.resolve("npx -y @o/srv", fake(
        {REGISTRY + "latest": json.dumps(SCOPED).encode()}))
    assert got["kind"] == "npm" and got["commit"] == "2.0.1"
    assert got["command"] == "npx -y @o/srv@2.0.1" and got["url"] == got["command"]
    payload = local_intakes.build_payload(
        form(url=got["url"], name=got["name"], commit=got["commit"], command=got["command"]),
        fake({REGISTRY + "2.0.1": json.dumps(SCOPED).encode()}))
    assert payload["spec"] == {
        "index": "npm", "name": "@o/srv", "version": "2.0.1", "integrity": INTEGRITY,
        "extras": [], "command": "srv", "argv": [], "git": "https://github.com/o/srv",
        "commit": SHA}


def test_an_npm_release_without_a_known_source_is_still_pinned():
    doc = {"version": "1.0.0", "dist": {"integrity": INTEGRITY},
           "repository": {"url": "https://github.com/o/mono.git", "directory": "pkg"}}
    registry = {"https://registry.npmjs.org/pkg/1.0.0": json.dumps(doc).encode()}
    got = local_intakes.resolve("npx pkg@1.0.0 /data", fake(registry))
    assert got["command"] == "npx -y pkg@1.0.0 /data"
    spec = local_intakes.build_payload(
        form(url=got["url"], name=got["name"], commit="1.0.0", command=got["command"]),
        fake(registry))["spec"]
    assert spec["integrity"] == INTEGRITY and spec["argv"] == ["/data"]
    assert "git" not in spec and "commit" not in spec


def test_an_npm_release_without_integrity_is_not_accepted():
    doc = {"version": "1.0.0", "dist": {}}
    got = local_intakes.resolve("npx pkg@1.0.0", fake(
        {"https://registry.npmjs.org/pkg/1.0.0": json.dumps(doc).encode()}))
    assert got["command"] == "" and "무결성" in got["note"]


def test_an_npm_pin_must_match_the_version_field():
    with pytest.raises(ControlError):
        local_intakes.build_payload(
            form(url="npx -y @o/srv@2.0.1", commit="9.9.9", command="npx -y @o/srv@2.0.1"),
            fake({}))


def test_an_unknown_package_is_an_error():
    with pytest.raises(ControlError):
        local_intakes.resolve("uvx nope==1", fake({}))
