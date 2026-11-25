"""루트에 실행 정의가 없는 저장소: 아래 폴더의 npm 패키지를 레지스트리 판본으로 고정한다."""

import importlib.util
import json
import sys
from pathlib import Path

from mint_litellm.control.services import local_intakes

SHA = "a" * 40
API = "https://api.github.com/repos/o/r"
RAW = f"https://raw.githubusercontent.com/o/r/{SHA}/"
INTEGRITY = "sha512-" + "A" * 86 + "=="


def fake(repo_url="git+https://github.com/o/r.git"):
    pages = {
        API: {"default_branch": "main"},
        f"{API}/commits/main": {"sha": SHA},
        f"{API}/git/trees/{SHA}?recursive=1": {"tree": [
            {"type": "blob", "path": "README.md"},
            {"type": "blob", "path": "packages/cli/package.json"},
            {"type": "blob", "path": "packages/mcp/package.json"},
        ]},
        RAW + "packages/cli/package.json": {"name": "o-cli", "bin": {"o": "x.js"}},
        RAW + "packages/mcp/package.json": {"name": "@o/r-mcp", "bin": {"r": "x.js"}},
        "https://registry.npmjs.org/@o/r-mcp": {"repository": {"url": repo_url}},
        "https://registry.npmjs.org/o-cli": {"repository": {"url": repo_url}},
        "https://registry.npmjs.org/@o/r-mcp/latest": {
            "name": "@o/r-mcp", "version": "1.2.0", "bin": {"r": "x.js"},
            "dist": {"integrity": INTEGRITY}},
    }

    def fetch(url):
        return json.dumps(pages[url]).encode() if url in pages else None

    return fetch


def test_the_server_pins_the_mcp_package_from_a_subfolder():
    found = local_intakes.resolve("https://github.com/o/r", fetch=fake())
    assert found["command"] == "npx -y @o/r-mcp@1.2.0" and found["kind"] == "npm"
    assert "packages/mcp/package.json" in found["note"]


def test_a_package_published_from_another_repository_is_not_used():
    found = local_intakes.resolve("https://github.com/o/r",
                                  fetch=fake("git+https://github.com/someone/else.git"))
    assert found["command"] == "" and "실행 명령" in found["note"]


def test_the_kit_turns_the_repository_into_the_npm_command():
    path = Path(__file__).resolve().parents[3] / "src/mint_litellm/endpoint/kit/mint_kit.py"
    spec = importlib.util.spec_from_file_location("mint_kit_subpkg", path)
    kit = importlib.util.module_from_spec(spec)
    sys.modules["mint_kit_subpkg"] = kit
    spec.loader.exec_module(kit)
    plain = fake()

    def fetch(url):
        body = plain(url)
        if body is None:
            raise kit.urllib.error.HTTPError(url, 404, "no", {}, None)
        return body

    assert kit.repo_command("https://github.com/o/r", fetch=fetch) == ["npx", "-y", "@o/r-mcp"]
