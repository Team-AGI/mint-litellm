"""설치기: 관리형·사용자 수준 설치, 재설치, 제거, 설치 상태 보고.

시스템 경로는 임시 폴더 아래로 옮긴다.
"""

import json
import shutil
import subprocess
import sys
import tarfile

import pytest
from kit_loader import KIT, load

from mint_litellm.endpoint.decide import ReportBody
from mint_litellm.endpoint.kit_build import build_kit, kit_version
from mint_litellm.endpoint.routes import REPORT_PATH

kit_module = load("mint_kit")
agent = load("mint_agent")

CONTRACT = {
    "schema_version": 1, "identity_kind": "stdio", "executable": "/usr/bin/node",
    "argv": ["/opt/srv/index.js"], "cwd": None, "executable_sha256": "ab" * 32,
    "script_sha256": None, "env": {}, "secret_refs": {},
}  # fmt: skip


@pytest.fixture
def folder(tmp_path):
    """내려받은 묶음을 푼 폴더."""
    data = build_kit(
        {"srv-1": CONTRACT, "srv-2": CONTRACT}, decide_url="https://mint.test", key="sk-user"
    )
    archive = tmp_path / "mint-kit.tar.gz"
    archive.write_bytes(data)
    with tarfile.open(archive) as bundle:
        bundle.extractall(tmp_path / "unpacked", filter="data")
    return tmp_path / "unpacked" / "mint-kit"


@pytest.fixture
def reports(monkeypatch):
    sent = []

    def post(url, key, payload, ca_file):
        sent.append((url, key, payload))
        return True

    monkeypatch.setattr(kit_module, "post", post)
    monkeypatch.setattr(kit_module, "claude_version", lambda home: None)
    monkeypatch.setattr(kit_module, "find_claude", lambda home: None)
    return sent


def make_kit(folder, tmp_path, managed):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    account = kit_module.Account("tester", home, 1000, 1000)
    return kit_module.Kit(folder, tmp_path / "root", managed, account, chown=False)


def managed_files(tmp_path):
    base = tmp_path / "root"
    return base / "etc/claude-code", base / "usr/local/lib/mint-endpoint"


def test_a_managed_install_writes_settings_hooks_launchers_and_the_key(folder, tmp_path, reports):
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    etc, programs = managed_files(tmp_path)
    settings = json.loads((etc / "managed-settings.json").read_text())
    assert settings["allowManagedHooksOnly"] is True
    assert set(settings["hooks"]) == {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
    before = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    assert before["onFailure"] == "block" and before["timeout"] == 3
    assert "onFailure" not in settings["hooks"]["PostToolUse"][0]["hooks"][0]
    # 시간 상한은 HTTP 대기 < 훅 내부 상한 < 하네스 시간 제한 순서이다.
    assert agent.HTTP_TIMEOUT < agent.HOOK_DEADLINE < before["timeout"]
    args = before["args"]
    assert args[:2] == ["/usr/local/lib/mint-endpoint/mint_agent.py", "pre"]
    assert args[args.index("--key-file") + 1] == "~/.config/mint/key"
    assert args[args.index("--contracts") + 1] == "/usr/local/lib/mint-endpoint/contracts.json"
    mcp = json.loads((etc / "managed-mcp.json").read_text())["mcpServers"]
    assert sorted(mcp) == ["srv-1", "srv-2"]
    assert mcp["srv-1"]["args"] == [
        "/usr/local/lib/mint-endpoint/mint_agent.py", "run", "--contracts",
        "/usr/local/lib/mint-endpoint/contracts.json", "--server", "srv-1",
    ]  # fmt: skip
    listed = json.loads((programs / "contracts.json").read_text())["servers"]
    assert listed["srv-1"]["executable"] == "/usr/bin/node"
    assert "identity_kind" not in listed["srv-1"]
    assert (programs / "mint_agent.py").read_bytes() == (KIT / "mint_agent.py").read_bytes()
    assert (tmp_path / "home/.config/mint/key").read_text() == "sk-user\n"
    assert state["mode"] == "managed" and state["mcp_servers"] == ["srv-1", "srv-2"]


def test_the_reports_fit_what_the_server_accepts(folder, tmp_path, reports):
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    assert kit.report(state, "installed") is True
    kit.uninstall()
    assert kit.report({"mode": "managed"}, "removed") is True
    (url, key, installed), (_, _, removed) = reports
    assert url == "https://mint.test" + REPORT_PATH and key == "sk-user"
    assert installed["mode"] == "managed" and installed["mcp_servers"] == ["srv-1", "srv-2"]
    assert removed["mode"] == "none" and removed["mcp_servers"] == []
    for payload in (installed, removed):
        ReportBody.model_validate(payload)
    assert installed["kit_version"] == kit_version()


def test_an_install_without_privileges_stays_in_the_user_account_and_says_so(
    folder, tmp_path, reports
):
    kit = make_kit(folder, tmp_path, managed=False)
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    original = json.dumps({"theme": "dark", "hooks": {"PreToolUse": [{"matcher": "Bash"}]}})
    (home / ".claude/settings.json").write_text(original)
    state = kit.install()
    assert state["mode"] == "user"
    kit.report(state, "installed")
    assert reports[0][2]["mode"] == "user"
    settings = json.loads((home / ".claude/settings.json").read_text())
    assert settings["theme"] == "dark"
    assert settings["hooks"]["PreToolUse"][0] == {"matcher": "Bash"}
    assert {e: len(m) for e, m in settings["hooks"].items()} == {
        "PreToolUse": 2, "PostToolUse": 1, "PostToolUseFailure": 1,
    }  # fmt: skip
    assert not (tmp_path / "root").exists()  # 시스템 경로는 건드리지 않는다.
    kit.install()  # 다시 설치해도 훅이 겹치지 않는다.
    again = json.loads((home / ".claude/settings.json").read_text())
    assert len(again["hooks"]["PreToolUse"]) == 2
    kit.uninstall()
    assert (home / ".claude/settings.json").read_text() == original  # 글자까지 되돌아온다.
    assert not (home / ".config/mint/key").exists()


def test_removing_a_user_install_deletes_a_settings_file_the_kit_created(folder, tmp_path, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    kit.install()
    assert (tmp_path / "home/.claude/settings.json").exists()
    kit.uninstall()
    assert not (tmp_path / "home/.claude/settings.json").exists()
    assert not (tmp_path / "home/.local/lib/mint-endpoint").exists()


def test_removal_leaves_no_managed_file_but_keeps_a_file_changed_since_install(
    folder, tmp_path, reports
):
    kit = make_kit(folder, tmp_path, managed=True)
    kit.install()
    etc, programs = managed_files(tmp_path)
    (etc / "managed-mcp.json").write_text("{}")  # 설치 뒤 누군가 바꾼 파일
    result = kit.uninstall()
    assert result["kept"] == ["/etc/claude-code/managed-mcp.json"]
    assert not (etc / "managed-settings.json").exists() and not programs.exists()
    assert kit.uninstall() == {"mode": "none"}  # 다시 제거해도 오류가 아니다.


def test_a_reinstall_replaces_the_files_and_the_key_of_the_previous_install(
    folder, tmp_path, reports
):
    kit = make_kit(folder, tmp_path, managed=True)
    kit.install()
    kit.config["key"] = "sk-newer"
    kit.install()
    assert (tmp_path / "home/.config/mint/key").read_text() == "sk-newer\n"
    etc, _ = managed_files(tmp_path)
    assert len(json.loads((etc / "managed-settings.json").read_text())["hooks"]) == 3


@pytest.mark.skipif(shutil.which("bash") is None or sys.platform == "win32", reason="needs bash")
def test_the_install_script_is_valid_shell():
    assert subprocess.run(["bash", "-n", str(KIT / "install.sh")]).returncode == 0


def test_the_root_option_keeps_paths_in_files_logical(folder, tmp_path, reports):
    kit = make_kit(folder, tmp_path, managed=True)
    kit.install()
    state = json.loads((managed_files(tmp_path)[1] / "state.json").read_text())
    assert "/usr/local/lib/mint-endpoint/mint_agent.py" in state["files"]
