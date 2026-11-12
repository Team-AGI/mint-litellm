"""설치기: 관리형·사용자 수준 설치, 재설치, 제거, 설치 상태 보고.

시스템 경로는 임시 폴더 아래로 옮긴다.
"""

import io
import json
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile

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


def unpack(tmp_path, servers=("srv-1", "srv-2"), **options):
    """내려받은 묶음을 푼 폴더."""
    data = build_kit(
        {name: CONTRACT for name in servers}, decide_url="https://mint.test", key="sk-user",
        **options,
    )  # fmt: skip
    if options.get("platform") == "windows":
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            bundle.extractall(tmp_path / "unpacked")
    else:
        archive = tmp_path / "mint-kit.tar.gz"
        archive.write_bytes(data)
        with tarfile.open(archive) as bundle:
            bundle.extractall(tmp_path / "unpacked", filter="data")
    return tmp_path / "unpacked" / "mint-kit"


@pytest.fixture
def folder(tmp_path):
    return unpack(tmp_path)


@pytest.fixture
def reports(monkeypatch):
    sent = []

    def post(url, key, payload, ca_file):
        sent.append((url, key, payload))
        return True

    monkeypatch.setattr(kit_module, "post", post)
    monkeypatch.setattr(kit_module, "claude_version", lambda home: None)
    monkeypatch.setattr(kit_module, "codex_version", lambda home: None)
    monkeypatch.setattr(kit_module, "find_claude", lambda home: None)
    return sent


def make_kit(folder, tmp_path, managed, **options):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    account = kit_module.Account("tester", home, 1000, 1000)
    options.setdefault("windows", False)  # 시험 배치는 실행하는 기기와 무관하다.
    return kit_module.Kit(folder, tmp_path / "root", managed, account, chown=False, **options)


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


# --- Codex ----------------------------------------------------------------------------------------


def codex_folder(tmp_path, **options):
    return unpack(tmp_path, harnesses=("codex",), **options)


def test_a_managed_codex_install_limits_servers_and_hooks_every_call(tmp_path, reports):
    kit = make_kit(codex_folder(tmp_path), tmp_path, managed=True, windows=False)
    state = kit.install()
    codex = tmp_path / "root/etc/codex"
    requirements = tomllib.loads((codex / "requirements.toml").read_text(encoding="utf-8"))
    assert requirements["allow_managed_hooks_only"] is True
    assert requirements["features"] == {"hooks": True}
    assert sorted(requirements["mcp_servers"]) == ["srv-1", "srv-2"]
    assert requirements["mcp_servers"]["srv-1"]["identity"]["command"]
    hooks = requirements["hooks"]
    assert hooks["managed_dir"] == "/usr/local/lib/mint-endpoint"
    assert set(hooks) == {"managed_dir", "PreToolUse", "PostToolUse"}
    before = hooks["PreToolUse"][0]
    assert before["matcher"] == "^mcp__" and before["hooks"][0]["timeout"] == 3
    line = before["hooks"][0]["command"]
    assert "/usr/local/lib/mint-endpoint/mint_agent.py pre --url https://mint.test" in line
    servers = tomllib.loads((codex / "managed_config.toml").read_text(encoding="utf-8"))
    assert servers["mcp_servers"]["srv-2"]["args"][1:] == [
        "run", "--contracts", "/usr/local/lib/mint-endpoint/contracts.json", "--server", "srv-2",
    ]  # fmt: skip
    assert not (tmp_path / "root/etc/claude-code").exists()  # 고르지 않은 도구는 건드리지 않는다.
    assert state["mcp_servers"] == ["srv-1", "srv-2"]
    kit.uninstall()
    assert not codex.exists()


def test_a_managed_codex_install_without_servers_still_writes_the_empty_table(tmp_path, reports):
    """표가 없으면 Codex는 서버를 제한하지 않는다. 비어 있는 표가 모두 끈다."""
    kit = make_kit(codex_folder(tmp_path, servers=()), tmp_path, managed=True, windows=False)
    kit.install()
    text = (tmp_path / "root/etc/codex/requirements.toml").read_text(encoding="utf-8")
    assert tomllib.loads(text)["mcp_servers"] == {}
    assert "\n[mcp_servers]\n" in text


def test_a_user_level_codex_install_edits_only_its_block_and_restores_the_file(tmp_path, reports):
    kit = make_kit(codex_folder(tmp_path), tmp_path, managed=False, windows=False)
    config = tmp_path / "home/.codex/config.toml"
    config.parent.mkdir(parents=True)
    original = 'model = "x"\n\n[features]\nother = true\n\n[mcp_servers.srv-2]\ncommand = "mine"\n'
    config.write_text(original, encoding="utf-8", newline="")
    state = kit.install()
    text = config.read_text(encoding="utf-8")
    assert text.startswith(original) and kit_module.BEGIN in text and kit_module.END in text
    parsed = tomllib.loads(text)
    assert parsed["mcp_servers"]["srv-1"]["command"]
    assert parsed["mcp_servers"]["srv-2"] == {"command": "mine"}  # 사용자가 정의한 이름은 그대로
    assert state["mcp_servers"] == ["srv-1"]
    assert parsed["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 3
    assert parsed["features"] == {"other": True}  # 사용자의 표에 끼어들지 않는다.
    kit.install()  # 다시 설치해도 구간은 하나이다.
    assert config.read_text(encoding="utf-8").count(kit_module.BEGIN) == 1
    kit.uninstall()
    assert config.read_text(encoding="utf-8") == original
    assert not (tmp_path / "root").exists()


def test_removing_a_user_level_codex_install_deletes_a_config_the_kit_created(tmp_path, reports):
    kit = make_kit(codex_folder(tmp_path), tmp_path, managed=False, windows=False)
    kit.install()
    config = tmp_path / "home/.codex/config.toml"
    assert tomllib.loads(config.read_text(encoding="utf-8"))["features"] == {"hooks": True}
    kit.uninstall()
    assert not config.exists()


def test_a_codex_config_changed_after_install_loses_only_our_block(tmp_path, reports):
    kit = make_kit(codex_folder(tmp_path), tmp_path, managed=False, windows=False)
    kit.install()
    config = tmp_path / "home/.codex/config.toml"
    config.write_text('model = "y"\n\n' + config.read_text(encoding="utf-8"), encoding="utf-8")
    kit.uninstall()
    assert config.read_text(encoding="utf-8") == 'model = "y"\n'


def test_both_tools_are_installed_and_reported_together(tmp_path, reports, monkeypatch):
    monkeypatch.setattr(kit_module, "claude_version", lambda home: "2.1.0 (Claude Code)")
    monkeypatch.setattr(kit_module, "codex_version", lambda home: "codex-cli 0.9.0")
    kit = make_kit(unpack(tmp_path, harnesses=("claude", "codex")), tmp_path, managed=True)
    state = kit.install()
    assert kit.report(state, "installed")
    assert (tmp_path / "root/etc/claude-code/managed-settings.json").exists()
    assert (tmp_path / "root/etc/codex/requirements.toml").exists()
    payload = reports[0][2]
    ReportBody.model_validate(payload)
    assert payload["claude_version"] == "2.1.0 (Claude Code) · codex-cli 0.9.0"


# --- Windows -------------------------------------------------------------------------------------


def test_a_managed_windows_install_uses_program_files_and_powershell_hooks(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=("claude", "codex"))
    assert sorted(p.name for p in folder.iterdir()) == [
        "install.cmd", "install.ps1", "kit.json", "mint_agent.py", "mint_kit.py",
    ]  # fmt: skip
    kit = make_kit(folder, tmp_path, managed=True, windows=True)
    state = kit.install()
    root = tmp_path / "root"
    settings = json.loads((root / "C/Program Files/ClaudeCode/managed-settings.json").read_text())
    before = settings["hooks"]["PreToolUse"][0]["hooks"][0]
    assert before["args"][0] == "C:/Program Files/MintEndpoint/mint_agent.py"
    assert before["onFailure"] == "block" and settings["allowManagedHooksOnly"] is True
    requirements = tomllib.loads(
        (root / "C/ProgramData/OpenAI/Codex/requirements.toml").read_text(encoding="utf-8")
    )
    assert requirements["hooks"]["windows_managed_dir"] == "C:/Program Files/MintEndpoint"
    command = requirements["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert command.startswith("& '") and "'pre' '--url' 'https://mint.test'" in command
    # Windows의 Codex는 관리자 서버 정의 파일이 없어 서버 정의가 사용자 설정 구간에 들어간다.
    block = tomllib.loads((tmp_path / "home/.codex/config.toml").read_text(encoding="utf-8"))
    assert sorted(block["mcp_servers"]) == ["srv-1", "srv-2"] and "hooks" not in block
    assert not (root / "C/ProgramData/OpenAI/Codex/managed_config.toml").exists()
    assert state["files"]["C:/Program Files/MintEndpoint/mint_agent.py"]
    kit.uninstall()
    assert not (tmp_path / "home/.codex/config.toml").exists()
    assert not (root / "C/Program Files/MintEndpoint").exists()
    assert not (root / "C/ProgramData/OpenAI").exists()


def test_a_user_level_windows_install_keeps_everything_in_the_profile(tmp_path, reports):
    kit = make_kit(unpack(tmp_path, platform="windows"), tmp_path, managed=False, windows=True)
    assert kit.install()["mode"] == "user"
    assert (tmp_path / "home/AppData/Local/MintEndpoint/mint_agent.py").exists()
    assert not (tmp_path / "root").exists()
    kit.uninstall()
    assert not (tmp_path / "home/.claude/settings.json").exists()


def test_a_dry_run_lists_the_files_and_changes_nothing(folder, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(kit_module, "post", lambda *a: pytest.fail("a dry run must not report"))
    home = tmp_path / "realhome"
    home.mkdir()
    assert kit_module.main(["--kit", str(folder), "--dry-run", "--home", str(home)]) == 0
    out = capsys.readouterr().out.replace("\\", "/")
    assert "mint_agent.py" in out and "managed-settings.json" in out
    assert "~/.config/mint/key" in out and "srv-1, srv-2" in out
    assert list(home.iterdir()) == []


def powershell():
    return shutil.which("pwsh") or shutil.which("powershell")


@pytest.mark.skipif(powershell() is None, reason="needs PowerShell")
def test_the_install_script_is_valid_powershell():
    script = (
        "[void][ScriptBlock]::Create((Get-Content -Raw -Encoding UTF8 -LiteralPath "
        f"'{KIT / 'install.ps1'}'))"
    )
    done = subprocess.run(
        [powershell(), "-NoProfile", "-Command", script], capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr
