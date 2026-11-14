"""관리형 단말의 게이트웨이 MCP 항목, 격리 사전 점검, `mint` 명령, Codex 훅 신뢰 표시."""

import json
import subprocess
import sys
import tomllib

import pytest
from kit_loader import load
from test_kit_install import CONTRACT, kit_module, make_kit, unpack

from mint_litellm.endpoint.decide import ReportBody

agent = load("mint_agent")
KEY = "sk-mcp-only"
URL = "https://mint.test/mcp"


def gateway_folder(tmp_path, **options):
    return unpack(tmp_path, harnesses=("claude", "codex"), gateway_key=KEY, **options)


def test_a_managed_install_puts_the_gateway_into_both_managed_lists_with_private_files(
    tmp_path, reports
):
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=True)
    state = kit.install()
    root = tmp_path / "root"
    claude = root / "etc/claude-code/managed-mcp.json"
    entry = json.loads(claude.read_text())["mcpServers"]["litellm_gateway"]
    assert entry == {"type": "http", "url": URL, "headers": {"Authorization": f"Bearer {KEY}"}}
    codex = root / "etc/codex"
    servers = tomllib.loads((codex / "managed_config.toml").read_text(encoding="utf-8"))
    assert servers["mcp_servers"]["litellm_gateway"] == {
        "url": URL, "http_headers": {"Authorization": f"Bearer {KEY}"},
    }
    requirements = tomllib.loads((codex / "requirements.toml").read_text(encoding="utf-8"))
    assert requirements["mcp_servers"]["litellm_gateway"] == {"identity": {"url": URL}}
    assert KEY not in (codex / "requirements.toml").read_text(encoding="utf-8")
    if sys.platform != "win32":  # 키가 든 파일은 소유자·그룹만 읽는다.
        assert claude.stat().st_mode & 0o777 == 0o640
        assert (codex / "managed_config.toml").stat().st_mode & 0o777 == 0o640
    # 게이트웨이는 승인 로컬 서버 목록이 아니다: 보고하는 서버 이름에 넣지 않는다(폐기로 오인).
    assert state["mcp_servers"] == ["srv-1", "srv-2"] and state["gateway"] == "litellm_gateway"
    listing = json.loads((root / "usr/local/lib/mint-endpoint/contracts.json").read_text())
    assert listing["gateways"] == ["litellm_gateway"]
    copied = json.loads((root / "usr/local/lib/mint-endpoint/kit.json").read_text())
    assert "gateway_key" not in copied and copied["gateway"]["url"] == URL
    kit.uninstall()
    assert not [f for f in root.rglob("*") if f.is_file()]  # 키가 든 파일을 포함해 남는 파일이 없다


def test_a_user_level_install_does_not_write_the_gateway_key(tmp_path, reports):
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=False)
    kit.install()
    written = [p for p in tmp_path.rglob("*") if p.is_file() and p.name != "mint-kit.tar.gz"]
    unpacked = tmp_path / "unpacked"
    for path in written:
        if unpacked in path.parents:
            continue
        assert KEY not in path.read_text(encoding="utf-8", errors="ignore")


def test_a_refresh_keeps_the_gateway_entry_and_the_gateway_list(tmp_path, reports):
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=True)
    state = kit.install()
    contract = {k: v for k, v in CONTRACT.items() if k != "identity_kind"}
    desired = [{"name": "srv-3", "contract": contract,
                "version": kit_module.contract_version(contract)}]  # fmt: skip
    assert kit.refresh(state, desired) == ["srv-3"]
    root = tmp_path / "root"
    listing = json.loads((root / "usr/local/lib/mint-endpoint/contracts.json").read_text())
    assert listing["gateways"] == ["litellm_gateway"] and "srv-3" in listing["servers"]
    mcp = json.loads((root / "etc/claude-code/managed-mcp.json").read_text())["mcpServers"]
    assert {"litellm_gateway", "srv-3"} <= set(mcp)
    codex = tomllib.loads((root / "etc/codex/managed_config.toml").read_text(encoding="utf-8"))
    assert {"litellm_gateway", "srv-3"} <= set(codex["mcp_servers"])


def test_an_approved_server_whose_tool_prefix_hides_behind_the_gateway_is_refused(
    tmp_path, reports
):
    folder = unpack(
        tmp_path, servers=("litellm_gateway__x",), harnesses=("claude",), gateway_key=KEY
    )
    kit = make_kit(folder, tmp_path, managed=True)
    with pytest.raises(SystemExit, match="게이트웨이 이름과 겹칩니다"):
        kit.install()


def test_the_windows_gateway_entry_lives_in_the_users_codex_config(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=("codex",), gateway_key=KEY)
    kit = make_kit(folder, tmp_path, managed=True, windows=True)
    kit.install()
    config = tmp_path / "home/.codex/config.toml"
    parsed = tomllib.loads(config.read_text(encoding="utf-8"))
    assert parsed["mcp_servers"]["litellm_gateway"]["url"] == URL


# --- 격리 사전 점검 ------------------------------------------------------------------------------


class Host:
    """bubblewrap·AppArmor가 있는 단말 대역."""

    def __init__(self, monkeypatch, *, probes, blocked, parser=True, which_bwrap=True):
        self.probes, self.calls = list(probes), []
        self.parsed = False
        monkeypatch.setattr(kit_module, "apparmor_blocks_userns", lambda: blocked)
        tools = {"bwrap": "/usr/bin/bwrap" if which_bwrap else None,
                 "apparmor_parser": "/usr/sbin/apparmor_parser" if parser else None}  # fmt: skip
        monkeypatch.setattr(kit_module.shutil, "which", lambda name: tools.get(name))
        monkeypatch.setattr(kit_module, "bwrap_probe", self.probe)
        monkeypatch.setattr(kit_module.os.path, "realpath", lambda path, **kw: path)
        monkeypatch.setattr(kit_module.subprocess, "run", self.run)

    def probe(self, bwrap):
        return self.probes.pop(0) if len(self.probes) > 1 else self.probes[0]

    def run(self, command, **kwargs):
        self.calls.append(command)
        self.parsed = True
        self.probes = [True]  # 프로필을 적용하면 격리가 동작한다.
        return subprocess.CompletedProcess(command, 0, b"", b"")


def strict_kit(tmp_path, **options):
    folder = unpack(tmp_path, harnesses=("claude",), **options)
    kit = make_kit(folder, tmp_path, managed=True, strict=True)
    (tmp_path / "root/etc/apparmor.d").mkdir(parents=True)
    return kit


def state_for(kit):
    return {"files": {}, "backups": {}}


def test_a_working_bwrap_needs_no_profile(tmp_path, monkeypatch):
    kit = strict_kit(tmp_path)
    host = Host(monkeypatch, probes=[True], blocked=True)
    state = state_for(kit)
    kit.ensure_sandbox_tool(state)
    assert host.calls == [] and "apparmor" not in state


def test_a_blocked_userns_gets_a_bwrap_profile_and_is_probed_again(tmp_path, monkeypatch):
    kit = strict_kit(tmp_path)
    host = Host(monkeypatch, probes=[False], blocked=True)
    state = state_for(kit)
    kit.ensure_sandbox_tool(state)
    path = tmp_path / "root/etc/apparmor.d/mint-bwrap"
    text = path.read_text()
    assert "/usr/bin/bwrap" in text and "userns," in text and "flags=(unconfined)" in text
    assert host.calls[0][:2] == ["/usr/sbin/apparmor_parser", "-r"]
    assert state["apparmor"] == "/etc/apparmor.d/mint-bwrap"
    assert state["files"]["/etc/apparmor.d/mint-bwrap"]  # 제거 때 지워지는 추적 파일이다.


def test_a_blocked_userns_that_cannot_be_fixed_stops_the_install_loudly(tmp_path, monkeypatch):
    (tmp_path / "b").mkdir()
    kit, other = strict_kit(tmp_path), strict_kit(tmp_path / "b")
    Host(monkeypatch, probes=[False], blocked=True, parser=False)
    with pytest.raises(SystemExit, match="AppArmor.*apparmor_restrict_unprivileged_userns"):
        kit.ensure_sandbox_tool(state_for(kit))
    Host(monkeypatch, probes=[False], blocked=False)
    with pytest.raises(SystemExit, match="bubblewrap이 서버를 격리하지 못합니다"):
        other.ensure_sandbox_tool(state_for(other))


def test_an_unsandboxed_allowance_warns_instead_of_stopping(tmp_path, monkeypatch, capsys):
    kit = strict_kit(tmp_path, allow_unsandboxed=True)
    Host(monkeypatch, probes=[False], blocked=True, parser=False)
    kit.ensure_sandbox_tool(state_for(kit))
    assert "경고" in capsys.readouterr().err


def test_a_missing_bwrap_that_cannot_be_installed_stops_the_install(tmp_path, monkeypatch):
    kit = strict_kit(tmp_path)
    Host(monkeypatch, probes=[False], blocked=False, which_bwrap=False)
    with pytest.raises(SystemExit, match="bubblewrap"):
        kit.ensure_sandbox_tool(state_for(kit))


def test_the_profile_names_the_real_bwrap_and_is_removed_with_the_install(tmp_path, monkeypatch):
    kit = strict_kit(tmp_path)
    Host(monkeypatch, probes=[False], blocked=True)
    state = {"files": {}, "backups": {}, "mode": "managed"}
    kit.ensure_sandbox_tool(state)
    kit.programs.mkdir(parents=True)
    kit.save_state(state)
    profile = tmp_path / "root/etc/apparmor.d/mint-bwrap"
    assert profile.exists() and state["apparmor"]
    kit.uninstall()
    assert not profile.exists()


# --- `mint` 명령 -------------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shim")
def test_the_shim_runs_the_installed_kit_and_defaults_to_status(tmp_path, reports):
    kit = make_kit(unpack(tmp_path), tmp_path, managed=True)
    kit.install()
    shim = tmp_path / "root/usr/local/bin/mint"
    text = shim.read_text()
    assert text.startswith("#!/bin/sh") and "set -- status" in text
    assert "-I -B /usr/local/lib/mint-endpoint/mint_kit.py" in text
    assert shim.stat().st_mode & 0o777 == 0o755
    kit.uninstall()
    assert not shim.exists()
    (tmp_path / "u").mkdir()
    user = make_kit(unpack(tmp_path / "u"), tmp_path / "u", managed=False)
    user.install()
    assert (tmp_path / "u/home/.local/bin/mint").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX accounts")
def test_status_without_privileges_reads_the_managed_install(tmp_path, reports, capsys):
    folder = unpack(tmp_path)
    make_kit(folder, tmp_path, managed=True).install()
    home = tmp_path / "other-home"
    home.mkdir()
    root = str(tmp_path / "root")
    assert kit_module.main(["status", "--kit", str(folder), "--home", str(home),
                            "--root", root]) == 0  # fmt: skip
    assert json.loads(capsys.readouterr().out)["mode"] == "managed"
    assert kit_module.main(["check", "--kit", str(folder), "--home", str(home),
                            "--root", root]) in (0, 1)  # fmt: skip
    assert json.loads(capsys.readouterr().out)["mode"] == "managed"
    empty = tmp_path / "x"
    empty.mkdir()
    assert kit_module.main(["status", "--kit", str(folder), "--home", str(home),
                            "--root", str(empty)]) == 0  # fmt: skip
    assert json.loads(capsys.readouterr().out) == {"mode": "none"}


# --- Codex 훅 신뢰 -----------------------------------------------------------------------------

USER_CONFIG = (
    f"{kit_module.BEGIN}\n[[hooks.PreToolUse]]\nmatcher = \"^mcp__\"\n{kit_module.END}\n"
)


def test_the_hook_trust_reading_follows_the_codex_trust_record():
    assert kit_module.codex_hook_trust('model = "x"\n') is None  # 묶음의 훅이 없다
    assert kit_module.codex_hook_trust(USER_CONFIG) == "untrusted"
    recorded = USER_CONFIG + '\n[hooks.state."k"]\ntrusted_hash = "sha256:ab"\n'
    assert kit_module.codex_hook_trust(recorded) == "trusted"


def test_a_user_level_codex_report_carries_the_trust_state_and_the_install_says_so(
    tmp_path, reports, capsys
):
    kit = make_kit(unpack(tmp_path, harnesses=("codex",)), tmp_path, managed=False)
    state = kit.install()
    assert kit.report(state, "installed")
    payload = reports[-1][2]
    ReportBody.model_validate(payload)
    assert payload["hook_trust"] == "untrusted"
    _, problems = kit.check(state)
    assert any("Codex" in problem for problem in problems)
    (tmp_path / "m").mkdir()
    managed = make_kit(unpack(tmp_path / "m", harnesses=("codex",)), tmp_path / "m", managed=True)
    managed_state = managed.install()
    assert managed.report(managed_state, "installed") and "hook_trust" not in reports[-1][2]


def test_the_agent_ignores_a_gateway_list_it_cannot_read(tmp_path):
    assert agent.gateway_servers(str(tmp_path / "missing.json")) == []
    broken = tmp_path / "c.json"
    broken.write_text('{"gateways": "x"}')
    assert agent.gateway_servers(str(broken)) == []


# --- Windows 관리형: 폐기 서버 프로세스·Codex 정의 동기화·AppContainer 정리 ---------------------


def windows_managed(tmp_path, monkeypatch, **options):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=("claude", "codex"), **options)
    return make_kit(folder, tmp_path, managed=True, windows=True)


def test_the_system_reporter_stops_a_retired_servers_launcher_by_its_command_line(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    kit.install()
    kit.system_mode = True
    agent_path = r"C:\Program Files\MintEndpoint\mint_agent.py"
    rows = [
        (10, 1, f'python "{agent_path}" run --contracts c.json --server gone'),
        (11, 1, f'python "{agent_path}" run --contracts c.json --server live'),
        (12, 1, r'python "D:\other\mint_agent.py" run --contracts c.json --server gone'),
    ]
    monkeypatch.setattr(kit_module, "process_entries", lambda windows: rows)
    killed = []
    monkeypatch.setattr(kit, "kill", lambda pid: killed.append(pid) or True)
    removed = kit.stop_by_command({"gone"})
    assert killed == [10] and removed == [{"kind": "process", "server": "gone", "target": None}]


def test_the_user_sync_aligns_the_codex_block_with_the_approved_and_retired_lists(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    state = kit.install()
    listing = json.loads((kit.programs / "contracts.json").read_text())
    listing["servers"]["srv-3"] = listing["servers"]["srv-1"]
    (kit.programs / "contracts.json").write_text(json.dumps(listing))
    (kit.programs / kit_module.RETIRED_FILE).write_text(json.dumps({"servers": ["srv-1"]}))
    _, problems = kit.check(state)
    assert any("install.cmd sync" in problem for problem in problems)
    done = kit.sync_codex_block(state)
    assert done == {"added": ["srv-3"], "dropped": ["srv-1"]}
    config = tomllib.loads(kit.codex_config().read_text(encoding="utf-8"))
    assert {"srv-2", "srv-3"} <= set(config["mcp_servers"]) and "srv-1" not in config["mcp_servers"]
    assert kit.sync_codex_block(state) == {"added": [], "dropped": []}


def test_the_agent_can_reconcile_without_starting_a_server(tmp_path):
    agent.main(["reconcile", "--contracts", "none", "--state-dir", str(tmp_path)])


def test_uninstall_unloads_the_profile_even_when_the_state_lost_its_name(tmp_path, monkeypatch):
    kit = strict_kit(tmp_path)
    calls = []
    monkeypatch.setattr(kit_module.shutil, "which", lambda name: "/usr/sbin/apparmor_parser")
    monkeypatch.setattr(kit_module.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    kit.root = None  # 실제 시스템에 설치한 경우
    state = {"files": {"/etc/apparmor.d/mint-bwrap": "x"}}  # 다시 설치해 `apparmor` 키가 없다.
    kit.unload_apparmor(state)
    assert [c[:2] for c in calls] == [["/usr/sbin/apparmor_parser", "-R"]]
    calls.clear()
    kit.unload_apparmor({"files": {}})
    assert calls == []
