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
    local = servers["mcp_servers"]["srv-1"]
    assert local["startup_timeout_sec"] == 120
    assert local["tool_timeout_sec"] == 330
    assert local["default_tools_approval_mode"] == "approve"
    assert servers["mcp_servers"]["litellm_gateway"] == {
        "url": URL, "http_headers": {"Authorization": f"Bearer {KEY}"},
        "default_tools_approval_mode": "approve",
        "tool_timeout_sec": 330,  # 승인 보류(최대 300초)보다 길게: 하네스가 먼저 끊지 않는다
    }
    settings = json.loads((root / "etc/claude-code/managed-settings.json").read_text())
    assert settings["env"] == {"MCP_TOOL_TIMEOUT": "330000", "MCP_TIMEOUT": "120000"}
    assert settings["permissions"]["allow"] == [
        "mcp__litellm_gateway__*", "mcp__srv-1__*", "mcp__srv-2__*"
    ]
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


def test_a_user_level_install_puts_the_gateway_into_the_users_own_settings(
    tmp_path, reports, monkeypatch
):
    calls = []
    monkeypatch.setattr(kit_module.Kit, "claude", lambda self: "/bin/claude")
    real = subprocess.run
    monkeypatch.setattr(
        kit_module.subprocess, "run",
        lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, b"", b"")
        if cmd[0] == "/bin/claude" else real(cmd, **kw),
    )  # fmt: skip
    kit = make_kit(gateway_folder(tmp_path), tmp_path, managed=False)
    state = kit.install()
    added = [c for c in calls if c[1:5] == ["mcp", "add-json", "-s", "user"]]
    gateway = json.loads(next(c[6] for c in added if c[5] == "litellm_gateway"))
    assert gateway == {"type": "http", "url": URL, "headers": {"Authorization": f"Bearer {KEY}"}}
    parsed = tomllib.loads((tmp_path / "home/.codex/config.toml").read_text(encoding="utf-8"))
    assert parsed["mcp_servers"]["litellm_gateway"]["url"] == URL
    assert parsed["mcp_servers"]["litellm_gateway"]["default_tools_approval_mode"] == "approve"
    user = json.loads((tmp_path / "home/.claude/settings.json").read_text())
    assert "mcp__litellm_gateway__*" in user["permissions"]["allow"]
    # 승인 서버 목록(보고)에는 넣지 않고 따로 추적해 제거 때 지운다.
    assert "litellm_gateway" not in state["mcp_servers"]
    assert state["user_gateway"] == "litellm_gateway" and state["gateway"] == "litellm_gateway"
    calls.clear()
    kit.uninstall()
    assert ["/bin/claude", "mcp", "remove", "-s", "user", "litellm_gateway"] in calls
    config = tmp_path / "home/.codex/config.toml"
    assert not config.exists() or "litellm_gateway" not in config.read_text(encoding="utf-8")


def test_a_kit_without_any_approved_local_server_still_installs_the_gateway(tmp_path, reports):
    folder = unpack(tmp_path, servers=(), harnesses=("claude", "codex"), gateway_key=KEY)
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    mcp = json.loads((tmp_path / "root/etc/claude-code/managed-mcp.json").read_text())
    assert list(mcp["mcpServers"]) == ["litellm_gateway"] and state["mcp_servers"] == []


def test_the_dry_run_lists_the_apparmor_profile_the_real_install_would_write(
    tmp_path, monkeypatch
):
    kit = make_kit(unpack(tmp_path, harnesses=("claude",)), tmp_path, managed=True, dry_run=True)
    host = Host(monkeypatch, probes=[False], blocked=True)
    state = state_for(kit)
    kit.ensure_sandbox_tool(state)
    assert "/etc/apparmor.d/mint-bwrap" in state["files"]
    assert host.calls == []  # 적용(apparmor_parser)은 하지 않는다.


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
    assert kit_module.main(["status", "--json", "--kit", str(folder), "--home", str(home),
                            "--root", root]) == 0  # fmt: skip
    assert json.loads(capsys.readouterr().out)["mode"] == "managed"
    assert kit_module.main(["status", "--kit", str(folder), "--home", str(home),
                            "--root", root]) == 0  # fmt: skip
    summary = capsys.readouterr().out
    assert "관리형" in summary and "다음 할 일" in summary and "sha" not in summary
    assert kit_module.main(["check", "--json", "--kit", str(folder), "--home", str(home),
                            "--root", root]) in (0, 1)  # fmt: skip
    assert json.loads(capsys.readouterr().out)["mode"] == "managed"
    empty = tmp_path / "x"
    empty.mkdir()
    assert kit_module.main(["status", "--json", "--kit", str(folder), "--home", str(home),
                            "--root", str(empty)]) == kit_module.EXIT_LINK  # fmt: skip
    seen = capsys.readouterr()
    assert seen.out == "" and json.loads(seen.err)["error"]["code"] == "not_installed"


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


def test_a_windows_managed_install_registers_the_user_sync_and_the_firewall_tasks(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    kit.root = None  # 실제 설치처럼 시스템 경로를 쓰는 배치(명령은 모두 가로챈다)
    calls = []
    monkeypatch.setattr(kit_module, "capture", lambda command: calls.append(command) or "SUCCESS")
    kit.programs = tmp_path / "programs"
    state = {"files": {}}
    kit.schedule_sync_task(state, "C:/Python312/python.exe", "C:/MintEndpoint/mint_kit.py")
    (sync,) = calls
    assert sync[:4] == ["schtasks", "/Create", "/TN", kit_module.SYNC_TASK_NAME]
    assert sync[sync.index("/RU") + 1] == kit.account.name and "/IT" in sync  # 사용자 권한
    assert sync[sync.index("/TR") + 1].endswith(f'mint_kit.py sync --kit "{kit.logical_programs}"')
    assert state["sync_task"] == kit_module.SYNC_TASK_NAME
    calls.clear()
    kit.schedule_net_task(state, "C:/Python312/python.exe")
    acl, create = calls
    assert acl[0] == "icacls" and acl[-1] == "*S-1-5-32-545:(WD)"  # 사용자는 요청 파일만 만든다
    assert create[:4] == ["schtasks", "/Create", "/TN", kit_module.NET_TASK_NAME]
    assert state["net_task"] == kit_module.NET_TASK_NAME
    assert (kit.programs / "net" / "req").is_dir()


def test_the_sync_task_is_for_every_managed_windows_install(tmp_path, reports, monkeypatch):
    kit = windows_managed(tmp_path, monkeypatch)
    kit.root = None
    calls = []
    monkeypatch.setattr(kit_module, "capture", lambda command: calls.append(command) or "SUCCESS")
    kit.harnesses = ["claude"]  # Codex가 없어도 훅 없는 AI 도구 연결·사용자 쪽 보고를 맡는다
    state = {}
    kit.schedule_sync_task(state, "python.exe", "mint_kit.py")
    assert state.get("sync_task") == kit_module.SYNC_TASK_NAME and len(calls) == 1
    kit.managed = False
    kit.schedule_sync_task({}, "python.exe", "mint_kit.py")
    kit.schedule_net_task({}, "python.exe")
    assert len(calls) == 1


def test_the_system_reporter_runs_the_user_sync_right_after_the_server_list_changes(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    state = kit.install()
    state["sync_task"] = kit_module.SYNC_TASK_NAME
    kit.save_state(state)
    ran = []
    monkeypatch.setattr(kit_module, "capture", lambda command: ran.append(command) or "ok")
    monkeypatch.setattr(kit_module, "windows_system", lambda: True)
    monkeypatch.setattr(kit_module, "untrusted_run", lambda *a, **k: None)
    monkeypatch.setattr(kit_module.Kit, "remediate", lambda self, state, names: [{"kind": "x"}])
    answer = {"retired": ["srv-1"], "desired": []}
    monkeypatch.setattr(kit_module.Kit, "report", lambda self, s, a: setattr(self, "answer", answer)
                        or True)
    kit_module.report_installed(kit.programs, home=kit.home, user=kit.account.name)
    assert ["schtasks", "/Run", "/TN", kit_module.SYNC_TASK_NAME] in ran


def test_uninstall_deletes_the_sync_and_firewall_tasks_and_the_rules(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    state = kit.install()
    state.update(task="T1", sync_task="T2", net_task="T3")
    kit.save_state(state)
    kit.root = None
    seen = []
    monkeypatch.setattr(kit_module, "capture", lambda command: seen.append(command) or "")
    monkeypatch.setattr(kit_module.Kit, "stop_launched", lambda self, names: [])
    monkeypatch.setattr(kit_module.Kit, "stop_by_command", lambda self, names: [])
    kit.clean_servers()
    deleted = [c[3] for c in seen if c[:2] == ["schtasks", "/Delete"]]
    assert deleted == []  # 작업 삭제는 uninstall 본문이 한다
    assert any("Remove-NetFirewallRule" in " ".join(c) and "MINT sandbox" in " ".join(c)
               for c in seen)  # fmt: skip


def test_stopping_a_windows_launcher_ends_its_server_first_and_waits_for_its_cleanup(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    kit.install()
    kit.system_mode = True
    agent_path = r"C:\Program Files\MintEndpoint\mint_agent.py"
    rows = [
        (10, 1, f'python "{agent_path}" run --contracts c.json --server gone'),
        (20, 10, "python.exe srv.py"),  # 실행기가 띄운 서버
        (30, 1, f'python "{agent_path}" run --contracts c.json --server live'),
    ]
    alive = [list(rows), [rows[2]]]  # 서버가 끝나자 실행기도 스스로 끝난다
    monkeypatch.setattr(kit_module, "process_entries", lambda windows: alive[0] if len(alive) > 1
                        else alive[-1])
    killed = []

    def kill(pid):
        killed.append(pid)
        if pid == 20:
            alive.pop(0)
        return True

    monkeypatch.setattr(kit, "kill", kill)
    monkeypatch.setattr(kit_module.time, "sleep", lambda s: None)
    assert kit.stop_by_command({"gone"}) == [{"kind": "process", "server": "gone", "target": None}]
    assert killed == [20]  # 실행기는 정리를 마치고 스스로 끝났으므로 끄지 않는다


def test_a_firewall_filtered_server_is_reported_as_filtered(tmp_path, monkeypatch):
    programs = tmp_path / "MintEndpoint"
    rules = programs / "net" / "rules"
    rules.mkdir(parents=True)
    for name, pid in (("mint.s.1", 1), ("mint.t.2", 2)):
        record = {"profile": name, "server": name.split(".")[1], "pid": pid, "start": "5"}
        (rules / f"{name}.json").write_text(json.dumps(record))
    monkeypatch.setattr(kit_module, "proc_start", lambda pid, windows: "5" if pid == 1 else "9")
    assert kit_module.net_filtered(programs, True) == {"s"}  # 끝난 실행기의 기록은 세지 않는다
    assert kit_module.net_filtered(programs, False) == set()
    items = [{"server": "s", "count": 1}, {"server": "t", "count": 1}]
    got = kit_module.with_sandbox(items, tmp_path, True, False, None, {"s"})
    assert [i.get("egress_filtered") for i in got] == [True, None]


def test_uninstall_cleans_up_the_servers_while_the_launcher_file_still_exists(
    tmp_path, reports, monkeypatch
):
    kit = windows_managed(tmp_path, monkeypatch)
    kit.install()
    seen = []
    launcher = kit.programs / "mint_agent.py"
    clean = lambda self: seen.append(launcher.exists())  # noqa: E731
    monkeypatch.setattr(kit_module.Kit, "clean_servers", clean)
    kit.uninstall()
    assert seen == [True]  # 실행기 파일이 지워진 뒤에는 정리 명령을 부를 수 없다


def test_uninstall_ends_running_reporters_but_not_itself(tmp_path, reports, monkeypatch):
    import os

    kit = windows_managed(tmp_path, monkeypatch)
    kit.install()
    kit.root = None
    here = r"C:\Program Files\MintEndpoint"
    tool = here + r"\mint_kit.py"
    rows = [
        (10, 1, f'python.exe -I -B "{tool}" report --kit "{here}" --if-due'),
        (11, 1, f'pythonw.exe -I -B "{tool}" sync --kit "{here}"'),
        (12, 1, f'python.exe "{tool}" uninstall'),
        (os.getpid(), 1, f'python.exe "{tool}" report --kit "{here}"'),
        (14, 1, r'python.exe -I -B "D:\other\mint_kit.py" report --kit "D:\other"'),
    ]
    monkeypatch.setattr(kit_module, "process_entries", lambda windows: rows)
    killed = []
    monkeypatch.setattr(kit_module.Kit, "kill", lambda self, pid: killed.append(pid) or True)
    kit.stop_reporters()
    assert killed == [10, 11]  # 제거 명령 자신·다른 설치 폴더의 것은 끄지 않는다


def test_a_reporter_that_outlives_the_uninstall_does_not_recreate_the_kit_folder(
    tmp_path, monkeypatch
):
    folder = tmp_path / "MintEndpoint"
    folder.mkdir()
    monkeypatch.setattr(kit_module, "KIT_GONE", folder)
    kit_module.write_atomic(folder / "state.json", b"{}", 0o644)  # 설치되어 있는 동안은 쓴다
    kit_module.shutil.rmtree(folder)
    with pytest.raises(OSError):
        kit_module.write_atomic(folder / "state.json", b"{}", 0o644)
    kit_module.mark_fast(folder, 1.0)  # 조용히 건너뛴다
    assert not folder.exists()
