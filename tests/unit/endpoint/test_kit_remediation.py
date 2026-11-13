"""폐기 서버 정리: 관리형 묶음은 자기 항목만 지우고, 실행기는 폐기 서버를 시작하지 않는다."""

import json
import tomllib

import pytest
from test_kit_agent import World
from test_kit_install import agent, kit_module, make_kit, unpack

from mint_litellm.endpoint.decide import ReportBody

BOTH = ("claude", "codex")


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def installed(tmp_path, *, managed=True, harnesses=BOTH, **options):
    folder = unpack(tmp_path, harnesses=harnesses)
    kit = make_kit(folder, tmp_path, managed=managed, **options)
    return kit, kit.install()


def launched(kit, server, pid, start):
    folder = kit.home / ".cache/mint/launched"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{server}-{pid}.json"
    path.write_text(json.dumps({"server": server, "pid": pid, "start": start}))
    return path


# -- 설정 항목 ------------------------------------------------------------------------------------


def test_a_managed_kit_removes_only_its_own_claude_entries_of_retired_servers(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("claude",))
    path = kit.managed_dir / "managed-mcp.json"
    data = json.loads(path.read_text())
    data["mcpServers"]["user-own"] = {"command": "node", "args": ["/opt/own/index.js"]}
    # 사용자가 같은 이름으로 바꿔 둔 항목은 묶음의 것이 아니다.
    data["mcpServers"]["srv-2"] = {"command": "node", "args": ["/opt/mine.js", "--server", "srv-2"]}
    path.write_text(json.dumps(data))
    removed = kit.remediate(state, ["srv-1", "srv-2", "user-own", "ghost"])
    assert removed == [{"kind": "config", "server": "srv-1", "target": "claude"}]
    assert sorted(json.loads(path.read_text())["mcpServers"]) == ["srv-2", "user-own"]
    assert json.loads((kit.programs / "state.json").read_text())["pending_removed"] == removed


def test_a_retired_server_that_is_not_in_the_kit_state_is_left_alone(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("claude",))
    before = (kit.managed_dir / "managed-mcp.json").read_bytes()
    assert kit.remediate(state, ["not-installed"]) == []
    assert (kit.managed_dir / "managed-mcp.json").read_bytes() == before
    assert "pending_removed" not in state


def test_the_removal_is_tracked_so_uninstalling_still_leaves_nothing_behind(tmp_path, reports):
    kit, state = installed(tmp_path)
    kit.remediate(state, ["srv-1"])
    assert kit.uninstall()["kept"] == []
    assert not (tmp_path / "root/etc/claude-code").exists()
    assert not (tmp_path / "root/etc/codex").exists()


def test_a_config_someone_else_changed_is_edited_but_stays_theirs_on_uninstall(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("claude",))
    path = kit.managed_dir / "managed-mcp.json"
    data = json.loads(path.read_text())
    data["note"] = "edited by an admin"
    path.write_text(json.dumps(data))
    kit.remediate(state, ["srv-1"])
    assert "srv-1" not in json.loads(path.read_text())["mcpServers"]
    assert kit.uninstall()["kept"] == [f"{kit.claude_dir}/managed-mcp.json"]


def test_codex_server_tables_of_retired_servers_are_removed_and_the_files_stay_valid(
    tmp_path, reports
):
    kit, state = installed(tmp_path, harnesses=("codex",))
    codex = kit.codex_managed_dir
    removed = kit.remediate(state, ["srv-1"])
    assert removed == [{"kind": "config", "server": "srv-1", "target": "codex"}]
    for name in ("requirements.toml", "managed_config.toml"):
        tables = tomllib.loads((codex / name).read_text(encoding="utf-8"))["mcp_servers"]
        assert list(tables) == ["srv-2"]
    # 모든 서버가 폐기되어도 서버 표는 남는다(표가 없으면 Codex는 서버를 제한하지 않는다).
    kit.remediate(state, ["srv-2"])
    text = (codex / "requirements.toml").read_text(encoding="utf-8")
    assert tomllib.loads(text)["mcp_servers"] == {}


def test_a_windows_managed_kit_edits_the_codex_block_but_not_the_users_own_tables(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=BOTH)
    kit = make_kit(folder, tmp_path, managed=True, windows=True)
    config = tmp_path / "home/.codex/config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers."srv-2"]\ncommand = "mine"\n', encoding="utf-8")
    state = kit.install()  # srv-2는 사용자가 이미 정의해 묶음이 건너뛴다.
    removed = kit.remediate(state, ["srv-1", "srv-2"])
    assert {"kind": "config", "server": "srv-1", "target": "codex"} in removed
    assert {"kind": "config", "server": "srv-1", "target": "claude"} in removed
    text = config.read_text(encoding="utf-8")
    assert tomllib.loads(text)["mcp_servers"] == {"srv-2": {"command": "mine"}}
    assert state["codex_config_sha"] == kit_module.sha256_bytes(config.read_bytes())


def test_a_user_level_install_is_never_remediated(tmp_path, reports):
    kit, state = installed(tmp_path, managed=False, harnesses=("claude",))
    settings = kit.home / ".claude/settings.json"
    before = settings.read_bytes()
    assert kit.remediate(state, ["srv-1", "srv-2"]) == []
    assert settings.read_bytes() == before
    assert "pending_removed" not in state


# -- 프로세스와 자동 시작 -----------------------------------------------------------------------


def test_only_processes_the_launcher_recorded_are_stopped_and_only_when_the_start_matches(
    tmp_path, reports, monkeypatch
):
    kit, state = installed(tmp_path, harnesses=("claude",))
    live = launched(kit, "srv-1", 111, "5000")
    reused = launched(kit, "srv-1", 222, "5000")
    other = launched(kit, "srv-2", 333, "7")
    starts = {111: "5000", 222: "9999", 333: "7"}
    killed = []
    monkeypatch.setattr(kit_module, "proc_start", lambda pid, windows: starts.get(pid))
    monkeypatch.setattr(kit_module.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    removed = kit.remediate(state, ["srv-1"])
    assert killed == [(111, kit_module.signal.SIGTERM)]
    assert {"kind": "process", "server": "srv-1", "target": None} in removed
    assert not live.exists() and not reused.exists()  # 재사용된 PID의 기록은 지우고 끄지 않는다.
    assert other.exists()  # 폐기되지 않은 서버는 그대로다.


def test_a_record_without_a_start_mark_is_never_trusted(tmp_path, reports, monkeypatch):
    kit, state = installed(tmp_path, harnesses=("claude",))
    path = launched(kit, "srv-1", 111, None)
    killed = []
    monkeypatch.setattr(kit_module, "proc_start", lambda pid, windows: "5000")
    monkeypatch.setattr(kit_module.os, "kill", lambda *a: killed.append(a))
    kit.remediate(state, ["srv-1"])
    assert killed == [] and not path.exists()


def test_windows_stops_the_launcher_tree_and_deletes_a_registered_task(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    kit = make_kit(unpack(tmp_path, platform="windows"), tmp_path, managed=True, windows=True)
    state = kit.install()
    launched(kit, "srv-1", 444, "1337")
    state["autostart"] = [{"server": "srv-1", "task": "MINT srv-1"},
                          {"server": "srv-2", "task": "MINT srv-2"}]
    calls = []

    def capture(command):
        calls.append(command)
        return "1337" if command[0] == "powershell" else "SUCCESS"

    monkeypatch.setattr(kit_module, "capture", capture)
    kit.root = None  # 예약 작업은 실제 설치에서만 지운다.
    removed = kit.remediate(state, ["srv-1"])
    assert ["taskkill", "/PID", "444", "/T", "/F"] in calls
    assert ["schtasks", "/Delete", "/TN", "MINT srv-1", "/F"] in calls
    assert ["schtasks", "/Delete", "/TN", "MINT srv-2", "/F"] not in calls
    assert {"kind": "autostart", "server": "srv-1", "target": "MINT srv-1"} in removed
    assert state["autostart"] == [{"server": "srv-2", "task": "MINT srv-2"}]


def test_a_registered_autostart_file_is_removed_only_while_it_is_still_ours(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("claude",))
    ours = kit.home / ".config/autostart/a.desktop"
    edited = kit.home / ".config/autostart/b.desktop"
    ours.parent.mkdir(parents=True)
    for path in (ours, edited):
        path.write_text("[Desktop Entry]\n")
        state["files"][str(path)] = kit_module.sha256_file(path)
    edited.write_text("[Desktop Entry]\nExec=changed\n")
    state["autostart"] = [{"server": "srv-1", "file": str(ours)},
                          {"server": "srv-1", "file": str(edited)}]
    removed = kit.remediate(state, ["srv-1"])
    assert not ours.exists() and edited.exists()
    assert {"kind": "autostart", "server": "srv-1", "target": "a.desktop"} in removed
    assert state["autostart"] == [{"server": "srv-1", "file": str(edited)}]


# -- 보고 -----------------------------------------------------------------------------------------


def test_what_was_removed_is_reported_once_and_then_forgotten(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("claude",))
    removed = kit.remediate(state, ["srv-1"])
    assert kit.report(state, "installed") is True
    payload = reports[-1][2]
    assert payload["removed"] == removed
    ReportBody.model_validate(payload)
    assert "pending_removed" not in state
    assert "pending_removed" not in json.loads((kit.programs / "state.json").read_text())
    kit.report(state, "installed")
    assert "removed" not in reports[-1][2]


def test_a_removal_that_could_not_be_reported_is_sent_with_the_next_report(
    tmp_path, reports, monkeypatch
):
    kit, state = installed(tmp_path, harnesses=("claude",))
    removed = kit.remediate(state, ["srv-1"])
    monkeypatch.setattr(kit_module, "post", lambda *args: None)
    assert kit.report(state, "installed") is False
    assert state["pending_removed"] == removed
    monkeypatch.setattr(kit_module, "post", lambda url, key, payload, ca: {"recorded": True})
    assert kit.report(state, "installed") is True
    assert "pending_removed" not in state


def stage_report(tmp_path, monkeypatch, mode, answer):
    programs = tmp_path / "programs"
    programs.mkdir()
    (programs / "kit.json").write_text(json.dumps(
        {"kit_version": "k" * 64, "decide_url": "https://mint.test", "harnesses": ["claude"]}))
    (programs / "state.json").write_text(json.dumps({"mode": mode, "mcp_servers": ["srv-1"]}))
    home = tmp_path / "rhome"
    (home / ".config/mint").mkdir(parents=True)
    (home / ".config/mint/key").write_text("sk-user\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    sent = []
    monkeypatch.setattr(
        kit_module, "post", lambda url, key, payload, ca: sent.append(payload) or answer
    )
    monkeypatch.setattr(kit_module, "claude_version", lambda h: None)
    monkeypatch.setattr(kit_module, "codex_version", lambda h: None)
    monkeypatch.setattr(kit_module, "scan_processes", lambda w: [])
    monkeypatch.setattr(kit_module, "scan_autostart", lambda h, w, u: [])
    return programs, home, sent


def test_the_retired_list_in_the_answer_is_cached_for_the_launcher(tmp_path, monkeypatch):
    answer = {"recorded": True, "retired": ["srv-1", 7, "old"]}
    programs, home, sent = stage_report(tmp_path, monkeypatch, "user", answer)
    assert kit_module.report_installed(programs, sleep=lambda s: None, now=lambda: 42.0) == 0
    cache = json.loads((home / ".cache/mint/retired.json").read_text())
    assert cache == {"servers": ["srv-1", "old"], "at": 42.0}
    assert len(sent) == 1  # 사용자 수준 설치는 아무것도 지우지 않으므로 다시 보고하지 않는다.
    assert agent.load_retired(str(home / ".cache/mint")) == {"srv-1", "old"}


def test_an_answer_without_a_list_leaves_the_last_known_list_in_place(tmp_path, monkeypatch):
    programs, home, _ = stage_report(tmp_path, monkeypatch, "user", {"recorded": True})
    (home / ".cache/mint").mkdir(parents=True)
    (home / ".cache/mint/retired.json").write_text(json.dumps({"servers": ["srv-1"], "at": 1.0}))
    assert kit_module.report_installed(programs, sleep=lambda s: None) == 0
    assert agent.load_retired(str(home / ".cache/mint")) == {"srv-1"}


def test_a_managed_report_that_removed_something_reports_again_at_once(tmp_path, monkeypatch):
    answer = {"recorded": True, "retired": ["x"]}
    programs, home, sent = stage_report(tmp_path, monkeypatch, "managed", answer)
    seen = []
    monkeypatch.setattr(
        kit_module.Kit, "remediate",
        lambda self, state, names: seen.append(names) or [{"kind": "process", "server": "x"}],
    )
    code = kit_module.report_installed(
        programs, home=home, user="tester", sleep=lambda s: None, now=lambda: 1.0
    )
    assert code == 0 and seen == [["x"]] and len(sent) == 2


# -- 시스템 타이머 ------------------------------------------------------------------------------


def test_a_managed_install_reports_from_a_system_timer_that_knows_the_users_home(tmp_path, reports):
    kit, state = installed(tmp_path, harnesses=("claude",))
    units = tmp_path / "root/etc/systemd/system"
    service = (units / "mint-report.service").read_text()
    assert "--home" in service and "--user tester" in service
    if state.get("links"):  # 링크를 만들 수 없는 곳(Windows 위의 시험)에서는 타이머가 없다.
        assert (units / "timers.target.wants/mint-report.timer").is_symlink()
        assert state["timer"] == "system"
    assert not (kit.home / ".config/systemd/user/mint-report.timer").exists()
    kit.uninstall()
    assert not list((tmp_path / "root/etc/systemd").rglob("mint-report*"))


def test_a_managed_windows_task_runs_as_system(tmp_path, reports, monkeypatch):
    calls = []
    monkeypatch.setattr(kit_module, "capture", lambda command: calls.append(command) or "SUCCESS")
    kit = make_kit(unpack(tmp_path, platform="windows"), tmp_path, managed=True, windows=True)
    kit.root = None
    kit.schedule_task({"files": {}, "backups": {}}, ["py", "report"])
    (command,) = calls
    assert command[command.index("/RU") + 1] == "SYSTEM"


# -- 실행기 ---------------------------------------------------------------------------------------


class Exec:
    def __init__(self):
        self.calls = []

    def __call__(self, target, argv, env):
        self.calls.append((target, argv))


def retire(state_dir, servers, at=1.0):
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "retired.json").write_text(json.dumps({"servers": servers, "at": at}))


def test_the_launcher_refuses_a_server_the_last_report_marked_retired(world, tmp_path):
    state = tmp_path / "cache"
    retire(state, ["srv-1"])
    started = Exec()
    with pytest.raises(agent.Refuse, match="retired"):
        agent.run_server("srv-1", world.listing, {}, execve=started, state_dir=str(state))
    assert started.calls == [] and not (state / "launched").exists()


def test_the_launcher_keeps_refusing_from_an_old_list_but_only_for_listed_servers(world, tmp_path):
    state = tmp_path / "cache"
    retire(state, ["other"], at=0.0)  # 보고 간격보다 훨씬 오래된 목록
    started = Exec()
    agent.run_server("srv-1", world.listing, {}, execve=started, state_dir=str(state))
    assert len(started.calls) == 1
    retire(state, ["srv-1"], at=0.0)
    with pytest.raises(agent.Refuse):
        agent.run_server("srv-1", world.listing, {}, execve=Exec(), state_dir=str(state))


@pytest.mark.parametrize("text", [None, "not json", "[]", '{"servers": "srv-1"}'])
def test_a_missing_or_unreadable_list_does_not_block_a_server(world, tmp_path, text):
    state = tmp_path / "cache"
    state.mkdir()
    if text is not None:
        (state / "retired.json").write_text(text)
    started = Exec()
    agent.run_server("srv-1", world.listing, {}, execve=started, state_dir=str(state))
    assert len(started.calls) == 1


def test_a_started_server_is_recorded_with_its_pid_and_start_mark(world, tmp_path, monkeypatch):
    state = tmp_path / "cache"
    monkeypatch.setattr(agent, "proc_start", lambda pid: "mark-1")
    agent.run_server("srv-1", world.listing, {}, execve=Exec(), state_dir=str(state))
    (path,) = (state / "launched").glob("*.json")
    expected = {"server": "srv-1", "pid": agent.os.getpid(), "start": "mark-1"}
    assert json.loads(path.read_text()) == expected


def test_a_launcher_that_cannot_record_still_starts_the_server(world, tmp_path):
    blocked = tmp_path / "cache"
    blocked.write_text("a file, not a folder")
    started = Exec()
    agent.run_server("srv-1", world.listing, {}, execve=started, state_dir=str(blocked))
    assert len(started.calls) == 1
