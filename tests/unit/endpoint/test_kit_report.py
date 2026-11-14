"""주기 보고: 시작 지연과 보고 간격 판단, 설치한 묶음의 보고 명령, 타이머 등록과 제거."""

import json
import random
import subprocess

import pytest
from test_kit_install import agent, kit_module, make_kit


def test_the_start_delay_is_spread_over_the_window_and_never_negative():
    assert kit_module.jitter_delay(1800, lambda: 0.0) == 0
    assert kit_module.jitter_delay(1800, lambda: 0.5) == 900
    assert kit_module.jitter_delay(1800, lambda: 0.999999) == 1799
    assert kit_module.jitter_delay(0) == 0 and kit_module.jitter_delay(-5) == 0
    spread = {kit_module.jitter_delay(1800, random.Random(i).random) for i in range(20)}
    assert len(spread) > 10 and all(0 <= delay < 1800 for delay in spread)


@pytest.mark.parametrize(("last", "now", "due"), [
    (None, 5000.0, True),
    (1000.0, 1000.0 + 3599, False),
    (1000.0, 1000.0 + 3600, True),
    (9000.0, 5000.0, True),  # 시계가 되돌아갔다
])
def test_a_start_report_is_skipped_when_one_went_out_within_the_hour(last, now, due):
    assert kit_module.report_due(last, now) is due


def installed(folder, tmp_path, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    state = kit.install()
    return kit, state


def test_an_install_registers_a_six_hour_timer_that_runs_the_installed_copy(
    folder, tmp_path, reports
):
    kit, state = installed(folder, tmp_path, reports)
    units = kit.home / ".config/systemd/user"
    service = (units / "mint-report.service").read_text()
    timer = (units / "mint-report.timer").read_text()
    assert "mint_kit.py" in service and " report --kit " in service and "Type=oneshot" in service
    assert "OnUnitActiveSec=6h" in timer and "RandomizedDelaySec=1800" in timer
    # 설치한 설정에는 키와 서버 목록이 없다(키는 사용자 파일에만 있다).
    copy = json.loads((kit.programs / "kit.json").read_text())
    assert "key" not in copy and "servers" not in copy and copy["decide_url"]
    assert (kit.programs / "mint_kit.py").read_bytes() == (folder / "mint_kit.py").read_bytes()
    assert str(units / "mint-report.timer") in state["files"]


def test_uninstalling_removes_the_timer_and_the_reporter(folder, tmp_path, reports):
    kit, _ = installed(folder, tmp_path, reports)
    kit.uninstall()
    assert not (kit.home / ".config/systemd/user/mint-report.timer").exists()
    assert not (kit.home / ".config/systemd/user/timers.target.wants/mint-report.timer").exists()
    assert not (kit.programs / "mint_kit.py").exists()


def test_a_user_level_uninstall_stops_the_timer_before_its_unit_files_go(
    folder, tmp_path, reports, monkeypatch
):
    kit, _ = installed(folder, tmp_path, reports)
    timer = kit.home / ".config/systemd/user/mint-report.timer"
    seen = []
    monkeypatch.setattr(
        kit_module, "capture", lambda command: seen.append((command[1:4], timer.exists()))
    )
    # 시험 배치는 시스템 경로를 쓰지 않으므로 사용자 타이머가 있는 것으로 본다.
    monkeypatch.setattr(kit, "user_timer", lambda state: True)
    kit.uninstall()
    assert seen == [(["--user", "disable", "--now"], True)]


def test_a_windows_install_asks_for_a_task_with_the_jitter_on_the_command(
    folder, tmp_path, reports, monkeypatch
):
    calls = []
    monkeypatch.setattr(kit_module, "capture", lambda command: calls.append(command) or "SUCCESS")
    kit = make_kit(folder, tmp_path, managed=False, windows=True)
    kit.root = None  # 실제 설치처럼 시스템 경로를 쓰는 배치
    state = {"files": {}, "backups": {}}
    kit.schedule_task(state, ["py", "-I", "-B", "C:/p/mint_kit.py", "report", "--kit", "C:/p"])
    (command,) = calls
    assert command[:2] == ["schtasks", "/Create"] and "/F" in command
    assert command[command.index("/MO") + 1] == "6"
    assert command[command.index("/TR") + 1].endswith("report --kit C:/p --jitter 1800")
    assert state["task"] == kit_module.TASK_NAME


def stage(tmp_path, monkeypatch, *, state=True, key="sk-user"):
    home = tmp_path / "rhome"
    programs = tmp_path / "programs"
    programs.mkdir()
    (programs / "kit.json").write_text(json.dumps(
        {"kit_version": "k" * 64, "decide_url": "https://mint.test", "harnesses": ["claude"]}))
    if state:
        (programs / "state.json").write_text(json.dumps(
            {"mode": "managed", "mcp_servers": ["srv-1"]}))
    if key:
        (home / ".config/mint").mkdir(parents=True)
        (home / ".config/mint/key").write_text(key + "\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return programs, home


def test_the_periodic_report_sends_the_installed_state_with_the_user_key(
    tmp_path, monkeypatch, reports
):
    programs, home = stage(tmp_path, monkeypatch)
    waited = []
    code = kit_module.report_installed(
        programs, jitter=1800, sleep=waited.append, rand=lambda: 0.5, now=lambda: 5000.0
    )
    assert code == 0 and waited == [900]
    (url, key, payload), = reports
    assert url == "https://mint.test/mint/v1/endpoint/report" and key == "sk-user"
    assert payload["action"] == "installed" and payload["mode"] == "managed"
    assert payload["mcp_servers"] == ["srv-1"] and "processes" in payload
    assert (home / ".cache/mint/last_report").read_text() == "5000.0"


def test_a_start_report_is_skipped_inside_the_hour_but_the_timer_always_reports(
    tmp_path, monkeypatch, reports
):
    programs, _ = stage(tmp_path, monkeypatch)
    now = [5000.0]
    run = lambda **kw: kit_module.report_installed(  # noqa: E731
        programs, sleep=lambda s: None, now=lambda: now[0], **kw)
    assert run(if_due=True) == 0 and len(reports) == 1
    now[0] += 600
    assert run(if_due=True) == 0 and len(reports) == 1
    assert run() == 0 and len(reports) == 2
    now[0] += 3600
    assert run(if_due=True) == 0 and len(reports) == 3


def test_a_failed_report_is_retried_at_the_next_start(tmp_path, monkeypatch, reports):
    programs, home = stage(tmp_path, monkeypatch)
    monkeypatch.setattr(kit_module, "post", lambda *args: False)
    assert kit_module.report_installed(programs, if_due=True, sleep=lambda s: None) == 1
    assert not (home / ".cache/mint/last_report").exists()


def test_nothing_is_reported_when_the_bundle_is_not_installed(tmp_path, monkeypatch, reports):
    programs, _ = stage(tmp_path, monkeypatch, state=False)
    assert kit_module.report_installed(programs, sleep=lambda s: None) == 0
    assert reports == []


def test_the_server_launcher_starts_the_start_report_without_waiting_for_it(
    tmp_path, monkeypatch
):
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda command, **kw: launched.append((command, kw)))
    agent.kick_report(str(tmp_path))
    assert launched == []  # 설치된 보고기가 없으면 아무것도 하지 않는다.
    (tmp_path / "mint_kit.py").write_text("")
    agent.kick_report(str(tmp_path))
    (command, options), = launched
    assert command[-4:] == ["report", "--kit", str(tmp_path), "--if-due"]
    assert options["stdout"] == subprocess.DEVNULL
