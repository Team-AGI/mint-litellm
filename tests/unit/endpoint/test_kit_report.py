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


def test_an_install_registers_a_short_tick_timer_that_runs_the_installed_copy(
    folder, tmp_path, reports
):
    kit, state = installed(folder, tmp_path, reports)
    units = kit.home / ".config/systemd/user"
    service = (units / "mint-report.service").read_text()
    timer = (units / "mint-report.timer").read_text()
    assert "mint_kit.py" in service and " report --tick --kit " in service
    assert "Type=oneshot" in service and "OnUnitActiveSec=20s" in timer
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


def test_a_windows_install_asks_for_a_one_minute_task(
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
    assert command[command.index("/SC") + 1] == "MINUTE"
    assert command[command.index("/MO") + 1] == "1"
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


def test_a_rejected_key_shows_up_in_check_and_makes_report_fail(
    tmp_path, monkeypatch, reports, capsys
):
    programs, home = stage(tmp_path, monkeypatch)

    def rejected(url, key, payload, ca_file):
        kit_module.last_http_error[:] = [401]
        return None

    monkeypatch.setattr(kit_module, "post", rejected)
    assert kit_module.report_installed(programs, sleep=lambda s: None) == 1
    assert (home / ".cache/mint/key_rejected").exists()
    kit = make_kit(programs, tmp_path, managed=False)
    kit.home = home
    _, problems = kit.check({"mode": "managed"})
    assert kit_module.KEY_REJECTED_TEXT in problems
    # 다시 보고가 닿으면 표시가 사라진다.
    monkeypatch.setattr(kit_module, "post", lambda *args: True)
    assert kit_module.report_installed(programs, sleep=lambda s: None) == 0
    assert not (home / ".cache/mint/key_rejected").exists()


def test_http_401_prints_korean_guidance(monkeypatch, capsys):
    import io
    import urllib.error
    import urllib.request

    def refuse(*args, **kw):
        raise urllib.error.HTTPError("http://x", 401, "no", {}, io.BytesIO())

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)
    assert kit_module.post("http://x", "k", {}, None) is None
    assert "한 줄 설치 명령" in capsys.readouterr().err


def test_a_reinstall_forgets_the_reported_tool_lists(folder, tmp_path, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    cache = kit.home / ".cache/mint"
    cache.mkdir(parents=True)
    (cache / "tools_sent.json").write_text("{}")
    (cache / "key_rejected").write_text("1")
    kit.install()
    assert not (cache / "tools_sent.json").exists()
    assert not (cache / "key_rejected").exists()


def test_the_hook_shows_korean_guidance_on_http_401():
    with pytest.raises(agent.Refuse, match="한 줄 설치 명령"):
        agent._call(lambda *a: (401, b""), "http://x", "/p", "k", {}, 1.0)


@pytest.mark.parametrize(("fast", "tick", "gap"), [
    (None, True, kit_module.REPORT_TICK_GAP),
    (None, False, 3600),
    (1100.0, True, 20),   # 짧은 주기 표식이 살아 있다
    (900.0, True, kit_module.REPORT_TICK_GAP),  # 표식이 지났다
    (1000.0 + 99999, True, kit_module.REPORT_TICK_GAP),  # 너무 먼 미래 값은 믿지 않는다
])
def test_the_report_gap_is_short_only_while_something_awaits_approval(fast, tick, gap):
    assert kit_module.report_gap(fast, 1000.0, tick) == gap


def test_work_to_apply_keeps_the_short_gap_on():
    pack = {"contract": {"pack": {"sha256": "a"}}}
    assert kit_module.needs_fast({}, True, 1000.0)
    assert kit_module.needs_fast({"inspections": [{"id": "x"}]}, False, 1000.0)
    # 웹으로 낸 신청이 진행 중이거나 방금 승인됐다(PC는 모른다): 짧은 주기로 받는다
    assert kit_module.needs_fast({"awaiting": True}, False, 1000.0)
    assert kit_module.REPORT_TICK_GAP <= 600
    assert kit_module.needs_fast({"desired": [pack]}, False, 1000.0)  # 허가 없음
    done = {**pack, "permit_until": "1970-01-01T01:00:00+00:00"}
    assert not kit_module.needs_fast({"desired": [done]}, False, 1000.0)
    assert not kit_module.needs_fast({"desired": [{"contract": {}}]}, False, 1000.0)


def test_a_tick_reports_every_twenty_seconds_while_marked_and_every_ten_minutes_otherwise(
    tmp_path, monkeypatch, reports
):
    programs, home = stage(tmp_path, monkeypatch)
    now = [5000.0]
    run = lambda: kit_module.report_installed(  # noqa: E731
        programs, tick=True, sleep=lambda s: None, now=lambda: now[0])
    run()
    assert len(reports) == 1
    now[0] += 300
    run()
    assert len(reports) == 1  # 10분 전
    (home / ".cache/mint/fast_until").write_text(str(now[0] + 100))  # 사용자가 신청했다
    run()
    assert len(reports) == 2
    now[0] += 19
    run()
    assert len(reports) == 2
    now[0] += 2
    run()
    assert len(reports) == 3
    now[0] += kit_module.REPORT_TICK_GAP
    run()
    assert len(reports) == 4


def test_a_missing_start_permit_pulls_one_report_then_starts():
    calls = []

    def start():
        calls.append("start")
        if calls.count("start") < 2:
            raise agent.NoPermit("missing")

    agent.start_with_permit_retry(start, lambda: calls.append("report"), 0, sleep=lambda s: None)
    assert calls == ["start", "report", "start"]


def test_a_start_permit_that_never_arrives_is_refused_after_a_few_tries():
    naps = []

    def start():
        raise agent.NoPermit("missing")

    with pytest.raises(agent.Refuse):
        agent.start_with_permit_retry(start, lambda: None, 8, sleep=naps.append)
    assert naps == [8, 8]


def test_a_windows_tick_repeats_every_twenty_seconds_only_while_a_fast_mark_is_live(
    tmp_path, monkeypatch
):
    import time

    runs, naps = [], []
    monkeypatch.setattr(kit_module.sys, "platform", "win32")
    monkeypatch.setattr(kit_module, "report_installed", lambda *a, **k: runs.append(1) or 0)
    monkeypatch.setattr(kit_module.time, "sleep", naps.append)
    argv = ["report", "--tick", "--kit", str(tmp_path), "--home", str(tmp_path)]
    assert kit_module.main(argv) == 0 and len(runs) == 1  # 표식이 없으면 가볍게 한 번
    (tmp_path / kit_module.FAST_FILE).write_text(str(time.time() + 300))
    assert kit_module.main(argv) == 0 and len(runs) == 4 and naps == [20, 20]
