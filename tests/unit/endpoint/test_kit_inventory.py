"""설치 보고에 담는 프로세스·자동 시작 인벤토리: 명령줄·항목 해석과 보고 본문 모양."""

import pytest
from kit_loader import load

from mint_litellm.endpoint.decide import ReportBody

kit = load("mint_kit")

RUN = "python3 /usr/local/lib/mint-endpoint/mint_agent.py run --contracts /c.json --server srv-1"


def test_only_the_kit_launcher_names_a_server():
    assert kit.server_of(RUN) == "srv-1"
    assert kit.server_of(RUN.replace("--server srv-1", "--server=srv-2")) == "srv-2"
    quoted = '"C:/Python/python.exe" "C:/p/mint_agent.py" run --contracts c --server srv-3'
    assert kit.server_of(quoted) == "srv-3"
    assert kit.server_of("python3 /usr/local/lib/mint-endpoint/mint_agent.py hook") is None
    assert kit.server_of("node /opt/srv/index.js --server x") is None


def test_an_autostart_entry_is_reported_only_when_it_points_at_an_mcp_launcher():
    unit = f"[Service]\nExecStart={RUN}\n"
    assert kit.autostart_item("systemd", "mcp.service", unit) == {
        "kind": "systemd", "name": "mcp.service", "server": "srv-1"}
    assert kit.autostart_item("run_key", "Tool", r"C:\tools\mcp-server.exe") == {
        "kind": "run_key", "name": "Tool", "server": None}
    assert kit.autostart_item("autostart", "a.desktop", "Exec=/usr/bin/firefox") is None


def test_cron_reboot_lines_are_picked_out_of_a_crontab():
    text = f"# m h\n0 * * * * backup\n@reboot {RUN}\n  @reboot /bin/true\n"
    assert kit.cron_reboot(text) == [f"@reboot {RUN}", "@reboot /bin/true"]


def test_registry_and_scheduled_task_listings_are_parsed():
    reg = (
        "\n" + r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" + "\n"
        "    Mint Srv    REG_SZ    python mint_agent.py run --contracts c --server srv-1\n"
        "    Other    REG_SZ    " + r"C:\x.exe" + "\n"
    )
    assert kit.parse_reg(reg) == [
        ("Mint Srv", "python mint_agent.py run --contracts c --server srv-1"),
        ("Other", r"C:\x.exe"),
    ]
    tasks = (
        '"HostName","TaskName","Task To Run"\n'
        + r'"PC","\MintSrv","python mint_agent.py run"' + "\n"
    )
    assert kit.parse_schtasks(tasks) == [(r"\MintSrv", "python mint_agent.py run")]


def test_the_linux_scan_reads_user_units_and_desktop_files(tmp_path, monkeypatch):
    units = tmp_path / ".config/systemd/user"
    desktop = tmp_path / ".config/autostart"
    units.mkdir(parents=True)
    desktop.mkdir(parents=True)
    (units / "mcp.service").write_text(f"ExecStart={RUN}\n", encoding="utf-8")
    (units / "other.service").write_text("ExecStart=/bin/true\n", encoding="utf-8")
    (desktop / "mcp.desktop").write_text("Exec=/opt/mcp-server\n", encoding="utf-8")
    monkeypatch.setattr(kit, "capture", lambda command: f"@reboot {RUN}\n")
    found = kit.scan_autostart(tmp_path, False, "tester")
    seen = {(i["kind"], i["name"], i["server"]) for i in found}
    assert seen >= {("systemd", "mcp.service", "srv-1"), ("cron", "@reboot", "srv-1"),
                    ("autostart", "mcp.desktop", None)}
    assert "other.service" not in {i["name"] for i in found}


def test_running_launchers_are_counted_per_server(monkeypatch):
    monkeypatch.setattr(kit, "process_commands", lambda windows: [RUN, RUN, "bash", "x --server a"])
    assert kit.scan_processes(False) == [{"server": "srv-1", "count": 2}]


@pytest.mark.parametrize("fail", [OSError, ValueError])
def test_an_inventory_that_cannot_be_read_never_blocks_the_report(tmp_path, monkeypatch, fail):
    def broken(*args):
        raise fail("no")

    monkeypatch.setattr(kit, "scan_processes", broken)
    instance = kit.Kit.__new__(kit.Kit)
    instance.windows, instance.home = False, tmp_path
    instance.account = kit.Account("tester", tmp_path, 1, 1)
    assert instance.inventory() == {}


def test_the_inventory_fits_what_the_server_accepts():
    body = {
        "kit_version": "k", "action": "removed", "mode": "none", "mcp_servers": [],
        "processes": [{"server": "srv-1", "count": 1}],
        "autostart": [{"kind": "cron", "name": "@reboot", "server": "srv-1"}],
    }
    parsed = ReportBody.model_validate(body)
    assert parsed.processes[0].server == "srv-1" and parsed.autostart[0].kind == "cron"
