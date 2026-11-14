"""관리자 권한 보고기의 신뢰 점검과 사용자 홈 접근 방식."""

import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest
from test_kit_install import kit_module, make_kit, unpack

DIR, FILE, LINK = stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK


def fake_lstat(table):
    def lstat(path):
        uid, mode = table.get(path, (0, DIR | 0o755))
        return SimpleNamespace(st_uid=uid, st_mode=mode)

    return lstat


def reason(path, table=None, real=None):
    return kit_module.untrusted_reason(
        path, lstat=fake_lstat(table or {}), realpath=lambda p: real or p
    )


def test_a_root_owned_interpreter_under_root_owned_folders_is_trusted():
    assert reason("/usr/bin/python3") is None


def test_an_interpreter_the_user_can_write_is_refused():
    table = {"/home/u/venv/bin/python": (1000, FILE | 0o755)}
    assert "not root-owned" in reason("/home/u/venv/bin/python", table)


def test_a_group_or_world_writable_parent_folder_is_refused():
    assert "writable by other users" in reason(
        "/opt/kit/mint_kit.py", {"/opt/kit": (0, DIR | 0o775)}
    )
    assert "writable by other users" in reason("/tmp/x", {"/tmp": (0, DIR | 0o1777)})


def test_a_link_that_leads_into_a_user_folder_is_refused_even_when_the_link_is_root_owned():
    table = {"/home/u/venv/bin/python": (1000, FILE | 0o755), "/home/u": (1000, DIR | 0o755)}
    found = reason("/usr/bin/python3", table, real="/home/u/venv/bin/python")
    assert found and "not root-owned" in found


def test_a_link_component_owned_by_the_user_is_refused():
    table = {"/usr/local/lib": (1000, LINK | 0o777)}
    assert "not root-owned" in reason("/usr/local/lib/mint/mint_kit.py", table)


def test_a_path_that_cannot_be_inspected_is_refused():
    def lstat(path):
        raise OSError

    found = kit_module.untrusted_reason("/x/y", lstat=lstat, realpath=lambda p: p)
    assert "cannot be inspected" in found


def acl(listing, owner="BUILTIN\\Administrators"):
    def run(command):
        if command[0] == "icacls":
            return listing
        return owner

    return run


SAFE_ACL = (
    "C:\\Program Files NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"
    "  BUILTIN\\Users:(OI)(CI)(RX)\n  BUILTIN\\Administrators:(OI)(CI)(F)\n"
)


def test_a_windows_path_only_administrators_can_write_is_trusted():
    assert kit_module.windows_untrusted_reason("C:/Program Files/Mint", acl(SAFE_ACL)) is None


GROUPS = [r"BUILTIN\Users", r"NT AUTHORITY\Authenticated Users", "Everyone"]


@pytest.mark.parametrize("group", GROUPS)
@pytest.mark.parametrize("right", ["(M)", "(F)", "(OI)(CI)(W)", "(I)(WD,AD)"])
def test_a_windows_path_other_users_can_write_is_refused(group, right):
    listing = SAFE_ACL + f"  {group}:{right}\n"
    found = kit_module.windows_untrusted_reason("C:/Program Files/Mint", acl(listing))
    assert found and "writable by other users" in found


STOCK_ROOT_ACL = (
    "C:\\ BUILTIN\\Administrators:(OI)(CI)(F)\n  NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n"
    "  BUILTIN\\Users:(OI)(CI)(RX)\n  NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(M)\n"
    "  NT AUTHORITY\\Authenticated Users:(AD)\n"
)


def acl_by_folder(folders, owner="BUILTIN\\Administrators"):
    def run(command):
        return folders.get(command[1], "") if command[0] == "icacls" else owner

    return run


@pytest.mark.skipif(sys.platform != "win32", reason="Windows drive path walk")
def test_a_stock_drive_root_does_not_make_a_program_files_interpreter_untrusted():
    folders = {
        "C:\\Program Files\\Python312\\python.exe": SAFE_ACL,
        "C:\\Program Files\\Python312": SAFE_ACL,
        "C:\\Program Files": SAFE_ACL,
        "C:\\": STOCK_ROOT_ACL,
    }
    path = "C:/Program Files/Python312/python.exe"
    assert kit_module.windows_untrusted_reason(path, acl_by_folder(folders)) is None


def test_create_rights_on_the_target_folder_itself_still_refuse():
    target = SAFE_ACL + "  BUILTIN\\Users:(AD)\n"
    run = acl_by_folder({"C:\\x": target, "C:\\": SAFE_ACL})
    assert "writable by other users" in kit_module.windows_untrusted_reason("C:/x", run)


def test_a_windows_path_owned_by_a_user_or_unreadable_is_refused():
    owned = kit_module.windows_untrusted_reason("C:/x", acl(SAFE_ACL, owner="PC\\alice"))
    assert owned and "not owned by an administrator" in owned
    assert "cannot be inspected" in kit_module.windows_untrusted_reason("C:/x", acl(""))


# -- 보고기 --------------------------------------------------------------------------------------


def stage(tmp_path, monkeypatch, mode="managed", answer=None):
    programs = tmp_path / "programs"
    programs.mkdir()
    (programs / "kit.json").write_text(json.dumps(
        {"kit_version": "k" * 64, "decide_url": "https://mint.test", "harnesses": ["claude"]}))
    (programs / "state.json").write_text(json.dumps({"mode": mode, "mcp_servers": []}))
    home = tmp_path / "rhome"
    (home / ".config/mint").mkdir(parents=True)
    (home / ".config/mint/key").write_text("sk-user\n")
    sent = []
    reply = {"recorded": True, "retired": ["x"]} if answer is None else answer
    monkeypatch.setattr(kit_module, "post", lambda u, k, p, c: sent.append(p) or reply)
    monkeypatch.setattr(kit_module, "claude_version", lambda h: None)
    monkeypatch.setattr(kit_module, "scan_processes", lambda w: [])
    monkeypatch.setattr(kit_module, "scan_outside", lambda w: [])
    monkeypatch.setattr(kit_module, "scan_autostart", lambda h, w, u: [])
    return programs, home, sent


def test_a_privileged_report_refuses_to_run_when_the_code_it_would_execute_is_not_trusted(
    tmp_path, monkeypatch, capsys
):
    programs, home, sent = stage(tmp_path, monkeypatch)
    monkeypatch.setattr(kit_module, "drop_target", lambda user: (1000, 1000))
    monkeypatch.setattr(
        kit_module, "untrusted_run", lambda *a, **k: "/home/u/venv is not root-owned"
    )
    code = kit_module.report_installed(programs, home=home, user="alice", sleep=lambda s: None)
    assert code == 1 and sent == []
    assert "refused" in capsys.readouterr().err
    assert not (home / ".cache/mint/last_report").exists()


def test_a_privileged_report_does_every_home_access_as_the_user_and_never_chowns(
    tmp_path, monkeypatch
):
    programs, home, sent = stage(tmp_path, monkeypatch)
    dropped = []

    def as_user(uid, gid, fn):
        dropped.append((uid, gid))
        return fn()

    monkeypatch.setattr(kit_module, "drop_target", lambda user: (1000, 1001))
    monkeypatch.setattr(kit_module, "untrusted_run", lambda *a, **k: None)
    monkeypatch.setattr(kit_module, "as_user", as_user)
    monkeypatch.setattr(kit_module.os, "chown", lambda *a: pytest.fail("root must not chown"),
                        raising=False)
    code = kit_module.report_installed(
        programs, home=home, user="alice", sleep=lambda s: None, now=lambda: 7.0
    )
    assert code == 0 and len(sent) == 1
    assert set(dropped) == {(1000, 1001)} and len(dropped) >= 4  # 키·기록, 목록, 인벤토리
    assert (home / ".cache/mint/retired.json").exists()
    assert not hasattr(kit_module, "hand_over")


def test_an_unprivileged_report_does_not_run_the_trust_check(tmp_path, monkeypatch):
    programs, home, sent = stage(tmp_path, monkeypatch, mode="user")
    monkeypatch.setattr(kit_module, "untrusted_run", lambda *a, **k: pytest.fail("not privileged"))
    assert kit_module.report_installed(programs, home=home, sleep=lambda s: None) == 0
    assert len(sent) == 1


def test_a_managed_install_refuses_an_untrusted_interpreter(tmp_path, reports, monkeypatch):
    kit = make_kit(unpack(tmp_path), tmp_path, managed=True, strict=True)
    monkeypatch.setattr(kit_module, "untrusted_reason", lambda path: f"{path} is not root-owned")
    monkeypatch.setattr(kit_module, "windows_untrusted_reason", lambda path: "not trusted")
    with pytest.raises(SystemExit, match="trusted interpreter"):
        kit.check_python(sys.executable)


# -- 사용자 홈과 관리형 파일의 안전한 접근 ---------------------------------------------------------




def test_a_system_reporter_never_touches_the_user_profile(tmp_path, monkeypatch):
    programs, home, sent = stage(tmp_path, monkeypatch)
    (programs / "reporter.key").write_text("sk-copy\n")
    gone = tmp_path / "no-such-profile"  # 프로필은 없고, 있어도 읽지 않는다
    autostart_args = []
    monkeypatch.setattr(kit_module, "windows_system", lambda: True)
    monkeypatch.setattr(kit_module, "untrusted_run", lambda *a, **k: None)
    monkeypatch.setattr(
        kit_module, "scan_autostart", lambda h, w, u, **kw: autostart_args.append(kw) or []
    )
    monkeypatch.setattr(kit_module, "post", lambda u, k, p, c: sent.append((k, p)) or
                        {"recorded": True, "retired": ["x"]})
    code = kit_module.report_installed(
        programs, home=gone, user="alice", sleep=lambda s: None, now=lambda: 9.0
    )
    assert code == 0
    assert sent[0][0] == "sk-copy"  # 키는 설치 폴더의 사본에서 읽는다.
    assert autostart_args == [{"profile": False}]
    assert (programs / "last_report").read_text() == "9.0"
    assert json.loads((programs / "retired.json").read_text())["servers"] == ["x"]
    assert not gone.exists() and not (home / ".cache").exists()


def test_a_system_reporter_leaves_profile_files_and_processes_alone(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=("claude", "codex"))
    kit = make_kit(folder, tmp_path, managed=True, windows=True)
    config = kit.codex_config()
    config.parent.mkdir(parents=True)
    state = kit.install()
    before = config.read_bytes()
    record = kit.home / ".cache/mint/launched/srv-1-5.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"server": "srv-1", "pid": 5, "start": "1"}))
    mark = kit.home / "AppData/mark.txt"
    mark.parent.mkdir(parents=True)
    mark.write_text("x")
    state["files"][str(mark)] = kit_module.sha256_file(mark)
    state["autostart"] = [{"server": "srv-1", "file": str(mark)}]
    kit.system_mode = True
    monkeypatch.setattr(kit_module, "capture", lambda c: pytest.fail("no process work"))
    monkeypatch.setattr(kit_module, "process_entries", lambda windows: [])  # 명령줄에 든 것이 없다
    kit.remediate(state, ["srv-1"])
    assert config.read_bytes() == before and record.exists() and mark.exists()
    assert state["autostart"] == [{"server": "srv-1", "file": str(mark)}]
    requirements = (kit.codex_managed_dir / "requirements.toml").read_text(encoding="utf-8")
    assert "srv-1" not in requirements  # 관리자 소유 요구 파일은 고친다.


def test_a_managed_windows_install_keeps_a_key_copy_for_the_reporter_and_locks_the_folder(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    kit = make_kit(unpack(tmp_path, platform="windows"), tmp_path, managed=True, windows=True)
    state = kit.install()
    copy = kit.programs / "reporter.key"
    assert copy.read_text() == "sk-user\n"
    assert str(copy).replace("\\", "/").endswith("MintEndpoint/reporter.key")
    assert any(k.endswith("MintEndpoint/reporter.key") for k in state["files"])
    calls = []
    monkeypatch.setattr(kit_module, "capture", lambda command: calls.append(command) or "ok")
    kit.root = None
    kit.lock_programs()
    folder, key = calls
    assert folder[1] == str(kit.programs) and "*S-1-5-32-545:(OI)(CI)RX" in folder
    assert "*S-1-5-32-544:(OI)(CI)F" in folder and not any("S-1-1-0" in a for a in folder)
    assert key[1] == str(copy) and key[-2:] == ["*S-1-5-18:F", "*S-1-5-32-544:F"]
    assert kit.uninstall()["kept"] == [] and not copy.exists()


def test_the_launcher_also_reads_the_list_the_system_reporter_keeps_in_the_kit_folder(
    tmp_path, monkeypatch
):
    from test_kit_install import agent

    kit_dir = tmp_path / "kit"
    kit_dir.mkdir()
    (kit_dir / "retired.json").write_text(json.dumps({"servers": ["old"], "at": 1.0}))
    monkeypatch.setattr(agent, "KIT_DIR", str(kit_dir))
    assert agent.load_retired(str(tmp_path / "no-cache")) == {"old"}
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "retired.json").write_text(json.dumps({"servers": ["other"]}))
    assert agent.load_retired(str(cache)) == {"old", "other"}



def test_a_managed_file_is_read_without_following_links_and_must_be_root_owned(tmp_path):
    path = tmp_path / "managed-mcp.json"
    path.write_text("{}")
    assert kit_module.read_trusted(path, need_root=False) == b"{}"
    # 시험 계정은 root가 아니므로(Windows는 쓰기 가능 파일) 확인을 통과하지 못한다.
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        with pytest.raises(OSError):
            kit_module.read_trusted(path, need_root=True)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_a_managed_file_that_was_swapped_for_a_link_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("{}")
    link = tmp_path / "managed-mcp.json"
    link.symlink_to(target)
    with pytest.raises(OSError):
        kit_module.read_trusted(link, need_root=False)


@pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="needs root to drop privileges",
)
def test_the_child_process_really_runs_with_the_users_ids():
    seen = kit_module.as_user(65534, 65534, lambda: [os.getuid(), os.getgid(), os.getgroups()])
    assert seen == [65534, 65534, []]
