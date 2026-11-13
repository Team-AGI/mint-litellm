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




def test_a_windows_profile_path_with_a_junction_or_a_foreign_owner_is_refused(
    tmp_path, monkeypatch
):
    home = tmp_path / "alice"
    cache = home / ".cache/mint"
    cache.mkdir(parents=True)
    mine = lambda command: "PC\\alice"  # noqa: E731
    assert kit_module.profile_unsafe(cache, home, "alice", mine) is False
    assert kit_module.profile_unsafe(cache, home, "alice", lambda c: "PC\\mallory") is True
    admin = lambda c: r"BUILTIN\Administrators"  # noqa: E731
    assert kit_module.profile_unsafe(cache, home, "alice", admin) is False
    real = os.lstat

    def junction(path, *a, **k):
        info = real(path, *a, **k)
        values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        flagged = str(path).endswith(".cache")
        values["st_file_attributes"] = kit_module.REPARSE_POINT if flagged else 0
        return SimpleNamespace(**values)

    monkeypatch.setattr(kit_module.os, "lstat", junction)
    assert kit_module.profile_unsafe(cache, home, "alice", mine) is True


def test_a_system_run_does_not_edit_a_user_config_whose_path_is_not_a_plain_user_folder(
    tmp_path, reports, monkeypatch
):
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramData", raising=False)
    folder = unpack(tmp_path, platform="windows", harnesses=("claude", "codex"))
    kit = make_kit(folder, tmp_path, managed=True, windows=True)
    state = kit.install()
    config = kit.codex_config()
    before = config.read_bytes()
    kit.guard_profile = True
    monkeypatch.setattr(kit_module, "profile_unsafe", lambda *a, **k: True)
    kit.remediate(state, ["srv-1"])
    assert config.read_bytes() == before
    assert "srv-1" in state["mcp_servers"]  # 지우지 못했으므로 다음 보고 때 다시 시도한다.


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
