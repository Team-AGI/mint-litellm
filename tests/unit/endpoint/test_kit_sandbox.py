"""서버 실행기의 격리: 계약에서 만든 bubblewrap 명령, 격리할 수 없을 때의 거부, 실제 격리."""

import json
import os
import shutil
import subprocess
import sys

import pytest
from kit_loader import load

agent = load("mint_agent")
kit = load("mint_kit")

HOME = "/home/alice"
CONTRACT = {
    "executable": "/opt/srv/bin/node",
    "argv": ["/opt/srv/app/index.js"],
    "cwd": "/work/job",
    "env": {"MODE": "ro"},
    "file_access": [
        {"path": "/data/in", "mode": "ro"},
        {"path": "/data/out", "mode": "rw"},
    ],
}


def pairs(args, flag):
    return [(args[i + 1], args[i + 2]) for i, a in enumerate(args) if a == flag]


def build(contract=None, home=HOME):
    doc = contract or CONTRACT
    return agent.bwrap_args(doc, [doc["executable"], *doc["argv"]], home, "bwrap")


def test_declared_paths_are_bound_with_their_declared_mode():
    args = build()
    ro = {src for src, _ in pairs(args, "--ro-bind-try")}
    rw = {src for src, _ in pairs(args, "--bind-try")}
    assert {"/data/in", "/work/job", "/opt/srv"} <= ro
    assert rw == {"/data/out"}
    assert args[args.index("--chdir") + 1] == "/work/job"
    assert args[args.index("--") + 1 :] == ["/opt/srv/bin/node", "/opt/srv/app/index.js"]


def test_the_network_is_closed_only_when_the_contract_declares_none():
    closed = build({**CONTRACT, "network": "none"})
    assert "--unshare-all" in closed and "--share-net" not in closed
    assert "/etc/resolv.conf" not in closed and "/etc/ssl" not in closed
    # 선언이 없는 이전 계약과 any는 열린다(주소가 인자에 없어도).
    for doc in (CONTRACT, {**CONTRACT, "network": "any"}):
        wide = build(doc)
        assert "--share-net" in wide and "/etc/resolv.conf" in wide


def test_a_package_runner_gets_only_its_cache_directories_read_write():
    npx = {**CONTRACT, "executable": "/usr/bin/npx", "argv": ["-y", "@scope/server@1.0.0"],
           "cwd": None, "file_access": []}  # fmt: skip
    assert agent.runner_caches(npx, HOME) == [f"{HOME}/.npm"]
    rw = {src for src, _ in pairs(build(npx), "--bind-try")}
    assert rw == {f"{HOME}/.npm"}
    uvx = {**npx, "executable": "/usr/local/bin/uvx", "argv": ["mcp-server-x"]}
    assert f"{HOME}/.cache/uv" in agent.runner_caches(uvx, HOME)
    pipx = {**npx, "executable": "/usr/bin/pipx", "argv": ["run", "tool"]}
    assert agent.runner_caches(pipx, HOME) == [f"{HOME}/.local/share/pipx", f"{HOME}/.cache/pipx"]
    # 실행기가 아니거나 실행기의 다른 하위 명령이면 붙이지 않는다.
    assert agent.runner_caches({**npx, "executable": "/usr/bin/node"}, HOME) == []
    assert agent.runner_caches({**pipx, "argv": ["install", "x"]}, HOME) == []


def test_the_process_is_tied_to_its_parent_and_its_terminal_session():
    args = build()
    assert {"--die-with-parent", "--new-session"} <= set(args)
    assert ("--tmpfs", "/tmp") == (args[args.index("--tmpfs")], args[args.index("--tmpfs") + 1])


def test_home_is_empty_and_only_declared_paths_appear_on_it():
    doc = {**CONTRACT, "file_access": [{"path": f"{HOME}/notes", "mode": "ro"}]}
    args = build(doc)
    assert ("--tmpfs", HOME) in [(args[i], args[i + 1]) for i in range(len(args) - 1)]
    assert HOME not in {src for src, _ in pairs(args, "--ro-bind-try")}
    assert f"{HOME}/notes" in {src for src, _ in pairs(args, "--ro-bind-try")}
    assert args.index(HOME) < args.index(f"{HOME}/notes")  # 임시 홈을 먼저 만든 뒤 붙인다.


def test_an_executable_at_the_top_of_home_binds_only_the_file():
    doc = {**CONTRACT, "executable": f"{HOME}/srv", "argv": [], "cwd": None,
           "file_access": []}
    assert agent.sandbox_mounts(doc, HOME) == [(f"{HOME}/srv", "ro")]
    assert build(doc)[build(doc).index("--chdir") + 1] == "/"


def test_nested_paths_with_the_same_mode_are_not_repeated_and_rw_wins():
    doc = {
        **CONTRACT,
        "file_access": [
            {"path": "/work/job/cache", "mode": "ro"},
            {"path": "/work/job/out", "mode": "rw"},
            {"path": "/work/job", "mode": "rw"},
        ],
    }
    assert agent.sandbox_mounts(doc, HOME) == [
        ("/opt/srv", "ro"),
        ("/work/job", "rw"),
        ("/work/job/cache", "ro"),
    ]


def plan(policy, *, which="/usr/bin/bwrap", ready=True, windows=False):
    return agent.plan_sandbox(
        CONTRACT, ["/opt/srv/bin/node", *CONTRACT["argv"]], policy, home=HOME,
        which=lambda name: which, ready=lambda path: ready, windows=windows,
    )  # fmt: skip


def test_a_managed_install_refuses_to_start_without_a_working_bwrap():
    managed = agent.Sandbox(managed=True)
    for which, ready in ((None, True), ("/usr/bin/bwrap", False)):
        with pytest.raises(agent.Refuse, match="bubblewrap"):
            plan(managed, which=which, ready=ready)


def test_an_operator_can_allow_an_unsandboxed_start_and_user_installs_fall_back():
    for policy in (agent.Sandbox(True, allow_unsandboxed=True), agent.Sandbox(False)):
        command, status = plan(policy, which=None)
        assert command is None and status == "none"
    command, status = plan(agent.Sandbox(True))
    assert status == "bwrap" and command[0] == "/usr/bin/bwrap"


def test_windows_uses_an_appcontainer_when_the_api_exists():
    got = agent.plan_sandbox(
        CONTRACT, [], agent.Sandbox(True), home=HOME, windows=True, win_ready=lambda: True
    )
    assert got == (None, "appcontainer")


def test_windows_without_appcontainer_refuses_when_managed_and_falls_back_otherwise():
    def plan_windows(policy):
        return agent.plan_sandbox(
            CONTRACT, [], policy, home=HOME, windows=True, win_ready=lambda: False
        )

    with pytest.raises(agent.Refuse, match="AppContainer"):
        plan_windows(agent.Sandbox(True))
    for policy in (agent.Sandbox(True, allow_unsandboxed=True), agent.Sandbox(False)):
        assert plan_windows(policy) == (None, "none")


def test_the_policy_comes_from_the_install_folder(tmp_path):
    assert agent.sandbox_policy(str(tmp_path)) == agent.Sandbox(True, False)  # 읽지 못하면 엄격
    (tmp_path / "state.json").write_text(json.dumps({"mode": "user"}))
    (tmp_path / "kit.json").write_text(json.dumps({"allow_unsandboxed": True}))
    assert agent.sandbox_policy(str(tmp_path)) == agent.Sandbox(False, True)
    (tmp_path / "kit.json").write_text(json.dumps({"allow_unsandboxed": "yes"}))
    assert agent.sandbox_policy(str(tmp_path)).allow_unsandboxed is False


def test_the_launch_record_carries_the_sandbox_status(tmp_path):
    agent.record_launch(str(tmp_path), "srv-1", "bwrap")
    (record,) = [json.loads(p.read_text()) for p in (tmp_path / "launched").iterdir()]
    assert record["sandbox"] == "bwrap" and record["server"] == "srv-1"


# --- 보고: 실행기 기록에서 프로세스 항목의 격리 상태를 만든다 ---------------------------------


def launched(home, server, pid, start, sandbox):
    folder = home / kit.STATE_REL / kit.LAUNCHED
    folder.mkdir(parents=True, exist_ok=True)
    record = {"server": server, "pid": pid, "start": start, "sandbox": sandbox}
    (folder / f"{server}-{pid}.json").write_text(json.dumps(record))


def test_process_items_get_the_status_of_live_launches_only(tmp_path, monkeypatch):
    monkeypatch.setattr(kit, "proc_start", lambda pid, windows: "t1" if pid != 9 else "other")
    launched(tmp_path, "a", 1, "t1", "bwrap")
    launched(tmp_path, "b", 2, "t1", "bwrap")
    launched(tmp_path, "b", 3, "t1", "none")
    launched(tmp_path, "c", 9, "t1", "none")  # 시작 시각이 달라 PID가 재사용된 기록이다.
    items = [{"server": n, "count": 1} for n in "abcd"]
    got = {i["server"]: i.get("sandbox") for i in kit.with_sandbox(items, tmp_path, False)}
    assert got == {"a": "bwrap", "b": "none", "c": None, "d": None}


def test_windows_processes_report_the_launcher_record_or_unsupported(tmp_path, monkeypatch):
    monkeypatch.setattr(kit, "proc_start", lambda pid, windows: "t1")
    launched(tmp_path, "a", 1, "t1", "appcontainer")
    items = [{"server": "a", "count": 1}, {"server": "b", "count": 1}]
    got = {i["server"]: i["sandbox"] for i in kit.with_sandbox(items, tmp_path, True)}
    assert got == {"a": "appcontainer", "b": "unsupported"}


def test_the_admin_reporter_does_not_read_user_profile_records(tmp_path, monkeypatch):
    monkeypatch.setattr(kit, "proc_start", lambda pid, windows: "t1")
    launched(tmp_path, "a", 1, "t1", "appcontainer")
    (item,) = kit.with_sandbox([{"server": "a", "count": 1}], tmp_path, True, read_records=False)
    assert item["sandbox"] == "unsupported"


# --- 실제 격리(Linux에 bubblewrap이 있을 때만) ----------------------------------------------


SYSTEM_PYTHON = "/usr/bin/python3"  # 시스템 인터프리터라 소유자와 무관하게 격리 안에서 열린다.


def _bwrap_works():
    path = shutil.which("bwrap")
    ready = bool(path) and sys.platform.startswith("linux") and agent.bwrap_ready(path)
    return ready and os.path.exists(SYSTEM_PYTHON)


real = pytest.mark.skipif(not _bwrap_works(), reason="needs Linux with a working bubblewrap")

SERVER = r"""
import json, socket, sys
out = {}
def attempt(name, fn):
    try:
        out[name] = fn()
    except Exception as exc:
        out[name] = "denied:" + type(exc).__name__
attempt("secret", lambda: open(sys.argv[1]).read())
attempt("declared_ro", lambda: open(sys.argv[2]).read())
def write_rw():
    open(sys.argv[3], "w").write("ok")
    return "written"
attempt("declared_rw", write_rw)
def write_ro():
    open(sys.argv[2], "w").write("no")
    return "written"
attempt("write_ro", write_ro)
def net():
    s = socket.socket(); s.settimeout(2); s.connect(("localhost", int(sys.argv[4]))); s.close()
    return "connected"
attempt("socket", net)
print(json.dumps(out))
"""


def contract_for(tmp_path, network="none"):
    secret = tmp_path / "secret.txt"
    secret.write_text("top")
    read_dir, write_dir = tmp_path / "in", tmp_path / "out"
    read_dir.mkdir(), write_dir.mkdir()
    (read_dir / "a.txt").write_text("hello")
    (tmp_path / "app").mkdir()
    script = tmp_path / "app" / "server.py"
    script.write_text(SERVER)
    listener = __import__("socket").socket()
    listener.bind(("localhost", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    argv = [str(script), str(secret), str(read_dir / "a.txt"),
            str(write_dir / "b.txt"), str(port)]  # fmt: skip
    doc = {
        "executable": SYSTEM_PYTHON, "argv": argv, "cwd": str(read_dir), "network": network,
        "file_access": [{"path": str(read_dir), "mode": "ro"},
                        {"path": str(write_dir), "mode": "rw"}],
    }  # fmt: skip
    return doc, listener, write_dir


def run_inside(doc):
    argv = [doc["executable"], *doc["argv"]]
    command = agent.bwrap_args(doc, argv, os.path.expanduser("~"), shutil.which("bwrap"))
    done = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@real
def test_the_sandboxed_server_reaches_only_what_the_contract_declares(tmp_path):
    doc, listener, write_dir = contract_for(tmp_path)
    try:
        seen = run_inside(doc)
    finally:
        listener.close()
    assert seen["declared_ro"] == "hello"
    assert seen["declared_rw"] == "written" and (write_dir / "b.txt").read_text() == "ok"
    assert seen["secret"].startswith("denied:")  # 선언하지 않은 파일
    assert seen["write_ro"].startswith("denied:")  # 읽기로 선언한 경로에는 쓸 수 없다.
    assert seen["socket"].startswith("denied:")  # 주소를 선언하지 않았다.


@real
def test_network_any_opens_the_network(tmp_path):
    doc, listener, _ = contract_for(tmp_path, network="any")
    try:
        seen = run_inside(doc)
    finally:
        listener.close()
    assert seen["socket"] == "connected"
    assert seen["secret"].startswith("denied:")  # 네트워크를 열어도 파일은 그대로 막힌다.


@real
def test_the_launcher_runs_the_server_inside_the_sandbox_and_exits_with_its_code(tmp_path):
    exe = tmp_path / "tool.sh"
    exe.write_text("#!/bin/sh\nexit 7\n")
    exe.chmod(0o755)
    digest = agent.sha256_file(str(exe))
    doc = {"executable": str(exe), "argv": [], "executable_sha256": digest,
           "script_sha256": None, "cwd": None, "env": {}}  # fmt: skip
    listing = tmp_path / "contracts.json"
    listing.write_text(json.dumps({"servers": {"s": doc}}))
    done = subprocess.run(
        [sys.executable, agent.__file__, "run", "--contracts", str(listing), "--server", "s",
         "--state-dir", str(tmp_path / "state")],
        capture_output=True, text=True, timeout=60,
    )  # fmt: skip
    assert done.returncode == 7
    (record,) = [json.loads(p.read_text()) for p in (tmp_path / "state/launched").iterdir()]
    assert record["sandbox"] == "bwrap"


@real
def test_a_package_runner_keeps_its_cache_and_leaves_the_rest_of_home_alone(tmp_path):
    home = tmp_path / "home"
    (home / ".npm").mkdir(parents=True)
    (home / "secret").write_text("x")
    runner = tmp_path / "tools" / "x" / "bin" / "npx"
    runner.parent.mkdir(parents=True)
    runner.write_text(
        '#!/bin/sh\necho cached > "$HOME/.npm/marker"\necho leaked > "$HOME/other"\n'
        '[ -e "$HOME/secret" ] && echo seen > "$HOME/.npm/secret-visible"\nexit 0\n'
    )
    runner.chmod(0o755)
    doc = {"executable": str(runner), "argv": ["-y", "pkg@1.0.0"], "cwd": None,
           "env": {"HOME": str(home)}, "network": "any"}  # fmt: skip
    command = agent.bwrap_args(doc, [str(runner), *doc["argv"]], str(home), shutil.which("bwrap"))
    env = {**os.environ, "HOME": str(home)}
    done = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 0, done.stderr
    assert (home / ".npm" / "marker").read_text() == "cached\n"
    assert not (home / "other").exists()  # 홈의 나머지는 비어 있는 임시 폴더다.
    assert not (home / ".npm" / "secret-visible").exists()
