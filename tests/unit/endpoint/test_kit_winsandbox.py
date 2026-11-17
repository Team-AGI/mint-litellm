"""Windows AppContainer 격리: 권한 목록·기능·명령 만들기(어디서나)와 실제 격리(Windows에서만)."""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest
from kit_loader import KIT, load

agent = load("mint_agent")

WIN = {
    "executable": r"C:\Users\alice\tools\node\node.exe",
    "argv": [r"C:\Users\alice\srv\index.js"],
    "cwd": r"C:\Users\alice\srv",
    "file_access": [
        {"path": r"C:\data\in", "mode": "ro"},
        {"path": r"C:\data\out", "mode": "rw"},
        {"path": r"C:\data\out\sub", "mode": "ro"},
    ],
}
ENV = {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"}


def no_file(_path):
    raise OSError


def grants(doc=None, present=None):
    return agent.win_grants(
        doc or WIN, r"C:\Users\alice", ENV,
        exists=lambda p: present is None or p in present, real=lambda p: p, read_text=no_file,
    )  # fmt: skip


def test_grants_cover_the_declared_paths_the_runtime_and_the_script_folder():
    got = {path: (mode, declared) for path, mode, declared in grants()}
    assert got[r"C:\Users\alice\tools\node"] == ("RX", False)
    assert got[r"C:\Users\alice\srv"] == ("R", False)  # 스크립트·작업 폴더
    assert got[r"C:\data\in"] == ("R", True)
    assert got[r"C:\data\out"] == ("M", True)
    assert r"C:\data\out\sub" not in got  # 상위 폴더가 더 센 권한으로 이미 있다.
    assert set(got) == {
        r"C:\Users\alice\tools\node", r"C:\Users\alice\srv", r"C:\data\in", r"C:\data\out",
    }  # fmt: skip


def test_grants_skip_system_folders_and_missing_paths():
    doc = dict(WIN, executable=r"C:\Program Files\nodejs\node.exe")
    assert r"C:\Program Files\nodejs" not in {g[0] for g in grants(doc)}
    assert [g[0] for g in grants(present={r"C:\data\in"})] == [r"C:\data\in"]


def test_a_virtual_environment_grants_its_whole_folder_and_its_base_interpreter_folder():
    doc = dict(WIN, executable=r"C:\proj\.venv\Scripts\python.exe", argv=[], cwd=None)
    got = agent.win_grants(
        doc, r"C:\Users\alice", ENV, exists=lambda p: True, real=lambda p: p,
        read_text=lambda p: "home = C:\\Python312\nversion = 3.12\n",
    )  # fmt: skip
    assert {(g[0], g[1]) for g in got} >= {(r"C:\proj\.venv", "RX"), (r"C:\Python312", "RX")}


def test_package_runner_caches_are_modify_grants_and_other_programs_get_none():
    doc = dict(WIN, executable=r"C:\Program Files\nodejs\npx.cmd", argv=["-y", "pkg"], cwd=None)
    paths = {p: m for p, m, _ in grants(doc)}
    assert paths[r"C:\Users\alice\AppData\Roaming\npm"] == "M"
    assert paths[r"C:\Users\alice\AppData\Local\npm-cache"] == "M"
    other = dict(doc, executable=r"C:\Program Files\Git\bin\git.exe")
    assert agent.win_runner_caches(other, r"C:\Users\alice") == []


def test_network_capabilities_follow_the_declaration():
    assert agent.win_capabilities({"network": "none"}) == []
    assert agent.win_capabilities({"network": "any"}) == ["S-1-15-3-1", "S-1-15-3-3"]
    assert agent.win_capabilities({}) == ["S-1-15-3-1", "S-1-15-3-3"]  # 선언 없는 이전 계약
    # 호스트 목록: 거를 수 없으므로 인터넷만 열고 사설망·수신 기능은 주지 않는다.
    assert agent.win_capabilities({"network": "hosts", "allowed_hosts": ["a.example"]}) == [
        "S-1-15-3-1"
    ]


def test_icacls_commands_grant_inheritably_on_folders_and_remove_by_sid():
    sid = "S-1-15-2-1"
    assert agent.icacls_args("d", sid, "M", True)[2:4] == ["/grant", "*S-1-15-2-1:(OI)(CI)(M)"]
    assert agent.icacls_args("f.txt", sid, "R", False)[3] == "*S-1-15-2-1:(R)"
    assert agent.icacls_args("d", sid, None, True)[2:4] == ["/remove", "*S-1-15-2-1"]


def test_a_stale_record_is_revoked_and_a_live_one_is_kept(tmp_path, monkeypatch):
    folder = tmp_path / agent.ACL_TRACK
    folder.mkdir()
    for name, start in (("dead", "old"), ("live", "now")):
        record = {"pid": 7, "start": start, "sid": "S-1-15-2-9", "paths": [name]}
        (folder / f"{name}.json").write_text(json.dumps(record))
    calls = []
    monkeypatch.setattr(agent, "proc_start", lambda pid: "now")
    monkeypatch.setattr(agent, "_icacls", lambda args: calls.append(list(args)) or True)
    agent.reconcile_appcontainers(str(tmp_path))
    assert [(c[1], c[2]) for c in calls] == [("dead", "/remove")]
    assert sorted(p.name for p in folder.iterdir()) == ["live.json"]


def test_a_launch_refuses_when_managed_and_falls_back_when_not(tmp_path, monkeypatch):
    exe = tmp_path / "srv.exe"
    exe.write_bytes(b"x")
    contracts = tmp_path / "c.json"
    doc = {"executable": str(exe), "executable_sha256": agent.sha256_file(str(exe)), "argv": []}
    contracts.write_text(json.dumps({"servers": {"s": doc}}))

    def boom(*args):
        raise agent.SandboxUnavailable("no profile")

    monkeypatch.setattr(agent, "plan_sandbox", lambda *a, **k: (None, "appcontainer"))
    monkeypatch.setattr(agent.AppContainerRun, "prepare", boom)
    with pytest.raises(agent.Refuse, match="AppContainer"):
        agent.run_server("s", str(contracts), {}, sandbox=agent.Sandbox(True))
    started = []  # 사용자 수준은 격리 없이 시작하고 ``none``을 기록한다.
    monkeypatch.setattr(os, "name", "posix")  # exec 경로를 타게 해 시작만 본다.
    agent.run_server(
        "s", str(contracts), {}, execve=lambda *a: started.append("exec"),
        state_dir=str(tmp_path / "st"), sandbox=agent.Sandbox(False),
    )  # fmt: skip
    (record,) = (tmp_path / "st" / "launched").iterdir()
    assert json.loads(record.read_text())["sandbox"] == "none" and started == ["exec"]


def hosts_launch(tmp_path, monkeypatch, why):
    exe = tmp_path / "srv.exe"
    exe.write_bytes(b"x")
    doc = {
        "executable": str(exe), "executable_sha256": agent.sha256_file(str(exe)), "argv": [],
        "network": "hosts", "allowed_hosts": ["a.example"],
    }  # fmt: skip
    contracts = tmp_path / "c.json"
    contracts.write_text(json.dumps({"servers": {"s": doc}}))
    asked = []

    class Box:
        def limit_hosts(self, server, entries):
            asked.append((server, entries))
            return why

        def run(self):
            return 0

    monkeypatch.setattr(agent, "plan_sandbox", lambda *a, **k: (None, "appcontainer"))
    monkeypatch.setattr(agent.AppContainerRun, "prepare", lambda *a: Box())
    closed = []
    Box.close = lambda self: closed.append(1)
    with pytest.raises(agent.Refuse if why else SystemExit):
        agent.run_server("s", str(contracts), {}, state_dir=str(tmp_path / "st"),
                         sandbox=agent.Sandbox(True))  # fmt: skip
    (record,) = (tmp_path / "st" / "launched").iterdir()
    assert asked == [("s", ["a.example"])] and bool(closed) is bool(why)
    return json.loads(record.read_text())


def test_hosts_on_windows_without_a_firewall_rule_refuses_to_start_and_says_so(
    tmp_path, monkeypatch, capsys
):
    record = hosts_launch(tmp_path, monkeypatch, "no helper")
    assert "mint-egress unfiltered" in capsys.readouterr().err
    assert record["egress_unfiltered"] is True and "egress_filtered" not in record


def test_hosts_on_windows_with_a_firewall_rule_is_recorded_as_filtered(
    tmp_path, monkeypatch, capsys
):
    record = hosts_launch(tmp_path, monkeypatch, None)
    assert "mint-egress firewall" in capsys.readouterr().err
    assert record["egress_filtered"] is True and "egress_unfiltered" not in record


# --- 호스트 허용 방화벽 ----------------------------------------------------------------------


def v4(*parts):
    return ".".join(str(part) for part in parts)


ALLOWED = v4(1, 2, 3, 4)
OTHER = v4(5, 6, 7, 8)
PUBLIC = v4(93, 184, 216, 34)
PRIVATE = v4(10, 0, 0, 5)
DOC = v4(198, 51, 100, 7)
ALL_V4 = f"{v4(0, 0, 0, 0)}-{v4(255, 255, 255, 255)}"
ALL_V6 = "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"


def ask_for(profile="mint.s.1", allow=()):
    return {"op": "allow", "profile": profile, "server": "s", "pid": 1, "start": "5",
            "allow": list(allow)}  # fmt: skip


def test_allowed_hosts_resolve_to_public_addresses_and_ports():
    names = {"a.example": [PUBLIC, PRIVATE], "b.example": ["2606:2800:220:1::1"]}

    def resolve(host, port):
        if host not in names:
            raise OSError("no name")
        return names[host]

    got = agent.egress_allow_list(["a.example:443", "b.example", "gone.example", DOC], resolve)
    assert got == [
        {"ip": DOC, "ports": None},
        {"ip": "2606:2800:220:1::1", "ports": None},
        {"ip": PUBLIC, "ports": [443]},
    ]  # 사설 주소와 풀리지 않는 이름은 빠진다.
    both = agent.egress_allow_list(["a.example:443", "a.example"], resolve)
    assert both == [{"ip": PUBLIC, "ports": None}]  # 포트 없는 선언이 모든 포트를 연다.
    assert agent.egress_allow_list(["*.example.com"], resolve) is None  # 풀 수 없다.


def test_the_blocked_ranges_are_everything_but_the_allowed_addresses():
    assert agent.address_gaps([ALLOWED])[:2] == [
        f"{v4(0, 0, 0, 0)}-{v4(1, 2, 3, 3)}", f"{v4(1, 2, 3, 5)}-{v4(255, 255, 255, 255)}",
    ]  # fmt: skip
    edges = [v4(0, 0, 0, 0), v4(255, 255, 255, 255)]
    assert agent.address_gaps(edges)[0] == f"{v4(0, 0, 0, 1)}-{v4(255, 255, 255, 254)}"
    v6 = [r for r in agent.address_gaps([ALLOWED, "::1"]) if ":" in r]
    assert v6 == ["::", "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]  # 한 주소는 범위가 아니다
    assert agent.address_gaps([]) == [ALL_V4, ALL_V6]
    assert agent.port_gaps([443]) == "1-442,444-65535"
    assert agent.port_gaps([1, 65535]) == "2-65534"


def test_the_rule_script_blocks_one_package_and_closes_on_failure():
    allow = [{"ip": ALLOWED, "ports": [443]}, {"ip": OTHER, "ports": None}]
    names = agent.net_rules("mint.s.7", allow)
    ranges = [v4(0, 0, 0, 0) + "-" + v4(1, 2, 3, 3), v4(1, 2, 3, 5) + "-" + v4(5, 6, 7, 7),
              v4(5, 6, 7, 9) + "-" + v4(255, 255, 255, 255), ALL_V6]  # fmt: skip
    assert names[0] == ("MINT sandbox mint.s.7 a", ",".join(ranges), 0, "")
    ports = "1-442,444-65535"
    assert names[1:] == [
        ("MINT sandbox mint.s.7 0/6", ALLOWED, 6, ports),
        ("MINT sandbox mint.s.7 0/17", ALLOWED, 17, ports),
    ]  # 허용 주소라도 선언한 포트 밖은 막는다(TCP·UDP)
    script = agent.net_script("S-1-15-2-1-2", "mint.s.7", allow)
    assert script.count("  Block '") == 3 and "$r.LocalAppPackageId = 'S-1-15-2-1-2'" in script
    assert "$r.Action = 0" in script and "$r.Direction = 2" in script  # 나가는 차단
    assert "$r.Grouping = 'MINT sandbox mint.s.7'" in script
    assert "$p.Rules.Remove($n)" in script  # 실패하면 이번에 만든 규칙만 지운다
    assert "$p.Rules.Item($rule)" in script  # 이미 있으면 주소만 바꾼다(갱신 중에도 열리지 않는다)
    assert "exit 3" in script and "exit 4" in script  # 방화벽 꺼짐·실패는 시작을 거부하게 알린다


def test_a_request_is_checked_before_it_is_acted_on():
    ok = ask_for("mint.srv-1.42", [{"ip": ALLOWED, "ports": [443, 80]}])
    assert agent.net_request(ok)["allow"] == [{"ip": ALLOWED, "ports": [80, 443]}]
    assert agent.net_request({"op": "drop", "profile": "mint.srv-1.42"}) == {
        "op": "drop", "profile": "mint.srv-1.42",
    }  # fmt: skip
    for bad in (
        {**ok, "profile": "other.srv.1"}, {**ok, "profile": "mint.a b.1"},
        {**ok, "allow": [{"ip": ALLOWED + "; calc", "ports": None}]},
        {**ok, "allow": [{"ip": ALLOWED, "ports": [70000]}]},
        {**ok, "allow": [{"ip": ALLOWED, "ports": []}]},
        {**ok, "start": "x"}, {**ok, "server": "a'b"}, {**ok, "op": "other"}, "text", None,
    ):
        assert agent.net_request(bad) is None


def test_the_helper_applies_requests_drops_stale_rules_and_leaves_a_result(tmp_path, monkeypatch):
    requests = tmp_path / "net" / "req"
    rules = tmp_path / "net" / "rules"
    requests.mkdir(parents=True)
    rules.mkdir()
    ask = ask_for(allow=[{"ip": ALLOWED, "ports": None}])
    (requests / "mint.s.1.json").write_text(json.dumps(ask))
    (requests / "bad.json").write_text(json.dumps({"op": "allow", "profile": "x"}))
    (requests / "half.json").write_text("{")
    (rules / "mint.old.2.json").write_text(
        json.dumps({"profile": "mint.old.2", "server": "old", "pid": 2, "start": "1"})
    )
    applied, dropped = [], []
    monkeypatch.setattr(agent, "net_apply", lambda folder, request: applied.append(request) or None)
    monkeypatch.setattr(agent, "net_drop", lambda folder, profile: dropped.append(profile))
    monkeypatch.setattr(agent, "proc_start", lambda pid: None)  # 실행기가 모두 끝났다
    agent.net_serve(str(tmp_path))
    assert [r["profile"] for r in applied] == ["mint.s.1"]
    assert dropped == ["mint.old.2"]
    assert json.loads((tmp_path / "net" / "done" / "mint.s.1.json").read_text())["ok"] is True
    assert sorted(p.name for p in requests.iterdir()) == ["half.json"]  # 쓰는 중일 수 있어 둔다


def test_a_plain_user_asks_through_the_task_and_waits_for_the_answer(tmp_path, monkeypatch):
    (tmp_path / "net" / "req").mkdir(parents=True)
    done = tmp_path / "net" / "done"
    done.mkdir()
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        answer = {"ok": False, "reason": "firewall disabled"}
        (done / "mint.s.1.json").write_text(json.dumps(answer))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(agent, "_elevated", lambda: False)
    monkeypatch.setattr(subprocess, "run", run)
    assert agent.net_ask(str(tmp_path), ask_for(), wait=2) == "firewall disabled"
    assert calls == [["schtasks", "/Run", "/TN", agent.NET_TASK]]
    assert json.loads((tmp_path / "net" / "req" / "mint.s.1.json").read_text())["pid"] == 1
    assert agent.net_ask(str(tmp_path / "x"), ask_for()) == "no helper"  # 설치가 만든 작업이 없다


def test_an_elevated_launcher_applies_the_rule_itself(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(agent, "_elevated", lambda: True)
    monkeypatch.setattr(agent, "net_apply", lambda folder, request: seen.append("apply") or None)
    monkeypatch.setattr(agent, "net_drop", lambda folder, profile: seen.append("drop"))
    assert agent.net_ask(str(tmp_path), ask_for()) is None
    assert agent.net_ask(str(tmp_path), {"op": "drop", "profile": "mint.s.1"}) is None
    assert agent.net_ask(str(tmp_path), {"op": "drop", "profile": "bad"}) == "bad request"
    assert seen == ["apply", "drop"]


def test_revoking_a_container_drops_its_firewall_rules_too(monkeypatch):
    seen = []
    monkeypatch.setattr(agent, "net_ask", lambda folder, request: seen.append(request))
    monkeypatch.setattr(agent, "_icacls", lambda args: True)
    agent._revoke({"profile": "mint.s.1", "sid": "S-1-15-2-9", "paths": [], "net": True})
    agent._revoke({"profile": "mint.s.2", "sid": "S-1-15-2-9", "paths": []})
    assert seen == [{"op": "drop", "profile": "mint.s.1"}]


# --- 실제 격리(Windows에서만) ---------------------------------------------------------------

windows_only = pytest.mark.skipif(
    sys.platform != "win32" or not agent.appcontainer_ready(), reason="needs Windows 8+"
)
BASE_PYTHON = getattr(sys, "_base_executable", sys.executable)

SERVER = r"""
import json, os, socket, sys
out = {"pid": os.getpid()}
def attempt(name, fn):
    try:
        out[name] = fn()
    except Exception as exc:
        out[name] = "denied:" + type(exc).__name__
out["echo"] = sys.stdin.readline().strip().upper()
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
    s = socket.socket(); s.settimeout(3); s.connect(("localhost", int(sys.argv[4]))); s.close()
    return "connected"
attempt("socket", net)
print(json.dumps(out), flush=True)
if len(sys.argv) > 5:
    import time
    time.sleep(120)
"""


def setup_launch(tmp_path, network, hang=False):
    """실행기 사본·계약·서버 스크립트를 만든다. 서버가 읽는 비밀 파일은 선언 경로 밖에 둔다."""
    kit_dir = tmp_path / "kit"
    kit_dir.mkdir()
    shutil.copy(KIT / "mint_agent.py", kit_dir / "mint_agent.py")
    (kit_dir / "state.json").write_text(json.dumps({"mode": "managed"}))
    (tmp_path / "secret.txt").write_text("top")
    read_dir, write_dir, app = tmp_path / "in", tmp_path / "out", tmp_path / "app"
    for folder in (read_dir, write_dir, app):
        folder.mkdir()
    (read_dir / "a.txt").write_text("hello")
    (app / "server.py").write_text(SERVER)
    listener = socket.socket()
    listener.bind(("localhost", 0))
    listener.listen(1)
    argv = [str(app / "server.py"), str(tmp_path / "secret.txt"), str(read_dir / "a.txt"),
            str(write_dir / "b.txt"), str(listener.getsockname()[1])]  # fmt: skip
    if hang:
        argv.append("hang")
    doc = {
        "executable": BASE_PYTHON, "executable_sha256": agent.sha256_file(BASE_PYTHON),
        "argv": argv, "network": network,
        "file_access": [{"path": str(read_dir), "mode": "ro"},
                        {"path": str(write_dir), "mode": "rw"}],
    }  # fmt: skip
    contracts = tmp_path / "contracts.json"
    contracts.write_text(json.dumps({"servers": {"srv": doc}}))
    state = str(tmp_path / "state")
    command = [BASE_PYTHON, str(kit_dir / "mint_agent.py"), "run", "--contracts",
               str(contracts), "--server", "srv", "--state-dir", state]  # fmt: skip
    return command, listener, write_dir


def sids_on(path):
    shown = subprocess.run(["icacls", str(path)], capture_output=True, text=True).stdout
    return "S-1-15-2-" in shown


def run_launcher(command):
    done = subprocess.run(command, input="hello\n", capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


@windows_only
@pytest.mark.parametrize("network", ["none", "any"])
def test_the_server_reaches_only_what_the_contract_declares(tmp_path, network):
    command, listener, write_dir = setup_launch(tmp_path, network)
    try:
        seen = run_launcher(command)
    finally:
        listener.close()
    assert seen["echo"] == "HELLO"  # 표준 입출력이 서버까지 이어진다.
    assert seen["declared_ro"] == "hello"
    assert seen["declared_rw"] == "written" and (write_dir / "b.txt").read_text() == "ok"
    assert seen["secret"].startswith("denied:")  # 선언하지 않은 파일
    assert seen["write_ro"].startswith("denied:")  # 읽기로 선언한 경로에는 쓸 수 없다.
    if network == "none":
        assert seen["socket"].startswith("denied:")
    # 끝난 뒤에는 서버를 위해 더한 권한과 추적 기록이 남지 않는다.
    assert not sids_on(tmp_path / "in") and not sids_on(tmp_path / "out")
    assert not list((tmp_path / "state" / agent.ACL_TRACK).glob("*.json"))
    record = json.loads(next((tmp_path / "state" / "launched").iterdir()).read_text())
    assert record["sandbox"] == "appcontainer"


@windows_only
def test_the_server_dies_with_the_launcher_and_leftovers_are_reconciled(tmp_path):
    command, listener, _ = setup_launch(tmp_path, "none", hang=True)
    proc = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        proc.stdin.write("hi\n")
        proc.stdin.flush()
        pid = json.loads(proc.stdout.readline())["pid"]
        assert agent.proc_start(pid) is not None
        proc.kill()
        proc.wait(timeout=30)
        for _ in range(50):
            if agent.proc_start(pid) is None:
                break
            time.sleep(0.2)
        assert agent.proc_start(pid) is None  # 작업 개체가 서버를 함께 끝냈다.
        assert sids_on(tmp_path / "in")  # 실행기가 정리하지 못해 권한이 남았다.
        agent.reconcile_appcontainers(str(tmp_path / "state"))
        assert not sids_on(tmp_path / "in")  # 다음 시작 때 정리된다.
    finally:
        listener.close()
        proc.kill()


@windows_only
def test_the_token_check_tells_a_contained_server_from_a_plain_child(tmp_path):
    kit = load("mint_kit")
    command, listener, _ = setup_launch(tmp_path, "none", hang=True)
    contained = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        stderr=subprocess.DEVNULL,
    )  # fmt: skip
    fake = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);time.sleep(60)"
    )
    plain = subprocess.Popen(
        [sys.executable, "-c", fake, "mint_agent.py", "run", "--contracts", "c"]
        + ["--server", "plain"]
    )  # fmt: skip
    try:
        contained.stdin.write("hi\n")
        contained.stdin.flush()
        contained.stdout.readline()  # 서버가 AppContainer 안에서 떠 있다.
        got = {}
        for _ in range(50):
            got = kit.windows_sandbox_status()
            if {"srv", "plain"} <= set(got):
                break
            time.sleep(0.2)
        assert got["srv"] == "appcontainer"
        assert got["plain"] == "none"
    finally:
        listener.close()
        contained.kill()
        plain.kill()


RPC_SERVER = r"""
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "tools/list":
        result = {"tools": [{"name": "echo", "description": "d", "inputSchema": {
            "type": "object", "properties": {"text": {"type": "string"}}}}]}
    else:
        result = {"echo": msg["method"]}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"""


@windows_only
def test_tools_list_is_captured_from_a_contained_server_and_calls_round_trip(tmp_path):
    command, listener, _ = setup_launch(tmp_path, "none")
    listener.close()
    script = tmp_path / "app" / "rpc.py"
    script.write_text(RPC_SERVER)
    contracts = tmp_path / "contracts.json"
    doc = json.loads(contracts.read_text())
    doc["servers"]["srv"]["argv"] = [str(script)]
    contracts.write_text(json.dumps(doc))
    requests = [{"jsonrpc": "2.0", "id": i, "method": m}
                for i, m in ((1, "initialize"), (2, "tools/list"), (3, "tools/call"))]  # fmt: skip
    done = subprocess.run(
        command, input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True, text=True, timeout=180,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr
    replies = [json.loads(line) for line in done.stdout.splitlines()]
    assert [r["id"] for r in replies] == [1, 2, 3]
    assert replies[2]["result"] == {"echo": "tools/call"}
    saved = json.loads((tmp_path / "state" / "tools" / "srv.json").read_text())
    assert [t["name"] for t in saved["tools"]] == ["echo"]
    record = json.loads(next((tmp_path / "state" / "launched").iterdir()).read_text())
    assert record["sandbox"] == "appcontainer"


def test_the_pipe_relay_forwards_both_ways_and_taps_the_list(tmp_path, monkeypatch):
    import io
    import types

    in_r, in_w = os.pipe()  # 서버 입력
    out_r, out_w = os.pipe()  # 서버 출력
    request = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
    reply = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "tools": [{"name": "t", "description": "d", "inputSchema": {"type": "object"}}]
                },
            }
        ).encode()
        + b"\n"
    )
    sink = io.BytesIO()
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(request)))
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(buffer=sink))
    run = agent.AppContainerRun()
    run.tap = agent.ToolListTap(str(tmp_path), "srv")
    run.parent_fds = (in_w, out_r)
    drain = run._start_relay()
    with os.fdopen(in_r, "rb") as server_in:
        assert server_in.readline() == request  # 하네스 -> 서버
        assert server_in.read() == b""  # 하네스 입력이 끝나면 서버 입력도 닫힌다.
    os.write(out_w, reply)
    os.close(out_w)  # 서버가 끝나 출력이 닫힌다.
    drain.join(5)
    assert sink.getvalue() == reply  # 서버 -> 하네스
    saved = json.loads((tmp_path / "tools" / "srv.json").read_text())
    assert [t["name"] for t in saved["tools"]] == ["t"]


@windows_only
def test_an_interactive_session_keeps_the_default_desktop():
    import ctypes

    session = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
    if session.value == 0:
        pytest.skip("session 0 creates its own desktop")
    assert agent.private_desktop("S-1-15-2-1") is None


def test_reconcile_also_deletes_profiles_whose_record_is_gone(tmp_path, monkeypatch):
    gone = []
    monkeypatch.setattr(agent, "stale_profiles", lambda: ["mint.s.7"])
    monkeypatch.setattr(agent, "_revoke", lambda record: gone.append(record))
    agent.reconcile_appcontainers(str(tmp_path))  # 기록 폴더가 없어도 정리한다
    assert gone == [{"profile": "mint.s.7"}]


@windows_only
def test_stale_profiles_lists_only_profiles_of_finished_launchers():
    assert all(agent.PROFILE_NAME.match(name) for name in agent.stale_profiles())
    live = f"mint.s.{os.getpid()}"
    assert live not in agent.stale_profiles()


@windows_only
def test_permission_changes_take_turns_across_threads():
    import threading

    order = []
    release = threading.Event()

    def first():
        with agent._acl_lock():
            order.append("first in")
            release.wait(5)
            order.append("first out")

    def second():
        with agent._acl_lock():
            order.append("second in")

    one = threading.Thread(target=first)
    one.start()
    while "first in" not in order:
        time.sleep(0.01)
    two = threading.Thread(target=second)
    two.start()
    time.sleep(0.3)
    assert "second in" not in order  # 앞선 변경이 끝나기 전에는 들어가지 못한다
    release.set()
    one.join(10)
    two.join(10)
    assert order == ["first in", "first out", "second in"]


def test_new_addresses_are_added_to_the_allowed_set_never_dropped():
    old = [{"ip": ALLOWED, "ports": [443]}, {"ip": OTHER, "ports": [80]}]
    new = [
        {"ip": ALLOWED, "ports": [8443]}, {"ip": DOC, "ports": None}, {"ip": OTHER, "ports": None},
    ]
    got = {item["ip"]: item["ports"] for item in agent.merge_allow(old, new)}
    assert got == {ALLOWED: [443, 8443], OTHER: None, DOC: None}
    assert {i["ip"] for i in agent.merge_allow(old, [])} == {ALLOWED, OTHER}
