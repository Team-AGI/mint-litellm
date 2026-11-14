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


# --- 호스트 허용 목록(network: hosts) -------------------------------------------------------


def quad(*parts):
    return ".".join(str(p) for p in parts)  # 소스에 주소 글자를 직접 두지 않는다


LO = quad(127, 0, 0, 1)
HOSTS = ["api.example.com", "*.cdn.example.com:443", f"{LO}:8080", "[::1]:9"]


def test_host_matching_is_exact_or_a_proper_subdomain_and_port_aware():
    ok, no = agent.host_matches, lambda *a: not agent.host_matches(*a)
    assert ok(HOSTS, "api.example.com", 1) and ok(HOSTS, "API.example.com.", 443)
    assert no(HOSTS, "example.com", 443) and no(HOSTS, "x.api.example.com", 443)
    assert ok(HOSTS, "a.cdn.example.com", 443) and ok(HOSTS, "a.b.cdn.example.com", 443)
    assert no(HOSTS, "a.cdn.example.com", 80) and no(HOSTS, "cdn.example.com", 443)
    assert no(HOSTS, "evilcdn.example.com", 443)  # 접미는 점 경계에서만
    assert ok(HOSTS, LO, 8080) and no(HOSTS, LO, 8081)
    assert ok(HOSTS, "[::1]", 9) and ok(HOSTS, "::1", 9)
    assert no(["*.0.0.1"], LO, 1)  # 와일드카드는 주소 글자에 맞지 않는다.


PUBLIC = quad(93, 184, 216, 34)


def fake(table):
    def resolve(host, port):
        if host not in table:
            raise OSError("no such name")
        return table[host]

    return resolve


def test_the_verdict_resolves_only_declared_names_and_refuses_private_answers():
    seen = []

    def resolve(host, port):
        seen.append(host)
        return {
            "api.example.com": [quad(10, 0, 0, 5), PUBLIC],
            "bad.cdn.example.com": [quad(10, 1, 1, 1)],
            "meta.cdn.example.com": [quad(169, 254, 169, 254)],
            "lo.cdn.example.com": ["::ffff:" + LO],
        }[host]

    verdict = lambda h, p: agent.egress_verdict(HOSTS, h, p, resolve)  # noqa: E731
    assert verdict("api.example.com", 443) == (PUBLIC, "ok")  # 사설 답은 건너뛴다.
    assert verdict("bad.cdn.example.com", 443)[0] is None
    assert verdict("meta.cdn.example.com", 443)[0] is None
    assert verdict("lo.cdn.example.com", 443)[0] is None
    assert verdict("other.example.org", 443) == (None, "host not declared")
    assert "other.example.org" not in seen  # 선언하지 않은 이름은 DNS로 새지 않는다.
    # 선언한 호스트 자체가 사설·루프백 주소 글자이면 그 주소만 허용한다.
    assert verdict(LO, 8080) == (LO, "ok")
    assert verdict("::1", 9) == ("::1", "ok")
    assert verdict(quad(127, 0, 0, 2), 8080)[0] is None
    assert agent.egress_verdict(HOSTS, "api.example.com", 1, fake({}))[1] == "name did not resolve"


def test_a_hosts_contract_runs_without_a_network_and_with_the_forwarder():
    doc = {**CONTRACT, "network": "hosts", "allowed_hosts": ["api.example.com"]}
    argv = [doc["executable"], *doc["argv"]]
    args = agent.bwrap_args(doc, argv, HOME, "bwrap", "/tmp/e", "/usr/bin/python3")
    assert "--unshare-all" in args and "--share-net" not in args
    assert "/etc/ssl" in args  # 인증서는 필요하다
    assert ("/tmp/e", agent.EGRESS_MOUNT) in pairs(args, "--ro-bind")
    tail = args[args.index("--") + 1 :]
    assert tail[:3] == ["/usr/bin/python3", "-I", "-c"] and tail[3] == agent.EGRESS_FORWARDER
    assert tail[4:] == [f"{agent.EGRESS_MOUNT}/proxy.sock", str(agent.EGRESS_PORT), agent.LOOPBACK,
                        "/opt/srv/bin/node", "/opt/srv/app/index.js"]  # fmt: skip
    with pytest.raises(agent.Refuse):  # 중계가 없으면 열어 두지 않고 시작하지 않는다.
        agent.bwrap_args(doc, [doc["executable"]], HOME, "bwrap")


def test_none_any_and_undeclared_networks_do_not_get_a_forwarder():
    for doc in ({**CONTRACT, "network": "none"}, {**CONTRACT, "network": "any"}, CONTRACT):
        args = build(doc)
        assert agent.EGRESS_FORWARDER not in args and agent.EGRESS_MOUNT not in args
    assert [agent.network_mode(d) for d in ({"network": "none"}, {"network": "hosts"}, {})] == [
        "none", "hosts", "open"]  # fmt: skip


def test_the_proxy_environment_overrides_inherited_bypass_lists():
    env = agent.proxy_env()
    url = f"http://{LO}:{agent.EGRESS_PORT}"
    assert {env[k] for k in ("HTTP_PROXY", "https_proxy", "ALL_PROXY")} == {url}
    assert env["NO_PROXY"] == "" == env["no_proxy"]


def test_refusal_counts_reach_the_process_report(tmp_path, monkeypatch):
    monkeypatch.setattr(kit, "proc_start", lambda pid, windows: "t1")
    launched(tmp_path, "s", 1, "t1", "bwrap")
    launched(tmp_path, "other", 2, "t1", "bwrap")
    path = tmp_path / kit.STATE_REL / kit.LAUNCHED / "s-1.json"
    agent.update_launch(str(path), egress_refused=3)
    items = [{"server": "s", "count": 1}, {"server": "other", "count": 1}]
    got = {i["server"]: i.get("egress_refused") for i in kit.with_sandbox(items, tmp_path, False)}
    assert got == {"s": 3, "other": None}


def test_unfiltered_flag_reaches_the_process_report(tmp_path, monkeypatch):
    monkeypatch.setattr(kit, "proc_start", lambda pid, windows: "t1")
    launched(tmp_path, "s", 1, "t1", "appcontainer")
    launched(tmp_path, "other", 2, "t1", "appcontainer")
    path = tmp_path / kit.STATE_REL / kit.LAUNCHED / "s-1.json"
    agent.update_launch(str(path), egress_unfiltered=True)
    items = [{"server": "s", "count": 1}, {"server": "other", "count": 1}]
    got = {i["server"]: i.get("egress_unfiltered") for i in kit.with_sandbox(items, tmp_path, True)}
    assert got == {"s": True, "other": None}


# --- 중계 판정(운영체제의 이름 해석 없이, 유닉스 소켓이 있는 곳에서) -----------------------------

import asyncio  # noqa: E402
import threading  # noqa: E402

posix = pytest.mark.skipif(os.name != "posix", reason="needs unix sockets")


class Echo:
    """로컬 시험 HTTP 서버(루프백). 받은 요청 경로를 본문으로 돌려준다."""

    def __init__(self):
        import http.server

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"hello " + self.path.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer((LO, 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def ask(sock_path, request: bytes, full: bool = True) -> bytes:
    async def go():
        reader, writer = await asyncio.open_unix_connection(sock_path)
        writer.write(request)
        data = await reader.read() if full else await reader.read(64)
        writer.close()
        return data

    return asyncio.run(go())


@posix
def test_the_proxy_forwards_declared_hosts_and_counts_what_it_refuses(tmp_path):
    echo, other = Echo(), Echo()
    refusals, lines = [], []
    sock = str(tmp_path / "p.sock")
    proxy = agent.EgressProxy([f"{LO}:{echo.port}", "named.example.com"], sock,
                              resolve=fake({"named.example.com": [LO]}),
                              log=lines.append, on_refuse=refusals.append)  # fmt: skip
    proxy.start()
    try:
        url = f"http://{LO}:{echo.port}/x?y=1"
        ok = ask(sock, f"GET {url} HTTP/1.1\r\nHost: h\r\n\r\n".encode())
        assert ok.startswith(b"HTTP/1.0 200") and ok.endswith(b"hello /x?y=1")
        undeclared = ask(sock, f"GET http://{LO}:{other.port}/ HTTP/1.1\r\n\r\n".encode())
        assert undeclared.startswith(b"HTTP/1.1 403")
        # 선언한 이름이 루프백으로 풀리면(주소 글자로 선언하지 않았으므로) 거절한다.
        named = ask(sock, b"CONNECT named.example.com:80 HTTP/1.1\r\n\r\n")
        assert named.startswith(b"HTTP/1.1 403")
        connect = ask(sock, f"CONNECT {LO}:{echo.port} HTTP/1.1\r\n\r\n".encode(), False)
        assert connect.startswith(b"HTTP/1.1 200 Connection Established")
        assert ask(sock, b"GET https://x/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400")
    finally:
        proxy.stop()
        echo.close(), other.close()
    assert refusals == [1, 2] and (proxy.allowed, proxy.refused) == (2, 2)
    assert any(f"allow {LO}" in x for x in lines) and any("refuse" in x for x in lines)


HOSTS_SERVER = r"""
import http.client, json, socket, sys, urllib.error, urllib.request
allowed, other, lo, proxy_port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
out = {}
def get(port):
    try:
        return urllib.request.urlopen(f"http://{lo}:{port}/ok", timeout=10).read().decode()
    except urllib.error.HTTPError as exc:
        return f"http {exc.code}"
    except Exception as exc:
        return "error " + type(exc).__name__
out["allowed"], out["other"] = get(allowed), get(other)
def tunnel():
    conn = http.client.HTTPConnection(lo, proxy_port, timeout=10)
    conn.set_tunnel(lo, int(allowed))
    conn.request("GET", "/tunnel")
    return conn.getresponse().read().decode()
def direct(port):
    s = socket.socket()
    s.settimeout(3)
    s.connect((lo, int(port)))
    return "connected"
for name, call in (("tunnel", tunnel), ("direct", lambda: direct(allowed))):
    try:
        out[name] = call()
    except Exception as exc:
        out[name] = "denied " + type(exc).__name__
print(json.dumps(out))
"""


@real
def test_a_hosts_server_reaches_only_declared_hosts_through_the_proxy(tmp_path):
    echo, other = Echo(), Echo()
    script = tmp_path / "server.py"
    script.write_text(HOSTS_SERVER)
    doc = {
        "executable": SYSTEM_PYTHON, "argv": [str(script), str(echo.port), str(other.port),
                                              agent.LOOPBACK, str(agent.EGRESS_PORT)],
        "executable_sha256": agent.sha256_file(SYSTEM_PYTHON), "script_sha256": None,
        "cwd": None, "env": {}, "network": "hosts", "allowed_hosts": [f"{LO}:{echo.port}"],
    }  # fmt: skip
    listing = tmp_path / "contracts.json"
    listing.write_text(json.dumps({"servers": {"s": doc}}))
    try:
        done = subprocess.run(
            [sys.executable, agent.__file__, "run", "--contracts", str(listing), "--server", "s",
             "--state-dir", str(tmp_path / "state")],
            capture_output=True, text=True, timeout=90,
        )  # fmt: skip
    finally:
        echo.close(), other.close()
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout)
    assert seen["allowed"] == "hello /ok" and seen["tunnel"] == "hello /tunnel"
    assert seen["other"] == "http 403"  # 선언하지 않은 호스트(포트)는 거절된다.
    assert seen["direct"].startswith("denied")  # 프록시를 거치지 않으면 어디에도 닿지 못한다.
    assert "mint-egress refuse" in done.stderr
    (record,) = [json.loads(p.read_text()) for p in (tmp_path / "state/launched").iterdir()]
    assert record["sandbox"] == "bwrap" and record["egress_refused"] == 1
    assert not list(__import__("pathlib").Path("/tmp").glob("mint-egress-*"))  # 중계 폴더는 지운다.


def test_windows_token_status_maps_children_of_launchers():
    launch = r"python C:\k\mint_agent.py run --contracts c --server "
    rows = [
        (10, 1, "python.exe", launch + "inside"),
        (11, 10, "python.exe", "server"),
        (12, 10, "conhost.exe", ""),  # 콘솔 호스트는 서버가 아니다.
        (20, 1, "python.exe", launch + "outside"),
        (21, 20, "node.exe", "server"),
        (30, 1, "python.exe", launch + "mixed"),
        (31, 30, "node.exe", "a"),
        (32, 30, "node.exe", "b"),
        (40, 1, "python.exe", launch + "locked"),
        (41, 40, "node.exe", "server"),
    ]
    mine = kit.win_container_name("inside", 10)
    sids = {11: "S-IN", 21: "", 31: "S-IN2", 32: "S-OTHER", 41: None}
    names = {mine: "S-IN", kit.win_container_name("mixed", 30): "S-IN2"}
    got = kit.classify_windows(rows, sids.get, lambda n: names.get(n, "S-X"))
    assert got == {"inside": "appcontainer", "outside": "none", "mixed": "none"}


def test_observed_token_status_beats_records_and_fills_the_admin_reporter(tmp_path, monkeypatch):
    monkeypatch.setattr(kit, "proc_start", lambda pid, windows: "t1")
    launched(tmp_path, "a", 1, "t1", "appcontainer")
    items = [{"server": n, "count": 1} for n in "abc"]
    observed = {"a": "none", "b": "appcontainer"}
    got = {
        i["server"]: i["sandbox"] for i in kit.with_sandbox(items, tmp_path, True, True, observed)
    }
    assert got == {"a": "none", "b": "appcontainer", "c": "unsupported"}
    (item,) = kit.with_sandbox([{"server": "b", "count": 1}], tmp_path, True, False, observed)
    assert item["sandbox"] == "appcontainer" and "egress_unfiltered" not in item
