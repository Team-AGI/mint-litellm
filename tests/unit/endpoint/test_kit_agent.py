"""단말 에이전트: 호출 전 판정, 호출 뒤 결과 보고, 승인된 계약만 시작하는 서버 실행기."""

import hashlib
import json
import os
import subprocess
import sys
import time

import pytest
from kit_loader import KIT, load

agent = load("mint_agent")
LINUX = sys.platform.startswith("linux")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class World:
    """승인된 서버 하나(실행 파일과 스크립트가 디스크에 있다)와 그 목록 파일."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.exe = tmp / "srv-bin"
        self.exe.write_bytes(b"binary-v1")
        self.script = tmp / "index.js"
        self.script.write_bytes(b"script-v1")
        self.doc = {
            "schema_version": 1, "identity_kind": "stdio", "executable": str(self.exe),
            "argv": [str(self.script)], "cwd": None, "executable_sha256": sha(b"binary-v1"),
            "script_sha256": sha(b"script-v1"), "env": {"MODE": "ro"}, "secret_refs": {},
        }  # fmt: skip
        self.listing = self.write_listing("contracts.json", self.doc)
        self.state = str(tmp / "state")

    def write_listing(self, name, doc):
        path = self.tmp / name
        path.write_text(json.dumps({"servers": {"srv-1": doc}}))
        return str(path)


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


class Wire:
    """결정·결과 경로 대역. 요청을 모으고 정해 둔 답을 준다."""

    def __init__(self, answer=None, status=200):
        self.answer = {"decision": "allow", "reference": "ref-1"} if answer is None else answer
        self.status = status
        self.requests = []

    def __call__(self, url, headers, body, timeout):
        self.requests.append((url, headers, json.loads(body)))
        raw = self.answer if isinstance(self.answer, bytes) else json.dumps(self.answer).encode()
        return self.status, raw


def event(**override):
    base = {"tool_name": "mcp__srv-1__search", "mcp_server": {"name": "srv-1"},
            "tool_input": {"q": "x"}, "tool_use_id": "toolu_1"}  # fmt: skip
    return base | override


def decide(world, wire, **override):
    agent.decide(
        event(**override), url="https://mint.test", key="sk-k", contracts=world.listing,
        state_dir=world.state, post=wire,
    )


def test_the_hook_reports_the_hashes_on_disk_and_no_identity_kind(world):
    wire = Wire()
    decide(world, wire)
    ((url, headers, body),) = wire.requests
    assert url == "https://mint.test/mint/v1/decide"
    assert headers["Authorization"] == "Bearer sk-k"
    assert (body["server"], body["tool"], body["tool_use_id"]) == ("srv-1", "search", "toolu_1")
    contract = body["contract"]
    assert "identity_kind" not in contract
    assert contract["executable_sha256"] == sha(b"binary-v1")
    assert contract["script_sha256"] == sha(b"script-v1")
    assert contract["env"] == {"MODE": "ro"} and contract["argv"] == [str(world.script)]


def test_a_server_file_that_changed_after_approval_is_reported_as_changed(world):
    world.script.write_bytes(b"script-v2")
    wire = Wire()
    decide(world, wire)
    assert wire.requests[0][2]["contract"]["script_sha256"] == sha(b"script-v2")
    world.exe.unlink()
    with pytest.raises(agent.Refuse, match="cannot be read"):
        decide(world, Wire())


def test_an_allowed_call_leaves_a_reference_for_the_result_hook(world):
    decide(world, Wire())
    path = os.path.join(world.state, "pending", "toolu_1")
    assert open(path).read() == "ref-1"
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "answer",
    [
        {"decision": "deny", "reference": "r:1", "error": {"code": "MINT-APPROVAL-ABSENT"}},
        {"decision": "maybe"},
        b"not json",
        b"x" * (agent.MAX_RESPONSE + 1),
        [],
    ],
)
def test_a_refusal_or_an_unreadable_answer_blocks_the_call(world, answer):
    with pytest.raises(agent.Refuse):
        decide(world, Wire(answer))
    assert not os.path.exists(os.path.join(world.state, "pending", "toolu_1"))


def test_an_error_status_or_an_unreachable_service_blocks_the_call(world):
    with pytest.raises(agent.Refuse, match="HTTP 503"):
        decide(world, Wire(status=503))

    def down(*args):
        raise OSError("refused")

    with pytest.raises(agent.Refuse, match="unreachable"):
        decide(world, down)


def test_a_server_that_is_not_approved_is_blocked_without_a_request(world):
    wire = Wire()
    with pytest.raises(agent.Refuse, match="not an approved"):
        decide(world, wire, tool_name="mcp__other__x", mcp_server={"name": "other"})
    assert wire.requests == []


def test_calls_that_are_not_mcp_tools_pass_without_a_request(world):
    wire = Wire()
    decide(world, wire, tool_name="Bash")
    assert wire.requests == []


def report(world, wire, failed=False, **override):
    return agent.report_result(
        event(**override), failed=failed, url="https://mint.test", key="sk-k",
        state_dir=world.state, post=wire,
    )


def test_the_call_identifier_is_never_used_as_a_path(world):
    decide(world, Wire(), tool_use_id="../escape")
    assert not os.path.exists(os.path.join(world.state, "pending"))
    assert report(world, Wire(), tool_use_id="../escape") is False


def test_the_result_hook_sends_the_reference_back_and_forgets_it(world):
    decide(world, Wire())
    wire = Wire({"recorded": True})
    assert report(world, wire, tool_response={"content": "ok"}) is True
    ((url, _, body),) = wire.requests
    assert url == "https://mint.test/mint/v1/result"
    size = len(json.dumps({"content": "ok"}))
    assert body == {"reference": "ref-1", "outcome": "success", "size_bytes": size}
    assert report(world, Wire()) is False  # 두 번 보고하지 않는다.


@pytest.mark.parametrize(
    ("extra", "outcome"), [({}, "error"), ({"is_interrupt": True}, "unknown")]
)
def test_a_failed_call_is_reported_as_an_error_or_an_unknown_outcome(world, extra, outcome):
    decide(world, Wire())
    wire = Wire({"recorded": True})
    assert report(world, wire, failed=True, **extra) is True
    assert wire.requests[0][2] == {"reference": "ref-1", "outcome": outcome}


def test_a_report_that_fails_keeps_the_reference_and_no_reference_sends_nothing(world):
    decide(world, Wire())
    assert report(world, Wire(status=500)) is False
    assert os.path.exists(os.path.join(world.state, "pending", "toolu_1"))
    wire = Wire()
    assert report(world, wire, tool_use_id="toolu_unknown") is False
    assert wire.requests == []


def test_references_older_than_a_day_are_removed_on_the_next_call(world):
    decide(world, Wire())
    old = os.path.join(world.state, "pending", "toolu_1")
    long_ago = time.time() - agent.PENDING_MAX_AGE - 60
    os.utime(old, (long_ago, long_ago))
    decide(world, Wire(), tool_use_id="toolu_2")
    assert sorted(os.listdir(os.path.join(world.state, "pending"))) == ["toolu_2"]


# --- 서버 실행기 -------------------------------------------------------------------------------


class Exec:
    def __init__(self):
        self.calls = []

    def __call__(self, target, argv, env):
        self.calls.append((target, argv, env))


def launch(world, environ=None):
    started = Exec()
    agent.run_server("srv-1", world.listing, environ or {}, execve=started)
    return started.calls


def test_the_launcher_starts_the_approved_server_with_a_clean_environment(world):
    environ = {
        "PATH": "/usr/bin", "LD_PRELOAD": "/tmp/x.so", "NODE_OPTIONS": "--inspect",
        "PYTHONPATH": "/tmp", "MODE": "rw",
    }  # fmt: skip
    ((target, argv, env),) = launch(world, environ)
    assert argv == [str(world.exe), str(world.script)]
    assert env == {"PATH": "/usr/bin", "MODE": "ro"}  # 승인된 값이 이긴다.
    assert isinstance(target, int)


def test_the_launcher_does_not_start_a_changed_executable_or_script(world):
    world.script.write_bytes(b"script-v2")
    with pytest.raises(agent.Refuse, match="script differs"):
        launch(world)
    world.script.write_bytes(b"script-v1")
    world.exe.write_bytes(b"binary-v2")
    with pytest.raises(agent.Refuse, match="executable differs"):
        launch(world)


def test_the_launcher_does_not_start_an_unknown_server_or_a_missing_list(world, tmp_path):
    with pytest.raises(agent.Refuse, match="not an approved"):
        agent.run_server("other", world.listing, {}, execve=Exec())
    with pytest.raises(agent.Refuse, match="cannot be read"):
        agent.run_server("srv-1", str(tmp_path / "none.json"), {}, execve=Exec())


def run_agent(*args, stdin=""):
    return subprocess.run(
        [sys.executable, str(KIT / "mint_agent.py"), *args],
        input=stdin, capture_output=True, text=True, timeout=30,
    )  # fmt: skip


def script_server(world, body: bytes, approved: bytes):
    """셸 스크립트 서버를 만들고, ``approved``의 해시로 승인한 목록 파일 경로를 돌려준다."""
    tool = world.tmp / "tool"
    tool.write_bytes(body)
    tool.chmod(0o755)
    doc = {**world.doc, "executable": str(tool), "argv": [], "script_sha256": None,
           "executable_sha256": sha(approved),
           "file_access": [{"path": str(world.tmp), "mode": "rw"}]}  # fmt: skip
    return tool, world.write_listing("tool.json", doc)


def test_a_refused_launch_exits_without_starting_anything(world):
    marker = world.tmp / "started"
    body = f"#!/bin/sh\necho started > '{marker}'\n".encode()
    _, listing = script_server(world, body, approved=b"something else")
    done = run_agent("run", "--contracts", listing, "--server", "srv-1")
    assert done.returncode == agent.REFUSED and not marker.exists()
    assert done.stdout == "" and "differs" in done.stderr


@pytest.mark.skipif(not LINUX, reason="executes a shell script")
def test_an_approved_script_server_really_starts_and_a_replaced_one_does_not(world):
    marker = world.tmp / "started"
    body = f"#!/bin/sh\necho started:$MODE > '{marker}'\n".encode()
    tool, listing = script_server(world, body, approved=body)
    args = ("run", "--contracts", listing, "--server", "srv-1")
    assert run_agent(*args).returncode == 0 and marker.read_text() == "started:ro\n"
    marker.unlink()
    tool.write_bytes(body + b"echo replaced\n")
    assert run_agent(*args).returncode == agent.REFUSED and not marker.exists()


def test_the_command_line_hook_blocks_on_bad_input_and_an_unreachable_service(world):
    key = world.tmp / "key"
    key.write_text("sk-k")
    base = (
        "--url", "http://localhost:9", "--key-file", str(key), "--contracts", world.listing,
        "--state-dir", world.state,
    )  # fmt: skip
    assert run_agent("pre", *base, stdin="not json").returncode == 2
    assert run_agent("pre", *base, stdin=json.dumps(event())).returncode == 2
    assert run_agent("pre", *base, stdin=json.dumps(event(tool_name="Bash"))).returncode == 0
    # 호출 뒤 훅은 어떤 경우에도 호출을 막지 않는다.
    assert run_agent("post", *base, stdin="not json").returncode == 0
    assert run_agent("post-failure", *base, stdin=json.dumps(event())).returncode == 0


def test_a_call_without_a_server_field_is_matched_to_the_approved_server(world):
    """Codex는 호출 정보에 서버 이름을 따로 주지 않는다."""
    wire = Wire()
    decide(world, wire, mcp_server=None)
    assert [(r[2]["server"], r[2]["tool"]) for r in wire.requests] == [("srv-1", "search")]
    with pytest.raises(agent.Refuse, match="no MCP server"):
        decide(world, wire, mcp_server=None, tool_name="mcp__other__x")
    assert len(wire.requests) == 1


def test_a_call_to_the_gateway_server_passes_the_hook_and_is_decided_inside_litellm(world):
    doc = json.loads(open(world.listing).read())
    doc["gateways"] = ["litellm_gateway"]
    open(world.listing, "w").write(json.dumps(doc))
    wire = Wire()
    for override in (
        {"tool_name": "mcp__litellm_gateway__mslearn_search",
         "mcp_server": {"name": "litellm_gateway"}},
        {"tool_name": "mcp__litellm_gateway__mslearn_search", "mcp_server": None},  # Codex
        {"tool_name": "mcp__litellm_gateway__mslearn_search",
         "mcp_server": {"name": "litellm-gateway"}},
        {"tool_name": "mcp__litellm-gateway__mslearn_search", "mcp_server": None},
    ):
        decide(world, wire, **override)
    assert wire.requests == []  # 로컬 판정 요청이 없다(서버 쪽 가드레일이 판정한다)
    assert not os.path.exists(os.path.join(world.state, "pending"))
    # 승인된 로컬 서버는 그대로 판정하고, 게이트웨이 접두를 가장한 이름은 통과시키지 않는다.
    decide(world, wire)
    assert [r[2]["server"] for r in wire.requests] == ["srv-1"]
    with pytest.raises(agent.Refuse, match="no MCP server"):
        decide(world, wire, mcp_server=None, tool_name="mcp__litellm_gatewayx__x")
    doc["gateways"] = []
    open(world.listing, "w").write(json.dumps(doc))
    with pytest.raises(agent.Refuse, match="no MCP server"):
        decide(world, wire, mcp_server=None, tool_name="mcp__litellm_gateway__x")


def test_a_local_server_named_like_the_gateway_is_still_decided_locally(world):
    doc = json.loads(open(world.listing).read())
    doc["servers"]["litellm_gateway__evil"] = doc["servers"].pop("srv-1")
    doc["gateways"] = ["litellm_gateway"]
    open(world.listing, "w").write(json.dumps(doc))
    wire = Wire()
    decide(world, wire, mcp_server=None, tool_name="mcp__litellm_gateway__evil__search")
    assert [r[2]["server"] for r in wire.requests] == ["litellm_gateway__evil"]


def test_the_hook_reads_utf8_input_whatever_the_console_encoding(world):
    key = world.tmp / "key"
    key.write_text("sk-k")
    body = json.dumps(event(tool_name="Bash", tool_input={"q": "한글 검색"}), ensure_ascii=False)
    done = subprocess.run(
        [sys.executable, str(KIT / "mint_agent.py"), "pre", "--url", "http://localhost:9",
         "--key-file", str(key), "--contracts", world.listing, "--state-dir", world.state],
        input=body.encode("utf-8"), capture_output=True, timeout=30,
    )  # fmt: skip
    assert done.returncode == 0


def test_without_exec_the_server_is_started_as_a_child_with_the_same_exit_code():
    with pytest.raises(SystemExit) as exit_:
        agent.spawn_and_exit(sys.executable, ["tool", "-c", "import sys; sys.exit(3)"], os.environ)
    assert exit_.value.code == 3


# --- 승인 결과 알림 ----------------------------------------------------------------------------


def test_the_notification_text_names_the_tool_and_never_carries_argument_values():
    ok = agent.notify_text({"server": "srv-1", "tool": "search", "outcome": "approved",
                            "arguments": {"q": "비밀"}, "display": {"q": "비밀"}})
    assert ok == "승인됨: srv-1.search — 같은 작업을 다시 요청하세요"
    no = agent.notify_text({"server": "srv-1", "tool": "search", "outcome": "rejected",
                            "reason": "범위\n밖 " + "x" * 300})
    assert no.startswith("거부됨: srv-1.search — 사유: 범위 밖 x") and len(no) < 200
    assert "\n" not in no and "비밀" not in ok + no
    assert agent.notify_text({"server": "s", "tool": "t", "outcome": "expired"}) is None
    assert agent.notify_text({"server": "s", "tool": "t", "outcome": "rejected"}) == "거부됨: s.t"


@pytest.mark.parametrize(
    ("system", "found", "first"),
    [("Windows", "powershell", "powershell"), ("Darwin", "osascript", "osascript"),
     ("Linux", "notify-send", "notify-send")],
)
def test_the_notification_command_follows_the_platform_and_passes_text_by_environment(
    system, found, first
):
    argv, env = agent.notify_command(system, "승인됨: a.b", which=lambda name: name)
    assert argv[0] == first and env["MINT_TEXT"] == "승인됨: a.b"
    if system != "Linux":
        assert "승인됨" not in " ".join(argv)  # 글은 명령줄에 들어가지 않는다
    assert agent.notify_command(system, "x", which=lambda name: None) is None


def test_polling_shows_each_new_outcome_and_keeps_the_cursor(world):
    wire = Wire({"cursor": "2026-01-01T00:00:00+00:00", "items": [
        {"server": "srv-1", "tool": "a", "outcome": "approved", "at": "x"},
        {"server": "srv-1", "tool": "b", "outcome": "rejected", "reason": "no", "at": "x"},
        {"server": "srv-1", "tool": "c", "outcome": "weird"},
    ]})
    shown = []
    kwargs = dict(url="https://mint.test", key="sk-k", state_dir=world.state, post=wire,
                  show=lambda text: shown.append(text) or True)
    os.makedirs(world.state)
    assert agent.poll_outcomes(**kwargs) == 2
    assert shown == ["승인됨: srv-1.a — 같은 작업을 다시 요청하세요", "거부됨: srv-1.b — 사유: no"]
    ((url, headers, body),) = wire.requests
    assert url == "https://mint.test/mint/v1/endpoint/outcomes" and body == {"since": None}
    agent.poll_outcomes(**kwargs)
    assert wire.requests[1][2] == {"since": "2026-01-01T00:00:00+00:00"}


def test_the_notify_loop_stops_after_a_notification_and_gives_up_when_unreachable(world):
    os.makedirs(world.state)
    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds

    items = [{"server": "s", "tool": "t", "outcome": "approved"}]
    wire = Wire({"cursor": "c", "items": []})
    answers = iter([[], [], items])

    def post(url, headers, body, timeout):
        wire.answer = {"cursor": "c", "items": next(answers)}
        return wire(url, headers, body, timeout)

    shown = []
    agent.notify_loop(url="https://mint.test", key="k", state_dir=world.state, post=post,
                      show=lambda t: shown.append(t) or True, sleep=sleep,
                      now=lambda: clock[0])
    assert len(shown) == 1 and len(wire.requests) == 3
    assert not os.path.exists(os.path.join(world.state, "notify.lock"))
    down = Wire(status=503)
    agent.notify_loop(url="https://mint.test", key="k", state_dir=world.state, post=down,
                      show=lambda t: True, sleep=sleep, now=lambda: clock[0])
    assert len(down.requests) == agent.NOTIFY_FAILURES


def test_a_blocked_call_with_an_open_request_starts_the_notifier_and_opt_out_is_honoured(
    world, monkeypatch
):
    started = []
    deny = {"decision": "deny", "reference": "r",
            "error": {"code": "MINT-CALL-APPROVAL-PENDING", "approval_requested": True}}
    with pytest.raises(agent.Refuse, match="approval_requested"):
        agent.decide(event(), url="https://mint.test", key="k", contracts=world.listing,
                     state_dir=world.state, post=Wire(deny), on_pending=lambda: started.append(1))
    assert started == [1]
    assert agent.notify_enabled(world.state, {}) and not agent.notify_enabled(
        world.state, {"MINT_NOTIFY": "0"})
    os.makedirs(world.state)
    open(os.path.join(world.state, agent.NOTIFY_OFF), "w").close()
    assert not agent.notify_enabled(world.state, {})


def test_hook_streams_are_read_and_written_as_utf8_whatever_the_locale_code_page():
    import io

    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp949")
    agent.utf8_streams(stream, object())  # 바꿀 수 없는 객체는 건너뛴다.
    stream.write("정책 위반")
    stream.flush()
    assert stream.buffer.getvalue().decode("utf-8") == "정책 위반"
