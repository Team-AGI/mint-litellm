"""단말 검사: 보고 응답의 검사 권한, 격리 실행(Linux 전용), 제출 흐름, 신청 환경 변수, 화면 탭 3."""

import io
import json
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta, timezone

import pytest
from test_kit_install import kit_module, make_kit
from test_kit_pack import GOOD, pack_of, served

linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux") or kit_module.inspect_ready() is None,
    reason="격리 실행은 bubblewrap이 되는 Linux에서만",
)
DIGEST = "d" * 64


@pytest.fixture(autouse=True)
def _offline(reports):
    """설치가 실제 도구를 부르지 않고 보고가 밖으로 나가지 않게 한다."""


def later(minutes=45):
    when = datetime.now(timezone.utc) + timedelta(minutes=minutes)  # noqa: UP017
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def remote(ident="ins-1", intake="in-1", server="pyghidra-mcp", digest=DIGEST, **kw):
    return {
        "id": ident, "intake_id": intake, "server": server, "pack_sha256": digest,
        "contract": {"executable": sys.executable, "pack": {"entry": "demo:main"}},
        "expires_at": later(), **kw,
    }  # fmt: skip


# --- 보고 응답 ---------------------------------------------------------------------------------


def answers(monkeypatch, sent, reply):
    def post(url, key, payload, ca_file):
        sent.append(payload)
        return reply[0]

    monkeypatch.setattr(kit_module, "post", post)


def test_the_report_asks_for_inspections_and_stores_them_apart_from_the_harness_config(
    tmp_path, folder, reports, monkeypatch
):
    kit = make_kit(folder, tmp_path, managed=False)
    state = kit.install()
    contracts = (kit.programs / "contracts.json").read_bytes()
    sent, reply = [], [{"inspections": [remote()], "desired": []}]
    answers(monkeypatch, sent, reply)
    assert kit.report(state, "installed") is True
    assert sent[0]["capabilities"] == ["inspect"]
    assert [i["id"] for i in kit_module.load_inspections(kit.home)] == ["ins-1"]
    path = kit.home / ".cache/mint/inspections.json"
    # 하네스 설정·계약 파일·시작 허가에는 검사 권한이 새지 않는다.
    assert (kit.programs / "contracts.json").read_bytes() == contracts
    others = [p for p in [*kit.home.rglob("*"), *kit.programs.rglob("*")] if p.is_file()]
    assert all(b"ins-1" not in p.read_bytes() for p in others if p != path)
    kit.report(state, "removed")
    assert "capabilities" not in sent[-1]


def test_inspections_that_vanish_expire_or_look_wrong_are_dropped(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    kit.install()
    gone = remote("ins-2", "in-2", expires_at="2001-01-01T00:00:00Z")
    bad = [remote("a b"), remote(digest="x"), {"id": "ins-9"}, "text", remote("ins-8", server="")]
    kit_module.save_inspections(kit.home, [remote(), remote("ins-3", "in-3"), gone, *bad])
    assert [i["id"] for i in kit_module.load_inspections(kit.home)] == ["ins-1", "ins-3"]
    kit_module.set_inspection(kit.home, "ins-1", phase="result", body={"x": 1})
    kit_module.save_inspections(kit.home, [remote()])  # ins-3은 응답에서 사라졌다
    kept = kit_module.load_inspections(kit.home)
    assert [i["id"] for i in kept] == ["ins-1"] and kept[0]["body"] == {"x": 1}
    kit_module.save_inspections(kit.home, [remote(digest="e" * 64)])  # 묶음이 바뀌면 진행을 잊는다
    assert "body" not in kit_module.load_inspections(kit.home)[0]
    kit_module.save_inspections(kit.home, None)
    assert kit_module.load_inspections(kit.home) == []
    assert not (kit.home / ".cache/mint/inspections.json").exists()


def test_a_revoked_inspection_disappears_on_the_next_report(tmp_path, folder, monkeypatch):
    kit = make_kit(folder, tmp_path, managed=False)
    state = kit.install()
    sent, reply = [], [{"inspections": [remote()]}]
    answers(monkeypatch, sent, reply)
    kit.report(state, "installed")
    assert kit_module.load_inspections(kit.home)
    reply[0] = {"desired": []}  # 철회: 응답에 없다
    kit.report(state, "installed")
    assert kit_module.load_inspections(kit.home) == []


# --- 제출 흐름 ---------------------------------------------------------------------------------


class InspectGateway:
    def __init__(self, packs=None, start=200, result=(200,)):
        self.packs, self.start, self.result, self.calls = packs or {}, start, list(result), []

    def json(self, method, path, body=None):
        self.calls.append((method, path.rsplit("/", 1)[-1], body))
        if path.endswith("/start"):
            return self.start, {"started": True}
        status = self.result.pop(0) if len(self.result) > 1 else self.result[0]
        return status, {"recorded": True}

    def download(self, path, cap):
        data = self.packs.get(path.rsplit("/", 1)[-1])
        return (200, io.BytesIO(data)) if data is not None else (404, None)


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(kit_module.sys, "platform", "linux")


def prepared(tmp_path, folder):
    kit = make_kit(folder, tmp_path, managed=False)
    kit.install()
    digest, data = served(pack_of(GOOD))
    kit_module.save_inspections(kit.home, [remote(digest=digest)])
    return kit, digest, data


def test_a_device_inspection_downloads_starts_runs_and_submits_once(tmp_path, folder, linux):
    kit, digest, data = prepared(tmp_path, folder)
    body = {"pack_sha256": digest, "complete": True, "tools": [{"name": "t"}], "detail": {}}
    seen, lines = [], []

    def body_of(item, pack, home):
        seen.append((item["id"], kit_module.ready_status(pack, digest)))
        return body

    gateway = InspectGateway(packs=data)
    assert kit_module.run_inspect(kit, gateway, "in-1", out=lines.append, body_of=body_of) == 0
    assert seen == [("ins-1", "ok")] and lines == ["검사 제출함"]
    assert [c[1] for c in gateway.calls] == ["start", "result"] and gateway.calls[1][2] == body
    assert not (kit.home / ".cache/mint/inspect-packs" / digest[:16]).exists()
    assert kit_module.load_inspections(kit.home)[0]["phase"] == "submitted"
    assert "body" not in kit_module.load_inspections(kit.home)[0]
    again = []
    assert kit_module.run_inspect(kit, gateway, "ins-1", out=again.append) == 0
    assert again == ["검사 제출함"] and len(gateway.calls) == 2


def test_a_lost_result_response_resends_the_same_body_without_starting_again(
    tmp_path, folder, linux
):
    kit, digest, data = prepared(tmp_path, folder)
    body = {"pack_sha256": digest, "complete": False, "tools": [], "detail": {"stage": "x"}}
    first = InspectGateway(packs=data, result=(0,))
    lines = []
    run = kit_module.run_inspect
    assert run(kit, first, "pyghidra-mcp", out=lines.append, body_of=lambda *a: body) == 1
    assert "다시 시도" in lines[-1]
    second = InspectGateway(packs=data, result=(200,))
    assert run(kit, second, "pyghidra-mcp", out=lines.append, body_of=lambda *a: 1 / 0) == 0
    assert [c[1] for c in second.calls] == ["result"] and second.calls[0][2] == body
    assert lines[-1] == "검사 제출함"


def test_a_start_that_was_already_taken_stops_before_running(tmp_path, folder, linux):
    kit, digest, data = prepared(tmp_path, folder)
    lines = []
    gateway = InspectGateway(packs=data, start=409)
    assert kit_module.run_inspect(kit, gateway, "ins-1", out=lines.append,
                                  body_of=lambda *a: 1 / 0) == 1
    assert lines == ["이미 시작했거나 만료되었습니다"]
    assert [c[1] for c in gateway.calls] == ["start"]


def test_a_tampered_download_never_starts_the_inspection(tmp_path, folder, linux):
    kit, digest, data = prepared(tmp_path, folder)
    name = next(iter(GOOD))
    flipped = bytearray(data[name])
    flipped[10] ^= 1
    data[name] = bytes(flipped)
    gateway = InspectGateway(packs=data)
    assert kit_module.run_inspect(kit, gateway, "ins-1", out=lambda t: 0,
                                  body_of=lambda *a: 1 / 0) == 1
    assert gateway.calls == []


def test_a_device_without_isolation_submits_the_refusal_reason(
    tmp_path, folder, linux, monkeypatch
):
    kit, digest, data = prepared(tmp_path, folder)
    monkeypatch.setattr(kit_module, "inspect_ready", lambda bwrap=None: None)
    monkeypatch.setattr(kit_module, "inspect_run", lambda *a, **k: 1 / 0)  # 실행하지 않는다
    gateway = InspectGateway(packs=data)
    assert kit_module.run_inspect(kit, gateway, "in-1", out=lambda t: 0) == 0
    sent = gateway.calls[-1][2]
    assert sent["complete"] is False and sent["tools"] == []
    assert sent["detail"]["stage"] == "sandbox" and sent["detail"]["stderr_tail"]
    assert len(sent["detail"]["stderr_tail"]) <= 2048


def test_windows_refuses_without_calling_the_server(tmp_path, folder, monkeypatch):
    kit, digest, data = prepared(tmp_path, folder)
    monkeypatch.setattr(kit_module.sys, "platform", "win32")
    gateway, lines = InspectGateway(packs=data), []
    assert kit_module.run_inspect(kit, gateway, "ins-1", out=lines.append) == 1
    assert lines == ["이 단말에서는 검사할 수 없습니다"] and gateway.calls == []


def test_an_unknown_target_or_missing_key_says_so(tmp_path, folder):
    kit, digest, data = prepared(tmp_path, folder)
    lines = []
    assert kit_module.run_inspect(kit, InspectGateway(), "nothing", out=lines.append) == 1
    assert lines[-1] == "검사할 항목이 없습니다"
    assert kit_module.run_inspect(kit, None, "ins-1", out=lines.append) == 1
    assert kit_module.find_inspection(kit.home, "pyghidra-mcp")["id"] == "ins-1"


# --- 격리 실행(Linux 전용) ---------------------------------------------------------------------

SERVER = textwrap.dedent(
    """
    import json, os, socket, subprocess, sys, time

    def probe():
        out = {}
        try:
            socket.create_connection((".".join(["1"] * 4), 53), timeout=2).close()
            out["net"] = "open"
        except OSError as exc:
            out["net"] = "closed"
        out["home"] = sorted(os.listdir(os.environ["HOME"]))
        out["env"] = sorted(os.environ)
        out["limits"] = {
            line.split(None, 2)[0] + line.split(None, 2)[1]: line.split()[-3]
            for line in open("/proc/self/limits").read().splitlines()[1:]
            if line.startswith(("Max cpu", "Max data", "Max processes"))
        }
        for target in sys.argv[1:]:
            try:
                open(os.path.join(target, "new.txt"), "w").close()
                out["write"] = "allowed"
            except OSError:
                out["write"] = "refused"
            out["read"] = sorted(os.listdir(target))
        return out

    def main():
        mode = os.environ.get("MODE", "ok")
        if mode == "crash":
            sys.stderr.write("GHIDRA_INSTALL_DIR is not set")
            return 3
        if mode == "hang":
            time.sleep(600)
        if mode == "child":
            subprocess.Popen(["sleep", "3000.321"])
        for line in sys.stdin:
            msg = json.loads(line)
            if "id" not in msg:
                continue
            if msg["method"] == "initialize":
                result = {"protocolVersion": "2025-06-18", "capabilities": {}}
            elif mode == "many":
                result = {"tools": [{"name": "t%d" % i, "description": "d"} for i in range(201)]}
            else:
                page = msg["params"].get("cursor")
                tool = {"name": "p2" if page else "p1",
                        "description": json.dumps(probe()) if not page else "x"}
                result = {"tools": [tool]}
                if not page:
                    result["nextCursor"] = "c2"
            print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
    """
)


def pack_dir(tmp_path):
    folder = tmp_path / "pack"
    (folder / "demo").mkdir(parents=True, exist_ok=True)
    (folder / "demo/__init__.py").write_text(SERVER)
    return folder


def run_box(tmp_path, mode="ok", seconds=20, access=(), **extra):
    folder = pack_dir(tmp_path)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    (home / "secret.txt").write_text("hidden")
    contract = {
        "executable": sys.executable, "pack": {"entry": "demo:main"}, "env": {"MODE": mode},
        "argv": [a["path"] for a in access], "file_access": list(access), **extra,
    }  # fmt: skip
    bwrap = kit_module.inspect_ready()
    cmd, env = kit_module.inspect_launch(contract, str(folder), str(home), bwrap)
    return kit_module.inspect_run(cmd, env, DIGEST, seconds=seconds), cmd, env


@linux_only
def test_the_box_has_no_network_an_empty_home_a_clean_env_and_read_only_files(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "lib.so").write_text("x")
    body, cmd, env = run_box(tmp_path, access=[{"path": str(data), "mode": "rw"}])
    assert "--share-net" not in cmd and "--unshare-net" in cmd
    assert body["complete"] is True and [t["name"] for t in body["tools"]] == ["p1", "p2"]
    seen = json.loads(body["tools"][0]["description"])
    assert seen["net"] == "closed" and seen["home"] == []
    assert set(seen["env"]) - {"PWD"} == {"PATH", "HOME", "LANG", "MODE"}
    assert seen["write"] == "refused" and seen["read"] == ["lib.so"]
    counted = seen["limits"]
    assert counted["Maxcpu"] == "30" and counted["Maxdata"] == str(1 << 30)
    assert int(counted["Maxprocesses"]) >= 64


@linux_only
def test_a_server_that_exits_early_reports_the_stage_the_exit_code_and_stderr(tmp_path):
    body, _, _ = run_box(tmp_path, mode="crash")
    assert body["complete"] is False and body["tools"] == []
    assert body["detail"]["stage"] == "initialize" and body["detail"]["exit_code"] == 3
    assert "GHIDRA_INSTALL_DIR" in body["detail"]["stderr_tail"]


@linux_only
def test_more_than_two_hundred_tools_is_not_a_complete_list(tmp_path):
    body, _, _ = run_box(tmp_path, mode="many")
    assert body["complete"] is False and body["tools"] == [] and body["detail"]["stage"] == "limit"


@linux_only
def test_a_server_that_never_answers_is_stopped_with_its_children(tmp_path):
    started = time.monotonic()
    body, _, _ = run_box(tmp_path, mode="hang", seconds=2)
    assert body["detail"]["stage"] == "timeout" and time.monotonic() - started < 10
    body, _, _ = run_box(tmp_path, mode="child", seconds=3)
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-f", "sleep 3000.321"], capture_output=True).stdout
    assert body["complete"] is True and left == b""


@linux_only
def test_the_rlimits_are_set_in_the_child_before_it_runs(tmp_path):
    code = "import resource;print(resource.getrlimit(resource.RLIMIT_CPU)[0],\
resource.getrlimit(resource.RLIMIT_DATA)[0],resource.getrlimit(resource.RLIMIT_NPROC)[0])"
    procs = kit_module.user_process_count()
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        preexec_fn=lambda: kit_module.apply_limits(procs),
    ).stdout.split()  # fmt: skip
    cpu, data, nproc = map(int, out)
    assert cpu == 30 and data == 1 << 30 and nproc <= procs + 64


def test_the_launch_never_shares_the_network_and_mounts_contract_paths_read_only(tmp_path):
    folder = tmp_path / "p"
    folder.mkdir()
    contract = {
        "executable": sys.executable, "pack": {"entry": "demo:main"},
        "file_access": [{"path": "/opt/ghidra", "mode": "rw"}, {"path": "/data/in", "mode": "ro"}],
        "env": {"GHIDRA_INSTALL_DIR": "/opt/ghidra", "LD_PRELOAD": "/x", "PATH": "/evil"},
    }  # fmt: skip
    cmd, env = kit_module.inspect_launch(contract, str(folder), "/home/u", "bwrap")
    assert "--share-net" not in cmd and cmd.count("--unshare-net") == 1
    assert "--bind" not in cmd and "--bind-try" not in cmd
    at = cmd.index("/opt/ghidra")
    assert cmd[at - 1: at + 2] == ["--ro-bind-try", "/opt/ghidra", "/opt/ghidra"]
    assert ["--tmpfs", "/home/u"] == cmd[cmd.index("/home/u") - 1: cmd.index("/home/u") + 1][:2]
    assert env["GHIDRA_INSTALL_DIR"] == "/opt/ghidra" and "LD_PRELOAD" not in env
    assert env["PATH"] == kit_module.INSPECT_PATH_ENV and env["HOME"] == "/home/u"
    broken = {**contract, "pack": {"entry": "nope"}}
    with pytest.raises(kit_module.PackError):
        kit_module.inspect_launch(broken, str(folder), "/home/u", "bwrap")


# --- 신청 환경 변수 ----------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS", "PATH",
    "HOME", "API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "1BAD", "A B",
])
def test_loader_and_secret_looking_names_are_refused(name):
    with pytest.raises(kit_module.AddError):
        kit_module.parse_env([f"{name}=x"])


def test_plain_names_stay_names_and_name_equals_value_becomes_values():
    values, names = kit_module.parse_env(["GHIDRA_INSTALL_DIR=/opt/ghidra", "TOKEN", "MODE=a=b"])
    assert values == {"GHIDRA_INSTALL_DIR": "/opt/ghidra", "MODE": "a=b"} and names == ["TOKEN"]
    assert kit_module.env_paths(values) == ["/opt/ghidra"]


def add_with(tmp_path, env, **kw):
    from test_kit_pack import FakeGateway, add_args

    gateway, lines = FakeGateway(), []
    code = kit_module.run_add(add_args(env=env, **kw), tmp_path, gateway, out=lines.append)
    return code, gateway.sent, lines


def test_add_sends_env_values_and_adds_read_access_for_path_values(tmp_path):
    code, sent, lines = add_with(tmp_path, ["GHIDRA_INSTALL_DIR=/opt/ghidra", "MODE=fast"])
    assert code == 0
    body = sent[0]
    assert body["env"] == {"GHIDRA_INSTALL_DIR": "/opt/ghidra", "MODE": "fast"}
    # 단말이 만든 본문을 서버 본문 모델이 그대로 받아야 한다(모르는 필드는 거부된다).
    from mint_litellm.endpoint.decide import IntakeBody

    IntakeBody.model_validate({**body, "request_id": "00000000-0000-4000-8000-000000000001"})
    assert {"path": "/opt/ghidra", "mode": "ro"} in body["file_access"]
    assert body["env_names"] == []
    assert any("/opt/ghidra" in line and "읽기" in line for line in lines)
    code, sent, _ = add_with(tmp_path, [], ro=["/opt/ghidra"])
    assert "env" not in sent[0]


def test_add_refuses_a_forbidden_env_before_sending_anything(tmp_path):
    code, sent, lines = add_with(tmp_path, ["LD_PRELOAD=/x"])
    assert code == 2 and sent == [] and "LD_PRELOAD" in lines[-1]


def test_the_interactive_prompt_asks_only_the_purpose_and_adds_path_values_as_read_access(tmp_path):
    from test_kit_pack import FakeGateway, add_args

    asked = []

    def read(question):
        asked.append(question)
        return "목적"

    gateway, lines = FakeGateway(), []
    args = add_args(yes=False, command=["uvx", "demo==1.0"], purpose=None,
                    env=["GHIDRA_INSTALL_DIR=/opt/ghidra"])
    code = kit_module.run_add(
        args, tmp_path, gateway, out=lines.append, read=read, tty=True, key=lambda: "enter")
    assert code == 0 and asked == ["목적 "]
    assert gateway.sent[0]["env"] == {"GHIDRA_INSTALL_DIR": "/opt/ghidra"}
    assert gateway.sent[0]["file_access"] == [{"path": "/opt/ghidra", "mode": "ro"}]


# --- 화면 탭 3 ---------------------------------------------------------------------------------


def screen_model(phase=None):
    need = {**remote(), "phase": phase} if phase else remote()
    return {
        "connected": True, "user": "u", "key": "ok", "mode": "관리형", "harnesses": ["claude"],
        "server_count": 0, "problems": [], "servers": [],
        "intakes": [{"id": "in-1", "server_id": "pyghidra-mcp", "status": "indeterminate",
                     "decision": None, "stage": "indeterminate", "next": "wait"}],
        "found": [], "inspections": {"in-1": need}, "now": time.time(),
    }  # fmt: skip


def test_tab_three_shows_the_remaining_time_and_s_starts_the_inspection():
    model, ui = screen_model(), {"tab": 2, "cursor": 0, "detail": False, "message": ""}
    lines = kit_module.render_screen(model, ui, 80, 24)
    assert any("단말 검사 필요 · s로 시작" in line for line in lines)
    assert all(kit_module.cell_width(line) <= 80 for line in lines)
    assert kit_module.handle_key("s", ui, model) == "inspect"
    done = screen_model("submitted")
    lines = kit_module.render_screen(done, ui, 80, 24)
    assert any("단말 검사 제출함" in line for line in lines)
    assert kit_module.handle_key("s", ui, done) is None
    plain = {**model, "inspections": {}}
    assert kit_module.handle_key("s", ui, plain) is None
    assert not any("단말 검사" in line for line in kit_module.render_screen(plain, ui, 80, 24))


def test_the_model_reads_stored_inspections_and_the_screen_runs_the_action(
    tmp_path, folder, reports
):
    kit = make_kit(folder, tmp_path, managed=False)
    state = kit.install()
    kit_module.save_inspections(kit.home, [remote()])
    me = {"user": "u", "servers": [], "intakes": [{"id": "in-1", "server_id": "pyghidra-mcp"}]}

    class Gate:
        def json(self, method, path, body=None):
            return 200, me

    model = kit_module.build_model(kit, state, Gate())
    assert model["inspections"] == {}  # 승인이 한 번이라 단말 검사는 기본 흐름에 없다
    model_with = {**model, "inspections": {"in-1": remote()}}
    assert kit_module.handle_key("s", {"tab": 2, "cursor": 0, "detail": False}, model_with)
    assert "inspect" in kit_module.CLI_COMMANDS


def test_the_inspection_reports_each_step_and_keeps_the_submitted_mark(tmp_path, folder, linux):
    kit, digest, data = prepared(tmp_path, folder)
    body = {"pack_sha256": digest, "complete": True, "tools": [], "detail": {}}
    steps = []
    gateway = InspectGateway(packs=data)
    code = kit_module.run_inspect(
        kit, gateway, "ins-1", out=lambda t: 0, body_of=lambda *a: body, progress=steps.append)
    assert code == 0 and steps[0].startswith("묶음 받는 중 1/")
    assert steps[-3:] == ["검사 시작", "도구 목록 받는 중", "제출 중"]
    kit_module.save_inspections(kit.home, [])  # 서버 목록에서 빠져도 제출 표시는 남는다
    assert kit_module.load_inspections(kit.home)[0]["phase"] == "submitted"
    row = {**screen_model("submitted")["intakes"][0], "reason": "x"}
    model = {**screen_model("submitted"), "intakes": [row]}
    ui = {"tab": 2, "cursor": 0, "detail": True, "message": ""}
    text = "\n".join(kit_module.render_screen(model, ui, 80, 24))
    assert "단말 검사 제출함 · 관리자 검토 중" in text
    open_text = "\n".join(kit_module.render_screen(screen_model(), ui, 80, 24))
    assert "단말 검사 필요 · s로 시작" in open_text
