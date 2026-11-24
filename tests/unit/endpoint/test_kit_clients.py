"""훅 없는 AI 도구: 설정 읽기·평문 키·자동 연결·보장, 실행기의 전송 전 중재, 연결 중지."""

import io
import json
import os
import threading

import pytest
from kit_loader import load
from test_kit_install import make_kit, unpack

from mint_litellm.endpoint.decide import ReportBody

kit_module = load("mint_kit")
agent = load("mint_agent")
KEY = "AIza" + "B" * 35  # 시험용 모양만 맞춘 값


def write(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --- 설정 읽기·평문 키 -------------------------------------------------------------------------


def test_other_ai_tools_are_read_and_keys_are_reported_without_values(tmp_path):
    home = tmp_path / "home"
    write(home / ".gemini/settings.json", {"mcpServers": {
        "maps": {"command": "npx", "args": ["-y", "maps-mcp"], "env": {"MAPS_API_KEY": KEY}},
        "notes": {"httpUrl": "https://notes.example.com/mcp"},
    }})  # fmt: skip
    write(home / ".config/Code/User/mcp.json", {"servers": {
        "git": {"type": "stdio", "command": "uvx", "args": ["mcp-server-git"]},
    }})  # fmt: skip
    (home / ".codeium/windsurf").mkdir(parents=True)
    (home / ".codeium/windsurf/mcp_config.json").write_text("{ not json")
    scan = kit_module.scan_mcp(home, (), windows=False)
    names = {(i["harness"], i["name"], i["kind"]) for i in scan["local_mcp"]}
    assert names == {("gemini", "maps", "stdio"), ("gemini", "notes", "http"),
                     ("vscode", "git", "stdio")}  # fmt: skip
    assert scan["plaintext_keys"] == [
        {"client": "gemini", "entry": "maps", "kind": "google", "where": "env"}
    ]
    assert KEY not in json.dumps(scan)
    assert scan["scan_errors"] == ["windsurf"]
    assert scan["counts"]["gemini"] == [2, 2]
    for item in scan["local_mcp"]:  # 서버가 받는 모양 그대로다
        ReportBody.model_validate({
            "kit_version": "1", "action": "installed", "mode": "user", "local_mcp": [item],
        })  # fmt: skip


@pytest.mark.parametrize(
    ("value", "field", "kind"),
    [
        ("sk-" + "ant-" + "a" * 30, "", "anthropic"),
        ("sk-" + "proj-" + "a" * 30, "", "openai"),
        ("ghp_" + "a" * 36, "", "github"),
        ("x" * 24, "GITLAB_TOKEN", "generic"),
        ("Bearer " + "x" * 30, "Authorization", "generic"),
        ("${env:OPENAI_API_KEY}", "OPENAI_API_KEY", None),
        ("%GITHUB_TOKEN%" + "x" * 10, "GITHUB_TOKEN", None),
        ("x" * 24, "MODE", None),
        ("short", "API_KEY", None),
    ],
)
def test_key_kinds(value, field, kind):
    assert kit_module.key_kind(value, field) == kind


def test_entries_of_this_kit_are_not_counted_as_outside_or_scanned_for_keys(tmp_path):
    home = tmp_path / "home"
    ours = {"command": "python3", "args": ["/x/mint_agent.py", "run", "--server", "srv-1"],
            "env": {"API_KEY": "y" * 30}}  # fmt: skip
    write(home / ".lmstudio/mcp.json", {"mcpServers": {"srv-1": ours}})
    scan = kit_module.scan_mcp(home, (), windows=False)
    assert scan["local_mcp"] == [] and scan["plaintext_keys"] == []
    assert scan["counts"]["lmstudio"] == [1, 0]


# --- 자동 연결 ---------------------------------------------------------------------------------


@pytest.fixture
def installed(tmp_path, reports):
    folder = unpack(tmp_path, servers=("srv-1", "srv-2"))
    kit = make_kit(folder, tmp_path, managed=False)
    home = kit.home
    write(home / ".gemini/settings.json", {"theme": "dark", "mcpServers": {
        "srv-2": {"command": "node", "args": ["mine.js"]},
    }})  # fmt: skip
    (home / ".config/Claude").mkdir(parents=True)
    kit.install()
    return kit


def test_install_connects_present_tools_and_keeps_user_entries(installed):
    home = installed.home
    gemini = json.loads((home / ".gemini/settings.json").read_text())
    assert gemini["theme"] == "dark"
    assert gemini["mcpServers"]["srv-2"] == {"command": "node", "args": ["mine.js"]}
    entry = gemini["mcpServers"]["srv-1"]
    assert entry["trust"] is True and kit_module.is_ours_entry(entry, "srv-1")
    args = entry["args"]
    assert args[args.index("--client") + 1] == "gemini" and "--mediate" in args
    assert args[args.index("--url") + 1] == "https://mint.test"
    desktop = json.loads((home / ".config/Claude/claude_desktop_config.json").read_text())
    assert set(desktop["mcpServers"]) == {"srv-1", "srv-2"}
    assert not (home / ".config/Code").exists()  # 없는 도구에는 쓰지 않는다
    record = kit_module.read_client_record(home)
    assert record["gemini"]["names"] == ["srv-1"] and record["claude_desktop"]["created"]


def test_rows_say_what_each_tool_is_covered_by(installed):
    home = installed.home
    scan = kit_module.scan_mcp(home, ("srv-1", "srv-2"), windows=False)
    rows = {r["client"]: r for r in kit_module.ai_client_rows(
        home, False, installed.harnesses, scan, kit_module.read_client_record(home))}
    assert rows["claude"]["coverage"] == "pre_call"
    assert (rows["gemini"]["connection"], rows["gemini"]["coverage"]) == ("mediated", "local_only")
    assert rows["gemini"]["restart_needed"] is True  # 아직 새 세션이 실행기를 띄우지 않았다
    agent.mark_client_start(str(home / ".cache/mint"), "gemini")
    rows = {r["client"]: r for r in kit_module.ai_client_rows(
        home, False, installed.harnesses, scan, kit_module.read_client_record(home))}
    assert rows["gemini"]["restart_needed"] is False
    ReportBody.model_validate({"kit_version": "1", "action": "installed", "mode": "user",
                               "ai_clients": list(rows.values())})  # fmt: skip


def test_a_retired_server_leaves_and_uninstall_removes_only_this_kits_entries(installed):
    home = installed.home
    write(home / ".cache/mint/retired.json", {"servers": ["srv-1"]})
    installed.connect_clients()
    gemini = json.loads((home / ".gemini/settings.json").read_text())
    assert "srv-1" not in gemini["mcpServers"] and "srv-2" in gemini["mcpServers"]
    installed.uninstall()
    gemini = json.loads((home / ".gemini/settings.json").read_text())
    assert gemini == {"theme": "dark", "mcpServers": {
        "srv-2": {"command": "node", "args": ["mine.js"]}}}  # fmt: skip
    assert not (home / ".config/Claude/claude_desktop_config.json").exists()  # 묶음이 만든 파일


def test_an_unreadable_settings_file_is_left_alone(installed):
    path = installed.home / ".gemini/settings.json"
    path.write_text("{ broken", encoding="utf-8")
    record = installed.connect_clients()
    assert path.read_text(encoding="utf-8") == "{ broken"
    assert record["gemini"]["failed"] is True


# --- 전송 전 중재 ------------------------------------------------------------------------------


class Pipe(io.BytesIO):
    def flush(self):
        pass


def call(rid, name="search", arguments=None):
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments or {}}}).encode() + b"\n"


def mediate(lines, judge, server_replies=b""):
    outcomes = []
    done = threading.Event()

    def outcome(*args):
        outcomes.append(args)
        done.set()

    mediator = agent.Mediator(judge, outcome)
    to_server, to_client = Pipe(), Pipe()
    mediator.sink = to_client
    mediator.feed(io.BytesIO(b"".join(lines)), to_server, None)
    mediator.drain(io.BytesIO(server_replies), to_client, None)
    if server_replies:
        done.wait(2)
    return to_server.getvalue(), to_client.getvalue(), outcomes


def test_an_allowed_call_is_sent_and_its_result_is_reported():
    seen = []
    sent, back, outcomes = mediate(
        [b'{"jsonrpc":"2.0","id":0,"method":"initialize"}\n', call(1, arguments={"q": 1})],
        lambda tool, arguments: seen.append((tool, arguments)) or "ref-1",
        b'{"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n',
    )
    assert seen == [("search", {"q": 1})]
    assert sent.count(b"\n") == 2 and b"tools/call" in sent
    assert outcomes and outcomes[0][:2] == ("ref-1", "success")
    assert back == b'{"jsonrpc":"2.0","id":1,"result":{"content":[]}}\n'


def test_a_denied_call_never_reaches_the_server_and_the_session_gets_a_tool_error():
    def judge(tool, arguments):
        raise agent.Refuse("관리자가 막은 도구입니다.")

    sent, back, _ = mediate([call("a")], judge)
    assert sent == b""
    reply = json.loads(back)
    assert reply["id"] == "a" and reply["result"]["isError"] is True
    assert "관리자가 막은 도구" in reply["result"]["content"][0]["text"]


def test_a_judge_error_or_bad_arguments_never_let_the_call_through():
    def broken(tool, arguments):
        raise RuntimeError("boom")

    sent, back, _ = mediate([call(7)], broken)
    assert sent == b"" and json.loads(back)["result"]["isError"] is True
    bad = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                      "params": {"name": "x", "arguments": [1]}}).encode() + b"\n"
    sent, back, _ = mediate([bad], lambda *a: "ref")
    assert sent == b"" and json.loads(back)["id"] == 8


def test_a_batch_forwards_the_rest_and_answers_the_denied_calls():
    def judge(tool, arguments):
        raise agent.Refuse("no")

    batch = json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]).encode() + b"\n"
    sent, back, _ = mediate([batch], judge)
    assert [m["id"] for m in json.loads(sent)] == [2]
    assert [m["id"] for m in json.loads(back)] == [1]


def test_an_oversized_call_is_not_sent():
    big = call(9, arguments={"blob": "x" * (agent.LINE_MAX + 10)})
    sent, back, _ = mediate([big], lambda *a: "ref")
    assert sent == b"" and json.loads(back)["id"] == 9


def test_the_mediated_judge_follows_the_outage_contract(tmp_path):
    listing = write(tmp_path / "contracts.json", {"servers": {"srv-1": {
        "executable": str(write(tmp_path / "bin", {})), "argv": [], "env": {},
    }}})  # fmt: skip
    state = str(tmp_path / "state")

    def down(*args):
        raise OSError("refused")

    mediator = agent.mediator_for("srv-1", contracts=str(listing), state_dir=state,
                                  url="https://mint.test", key="k", post=down, client="gemini")
    assert mediator.judge("search", {}) is None  # 승인 서버: 통과·기록
    (line,) = [json.loads(x) for x in open(os.path.join(state, agent.OFFLINE_FILE))]
    assert (line["server"], line["harness"]) == ("srv-1", "gemini")
    open(os.path.join(state, agent.PAUSED_FILE), "w").write("1")
    with pytest.raises(agent.Refuse, match="관리 AI 연결을 중지"):
        mediator.judge("search", {})


def test_a_paused_pc_does_not_start_servers(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / agent.PAUSED_FILE).write_text("2")
    with pytest.raises(agent.Refuse, match="관리 AI 연결을 중지"):
        agent.run_server("srv-1", str(tmp_path / "none.json"), {}, state_dir=str(state))


# --- 보고 응답: 중지·장애 기록 -----------------------------------------------------------------


def test_offline_calls_are_grouped_and_kept_until_the_report_succeeds(tmp_path):
    home = tmp_path / "home"
    state = str(home / ".cache/mint")
    for tool in ("a", "a", "b"):
        agent.record_offline(state, "srv-1", tool, "claude")
    first = kit_module.read_offline(home)
    assert sorted((g["tool"], g["count"]) for g in first) == [("a", 2), ("b", 1)]
    agent.record_offline(state, "srv-1", "c", "claude")  # 보고가 실패하면 다음에 함께 보낸다
    again = kit_module.read_offline(home)
    assert sorted((g["tool"], g["count"]) for g in again) == [("a", 2), ("b", 1), ("c", 1)]


def test_the_pause_answer_marks_the_pc_and_resume_clears_it(installed, tmp_path):
    kit, home = installed, installed.home
    folder = tmp_path / "admin"
    kit.answer = {"paused": True, "pause_gen": 4}
    assert kit_module.apply_user_answer(kit, lambda fn: fn(), home, folder, True)
    assert kit_module.read_paused_gen(home / ".cache/mint") == 4
    assert kit_module.read_paused_gen(folder) == 4
    kit.answer = {"paused": False, "pause_gen": 4}
    assert kit_module.apply_user_answer(kit, lambda fn: fn(), home, folder, True)
    assert kit_module.read_paused_gen(home / ".cache/mint") is None
    assert kit_module.read_paused_gen(folder) is None


def test_antigravity_uses_its_new_settings_folder_and_an_empty_file_is_empty_settings(
    tmp_path, reports
):
    kit = make_kit(unpack(tmp_path, servers=("srv-1",)), tmp_path, managed=False)
    new = kit.home / ".gemini/config/mcp_config.json"
    new.parent.mkdir(parents=True)
    new.write_text("")  # 도구가 빈 파일로 만들어 둔다
    (kit.home / ".gemini/antigravity").mkdir()  # 옛 판본의 상태 폴더도 남아 있다
    kit.install()
    assert list(json.loads(new.read_text())["mcpServers"]) == ["srv-1"]
    assert not (kit.home / ".gemini/antigravity/mcp_config.json").exists()
    assert kit_module.scan_mcp(kit.home, (), windows=False)["scan_errors"] == []


def test_a_resumed_pc_starts_right_after_pulling_a_report_and_a_paused_one_fails_fast():
    state = {"paused": True}
    calls = []

    def start():
        calls.append("start")
        if state["paused"]:
            raise agent.Paused(agent.PAUSED_TEXT)
        return "started"

    def report_resumed():
        calls.append("report")
        state["paused"] = False  # 보고 응답이 재개를 알려 표지를 지웠다

    def no_sleep(seconds):
        raise AssertionError("중지는 기다리지 않는다")

    assert agent.start_with_permit_retry(start, report_resumed, 8, no_sleep) == "started"
    assert calls == ["start", "report", "start"]
    state["paused"], calls[:] = True, []
    with pytest.raises(agent.Paused):
        agent.start_with_permit_retry(start, lambda: calls.append("report"), 8, no_sleep)
    assert calls == ["start", "report", "start"]


def test_the_mediated_request_names_the_tool_or_app_and_the_server_accepts_it(tmp_path):
    from mint_litellm.endpoint.decide import DecideBody

    listing = write(tmp_path / "contracts.json", {"servers": {"srv-1": {
        "executable": str(write(tmp_path / "bin", {})), "argv": [], "env": {},
    }}})  # fmt: skip
    sent = []

    def post(url, headers, body, timeout):
        sent.append(json.loads(body))
        return 200, json.dumps({"decision": "allow", "reference": "r1"}).encode()

    mediator = agent.mediator_for("srv-1", contracts=str(listing), state_dir=str(tmp_path / "s"),
                                  url="https://mint.test", key="k", post=post, client="app-bot")
    assert mediator.judge("search", {"q": 1}) == "r1"
    assert sent[0]["client"] == "app-bot"
    body = {"server": "builtin:claude", "tool": "Bash", "arguments": {}, "client": "app-bot"}
    assert DecideBody.model_validate(body).client == "app-bot"  # 서버가 받는 값이다
