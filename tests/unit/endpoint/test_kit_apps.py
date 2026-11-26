"""앱 자격(자체 스크립트): mint app 명령. 키는 PC에만 두고 스크립트에는 환경 변수로 넘긴다."""

import argparse
import json
import os
from datetime import UTC, datetime

import pytest
from kit_loader import load
from test_kit_install import make_kit, unpack

kit_module = load("mint_kit")
SECRET = "sk-app-" + "x" * 24
FUTURE = datetime(2099, 1, 1, tzinfo=UTC).isoformat()
PAST = datetime(2000, 1, 1, tzinfo=UTC).isoformat()


class FakeGateway:
    def __init__(self, replies):
        self.replies, self.calls = replies, []

    def json(self, method, path, body=None):
        self.calls.append((method, path, body))
        return self.replies.get((method, path.split("/")[-1] if method == "DELETE" else path),
                                (404, {"detail": "없음"}))


@pytest.fixture
def kit(tmp_path, reports):
    kit = make_kit(unpack(tmp_path, servers=("srv-1",)), tmp_path, managed=False)
    kit.install()
    return kit


def app_args(action, **values):
    base = {"app_action": action, "name": None, "days": None, "command": None, "shell": None}
    return argparse.Namespace(**{**base, **values})


def new_reply(name="bot"):
    return {("POST", kit_module.APPS_PATH): (201, {
        "id": "a1", "name": name, "key": SECRET, "key_alias": "mint-kit-app-bot-abc",
        "expires_at": FUTURE, "base_url": "https://mint.test",
        "mcp_url": "https://mint.test/mcp", "servers": ["docs-search"]})}


def run(kit, action, gateway=None, **values):
    lines = []
    code = kit_module.run_app(app_args(action, **values), kit, kit.load_state(), gateway,
                              out=lines.append, call=values.pop("call", None))
    return code, lines


def test_new_keeps_the_key_on_this_pc_only_and_says_how_to_run(kit):
    gateway = FakeGateway(new_reply())
    code, lines = run(kit, "new", gateway, name="bot", days=7)
    assert code == 0
    assert gateway.calls == [("POST", kit_module.APPS_PATH, {"name": "bot", "days": 7})]
    stored = json.loads(kit_module.app_file(kit.home, "bot").read_text())
    assert stored["key"] == SECRET and stored["id"] == "a1"
    if os.name == "posix":
        assert kit_module.app_file(kit.home, "bot").stat().st_mode & 0o777 == 0o600
    assert not any(SECRET in line for line in lines)  # 화면에 키를 보이지 않는다
    assert any("mint app run bot" in line for line in lines)
    code, lines = run(kit, "new", FakeGateway(new_reply()), name="bot")
    assert code == 1 and "이미" in lines[0]


def test_run_passes_the_key_only_as_environment_variables(kit):
    run(kit, "new", FakeGateway(new_reply()), name="bot")
    seen = {}

    def call(command, env):
        seen.update(command=command, env=env)
        return 0

    code, _ = run(kit, "run", name="bot", command=["--", "python", "bot.py"], call=call)
    assert code == 0 and seen["command"][1:] == ["bot.py"]
    assert os.path.basename(seen["command"][0]).lower().startswith("python")
    env = seen["env"]
    assert env["OPENAI_BASE_URL"] == "https://mint.test/v1" and env["OPENAI_API_KEY"] == SECRET
    assert env["ANTHROPIC_BASE_URL"] == "https://mint.test" and env["MINT_APP"] == "bot"
    assert env["MINT_MCP_URL"] == "https://mint.test/mcp"


def test_env_prints_shell_lines_and_mcp_config_has_no_key_literal(kit):
    run(kit, "new", FakeGateway(new_reply()), name="bot")
    code, lines = run(kit, "env", name="bot", shell="sh")
    assert code == 0 and "export OPENAI_BASE_URL=https://mint.test/v1" in lines
    _, lines = run(kit, "env", name="bot", shell="powershell")
    assert "$env:MINT_APP = 'bot'" in lines
    code, lines = run(kit, "mcp", name="bot")
    config = json.loads(lines[0])["mcpServers"]
    assert SECRET not in lines[0]
    assert config["litellm_gateway"]["headers"] == {"Authorization": "Bearer ${MINT_APP_KEY}"}
    args = config["srv-1"]["args"]
    assert "--mediate" in args and args[args.index("--client") + 1] == "app-bot"


def test_list_and_remove(kit):
    run(kit, "new", FakeGateway(new_reply()), name="bot")
    gateway = FakeGateway({("GET", kit_module.APPS_PATH): (200, {"apps": [
        {"id": "a1", "name": "bot", "expires_at": FUTURE, "revoked_at": None},
        {"id": "a0", "name": "old", "expires_at": PAST, "revoked_at": None},
    ]})})  # fmt: skip
    code, lines = run(kit, "list", gateway)
    assert code == 0 and "사용 중" in lines[1] and "키 있음" in lines[1] and "만료" in lines[2]
    gateway = FakeGateway({("DELETE", "a1"): (200, {"revoked": True})})
    code, lines = run(kit, "rm", gateway, name="bot")
    assert code == 0 and gateway.calls == [("DELETE", f"{kit_module.APPS_PATH}/a1", None)]
    assert not kit_module.app_file(kit.home, "bot").exists()


def test_bad_names_expired_apps_and_missing_keys_are_refused(kit):
    assert run(kit, "new", FakeGateway(new_reply()), name="Bad Name")[0] == 2
    assert run(kit, "run", name="ghost", command=["python"])[0] == 1
    reply = new_reply()
    reply[("POST", kit_module.APPS_PATH)][1]["expires_at"] = PAST
    run(kit, "new", FakeGateway(reply), name="bot")
    code, lines = run(kit, "run", name="bot", command=["python"])
    assert code == 1 and "만료" in lines[0]
    conflict = FakeGateway({("POST", kit_module.APPS_PATH): (409, {
        "detail": "같은 이름의 앱이 이미 있습니다."})})  # fmt: skip
    kit_module.app_file(kit.home, "bot").unlink()
    code, lines = run(kit, "new", conflict, name="bot")
    assert code == 1 and not kit_module.app_file(kit.home, "bot").exists()
    assert lines == ["앱 자격을 만들지 못했습니다: 같은 이름의 앱이 이미 있습니다."]


def test_the_cli_parses_app_commands(kit, monkeypatch):
    seen = {}
    monkeypatch.setattr(kit_module, "open_installed", lambda folder: (kit, {}, None))
    monkeypatch.setattr(kit_module, "run_app", lambda args, *rest: seen.update(vars(args)) or 0)
    assert kit_module.cli_main(["app", "run", "bot", "--", "python", "x.py", "--flag"]) == 0
    assert seen["name"] == "bot" and kit_module.app_command(seen["command"]) == [
        "python", "x.py", "--flag"]
    assert kit_module.cli_main(["app", "new", "bot", "--days", "7"]) == 0 and seen["days"] == 7


def test_rm_never_claims_a_revoke_it_did_not_make_and_run_explains_a_missing_command(
    kit, monkeypatch
):
    listing = FakeGateway({("GET", kit_module.APPS_PATH): (200, {"apps": []})})
    code, lines = run(kit, "rm", listing, name="typo")
    assert code == 1 and "없습니다" in lines[0]
    code, lines = run(kit, "rm", FakeGateway({("GET", kit_module.APPS_PATH): (0, None)}),
                      name="typo")
    assert code == 1 and "회수하고" not in lines[0]
    assert run(kit, "new", FakeGateway(new_reply()), name="bot\n")[0] == 2
    run(kit, "new", FakeGateway(new_reply()), name="bot")
    code, lines = run(kit, "run", name="bot", command=["--", "no-such-command-xyz"])
    assert code == 127 and "실행하지 못했습니다" in lines[0]
    seen = []
    monkeypatch.setattr(kit_module.shutil, "which",
                        lambda name, *a, **k: "C:/nodejs/npx.CMD" if name == "npx" else None)
    run(kit, "run", name="bot", command=["--", "npx", "tsx", "a.ts"],
        call=lambda command, env: seen.append(command) or 0)
    assert seen == [["C:/nodejs/npx.CMD", "tsx", "a.ts"]]  # Windows .cmd 명령도 띄운다


def test_a_server_started_from_an_app_script_never_gets_the_app_key():
    agent = load("mint_agent")
    env = agent.launch_env({"env": {"A": "1"}}, {
        "MINT_APP_KEY": SECRET, "OPENAI_API_KEY": SECRET, "ANTHROPIC_API_KEY": SECRET,
        "OPENAI_BASE_URL": "https://mint.test/v1", "GITHUB_TOKEN": "user-own", "PATH": "/bin"})
    assert SECRET not in env.values()
    assert env == {"OPENAI_BASE_URL": "https://mint.test/v1", "GITHUB_TOKEN": "user-own",
                   "PATH": "/bin", "TZ": "Etc/UTC", "A": "1"}


def test_servers_see_utc_unless_the_approved_contract_sets_a_timezone():
    """시간대를 도구 정의에 넣는 서버가 PC마다 다른 정의를 내놓지 않게 한다."""
    agent = load("mint_agent")
    assert agent.launch_env({}, {"TZ": "Asia/Seoul", "PATH": "/bin"})["TZ"] == "Etc/UTC"
    assert agent.launch_env({"env": {"TZ": "Asia/Seoul"}}, {})["TZ"] == "Asia/Seoul"
