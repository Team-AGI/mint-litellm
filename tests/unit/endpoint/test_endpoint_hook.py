import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import mint_litellm
from mint_litellm.endpoint import hook

HOOK = Path(mint_litellm.__file__).parent / "endpoint" / "hook.py"


def mcp_config(tmp_path, command=None):
    script = tmp_path / "server.py"
    script.write_text("print('x')\n", encoding="utf-8")
    config = {
        "mcpServers": {
            "cnt": {
                "command": command or sys.executable,
                "args": [str(script), "log.txt"],
                "env": {"MODE": "test"},
            }
        }
    }
    return config, script


def event(**override):
    base = {
        "tool_name": "mcp__cnt__echo",
        "mcp_server": {"name": "cnt", "source": "dynamic"},
        "tool_input": {"text": "hi"},
        "tool_use_id": "toolu_1",
        "cwd": "/work",
    }
    base.update(override)
    return base


def answering(status=200, document=None, raw=None, exc=None, seen=None):
    def post(url, headers, body, timeout):
        if seen is not None:
            seen.append((url, headers, json.loads(body), timeout))
        if exc is not None:
            raise exc
        return status, raw if raw is not None else json.dumps(document).encode()

    return post


def run_decide(tmp_path, post, ev=None):
    config, _ = mcp_config(tmp_path)
    hook.decide(ev or event(), url="http://svc/", key="sk-user", mcp_config=config, post=post)


def test_allow_returns_silently_and_sends_the_declared_contract(tmp_path):
    seen: list = []
    run_decide(tmp_path, answering(document={"decision": "allow", "reference": "r:1"}, seen=seen))
    ((url, headers, payload, timeout),) = seen
    assert url == "http://svc/mint/v1/decide" and headers["Authorization"] == "Bearer sk-user"
    assert payload["server"] == "cnt" and payload["tool"] == "echo"
    assert payload["arguments"] == {"text": "hi"} and timeout == hook.HTTP_TIMEOUT
    contract = payload["contract"]
    assert contract["executable_sha256"] == hook.sha256_file(contract["executable"])
    assert contract["script_sha256"] == hook.sha256_file(contract["argv"][0])
    assert contract["env"] == {"MODE": "test"} and "exec_definition_match" not in payload


def test_deny_blocks_with_code_and_reference(tmp_path):
    document = {"decision": "deny", "reference": "r:9", "error": {"code": "MINT-X"}}
    with pytest.raises(hook.Refuse, match="MINT-X.*r:9"):
        run_decide(tmp_path, answering(document=document))


@pytest.mark.parametrize(
    "post",
    [
        answering(status=500, document={"decision": "allow"}),
        answering(status=401, document={"decision": "allow"}),
        answering(raw=b"{not json"),
        answering(raw=b"[]"),
        answering(document={"decision": "maybe"}),
        answering(document={}),
        answering(raw=b" " * (hook.MAX_RESPONSE + 1)),
        answering(exc=TimeoutError()),
        answering(exc=ConnectionRefusedError()),
    ],
)
def test_anything_but_a_clean_allow_blocks(tmp_path, post):
    with pytest.raises(hook.Refuse):
        run_decide(tmp_path, post)


@pytest.mark.parametrize(
    "ev",
    [
        event(mcp_server=None),
        event(tool_name="mcp__other__echo"),
        event(tool_name="mcp__cnt__"),
        event(tool_input="text"),
        event(mcp_server={"name": "missing"}, tool_name="mcp__missing__echo"),
    ],
)
def test_malformed_or_unknown_calls_block_without_asking(tmp_path, ev):
    seen: list = []
    with pytest.raises(hook.Refuse):
        run_decide(tmp_path, answering(document={"decision": "allow"}, seen=seen), ev)
    assert seen == []


def test_missing_command_blocks(tmp_path):
    config, _ = mcp_config(tmp_path, command="no-such-command-xyz")
    with pytest.raises(hook.Refuse, match="not found"):
        hook.decide(
            event(),
            url="http://svc",
            key="k",
            mcp_config=config,
            post=answering(document={"decision": "allow"}),
        )


def test_non_mcp_tools_are_not_this_hooks_business(tmp_path):
    seen: list = []
    run_decide(tmp_path, answering(document={"decision": "deny"}, seen=seen), {"tool_name": "Bash"})
    assert seen == []


# ---- 프로세스 단위: 종료 코드와 시간 상한 -------------------------------------------------------


class Service(BaseHTTPRequestHandler):
    mode = "allow"
    hits = 0

    def do_POST(self):
        type(self).hits += 1
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.mode == "hang":
            time.sleep(2)
        answer = {
            "allow": {"decision": "allow", "reference": "r:1"},
            "deny": {"decision": "deny", "reference": "r:2", "error": {"code": "MINT-D"}},
        }
        body = json.dumps(answer.get(self.mode, {})).encode()
        self.send_response(500 if self.mode == "error" else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def service():
    server = HTTPServer(("localhost", 0), Service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Service.hits = 0
    yield server
    server.shutdown()


def run_process(tmp_path, service, mode, *flags, ev=None):
    config, _ = mcp_config(tmp_path)
    (tmp_path / "mcp.json").write_text(json.dumps(config), encoding="utf-8")
    (tmp_path / "key").write_text("sk-user\n", encoding="utf-8")
    Service.mode = mode
    started = time.monotonic()
    done = subprocess.run(
        [
            sys.executable,
            str(HOOK),
            "--url",
            f"http://localhost:{service.server_port}",
            "--key-file",
            str(tmp_path / "key"),
            "--mcp-config",
            str(tmp_path / "mcp.json"),
            *flags,
        ],
        input=json.dumps(ev or event()),
        capture_output=True,
        text=True,
        timeout=30,
    )
    return done, time.monotonic() - started


def test_process_exit_codes(tmp_path, service):
    allowed, _ = run_process(tmp_path, service, "allow")
    assert (allowed.returncode, allowed.stdout, allowed.stderr) == (0, "", "")
    denied, _ = run_process(tmp_path, service, "deny")
    assert denied.returncode == 2 and "MINT-D" in denied.stderr and denied.stdout == ""
    errored, _ = run_process(tmp_path, service, "error")
    assert errored.returncode == 2


def test_process_never_retries(tmp_path, service):
    run_process(tmp_path, service, "error")
    assert Service.hits == 1


def test_http_timeout_blocks_before_the_deadline(tmp_path, service):
    done, elapsed = run_process(
        tmp_path, service, "hang", "--http-timeout", "0.5", "--deadline", "3"
    )
    assert done.returncode == 2 and "unreachable" in done.stderr and elapsed < 3


def test_watchdog_blocks_when_the_http_layer_does_not_return(tmp_path, service):
    done, elapsed = run_process(
        tmp_path, service, "hang", "--http-timeout", "30", "--deadline", "0.8"
    )
    assert done.returncode == 2 and "timed out" in done.stderr and elapsed < 4


def test_unreadable_input_or_files_block(tmp_path, service):
    garbage = subprocess.run(
        [
            sys.executable,
            str(HOOK),
            "--url",
            "http://localhost:1",
            "--key-file",
            "nope",
            "--mcp-config",
            "nope",
        ],
        input="not json",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert garbage.returncode == 2 and garbage.stdout == ""
    usage = subprocess.run([sys.executable, str(HOOK)], capture_output=True, text=True, timeout=30)
    assert usage.returncode == 2
