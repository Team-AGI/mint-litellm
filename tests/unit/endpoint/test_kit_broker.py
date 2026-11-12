"""훅의 연결 재사용: 호출마다 새 프로세스인 훅이 중계를 거쳐 결정 서버 연결을 이어 쓴다."""

import http.server
import json
import os
import subprocess
import sys
import threading
import time

import pytest
from kit_loader import KIT, load
from test_kit_agent import World

agent = load("mint_agent")
pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="유닉스 소켓")


class Server:
    """연결 수를 세는 HTTP/1.1 서버. ``drop``이면 응답 뒤 연결을 말없이 닫는다. 답은 값이나 함수."""

    def __init__(self, drop=False, answer=None):
        outer = self
        self.connections = 0
        self.requests = 0
        self.answer = answer or {"decision": "allow", "reference": "ref-1"}

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                outer.connections += 1

            def do_POST(self):
                sent = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests += 1
                answer = outer.answer(sent) if callable(outer.answer) else outer.answer
                raw = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = drop

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/mint/v1/decide"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    made = []

    def make(**kwargs):
        made.append(Server(**kwargs))
        return made[-1]

    yield make
    for item in made:
        item.close()


@pytest.fixture
def broker(tmp_path):
    sock = str(tmp_path / "conn.sock")
    thread = threading.Thread(target=agent.serve_broker, args=(sock, None, 0.5), daemon=True)
    thread.start()
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.02)
    yield sock, thread


def send(sock, url):
    headers = {"Content-Type": "application/json"}
    return agent.broker_post(sock, url, headers, '{"a": "한"}'.encode(), 2.0)


def test_sequential_requests_share_one_connection_and_the_broker_ends_when_idle(server, broker):
    sock, thread = broker
    srv = server()
    for _ in range(3):
        status, raw = send(sock, srv.url)
        assert status == 200 and json.loads(raw)["decision"] == "allow"
    assert (srv.requests, srv.connections) == (3, 1)
    assert oct(os.stat(sock).st_mode & 0o777) == "0o600"
    thread.join(5)
    assert not thread.is_alive() and not os.path.exists(sock)


def test_a_connection_the_server_closed_while_idle_is_replaced_once(server, broker):
    sock, _ = broker
    srv = server(drop=True)
    assert send(sock, srv.url)[0] == 200
    assert send(sock, srv.url)[0] == 200
    assert (srv.requests, srv.connections) == (2, 2)


def test_without_a_broker_the_hook_may_send_directly_but_a_failed_forward_is_an_error(
    tmp_path, server, broker
):
    with pytest.raises(agent.BrokerDown):
        send(str(tmp_path / "missing.sock"), "http://127.0.0.1:1/")
    sock, _ = broker
    with pytest.raises(OSError, match="ConnectionRefusedError"):
        send(sock, "http://127.0.0.1:1/mint/v1/decide")


def test_the_hook_process_reuses_the_connection_through_the_broker(tmp_path, server):
    world, srv = World(tmp_path), server()
    key = tmp_path / "key"
    key.write_text("sk-k")
    state = tmp_path / "s"
    base = [sys.executable, str(KIT / "mint_agent.py")]
    common = ["--url", srv.url.rsplit("/mint/", 1)[0], "--key-file", str(key),
              "--contracts", world.listing, "--state-dir", str(state)]  # fmt: skip
    daemon = subprocess.Popen([*base, "serve", *common, "--idle", "1"])
    try:
        for _ in range(100):
            if (state / "conn.sock").exists():
                break
            time.sleep(0.02)
        event = {"tool_name": "mcp__srv-1__search", "mcp_server": {"name": "srv-1"},
                 "tool_input": {"q": "x"}, "tool_use_id": "toolu_1"}  # fmt: skip
        for _ in range(3):
            done = subprocess.run([*base, "pre", *common], input=json.dumps(event).encode(),
                                  capture_output=True, timeout=10)  # fmt: skip
            assert done.returncode == 0, done.stderr
        assert (srv.requests, srv.connections) == (3, 1)
    finally:
        daemon.wait(10)


def test_the_hook_without_a_broker_still_decides_directly(tmp_path, server):
    world, srv = World(tmp_path), server(answer={"decision": "deny", "reference": "r:1"})
    key = tmp_path / "key"
    key.write_text("sk-k")
    event = {"tool_name": "mcp__srv-1__search", "mcp_server": {"name": "srv-1"},
             "tool_input": {"q": "x"}, "tool_use_id": "toolu_1"}  # fmt: skip
    done = subprocess.run(
        [sys.executable, str(KIT / "mint_agent.py"), "pre", "--url", srv.url.rsplit("/mint/", 1)[0],
         "--key-file", str(key), "--contracts", world.listing, "--state-dir", str(tmp_path / "s"),
         "--no-keepalive"],
        input=json.dumps(event).encode(), capture_output=True, timeout=10,
    )  # fmt: skip
    assert done.returncode == 2 and b"blocked by MINT" in done.stderr and srv.requests == 1


def test_a_refusal_with_a_mint_code_names_the_code_and_nothing_else_leaks_through():
    body = json.dumps({"detail": json.dumps({"error": {"code": "MINT-ENDPOINT-NOT-READY"}})})
    wire = lambda *a: (503, body.encode())  # noqa: E731
    with pytest.raises(agent.Refuse, match=r"HTTP 503, MINT-ENDPOINT-NOT-READY"):
        agent._call(wire, "https://m", "/p", "k", {}, 1.0)
    spaced = json.dumps({"detail": json.dumps({"error": {"code": "a b"}})}).encode()
    for odd in (b"not json", b'{"detail": "x"}', spaced):
        with pytest.raises(agent.Refuse, match=r"\(HTTP 503\)$"):
            agent._call(lambda *a, odd=odd: (503, odd), "https://m", "/p", "k", {}, 1.0)
