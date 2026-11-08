"""콘솔 수신 주소: ``*``은 주소족을 못 박지 않고 모든 주소에 연다."""

import argparse
import socket
import threading
import time

import pytest

from mint_litellm.console import server


def test_star_and_empty_mean_every_address_and_names_pass_through():
    assert server.bind_host("*") is None and server.bind_host("") is None
    assert server.bind_host("localhost") == "localhost"
    assert server.bind_host("::") == "::"


def test_serve_hands_every_address_to_uvicorn_as_no_host(monkeypatch):
    uvicorn = pytest.importorskip("uvicorn")
    seen = {}
    monkeypatch.setattr(server, "create_app", lambda config: object())
    monkeypatch.setattr(server.ConsoleConfig, "from_env", classmethod(lambda cls, env: None))
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    args = argparse.Namespace(host="*", port=8080, ssl_certfile=None, ssl_keyfile=None)
    assert server.serve(args, {}) == 0
    assert seen["host"] is None and seen["port"] == 8080


def test_every_address_is_reachable_over_ipv4():
    """주소를 못 박지 않은 소켓은 IPv4 연결도 받는다(IPv6가 없는 컨테이너의 조건)."""
    uvicorn = pytest.importorskip("uvicorn")

    async def app(scope, receive, send):
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    with socket.socket() as probe:
        probe.bind(("localhost", 0))
        port = probe.getsockname()[1]
    instance = uvicorn.Server(uvicorn.Config(
        app, host=server.bind_host("*"), port=port, log_level="error"))
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not instance.started and time.monotonic() < deadline:
            time.sleep(0.05)
        assert instance.started
        address = socket.gethostbyname("localhost")  # IPv4 주소 하나
        with socket.create_connection((address, port), timeout=5) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            assert client.recv(64).startswith(b"HTTP/1.1 204")
    finally:
        instance.should_exit = True
        thread.join(10)
