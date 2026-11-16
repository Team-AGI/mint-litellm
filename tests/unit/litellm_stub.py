"""LiteLLM 관리 API 응답을 고정값으로 돌려주는 로컬 HTTP 서버.

고정값은 v1.106.6 이미지에서 제어 평면 키(proxy_admin + allowed_routes)로 받은 실제 응답이다.
클라이언트의 HTTP 경로는 그대로 실행되고, 서버만 응답을 고정한다.
"""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

FIXTURES = Path(__file__).parent / "fixtures" / "litellm"
GOOD_KEY = "7626ae7acbe30f3a1801b7fcbe51ede42ea931c58a9852e739b3d6ec62602a4e"
ALIAS_KEY = "e2fe7415a7d4d8409a9aa58bf5977df264ee486073430ee7b67f371192b73b69"
CONTROL_KEY = "control-plane-key"


def fixture(name: str):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def key_entry(alias: str) -> dict:
    return next(k for k in fixture("key_list_full")["keys"] if k["key_alias"] == alias)


class StubLiteLLM:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, frozenset], tuple[int, object]] = {}
        self.requests: list[tuple[str, dict, str]] = []
        self.defaults()
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parts = urlsplit(self.path)
                params = dict(parse_qsl(parts.query))
                stub.requests.append((parts.path, params, self.headers.get("Authorization", "")))
                status, body = stub.routes.get(
                    (parts.path, frozenset(params.items())),
                    stub.routes.get((parts.path, frozenset()), (404, {"error": "not found"})),
                )
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("localhost", 0), Handler)
        # localhost가 IPv6 주소를 먼저 시도하면 연결 거부를 기다리는 지연이 생긴다.
        self.url = f"http://{socket.gethostbyname('localhost')}:{self._server.server_port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def set(self, path: str, body: object, status: int = 200, **params: str) -> None:
        self.routes[(path, frozenset(params.items()))] = (status, body)

    def defaults(self) -> None:
        self.set("/v1/mcp/server", fixture("server_list"))
        self.set("/v1/mcp/server/ctl-everything", fixture("server_get"))
        self.set("/v1/mcp/server/nonexistent", fixture("server_not_found"), 404)
        self.set("/user/info", fixture("user_info"), user_id="human-1")
        second_user = fixture("user_info")
        second_user["user_id"] = second_user["user_info"]["user_id"] = "human-2"
        self.set("/user/info", second_user, user_id="human-2")
        third_user = json.loads(json.dumps(second_user))  # 키 주인이 아닌 승인자용
        third_user["user_id"] = third_user["user_info"]["user_id"] = "human-3"
        self.set("/user/info", third_user, user_id="human-3")
        self.set("/user/info", fixture("user_not_found"), 404, user_id="nobody")
        self.set("/key/info", fixture("key_info"), key=GOOD_KEY)
        self.set("/key/info", {"key": ALIAS_KEY, "info": key_entry("k-alias")}, key=ALIAS_KEY)
        self.set("/key/list", fixture("key_list_full"))
        self.set("/team/list", fixture("team_list"))
        self.set("/team/info", fixture("team_info"), team_id="team-op")
        self.set("/guardrails/list", fixture("guardrails_empty"))

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
