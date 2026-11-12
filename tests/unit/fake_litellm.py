"""상태를 가진 LiteLLM 관리 API 모의 서버(권한 동기화 시험용).

실측한 동작만 흉내 낸다: ``/key/update``·``/team/update``는 ``object_permission``의 두 필드를 각각
통째로 바꾸고(보내지 않은 필드는 그대로), 팀 소속 키의 ``mcp_servers``가 팀 허용 서버를 넘으면 403,
제출 서버는 ``pending_review``에서 승인 호출로 ``active``가 되며 이미 ``active``면 400이다. 서버
목록(``/v1/mcp/server``)은 ``active``만 보인다. 시험은 ``keys``·``teams``·``servers``를 직접 바꿔
외부 삭제나 다른 관리자의 수정을 만든다.
"""

import copy
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

CONTROL_KEY = "fake-control-key"


def _permission(servers=None, tools=None) -> dict:
    return {"mcp_servers": list(servers or []), "mcp_tool_permissions": dict(tools or {}),
            "mcp_access_groups": []}


class FakeLiteLLM:
    def __init__(self) -> None:
        self.keys: dict[str, dict] = {}
        self.teams: dict[str, dict] = {}
        self.servers: dict[str, dict] = {}
        self.requests: list[tuple[str, str, object]] = []
        self.before_write = None  # 쓰기를 처리하기 전에 부르는 함수(동시 수정 흉내)
        self.after_write = None  # 쓰기를 처리한 뒤 부르는 함수(응답 직후 덮어쓰는 흉내)
        self.ignore_allow_all_keys = False  # 서버 수정이 allow_all_keys 끄기를 무시하는 흉내
        self.generated: list[dict] = []  # /key/generate 본문
        self.fail_writes: dict[str, int] = {}  # 경로 -> 강제로 낼 상태 코드
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status: int, body) -> None:
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _handle(self) -> None:
                parts = urlsplit(self.path)
                params = dict(parse_qsl(parts.query))
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                if self.headers.get("Authorization") != f"Bearer {CONTROL_KEY}":
                    return self._reply(401, {"error": "bad key"})
                fake.requests.append((self.command, parts.path, body))
                status, reply = fake.route(self.command, parts.path, params, body)
                self._reply(status, reply)

            do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("localhost", 0), Handler)
        self.url = f"http://{socket.gethostbyname('localhost')}:{self._server.server_port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    # --- 상태 만들기 -------------------------------------------------------------

    def add_team(self, team_id: str, servers=None, tools=None, **fields) -> dict:
        team = {"team_id": team_id, "blocked": False, "models": [], "max_budget": None,
                "metadata": {}, "object_permission": _permission(servers, tools), **fields}
        self.teams[team_id] = team
        return team

    def add_key(self, token: str, team_id: str | None = None, servers=None, tools=None,
                **fields) -> dict:
        key = {"key": token, "user_id": "user-1", "team_id": team_id, "blocked": None,
               "models": [], "max_budget": None, "allowed_routes": [], "metadata": {},
               "object_permission": None if servers is None and tools is None
               else _permission(servers, tools), **fields}
        self.keys[token] = key
        return key

    def add_server(
        self, server_id: str, status: str = "active", tools: dict | None = None
    ) -> dict:
        server = {"tools": tools or {}, "pinned": False, "server_id": server_id,
                  "server_name": server_id, "approval_status": status, "url": None,
                  "pinned_tools": None, "allow_all_keys": False, "credentials": {"secret": "x"}}
        self.servers[server_id] = server
        return server

    def permission(self, kind: str, target_id: str) -> tuple[list[str], dict]:
        record = (self.keys if kind == "key" else self.teams)[target_id]
        perm = record.get("object_permission") or {}
        return list(perm.get("mcp_servers") or []), dict(perm.get("mcp_tool_permissions") or {})

    def writes(self, path: str | None = None) -> list:
        return [r for r in self.requests if r[0] != "GET" and (path is None or r[1] == path)]

    # --- 라우팅 ------------------------------------------------------------------

    def route(self, method: str, path: str, params: dict, body):
        if method != "GET":
            if self.before_write is not None:
                self.before_write(method, path, body)
            forced = self.fail_writes.get(f"{method} {path}", self.fail_writes.get(path))
            if forced is not None:
                return forced, {"error": "forced"}
        if method == "GET" and path == "/key/info":
            key = self.keys.get(params.get("key", ""))
            return (200, {"key": key["key"], "info": copy.deepcopy(key)}) if key else (404, {})
        if method == "GET" and path == "/team/info":
            team = self.teams.get(params.get("team_id", ""))
            return (200, {"team_id": team["team_id"], "team_info": copy.deepcopy(team)}) \
                if team else (404, {})
        if method == "GET" and path == "/v1/mcp/server":
            return 200, [copy.deepcopy(s) for s in self.servers.values()
                         if s["approval_status"] == "active"]
        if method == "PUT" and path == "/v1/mcp/server":
            server = self.servers.get(body["server_id"])
            if server is None:
                return 404, {"detail": {"error": "not found"}}
            if not self.ignore_allow_all_keys:
                server.update({k: v for k, v in body.items() if k != "server_id"})
            return 200, copy.deepcopy(server)
        if path.startswith("/v1/mcp/server/"):
            rest = path[len("/v1/mcp/server/"):]
            server_id, _, action = rest.partition("/")
            server = self.servers.get(server_id)
            if server is None:
                return 404, {"detail": {"error": "not found"}}
            if method == "GET" and not action:
                return 200, {k: v for k, v in copy.deepcopy(server).items() if k != "tools"}
            if method == "POST" and action == "pin":
                server["pinned"] = True
                return 200, copy.deepcopy(server["tools"])
            if method == "DELETE" and action == "pin":
                server["pinned"] = False
                return 200, {"server_id": server_id, "status": "unpinned"}
            if method == "PUT" and action == "approve":
                if server["approval_status"] == "active":
                    return 400, {"detail": {"error": "MCP server is already active."}}
                server["approval_status"] = "active"
                return 200, copy.deepcopy(server)
        if method == "POST" and path == "/key/generate":
            self.generated.append(body)
            return 200, {"key": f"sk-generated-{len(self.generated)}",
                         "key_alias": body["key_alias"]}
        if method == "POST" and path == "/key/delete":
            return 200, {"deleted_keys": body["key_aliases"]}
        if method == "POST" and path in ("/key/update", "/team/update"):
            result = self._update(path, body)
            if self.after_write is not None:
                self.after_write(method, path, body)
            return result
        return 404, {"error": "no route"}

    def _update(self, path: str, body: dict):
        kind = "key" if path == "/key/update" else "team"
        records = self.keys if kind == "key" else self.teams
        record = records.get(body["key" if kind == "key" else "team_id"])
        if record is None:
            return 404, {"error": "not found"}
        incoming = body.get("object_permission") or {}
        if kind == "key" and record.get("team_id") and "mcp_servers" in incoming:
            team = self.teams[record["team_id"]]
            allowed = set((team.get("object_permission") or {}).get("mcp_servers") or [])
            if not set(incoming["mcp_servers"]) <= allowed:
                return 403, {"error": {"message": "Key requests MCP servers not allowed by team"}}
        perm = record.get("object_permission") or _permission()
        for field in ("mcp_servers", "mcp_tool_permissions"):
            if field in incoming:
                perm[field] = copy.deepcopy(incoming[field])
        record["object_permission"] = perm
        view = copy.deepcopy(record)
        return 200, view if kind == "key" else {"team_id": record["team_id"], "data": view}
