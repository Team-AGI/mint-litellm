"""콘솔 시험의 고정 장치: 키별로 응답하는 LiteLLM 대역과, 실제 제어 로그인으로 접속하는 콘솔 앱.

대역의 응답 형태(필드 이름·상태 코드·오류 메시지)는 LiteLLM 1.106.6에서 본인 키와 제어 평면 키로
받은 실제 응답을 따른다. 클라이언트의 HTTP 경로는 그대로 실행되고 서버만 응답을 고정한다.
"""

import base64
import dataclasses
import hashlib
import json
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest
from ctl_fixtures import INSTANCE

psycopg = pytest.importorskip("psycopg")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402
from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm.console.app import create_app  # noqa: E402
from mint_litellm.console.core import ConsoleConfig  # noqa: E402
from mint_litellm.control import operators  # noqa: E402
from mint_litellm.control.config import ControlConfig  # noqa: E402
from mint_litellm.control.litellm_admin import LiteLLMAdmin  # noqa: E402
from mint_litellm.control.settings_store import ensure  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402
from mint_litellm.types.settings import Mode  # noqa: E402

CONTROL_KEY = "control-plane-key"
HEX = "ab" * 32


def token_of(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def key_info(user_id: str | None, **extra) -> dict:
    info = {"key_alias": "k", "expires": None, "user_id": user_id, "blocked": None,
            "team_id": None, "metadata": {}}
    info.update(extra)
    return {"key": "", "info": info}


def user_info(user_id: str, role: str = "internal_user") -> dict:
    return {"user_id": user_id, "user_info": {"user_id": user_id, "user_role": role}, "keys": []}


def auth_error(message: str, kind: str = "auth_error") -> dict:
    return {"error": {"message": message, "type": kind, "param": "None", "code": "401"}}


def fake_ui_token(claims: dict) -> str:
    """서명 없는 JWT 꼴(콘솔은 본문만 읽는다)."""
    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'HS256'})}.{part(claims)}.sig"


class LiteLLMStub:
    """``(경로, 인증 값, key 쿼리)``별 응답. 등록되지 않은 요청은 404이다."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str, str | None], tuple[int, object]] = {}
        self.requests: list[tuple[str, str, dict]] = []
        self.logins: dict[str, tuple[str, dict]] = {}
        self.posts: list[tuple[str, dict]] = []
        self.login_status = 0
        self.post_auth: list[str] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parts = urlsplit(self.path)
                params = dict(parse_qsl(parts.query))
                bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
                stub.requests.append((parts.path, bearer, params))
                status, body = stub.routes.get(
                    (parts.path, bearer, params.get("key") or params.get("user_id")),
                    (404, {"error": {"message": "not found", "code": "404"}}),
                )
                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self):  # noqa: N802
                """``/v2/login``: ``stub.logins[아이디] = (비밀번호, 화면 토큰 본문)``."""
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                stub.posts.append((urlsplit(self.path).path, body))
                stub.post_auth.append(self.headers.get("Authorization", ""))
                known = stub.logins.get(body.get("username"))
                if urlsplit(self.path).path == "/user/update":
                    status, reply = 200, {}
                elif (urlsplit(self.path).path == "/v2/login" and known
                      and known[0] == body["password"]):
                    status, reply = 200, {"redirect_url": "x", "token": fake_ui_token(known[1])}
                elif stub.login_status:
                    status, reply = stub.login_status, {"error": {"message": "x"}}
                else:
                    status, reply = 401, {"error": {"message": "Invalid credentials"}}
                payload = json.dumps(reply).encode()
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

    def own(self, key: str, user_id: str | None, role: str = "internal_user", **extra) -> None:
        """사람이 낸 본인 키: ``/key/info``와 ``/user/info``(쿼리 없음)."""
        body = key_info(user_id, **extra)
        body["key"] = token_of(key)
        self.routes[("/key/info", key, None)] = (200, body)
        if user_id:
            self.routes[("/user/info", key, None)] = (200, user_info(user_id, role))
        else:
            self.routes[("/user/info", key, None)] = (
                404, {"error": {"message": "User None not found", "code": "404"}})

    def control(self, key: str, user_id: str, role: str = "internal_user", **extra) -> None:
        """제어 평면 키로 보는 같은 키(해시)와 사용자."""
        token = token_of(key)
        body = key_info(user_id, **extra)
        body["key"] = token
        self.routes[("/key/info", CONTROL_KEY, token)] = (200, body)
        self.routes[("/user/info", CONTROL_KEY, user_id)] = (200, user_info(user_id, role))

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@dataclass
class Keys:
    admin = "sk-admin"
    approver = "sk-approver"
    viewer = "sk-viewer"
    stranger = "sk-stranger"


USERS = {"admin": "human-1", "approver": "human-2", "viewer": "human-3"}
TOKENS = {"admin": "mint_admin_token", "approver": "mint_approver_token",
          "viewer": "mint_viewer_token"}


@pytest.fixture
def stub() -> Iterator[LiteLLMStub]:
    server = LiteLLMStub()
    for role, user in USERS.items():
        key = getattr(Keys, role)
        server.own(key, user)
        server.control(key, user)
    server.own(Keys.stranger, "human-9")
    server.control(Keys.stranger, "human-9")
    yield server
    server.close()


def login_url(url: str, user: str = "mint_control_app", password: str = "pw-control") -> str:
    params = conninfo_to_dict(url)
    params.update(user=user, password=password)
    return make_conninfo(**params)


@pytest.fixture
def world(fresh_db, login_roles, stub, tmp_path):
    """운영자 세 명(관리자·승인자·조회자)과 조직·서버가 있는 배치와 콘솔 앱."""
    with psycopg.connect(fresh_db) as admin:
        ensure(admin, INSTANCE)
        admin.execute(
            "INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, 'acme', 'A사')",
            (INSTANCE,),
        )
        for role, user in USERS.items():
            admin.execute(
                "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
                " VALUES (%s, %s, %s, %s, %s)",
                (INSTANCE, role, role, operators.hash_token(TOKENS[role]), user),
            )
        for server_id, status in (("srv-ok", "approved"), ("srv-wait", "awaiting_approval")):
            admin.execute(
                "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256,"
                " transport, auth_type, registered_by) VALUES (gen_random_uuid(), %s, %s,"
                " 'awaiting_approval', %s, 'http', 'none', 'admin')",
                (INSTANCE, server_id, HEX),
            )
            if status == "approved":
                admin.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = %s",
                              (server_id,))
            admin.execute(
                "INSERT INTO mint.usage_relations (id, instance_id, org_id, purpose, server_id)"
                " VALUES (gen_random_uuid(), %s, 'acme', '업무', %s)",
                (INSTANCE, server_id),
            )
    url = login_url(fresh_db)
    stage2 = Stage2Settings(export_dir=Path(tmp_path), export_hmac_key=b"k" * 32)
    control = ControlConfig(url, INSTANCE, stub.url, None, None, Mode.ENFORCE, 1)
    config = ConsoleConfig(
        control, stage2, stub.url, None, url,
        login_url(fresh_db, "mint_staff_app", "pw-staff"),
        key_login=True,
    )
    app = create_app(config)
    client = TestClient(app, base_url="https://testserver", follow_redirects=False)
    yield World(fresh_db, url, config, client, stub, app)
    client.close()


@dataclass
class World:
    admin_url: str
    url: str
    config: ConsoleConfig
    client: TestClient
    stub: LiteLLMStub
    app: object

    def query(self, sql: str, *params):
        with psycopg.connect(self.admin_url) as conn:
            cur = conn.execute(sql, params or None)
            return cur.fetchall() if cur.description else None

    def session_client(self, role: str = "admin") -> TestClient:
        """로그인한 새 클라이언트."""
        client = TestClient(self.app, base_url="https://testserver", follow_redirects=False)
        response = client.post("/login", data={"key": getattr(Keys, role)})
        assert response.status_code == 303, response.text
        return client

    def client_with(self, **stage2) -> TestClient:
        """세션 설정을 바꾼 콘솔 앱의 새 클라이언트(시간 창 시험용)."""
        config = dataclasses.replace(
            self.config, stage2=dataclasses.replace(self.config.stage2, **stage2)
        )
        return TestClient(create_app(config), base_url="https://testserver",
                          follow_redirects=False)

    def csrf(self, client: TestClient) -> str:
        from mint_litellm.console.core import COOKIE
        from mint_litellm.control.services.console_sessions import csrf_token

        return csrf_token(client.cookies[COOKIE])

    def with_control_key(self) -> None:
        """승인·운영자 등록처럼 LiteLLM 읽기가 필요한 변경을 켠다."""
        admin = LiteLLMAdmin(self.stub.url, CONTROL_KEY)
        object.__setattr__(self.config, "litellm_admin", admin)
