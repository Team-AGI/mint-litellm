#!/usr/bin/env python3
"""MINT 단말 에이전트(표준 라이브러리만, Python 3.9 이상). 파일 하나로 배포한다.

하위 명령:
  pre   호출 전 훅. 도구 호출마다 MINT 결정 경로에 판정을 묻고, 허용이 아니면 종료 코드 2로
        호출을 막는다. 오류는 모두 차단이다. 허용은 아무것도 출력하지 않고 종료 코드 0으로
        끝낸다(하네스의 권한 흐름을 그대로 두며 이 훅이 권한을 대신 주지 않는다).
  post  호출 뒤 훅(성공)과 post-failure(실패). 판정 때 받은 참조를 MINT에 돌려 결과를 보고한다.
        보고하지 못해도 호출에는 영향이 없고, MINT는 보고 없는 호출을 결과 미확인으로 남긴다.
  serve 연결 중계(내부용). 훅은 호출마다 새 프로세스라 연결을 이어 쓸 수 없으므로, 사용자
        전용 소켓을 가진 작은 프로세스가 결정 서버와의 연결을 유지하고 훅이 이를 거쳐 보낸다.
        중계에 닿지 못하면 훅이 직접 보내며(느릴 뿐 판정은 같다), 요청이 한동안 없으면 끝난다.
  run   MCP 서버 실행기(Linux는 승인된 계약에서 만든 bubblewrap, Windows는 AppContainer 격리 안에서
        시작한다).
        승인된 실행 계약과 디스크의 실행 파일·스크립트 해시가 모두 같을 때만
        서버를 시작하고, 아니면 시작하지 않고 종료 코드 126으로 끝난다. 마지막 설치 보고 응답이
        폐기·미승인으로 알린 서버(사용자 캐시나 설치 폴더의 ``retired.json``)도
        시작하지 않는다. 캐시는
        오래되어도 그대로 쓰며(목록에 든 서버만 막는다), 시작한 프로세스는 보고기가 끌 수 있게
        PID와 시작 시각을 사용자 캐시에 기록한다.

Claude Code와 Codex가 같은 훅 입력(도구 이름 ``mcp__서버__도구``, 호출 식별자)을 준다. Codex는
서버 이름을 따로 주지 않아 승인 목록의 서버 이름과 도구 이름의 접두로 서버를 찾는다. Windows에서
서버 실행기는 exec 대신 자식 프로세스로 서버를 띄우고 같은 종료 코드로 끝난다.

시간 상한은 HTTP 대기 < 훅 내부 상한 < 하네스 ``timeout`` 순서여야 한다. 하네스는 시간 초과나
시작 실패를 기본적으로 통과시키므로 관리형 설정에 ``"onFailure": "block"``을 함께 둔다.
출력이 JSON처럼 보여도 해석되지 않으면 일반 글로 취급되어 통과하므로 허용 때는 출력하지 않는다.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import ntpath
import os
import posixpath
import re
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NamedTuple

DECIDE_PATH = "/mint/v1/decide"
RESULT_PATH = "/mint/v1/result"
MAX_RESPONSE = 64 * 1024
HTTP_TIMEOUT = 2.0
HOOK_DEADLINE = 2.5
# 판정 참조는 호출 뒤 훅이 읽을 때까지만 둔다. 이 시간이 지난 파일은 다음 호출 때 지운다.
PENDING_MAX_AGE = 86400
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
# 승인된 계약이 값을 정하지 않은 한, 시작 직전에 물려받지 않는 환경 변수.
ENV_DENIED = re.compile(r"^(LD_|DYLD_|NODE_OPTIONS$|NODE_PATH$|PYTHON|BASH_ENV$|ENV$)")
REFUSED = 126
STATE_DIR = "~/.cache/mint"
KIT_DIR = os.path.dirname(os.path.abspath(__file__))  # Windows SYSTEM 보고기는 목록을 여기 둔다
RETIRED_FILE = "retired.json"
LAUNCHED = "launched"
# 연결 중계는 요청이 이 시간(초) 없으면 끝난다. 소켓 경로는 운영체제 상한 안이어야 한다.
BROKER_SOCKET = "conn.sock"
BROKER_IDLE = 300.0
BROKER_SOCKET_MAX = 100

Post = Callable[[str, "dict[str, str]", bytes, float], "tuple[int, bytes]"]


class Refuse(Exception):
    """호출이나 서버 시작을 막아야 하는 사유. 메시지는 사용자에게 보인다."""


def sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 1 << 20)
        if not block:
            return digest.hexdigest()
        digest.update(block)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def script_path(contract: Mapping[str, Any]) -> str | None:
    """계약 인자 중 처음으로 나오는, 존재하는 절대 경로 파일(서버가 읽는 스크립트)."""
    for item in contract.get("argv") or []:
        if isinstance(item, str) and os.path.isabs(item) and os.path.isfile(item):
            return item
    return None


def observed_contract(approved: Mapping[str, Any], fd: int | None = None) -> dict[str, Any]:
    """승인된 계약에 지금 디스크의 실행 파일·스크립트 해시를 넣은 계약.

    ``fd``가 있으면 실행 파일은 그 기술자에서 읽는다(시작 직전 검증이 실행할 파일 그대로를 본다).
    """
    try:
        contract = {k: v for k, v in approved.items() if k != "identity_kind"}
        contract["executable_sha256"] = (
            sha256_file(approved["executable"]) if fd is None else sha256_fd(fd)
        )
        if approved.get("script_sha256") is not None:
            script = script_path(approved)
            if script is None:
                raise Refuse("server script was not found")
            contract["script_sha256"] = sha256_file(script)
    except OSError as exc:
        raise Refuse(f"server files cannot be read ({type(exc).__name__})") from exc
    return contract


def load_contract(path: str, server: str) -> dict[str, Any]:
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as handle:
            entry = (json.load(handle).get("servers") or {}).get(server)
    except (OSError, ValueError) as exc:
        raise Refuse("approved server list cannot be read") from exc
    if not isinstance(entry, dict) or not isinstance(entry.get("executable"), str):
        raise Refuse(f"server {server} is not an approved local server")
    return entry


def load_retired(state_dir: str) -> set[str]:
    """마지막 보고 응답의 폐기 서버 이름(사용자 캐시와 이 파일이 있는 설치 폴더의 목록을 합친다).
    목록이 없거나 읽을 수 없으면 그 몫은 비어 있다(알 수 없다)."""
    names: set[str] = set()
    for folder in (os.path.expanduser(state_dir), KIT_DIR):
        try:
            with open(os.path.join(folder, RETIRED_FILE), encoding="utf-8") as handle:
                listed = json.load(handle).get("servers")
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(listed, list):
            names |= {name for name in listed if isinstance(name, str)}
    return names


def proc_start(pid: int) -> str | None:
    """프로세스의 시작 시각 표지(보고기가 재사용된 PID를 가려내는 데 쓴다). 모르면 None."""
    if os.name == "nt":
        return _win_proc_start(pid)
    try:
        with open(f"/proc/{int(pid)}/stat", encoding="utf-8", errors="replace") as handle:
            stat = handle.read()
    except OSError:
        return None
    return stat.rsplit(")", 1)[-1].split()[19] if ")" in stat else None


def record_launch(state_dir: str, server: str, sandbox: str | None = None) -> None:
    """시작할 서버 프로세스(exec 뒤에도 같은 PID)를 기록한다. 기록하지 못해도 시작은 막지 않는다."""
    try:
        folder = os.path.join(os.path.expanduser(state_dir), LAUNCHED)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        pid = os.getpid()
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", server)[:100]
        record = {"server": server, "pid": pid, "start": proc_start(pid)}
        if sandbox:
            record["sandbox"] = sandbox
        with open(os.path.join(folder, f"{name}-{pid}.json"), "w", encoding="utf-8") as handle:
            json.dump(record, handle)
    except OSError:
        pass


def server_prefix(server: str) -> str:
    return "mcp__" + re.sub(r"[^a-zA-Z0-9_-]", "_", server) + "__"


def known_servers(path: str) -> list[str]:
    """승인 목록의 서버 이름. 목록을 읽지 못하면 비어 있다(그러면 호출은 막힌다)."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as handle:
            return [str(name) for name in (json.load(handle).get("servers") or {})]
    except (OSError, ValueError, AttributeError):
        return []


def server_and_tool(event: Mapping[str, Any], known: Sequence[str] = ()) -> tuple[str, str]:
    name = event.get("tool_name")
    server = (event.get("mcp_server") or {}).get("name")
    if server is None and isinstance(name, str):
        # Codex는 서버 이름을 따로 주지 않는다. 승인된 서버 중 도구 이름의 접두와 맞는 것을 쓴다.
        server = next((s for s in known if name.startswith(server_prefix(s))), None)
    if not isinstance(server, str) or not isinstance(name, str):
        raise Refuse("hook input has no MCP server or tool name")
    prefix = server_prefix(server)
    if not name.startswith(prefix) or len(name) == len(prefix):
        raise Refuse("tool name does not match the MCP server")
    return server, name[len(prefix) :]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_post(
    url: str, headers: dict[str, str], body: bytes, timeout: float, ca_file: str | None = None
) -> tuple[int, bytes]:
    import ssl

    handlers: list[Any] = [_NoRedirect()]
    if url.startswith("https:"):
        context = ssl.create_default_context(cafile=ca_file)
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE + 1)


class BrokerDown(Exception):
    """중계 프로세스에 닿지 못했다. 요청은 보내지 않았으므로 직접 보내도 된다."""


def broker_post(
    sock_path: str, url: str, headers: dict[str, str], body: bytes, timeout: float
) -> tuple[int, bytes]:
    request = json.dumps(
        {"url": url, "headers": headers, "body": body.decode(), "timeout": timeout}
    ).encode()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except (AttributeError, OSError) as exc:
        raise BrokerDown from exc
    with sock:
        sock.settimeout(timeout)
        try:
            sock.connect(sock_path)
        except OSError as exc:
            raise BrokerDown from exc
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        chunks, size = [], 0
        while block := sock.recv(65536):
            chunks.append(block)
            size += len(block)
            if size > 8 * MAX_RESPONSE:
                raise OSError("broker answer is too large")
    reply = json.loads(b"".join(chunks))
    if "error" in reply:
        raise OSError(f"broker request failed ({reply['error']})")
    return reply["status"], reply["body"].encode()


# 유닉스 소켓이 없는 운영체제에서도 이 파일을 읽을 수 있게 한다(중계는 쓰이지 않는다).
_UnixServer = getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)


class _Broker(socketserver.ThreadingMixIn, _UnixServer):
    daemon_threads = True

    def __init__(self, path: str, ca_file: str | None) -> None:
        super().__init__(path, _BrokerHandler)
        self.ca_file = ca_file
        self.idle = False
        self.lock = threading.Lock()
        # ponytail: 주소마다 쉬는 연결 하나. 동시에 여러 훅이 오면 나머지는 새로 연결하고 닫는다.
        self.pool: dict[tuple[str, str], http.client.HTTPConnection] = {}

    def handle_timeout(self) -> None:
        self.idle = True

    def _connect(self, parts: urllib.parse.SplitResult, timeout: float):
        if parts.scheme == "https":
            context = ssl.create_default_context(cafile=self.ca_file)
            return http.client.HTTPSConnection(
                parts.hostname, parts.port, timeout=timeout, context=context
            )
        if parts.scheme == "http":
            return http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)
        raise ValueError("unsupported scheme")

    def forward(self, url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes]:
        parts = urllib.parse.urlsplit(url)
        origin = (parts.scheme, parts.netloc)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        for attempt in (0, 1):
            with self.lock:
                conn = self.pool.pop(origin, None)
            reused = conn is not None
            if conn is None:
                conn = self._connect(parts, timeout)
            try:
                if conn.sock is not None:
                    conn.sock.settimeout(timeout)
                conn.request("POST", target, body=body, headers=headers)
                response = conn.getresponse()
                data = response.read(MAX_RESPONSE + 1)
            except (ConnectionError, http.client.BadStatusLine):
                conn.close()
                if reused and attempt == 0:
                    continue  # 서버가 쉬던 연결을 닫았다: 새 연결로 한 번 더
                raise
            except BaseException:
                conn.close()
                raise
            with self.lock:
                if len(data) > MAX_RESPONSE or response.will_close or origin in self.pool:
                    conn.close()
                else:
                    self.pool[origin] = conn
            return response.status, data
        raise OSError("unreachable")


class _BrokerHandler(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self) -> None:
        try:
            request = json.loads(self.rfile.read(4 * MAX_RESPONSE))
            status, raw = self.server.forward(  # type: ignore[attr-defined]
                request["url"], request["headers"], request["body"].encode(),
                float(request["timeout"]),
            )  # fmt: skip
            reply: dict[str, Any] = {"status": status, "body": raw.decode("utf-8", "replace")}
        except Exception as exc:
            reply = {"error": type(exc).__name__}
        self.wfile.write(json.dumps(reply).encode())


def serve_broker(sock_path: str, ca_file: str | None, idle: float = BROKER_IDLE) -> None:
    os.makedirs(os.path.dirname(sock_path), mode=0o700, exist_ok=True)
    if os.path.exists(sock_path):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.connect(sock_path)
            return  # 이미 중계가 떠 있다.
        except OSError:
            os.unlink(sock_path)  # 죽은 중계가 남긴 소켓
    previous = os.umask(0o177)
    try:
        server = _Broker(sock_path, ca_file)
    finally:
        os.umask(previous)
    server.timeout = idle
    try:
        while not server.idle:
            server.handle_request()
    finally:
        server.server_close()
        try:
            os.unlink(sock_path)
        except OSError:
            pass


def start_broker(state_dir: str, contracts: str, ca_file: str | None) -> None:
    """중계를 뒤에서 띄운다(이번 호출은 직접 보낸다). 띄우지 못해도 판정은 그대로다."""
    if os.name != "posix" or len(os.path.join(state_dir, BROKER_SOCKET)) >= BROKER_SOCKET_MAX:
        return
    command = [sys.executable, os.path.abspath(__file__), "serve", "--contracts", contracts,
               "--state-dir", state_dir]  # fmt: skip
    if ca_file:
        command += ["--ca-file", ca_file]
    try:
        subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
        )  # fmt: skip
    except OSError:
        pass


def _refusal_code(raw: bytes) -> str:
    """거절 응답에 MINT 오류 코드가 있으면 ``, 코드`` 꼴로 돌려준다."""
    try:
        code = json.loads(json.loads(raw)["detail"])["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return ""
    ok = isinstance(code, str) and re.fullmatch(r"MINT-[A-Z0-9-]{1,64}", code)
    return f", {code}" if ok else ""


def _call(post: Post, base: str, path: str, key: str, payload: dict, timeout: float) -> dict:
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        status, raw = post(base.rstrip("/") + path, headers, json.dumps(payload).encode(), timeout)
    except (OSError, ValueError) as exc:
        raise Refuse(f"decision service is unreachable ({type(exc).__name__})") from exc
    if status != 200:
        raise Refuse(f"decision service refused the request (HTTP {status}{_refusal_code(raw)})")
    try:
        answer = json.loads(raw) if len(raw) <= MAX_RESPONSE else None
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        raise Refuse("decision service sent an unreadable answer")
    return answer


def clean_pending(directory: str, now: float | None = None) -> None:
    cutoff = (time.time() if now is None else now) - PENDING_MAX_AGE
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        path = os.path.join(directory, name)
        try:
            if os.path.getmtime(path) < cutoff:
                os.unlink(path)
        except OSError:
            pass


def decide(
    event: Mapping[str, Any],
    *,
    url: str,
    key: str,
    contracts: str,
    state_dir: str,
    post: Post,
    http_timeout: float = HTTP_TIMEOUT,
) -> None:
    """허용이면 조용히 돌아오고, 그 밖에는 ``Refuse``를 던진다."""
    name = event.get("tool_name")
    if not isinstance(name, str) or not name.startswith("mcp__"):
        return  # MCP 호출이 아니면 이 훅의 대상이 아니다.
    server, tool = server_and_tool(event, known_servers(contracts))
    arguments = event.get("tool_input")
    if not isinstance(arguments, dict):
        raise Refuse("tool arguments are not an object")
    tool_use_id = event.get("tool_use_id")
    payload = {
        "server": server,
        "tool": tool,
        "arguments": arguments,
        "contract": observed_contract(load_contract(contracts, server)),
        "tool_use_id": tool_use_id,
    }
    answer = _call(post, url, DECIDE_PATH, key, payload, http_timeout)
    if answer.get("decision") not in {"allow", "deny"}:
        raise Refuse("decision service sent an unreadable answer")
    if answer["decision"] == "deny":
        error = answer.get("error") if isinstance(answer.get("error"), dict) else {}
        code = error.get("code", "denied")
        raise Refuse(f"blocked by MINT: {code} reference={answer.get('reference')}")
    # 호출 뒤 훅이 결과를 보고할 수 있게 판정 참조를 호출 식별자로 남긴다.
    if isinstance(tool_use_id, str) and SAFE_ID.match(tool_use_id) and answer.get("reference"):
        pending = os.path.join(state_dir, "pending")
        os.makedirs(pending, mode=0o700, exist_ok=True)
        clean_pending(pending)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        with os.fdopen(os.open(os.path.join(pending, tool_use_id), flags, 0o600), "w") as handle:
            handle.write(str(answer["reference"]))


def report_result(
    event: Mapping[str, Any],
    *,
    failed: bool,
    url: str,
    key: str,
    state_dir: str,
    post: Post,
    http_timeout: float = HTTP_TIMEOUT,
) -> bool:
    """판정 참조가 남은 호출의 결과를 보고한다. 보고했으면 참, 보고할 것이 없거나 실패면 거짓."""
    tool_use_id = event.get("tool_use_id")
    if not isinstance(tool_use_id, str) or not SAFE_ID.match(tool_use_id):
        return False
    path = os.path.join(state_dir, "pending", tool_use_id)
    try:
        with open(path, encoding="utf-8") as handle:
            reference = handle.read(256).strip()
    except OSError:
        return False
    payload: dict[str, Any] = {"reference": reference}
    if failed:
        # 사용자가 중단한 호출은 도구가 실행됐는지 알 수 없다.
        payload["outcome"] = "unknown" if event.get("is_interrupt") else "error"
    else:
        payload["outcome"] = "success"
        payload["size_bytes"] = len(json.dumps(event.get("tool_response", "")).encode("utf-8"))
    try:
        _call(post, url, RESULT_PATH, key, payload, http_timeout)
    except Refuse:
        return False
    try:
        os.unlink(path)
    except OSError:
        pass
    return True


def launch_env(approved: Mapping[str, Any], inherited: Mapping[str, str]) -> dict[str, str]:
    """상속한 환경에서 위험한 변수를 빼고 승인된 환경 값을 얹는다."""
    env = {k: v for k, v in inherited.items() if not ENV_DENIED.match(k)}
    env.update({str(k): str(v) for k, v in (approved.get("env") or {}).items()})
    return env


def verify_launch(approved: Mapping[str, Any], fd: int) -> None:
    """열어 둔 실행 파일과 스크립트가 승인된 계약과 같지 않으면 ``Refuse``."""
    seen = observed_contract(approved, fd)
    if seen["executable_sha256"] != approved.get("executable_sha256"):
        raise Refuse("server executable differs from the approved contract")
    if seen.get("script_sha256") != approved.get("script_sha256"):
        raise Refuse("server script differs from the approved contract")


# --- 서버 격리(Linux bubblewrap) ------------------------------------------------------------
# 승인된 실행 계약에서 격리 명령을 만든다. 네트워크는 전부 허용 아니면 전부 차단이다(호스트별
# 거름은 하지 않는다). Windows는 아래 AppContainer 격리를 쓴다.
SANDBOX_SYSTEM = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
SANDBOX_ETC = (
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/localtime",
)  # fmt: skip
SANDBOX_ETC_NET = (
    "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl", "/etc/ca-certificates",
    "/etc/pki",
)  # fmt: skip
# 패키지 실행기는 내려받은 패키지를 캐시에 두므로 실행기별 캐시 폴더(홈 기준)만 읽기·쓰기로 붙인다.
RUNNER_CACHES = {
    "npx": (".npm",), "npm": (".npm",), "yarn": (".cache/yarn", ".yarn"),
    "pnpm": (".local/share/pnpm", ".cache/pnpm", ".npm"), "bunx": (".bun", ".cache/bun"),
    "bun": (".bun", ".cache/bun"), "uvx": (".cache/uv", ".local/share/uv"),
    "uv": (".cache/uv", ".local/share/uv"), "pipx": (".local/share/pipx", ".cache/pipx"),
}  # fmt: skip
RUNNER_ARGS = {"npm": ("exec", "x"), "pnpm": ("dlx", "exec"), "yarn": ("dlx",), "bun": ("x",),
               "pipx": ("run",), "uv": ("tool",)}  # fmt: skip


class Sandbox(NamedTuple):
    """격리 정책. ``managed``이면 격리할 수 없을 때 시작하지 않는다(허용하지 않는 한)."""

    managed: bool
    allow_unsandboxed: bool = False


def sandbox_policy(folder: str = KIT_DIR) -> Sandbox:
    """설치 폴더의 상태·설정에서 격리 정책을 읽는다. 읽지 못하면 관리형(엄격)으로 본다."""

    def read(name: str) -> dict:
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    return Sandbox(
        managed=read("state.json").get("mode") != "user",
        allow_unsandboxed=read("kit.json").get("allow_unsandboxed") is True,
    )


def declares_network(contract: Mapping[str, Any]) -> bool:
    """계약이 ``network: none``을 선언하지 않았으면 네트워크를 연다(선언이 없는 이전 계약 포함)."""
    return contract.get("network") != "none"


def runner_caches(contract: Mapping[str, Any], home: str) -> list[str]:
    """패키지 실행기(npx·uvx·pipx run 등)면 그 실행기의 캐시 폴더(홈의 다른 것은 붙이지 않는다)."""
    name = re.sub(r"\.(exe|cmd|bat)$", "", posixpath.basename(str(contract["executable"])).lower())
    first = (contract.get("argv") or [""])[:1]
    needs = RUNNER_ARGS.get(name)
    if name not in RUNNER_CACHES or (needs and (not first or first[0] not in needs)):
        return []
    return [posixpath.join(home, rel) for rel in RUNNER_CACHES[name]] if home else []


def _under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def _runtime_dir(path: str, home: str) -> str:
    """실행 파일이 쓰는 묶음 폴더(``<접두>/bin/x``의 접두). 너무 넓으면 파일 하나만."""
    prefix = posixpath.dirname(posixpath.dirname(path))
    broad = prefix.count("/") < 2 or _under(home, prefix) or prefix in ("/opt", "/srv", "/mnt")
    return path if broad else prefix


def link_chain(path: str) -> list[str]:
    """실행 파일에서 심볼릭 링크를 따라간 경로들(처음 경로, 각 단계의 대상, 최종 실제 경로)."""
    if os.name != "posix":
        return [path]
    chain = [path]
    for _ in range(8):
        if not os.path.islink(chain[-1]):
            break
        target = os.readlink(chain[-1])
        chain.append(posixpath.normpath(posixpath.join(posixpath.dirname(chain[-1]), target)))
    return [*chain, os.path.realpath(path)]


def sandbox_mounts(approved: Mapping[str, Any], home: str) -> list[tuple[str, str]]:
    """격리 안에 붙일 (경로, ro|rw). 상위 경로가 먼저 오도록 정렬한다."""
    executable = approved["executable"]
    found: dict[str, str] = {}

    def add(path: str, mode: str) -> None:
        if posixpath.isabs(path) and not any(_under(path, s) for s in SANDBOX_SYSTEM):
            if found.get(path) != "rw":
                found[path] = mode

    for path in dict.fromkeys(link_chain(executable)):
        add(_runtime_dir(path, home), "ro")
    script = script_path(approved)
    if script:
        folder = posixpath.dirname(script)
        add(script if folder.count("/") < 2 or _under(home, folder) else folder, "ro")
    if approved.get("cwd"):
        add(approved["cwd"], "ro")
    for cache in runner_caches(approved, home):
        add(cache, "rw")
    for entry in approved.get("file_access") or ():
        add(entry["path"], "rw" if entry.get("mode") == "rw" else "ro")
    ordered = sorted(found.items(), key=lambda item: (item[0].count("/"), item[0]))
    kept: list[tuple[str, str]] = []
    for path, mode in ordered:  # 상위 경로가 같은 권한으로 이미 붙었으면 건너뛴다.
        if not any(_under(path, base) and m == mode for base, m in kept if base != path):
            kept.append((path, mode))
    return kept


def bwrap_args(
    approved: Mapping[str, Any], argv: Sequence[str], home: str, bwrap: str = "bwrap"
) -> list[str]:
    """계약에서 만든 bubblewrap 명령. 시스템 폴더·계약 경로만 붙고, 선언하지 않은 경로는 없다."""
    network = declares_network(approved)
    args = [bwrap, "--unshare-all", "--die-with-parent", "--new-session"]
    if network:
        args.append("--share-net")
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in (*SANDBOX_SYSTEM, *SANDBOX_ETC, *(SANDBOX_ETC_NET if network else ())):
        args += ["--ro-bind-try", path, path]
    if home and home != "/" and not any(_under(home, s) for s in SANDBOX_SYSTEM):
        args += ["--tmpfs", home]  # 홈은 비어 있는 임시 폴더. 선언한 경로만 그 위에 붙는다.
    for path, mode in sandbox_mounts(approved, home):
        args += ["--bind-try" if mode == "rw" else "--ro-bind-try", path, path]
    args += ["--chdir", approved.get("cwd") or "/", "--", approved["executable"], *argv[1:]]
    return args


def bwrap_ready(bwrap: str) -> bool:
    """이 단말에서 bubblewrap이 실제로 격리를 만들 수 있는가(사용자 이름공간이 막혀 있으면 거짓)."""
    probe = [bwrap, "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--", "/bin/true"]
    try:
        return subprocess.run(probe, capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# --- 서버 격리(Windows AppContainer) --------------------------------------------------------
# 서버를 시작할 때마다 AppContainer 프로필을 만들고(이름에 실행기 PID가 든다), 그 SID에
# 선언한 경로와
# 실행 파일 폴더·패키지 실행기 캐시의 접근 권한(ACE)을 더한 뒤 서버를 시작한다. 서버가 끝나면
# ACE와 프로필을 지우고, 실행기가 죽어 남은 것은 다음 시작 때 정리한다. 서버는 작업 개체에
# 들어가므로
# 실행기가 끝나면 함께 끝난다. 네트워크는 ``none``이면 기능이 없고, 그 밖에는 ``internetClient``·
# ``privateNetworkClientServer``를 준다. 한계: AppContainer의 루프백(localhost) 차단은 기본값이고
# 이 실행기는 시스템 설정을 바꾸지 않으므로, 선언이 ``any``여도 같은 단말의 로컬 수신기에는 닿지
# 못한다. 호스트별 거름은 하지 않는다.
WIN_SYSTEM_ENV = ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
WIN_CAPS = {"internetClient": "S-1-15-3-1", "privateNetworkClientServer": "S-1-15-3-3"}
WIN_RUNNER_CACHES = {
    "npx": ("AppData/Roaming/npm", "AppData/Local/npm-cache"),
    "npm": ("AppData/Roaming/npm", "AppData/Local/npm-cache"),
    "yarn": ("AppData/Local/Yarn", ".yarn"),
    "pnpm": ("AppData/Local/pnpm", "AppData/Local/pnpm-cache"),
    "bunx": (".bun",), "bun": (".bun",),
    "uvx": ("AppData/Local/uv", "AppData/Roaming/uv"),
    "uv": ("AppData/Local/uv", "AppData/Roaming/uv"),
    "pipx": (".local/pipx", "AppData/Local/pipx"),
}  # fmt: skip
ACL_TRACK = "appcontainer"
ALREADY_EXISTS = 0x800700B7
WIN_RANK = {"R": 0, "RX": 1, "M": 2}


class SandboxUnavailable(Exception):
    """AppContainer를 만들거나 그 안에서 시작하지 못했다(서버는 아직 시작되지 않았다)."""


def win_capabilities(contract: Mapping[str, Any]) -> list[str]:
    """계약의 네트워크 선언에서 AppContainer 기능 SID. ``none``이면 없다."""
    return list(WIN_CAPS.values()) if declares_network(contract) else []


def _wunder(path: str, base: str) -> bool:
    path, base = ntpath.normcase(ntpath.normpath(path)), ntpath.normcase(ntpath.normpath(base))
    return path == base or path.startswith(base.rstrip("\\") + "\\")


def win_runner_caches(contract: Mapping[str, Any], home: str) -> list[str]:
    name = re.sub(r"\.(exe|cmd|bat)$", "", ntpath.basename(str(contract["executable"])).lower())
    first = (contract.get("argv") or [""])[:1]
    needs = RUNNER_ARGS.get(name)
    if name not in WIN_RUNNER_CACHES or (needs and (not first or first[0] not in needs)):
        return []
    join = ntpath.join
    return [ntpath.normpath(join(home, rel)) for rel in WIN_RUNNER_CACHES[name]] if home else []


def win_grants(
    approved: Mapping[str, Any],
    home: str,
    environ: Mapping[str, str],
    *,
    exists: Callable[[str], bool] = os.path.exists,
    real: Callable[[str], str] = os.path.realpath,
    read_text: Callable[[str], str] | None = None,
) -> list[tuple[str, str, bool]]:
    """AppContainer에 줄 (경로, 권한, 선언한 경로인가). 권한은 ``R``읽기·``RX``읽고 실행·``M``수정.

    상위 폴더가 같거나 더 센 권한으로 이미 있으면 건너뛴다. 시스템 폴더(Windows·Program Files)는
    이미 읽을 수 있고 쓸 수 없으므로 선언하지 않은 경로에서는 뺀다. 없는 경로는 붙이지 않는다.
    """
    found: dict[str, tuple[str, str, bool]] = {}
    system = [environ[k] for k in WIN_SYSTEM_ENV if environ.get(k)]

    def add(path: str, mode: str, declared: bool = False) -> None:
        if not path or not ntpath.isabs(path) or not exists(path):
            return
        if not declared and any(_wunder(path, base) for base in system):
            return
        key = ntpath.normcase(ntpath.normpath(path))
        old = found.get(key)
        if old is None or WIN_RANK[mode] > WIN_RANK[old[1]]:
            found[key] = (ntpath.normpath(path), mode, declared or bool(old and old[2]))
        elif declared:
            found[key] = (*old[:2], True)

    folder = ntpath.dirname(real(approved["executable"]))
    add(folder, "RX")
    try:  # 가상 환경이면 그 바탕 인터프리터 폴더도 읽어야 한다.
        cfg = ntpath.join(ntpath.dirname(folder), "pyvenv.cfg")
        text = read_text(cfg) if read_text else open(cfg, encoding="utf-8").read()
        for line in text.splitlines():
            if line.lower().startswith("home") and "=" in line:
                add(line.split("=", 1)[1].strip(), "RX")
    except OSError:
        pass
    script = script_path(approved)
    if script:
        add(ntpath.dirname(script), "R")
    if approved.get("cwd"):
        add(approved["cwd"], "R")
    for cache in win_runner_caches(approved, home):
        add(cache, "M")
    for entry in approved.get("file_access") or ():
        add(str(entry["path"]), "M" if entry.get("mode") == "rw" else "R", True)
    kept = []
    for key, item in sorted(found.items(), key=lambda kv: kv[0].count("\\")):
        covered = any(
            _wunder(key, base) and WIN_RANK[other[1]] >= WIN_RANK[item[1]]
            for base, other in found.items()
            if base != key
        )
        if not covered:
            kept.append(item)
    return kept


def icacls_args(path: str, sid: str, mode: str | None, directory: bool) -> list[str]:
    """``mode``가 있으면 그 SID에 권한을 더하고, 없으면 그 SID의 항목을 지우는 icacls 명령."""
    if mode is None:
        return ["icacls", path, "/remove", "*" + sid, "/Q"]
    flags = "(OI)(CI)" if directory else ""
    return ["icacls", path, "/grant", f"*{sid}:{flags}({mode})", "/Q"]


def _icacls(args: Sequence[str]) -> bool:
    try:
        return subprocess.run(args, capture_output=True, timeout=300).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _win_api():
    """ctypes 함수 묶음. Windows 8 이상이 아니면 ``SandboxUnavailable``."""
    if os.name != "nt":
        raise SandboxUnavailable("not Windows")
    import ctypes
    from ctypes import wintypes as w

    class SidAttr(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", w.DWORD)]

    class SecCaps(ctypes.Structure):
        _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                    ("CapabilityCount", w.DWORD), ("Reserved", w.DWORD)]  # fmt: skip

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
            ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD),
            ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD),
            ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD), ("wShowWindow", w.WORD),
            ("cbReserved2", w.WORD), ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", ctypes.c_void_p), ("hStdOutput", ctypes.c_void_p),
            ("hStdError", ctypes.c_void_p), ("lpAttributeList", ctypes.c_void_p),
        ]  # fmt: skip

    class ProcInfo(ctypes.Structure):
        _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                    ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]  # fmt: skip

    class JobLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD),
            ("SchedulingClass", w.DWORD), ("IoCounters", ctypes.c_uint64 * 6),
            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]  # fmt: skip

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv")
    if not hasattr(userenv, "CreateAppContainerProfile"):
        raise SandboxUnavailable("AppContainer API missing")
    vp, ws, size = ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_size_t
    k32.OpenProcess.restype = vp
    k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k32.CloseHandle.argtypes = [vp]
    k32.GetProcessTimes.argtypes = [vp, vp, vp, vp, vp]
    k32.GetExitCodeProcess.argtypes = [vp, vp]
    k32.CreateJobObjectW.restype = vp
    k32.CreateJobObjectW.argtypes = [vp, ws]
    k32.SetInformationJobObject.argtypes = [vp, ctypes.c_int, vp, w.DWORD]
    k32.AssignProcessToJobObject.argtypes = [vp, vp]
    k32.InitializeProcThreadAttributeList.argtypes = [vp, w.DWORD, w.DWORD, vp]
    k32.UpdateProcThreadAttribute.argtypes = [vp, w.DWORD, size, vp, size, vp, vp]
    k32.DeleteProcThreadAttributeList.argtypes = [vp]
    k32.CreateProcessW.argtypes = [ws, ws, vp, vp, w.BOOL, w.DWORD, vp, ws, vp, vp]
    k32.ResumeThread.argtypes = [vp]
    k32.TerminateProcess.argtypes = [vp, w.UINT]
    k32.WaitForSingleObject.argtypes = [vp, w.DWORD]
    k32.LocalFree.argtypes = [vp]
    adv.ConvertStringSidToSidW.argtypes = [ws, vp]
    adv.ConvertSidToStringSidW.argtypes = [vp, vp]
    userenv.CreateAppContainerProfile.argtypes = [ws, ws, ws, vp, w.DWORD, vp]
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [ws, vp]
    userenv.DeleteAppContainerProfile.argtypes = [ws]
    userenv.GetAppContainerFolderPath.argtypes = [ws, vp]
    return ctypes, k32, adv, userenv, (SidAttr, SecCaps, StartupInfo, ProcInfo, JobLimits)


def _win_proc_start(pid: int) -> str | None:
    """Windows 프로세스 생성 시각(FILETIME). 보고기의 ``StartTime.ToFileTimeUtc()``와 같은 값."""
    try:
        ctypes, k32, *_ = _win_api()
    except SandboxUnavailable:
        return None
    handle = k32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    try:
        code = ctypes.c_uint32()
        if not k32.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value != 259:
            return None  # 끝난 프로세스(남은 핸들 때문에 개체만 남은 경우 포함)
        times = (ctypes.c_uint64 * 4)()
        found = k32.GetProcessTimes(
            ctypes.c_void_p(handle), *[ctypes.byref(times, 8 * i) for i in range(4)]
        )
        return str(times[0]) if found else None
    finally:
        k32.CloseHandle(handle)


def appcontainer_ready() -> bool:
    """이 단말에서 AppContainer API를 쓸 수 있는가(Windows 8 이상)."""
    try:
        _win_api()
    except SandboxUnavailable:
        return False
    return True


def _track_dir(state_dir: str | None) -> str | None:
    return os.path.join(os.path.expanduser(state_dir), ACL_TRACK) if state_dir else None


def _revoke(record: Mapping[str, Any]) -> None:
    for path in record.get("paths") or ():
        _icacls(icacls_args(path, record["sid"], None, False))
    if record.get("profile") and os.name == "nt":
        try:
            _win_api()[3].DeleteAppContainerProfile(record["profile"])
        except SandboxUnavailable:
            pass


def reconcile_appcontainers(state_dir: str | None) -> None:
    """실행기가 죽어 남은 AppContainer 항목(ACE·프로필)을 지운다. 살아 있는 실행기의 것은 둔다."""
    folder = _track_dir(state_dir)
    if not folder or not os.path.isdir(folder):
        return
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        try:
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
            if proc_start(int(record["pid"])) == record["start"]:
                continue
            _revoke(record)
            os.unlink(path)
        except (OSError, ValueError, KeyError, TypeError):
            continue


class AppContainerRun:
    """AppContainer 안의 서버. ``prepare``가 멈춘 채로 만들고 ``run``이 끝까지 돌린다."""

    def __init__(self) -> None:
        self.record: dict[str, Any] = {"paths": []}
        self.track: str | None = None
        self.job = self.process = self.thread = None
        self.api: Any = None

    @classmethod
    def prepare(
        cls, server: str, approved: Mapping[str, Any], argv: Sequence[str],
        env: Mapping[str, str], home: str, state_dir: str | None,
    ) -> AppContainerRun:  # fmt: skip
        self = cls()
        self.api = _win_api()
        ctypes, k32, adv, userenv, _types = self.api
        reconcile_appcontainers(state_dir)
        profile = "mint." + re.sub(r"[^A-Za-z0-9_-]", "_", server)[:32] + f".{os.getpid()}"
        sid = ctypes.c_void_p()
        hr = userenv.CreateAppContainerProfile(
            profile, profile, "MINT server sandbox", None, 0, ctypes.byref(sid)
        )
        if hr & 0xFFFFFFFF == ALREADY_EXISTS:
            hr = userenv.DeriveAppContainerSidFromAppContainerName(profile, ctypes.byref(sid))
        if hr != 0:
            raise SandboxUnavailable(f"AppContainer profile failed ({hr & 0xFFFFFFFF:#x})")
        text = ctypes.c_void_p()
        if not adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise SandboxUnavailable("SID conversion failed")
        self.record.update(pid=os.getpid(), start=proc_start(os.getpid()), profile=profile,
                           sid=ctypes.wstring_at(text))  # fmt: skip
        k32.LocalFree(text)
        track = _track_dir(state_dir)
        try:
            if track:
                os.makedirs(track, exist_ok=True)
                self.track = os.path.join(track, profile + ".json")
            self._save()
            for path, mode, declared in win_grants(approved, home, os.environ):
                self.record["paths"].append(path)
                self._save()
                granted = _icacls(icacls_args(path, self.record["sid"], mode, os.path.isdir(path)))
                if declared and not granted:
                    raise SandboxUnavailable(f"cannot grant access to {path}")
            self._start(approved, argv, env, sid)
        except BaseException:
            self.close()
            raise
        return self

    def _save(self) -> None:
        if self.track:
            with open(self.track, "w", encoding="utf-8") as handle:
                json.dump(self.record, handle)

    def _start(self, approved, argv, env, sid) -> None:
        ctypes, k32, adv, userenv, types = self.api
        SidAttr, SecCaps, StartupInfo, ProcInfo, JobLimits = types
        wanted = win_capabilities(approved)
        caps = []
        for text in wanted:
            caps.append(ctypes.c_void_p())
            adv.ConvertStringSidToSidW(text, ctypes.byref(caps[-1]))
        cap_array = (SidAttr * max(len(caps), 1))(*[SidAttr(c, 4) for c in caps])  # 4 = 사용 중
        listed = ctypes.cast(cap_array, ctypes.c_void_p) if caps else None
        security = SecCaps(sid, listed, len(caps), 0)
        handles = []
        for fd in (0, 1, 2):
            try:
                handle = __import__("msvcrt").get_osfhandle(fd)
                os.set_handle_inheritable(handle, True)
            except (OSError, ValueError):
                handle = None
            handles.append(handle)
        unique = list(dict.fromkeys(h for h in handles if h))
        handle_array = (ctypes.c_void_p * max(len(unique), 1))(*unique)
        length = ctypes.c_size_t(0)
        k32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not k32.InitializeProcThreadAttributeList(buffer, 2, 0, ctypes.byref(length)):
            raise SandboxUnavailable("attribute list failed")
        try:
            # 20009 = SECURITY_CAPABILITIES, 20002 = HANDLE_LIST
            if not k32.UpdateProcThreadAttribute(
                buffer, 0, 0x20009, ctypes.byref(security), ctypes.sizeof(security), None, None
            ) or not k32.UpdateProcThreadAttribute(
                buffer, 0, 0x20002, handle_array, ctypes.sizeof(handle_array), None, None
            ):
                raise SandboxUnavailable("attribute update failed")
            info = StartupInfo()
            info.cb = ctypes.sizeof(StartupInfo)
            info.dwFlags = 0x100  # STARTF_USESTDHANDLES
            info.hStdInput, info.hStdOutput, info.hStdError = handles
            info.lpAttributeList = ctypes.cast(buffer, ctypes.c_void_p)
            block = {str(k): str(v) for k, v in env.items()}
            temp = self._temp_dir()
            if temp:
                block["TEMP"] = block["TMP"] = temp
            pairs = sorted(block.items(), key=lambda i: i[0].lower())
            joined = "".join(f"{k}={v}\0" for k, v in pairs)
            env_buffer = ctypes.create_unicode_buffer(joined + "\0", len(joined) + 2)
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline([approved["executable"], *argv[1:]])
            )
            proc = ProcInfo()
            flags = 0x80000 | 0x4 | 0x400  # 확장 시작 정보, 멈춘 채로 생성, 유니코드 환경
            if not k32.CreateProcessW(
                approved["executable"], command, None, None, True, flags, env_buffer,
                approved.get("cwd") or None, ctypes.byref(info), ctypes.byref(proc),
            ):  # fmt: skip
                raise SandboxUnavailable(f"CreateProcess failed ({ctypes.get_last_error()})")
        finally:
            k32.DeleteProcThreadAttributeList(buffer)
        self.process, self.thread = proc.hProcess, proc.hThread
        self.job = k32.CreateJobObjectW(None, None)
        limits = JobLimits()
        limits.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not (
            self.job
            and k32.SetInformationJobObject(
                self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            )
            and k32.AssignProcessToJobObject(self.job, self.process)
        ):
            k32.TerminateProcess(self.process, 1)
            raise SandboxUnavailable("job object failed")

    def _temp_dir(self) -> str | None:
        ctypes, _k32, _adv, userenv, _types = self.api
        out = ctypes.c_void_p()
        if userenv.GetAppContainerFolderPath(self.record["sid"], ctypes.byref(out)) != 0:
            return None
        try:
            folder = os.path.join(ctypes.wstring_at(out), "AC", "Temp")
        finally:
            ctypes.WinDLL("ole32").CoTaskMemFree(out)
        return folder if os.path.isdir(folder) else None

    def run(self) -> int:
        """서버를 풀어 끝날 때까지 기다리고 종료 코드를 돌려준다. 끝나면 권한·프로필을 정리한다."""
        ctypes, k32, *_ = self.api
        try:
            k32.ResumeThread(self.thread)
            while k32.WaitForSingleObject(self.process, 500) == 0x102:  # 시간 초과면 다시 기다린다.
                pass
            code = ctypes.c_uint32()
            k32.GetExitCodeProcess(self.process, ctypes.byref(code))
            return int(code.value)
        finally:
            self.close()

    def close(self) -> None:
        if self.api:
            # 작업 개체를 닫으면 남은 자식도 끝난다.
            for handle in (self.thread, self.process, self.job):
                if handle:
                    self.api[1].CloseHandle(handle)
            self.thread = self.process = self.job = None
        _revoke(self.record)
        if self.track:
            try:
                os.unlink(self.track)
            except OSError:
                pass


def plan_sandbox(
    approved: Mapping[str, Any],
    argv: Sequence[str],
    policy: Sandbox,
    *,
    home: str,
    which: Callable[[str], str | None] = shutil.which,
    ready: Callable[[str], bool] = bwrap_ready,
    windows: bool | None = None,
    win_ready: Callable[[], bool] = appcontainer_ready,
) -> tuple[list[str] | None, str]:
    """(격리 명령 또는 None, 상태). 상태는 ``bwrap``·``appcontainer``·``none``(격리 못 함).

    Windows(``appcontainer``)는 명령이 아니라 실행기가 직접 AppContainer를 만들어 시작하므로 명령은
    None이다. 관리형 설치는 격리할 수 없으면 시작을 거부한다(``allow_unsandboxed``가 아니면).
    """
    if os.name == "nt" if windows is None else windows:
        if win_ready():
            return None, "appcontainer"
        return unsandboxed(
            policy,
            "AppContainer를 쓸 수 없어 서버를 시작하지 않았습니다. 관리자에게 알려 "
            "Windows 버전을 확인하게 하세요.",
        )
    bwrap = which("bwrap")
    if bwrap and ready(bwrap):
        return bwrap_args(approved, argv, home, bwrap), "bwrap"
    return unsandboxed(
        policy,
        "격리 도구(bubblewrap)를 쓸 수 없어 서버를 시작하지 않았습니다. 관리자에게 알려 "
        "bubblewrap을 설치하거나 사용자 이름공간을 허용하게 하세요.",
    )


def unsandboxed(policy: Sandbox, message: str) -> tuple[None, str]:
    """격리할 수 없을 때: 관리형은 시작하지 않고(허용하지 않는 한), 그 밖에는 격리 없이 시작한다."""
    if policy.managed and not policy.allow_unsandboxed:
        raise Refuse(message)
    return None, "none"


def spawn_and_exit(path: str, argv: list[str], env: Mapping[str, str]) -> None:
    """exec가 없는 Windows용. 자식을 띄워 표준 입출력을 그대로 잇고 같은 종료 코드로 끝난다."""
    sys.exit(subprocess.call([path, *argv[1:]], env=dict(env)))


def run_server(
    server: str,
    contracts: str,
    environ: Mapping[str, str],
    execve: Callable[..., Any] | None = None,
    state_dir: str | None = None,
    sandbox: Sandbox | None = None,
) -> None:
    """승인된 서버만 시작한다. 검증을 통과하지 못하면 ``Refuse``이고 서버는 시작되지 않는다.

    ``state_dir``가 있으면 폐기 서버 목록을 확인하고 시작한 프로세스를 기록한다. ``sandbox``가
    있으면 계약에서 만든 격리(Linux bubblewrap, Windows AppContainer) 안에서 시작하고(실행기가
    부모로 남는다), 관리형이면 격리할 수 없을 때 ``Refuse``이다. 없으면(시험용) 격리하지 않는다.
    """
    if state_dir is not None and server in load_retired(state_dir):
        raise Refuse(f"server {server} was retired by MINT")
    approved = load_contract(contracts, server)
    executable = approved["executable"]
    try:
        fd = os.open(executable, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise Refuse(f"server executable cannot be opened ({type(exc).__name__})") from exc
    verify_launch(approved, fd)
    argv = [executable, *[str(item) for item in approved.get("argv") or []]]
    env = launch_env(approved, environ)
    if approved.get("cwd"):
        os.chdir(approved["cwd"])
    wrapped, status, box = None, None, None
    home = env.get("HOME") or os.path.expanduser("~")
    if sandbox is not None:
        wrapped, status = plan_sandbox(approved, argv, sandbox, home=home)
    if status == "appcontainer":
        try:
            box = AppContainerRun.prepare(server, approved, argv, env, home, state_dir)
        except SandboxUnavailable as exc:
            _, status = unsandboxed(
                sandbox,
                f"AppContainer 격리를 만들지 못해 서버를 시작하지 않았습니다({exc}). "
                "관리자에게 알려 주세요.",
            )
    if state_dir is not None:
        record_launch(state_dir, server, status)
    if box is not None:
        os.close(fd)
        sys.exit(box.run())
    if wrapped is not None:
        os.close(fd)
        spawn_and_exit(wrapped[0], wrapped, env)
    # 한계: 실행 파일은 검증한 기술자로 실행해 바꿔치기를 막지만, 셸 스크립트처럼 기술자로
    # 실행할 수 없으면 경로 실행으로 물러나 검증과 실행 사이에 틈이 남는다. 읽는 스크립트도
    # 경로로 열린다. 관리형 설치의 쓰기 금지 경로가 틈을 줄이며, 완전히 닫으려면 검증한 사본으로
    # 실행한다.
    if execve is None and os.name == "nt":
        # 한계: Windows는 열어 둔 기술자로 실행할 수 없어 닫고 경로로 실행한다(검증과 실행 사이 틈).
        os.close(fd)
        spawn_and_exit(executable, argv, env)
    execve = execve or os.execve
    try:
        execve(fd, argv, env)
    except OSError:
        execve(executable, argv, env)


def kick_report(folder: str) -> None:
    """서버 실행기가 시작될 때 설치 상태 보고를 백그라운드로 부른다(1시간 안에 보냈으면 건너뜀).

    설치된 ``mint_kit.py``가 없거나 띄우지 못해도 서버 시작에는 영향이 없다.
    """
    tool = os.path.join(folder, "mint_kit.py")
    if not os.path.isfile(tool):
        return
    null = subprocess.DEVNULL
    quiet = {"stdin": null, "stdout": null, "stderr": null}
    detach = {"creationflags": 0x08000008} if os.name == "nt" else {"start_new_session": True}
    try:
        subprocess.Popen(
            [sys.executable, "-I", "-B", tool, "report", "--kit", folder, "--if-due"],
            **quiet, **detach,
        )
    except OSError:
        pass


def _give_up(code: int, message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    os._exit(code)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["pre", "post", "post-failure", "run", "serve"])
    parser.add_argument("--url")
    parser.add_argument("--key-file")
    parser.add_argument("--contracts", required=True)
    parser.add_argument("--state-dir")
    parser.add_argument("--ca-file")
    parser.add_argument("--server")
    parser.add_argument("--no-keepalive", action="store_true")
    parser.add_argument("--idle", type=float, default=BROKER_IDLE)
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT)
    parser.add_argument("--deadline", type=float, default=HOOK_DEADLINE)
    args = parser.parse_args(argv)

    if args.command == "serve":
        serve_broker(
            os.path.join(os.path.expanduser(args.state_dir), BROKER_SOCKET), args.ca_file, args.idle
        )
        return
    if args.command == "run":
        kick_report(os.path.dirname(os.path.abspath(__file__)))
        try:
            run_server(
                args.server or "", args.contracts, os.environ,
                state_dir=args.state_dir or STATE_DIR, sandbox=sandbox_policy(),
            )  # fmt: skip
        except SystemExit:
            raise  # 격리·Windows 실행은 서버의 종료 코드로 끝난다.
        except Refuse as exc:
            _give_up(REFUSED, f"MINT refused to start the server: {exc}")
        except BaseException as exc:  # 어떤 예외도 시작으로 새지 않는다.
            _give_up(REFUSED, f"MINT launcher failed: {type(exc).__name__}")
        return

    blocking = args.command == "pre"
    notice = "MINT hook timed out" + ("; the call is blocked" if blocking else "")
    watchdog = threading.Timer(args.deadline, _give_up, [2 if blocking else 0, notice])
    watchdog.daemon = True
    watchdog.start()
    try:
        event = json.loads(sys.stdin.buffer.read())  # 지역 인코딩이 아니라 UTF-8 그대로
        if not isinstance(event, dict):
            raise Refuse("hook input is not an object")
        with open(os.path.expanduser(args.key_file), encoding="utf-8") as handle:
            key = handle.read().strip()
        state_dir = os.path.expanduser(args.state_dir)

        sock_path = os.path.join(state_dir, BROKER_SOCKET)

        def post(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes]:
            if not args.no_keepalive:
                try:
                    return broker_post(sock_path, url, headers, body, timeout)
                except BrokerDown:
                    start_broker(state_dir, args.contracts, args.ca_file)
            return http_post(url, headers, body, timeout, args.ca_file)

        if blocking:
            decide(
                event, url=args.url, key=key, contracts=os.path.expanduser(args.contracts),
                state_dir=state_dir, post=post, http_timeout=args.http_timeout,
            )
        else:
            report_result(
                event, failed=args.command == "post-failure", url=args.url, key=key,
                state_dir=state_dir, post=post, http_timeout=args.http_timeout,
            )
    except Refuse as exc:
        if blocking:
            _give_up(2, str(exc))
    except BaseException as exc:  # 어떤 예외도 허용으로 새지 않는다.
        if blocking:
            _give_up(2, f"MINT hook failed: {type(exc).__name__}")
    watchdog.cancel()
    sys.exit(0)


if __name__ == "__main__":
    main()
