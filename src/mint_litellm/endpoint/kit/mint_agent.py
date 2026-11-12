#!/usr/bin/env python3
"""MINT 단말 에이전트(표준 라이브러리만, Python 3.9 이상). 파일 하나로 배포한다.

하위 명령:
  pre   호출 전 훅. 도구 호출마다 MINT 결정 경로에 판정을 묻고, 허용이 아니면 종료 코드 2로
        호출을 막는다. 오류는 모두 차단이다. 허용은 아무것도 출력하지 않고 종료 코드 0으로
        끝낸다(하네스의 권한 흐름을 그대로 두며 이 훅이 권한을 대신 주지 않는다).
  post  호출 뒤 훅(성공)과 post-failure(실패). 판정 때 받은 참조를 MINT에 돌려 결과를 보고한다.
        보고하지 못해도 호출에는 영향이 없고, MINT는 보고 없는 호출을 결과 미확인으로 남긴다.
  run   MCP 서버 실행기. 승인된 실행 계약과 디스크의 실행 파일·스크립트 해시가 모두 같을 때만
        서버를 시작하고, 아니면 시작하지 않고 종료 코드 126으로 끝난다.

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
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any

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


def _call(post: Post, base: str, path: str, key: str, payload: dict, timeout: float) -> dict:
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        status, raw = post(base.rstrip("/") + path, headers, json.dumps(payload).encode(), timeout)
    except (OSError, ValueError) as exc:
        raise Refuse(f"decision service is unreachable ({type(exc).__name__})") from exc
    if status != 200:
        raise Refuse(f"decision service refused the request (HTTP {status})")
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


def spawn_and_exit(path: str, argv: list[str], env: Mapping[str, str]) -> None:
    """exec가 없는 Windows용. 자식을 띄워 표준 입출력을 그대로 잇고 같은 종료 코드로 끝난다."""
    sys.exit(subprocess.call([path, *argv[1:]], env=dict(env)))


def run_server(
    server: str,
    contracts: str,
    environ: Mapping[str, str],
    execve: Callable[..., Any] | None = None,
) -> None:
    """승인된 서버만 시작한다. 검증을 통과하지 못하면 ``Refuse``이고 서버는 시작되지 않는다."""
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


def _give_up(code: int, message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()
    os._exit(code)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["pre", "post", "post-failure", "run"])
    parser.add_argument("--url")
    parser.add_argument("--key-file")
    parser.add_argument("--contracts", required=True)
    parser.add_argument("--state-dir")
    parser.add_argument("--ca-file")
    parser.add_argument("--server")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT)
    parser.add_argument("--deadline", type=float, default=HOOK_DEADLINE)
    args = parser.parse_args(argv)

    if args.command == "run":
        try:
            run_server(args.server or "", args.contracts, os.environ)
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

        def post(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes]:
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
