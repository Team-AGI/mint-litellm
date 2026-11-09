"""Claude Code 호출 전(PreToolUse) 훅. 표준 라이브러리만 쓰며 파일 하나로 배포할 수 있다.

MCP 도구 호출마다 MINT 결정 경로에 판정을 묻고, 허용이 아니면 종료 코드 2로 호출을 막는다.
오류는 모두 차단이다. 허용은 아무것도 출력하지 않고 종료 코드 0으로 끝낸다(하네스의 권한
흐름을 그대로 두며 이 훅이 권한을 대신 주지 않는다). 이 훅은 재시도하지 않는다.

시간 상한은 HTTP 대기 < 훅 내부 상한 < 하네스 ``timeout`` 순서여야 한다. 하네스는 시간 초과나
시작 실패를 기본적으로 통과시키므로 관리형 설정에 ``"onFailure": "block"``을 함께 둔다.
출력이 JSON처럼 보여도 해석되지 않으면 일반 글로 취급되어 통과하므로 허용 때는 출력하지 않는다.

사용 예(관리형 설정 ``hooks.PreToolUse``의 명령):
    python3 hook.py --url URL --key-file FILE --mcp-config FILE [--ca-file FILE]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

DECIDE_PATH = "/mint/v1/decide"
MAX_RESPONSE = 64 * 1024
HTTP_TIMEOUT = 2.0
HOOK_DEADLINE = 2.5

Post = Callable[[str, dict[str, str], bytes, float], tuple[int, bytes]]


class Refuse(Exception):
    """호출을 막아야 하는 사유. 메시지는 사용자에게 보인다."""


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def server_and_tool(event: Mapping[str, Any]) -> tuple[str, str]:
    server = (event.get("mcp_server") or {}).get("name")
    name = event.get("tool_name")
    if not isinstance(server, str) or not isinstance(name, str):
        raise Refuse("hook input has no MCP server or tool name")
    prefix = "mcp__" + re.sub(r"[^a-zA-Z0-9_-]", "_", server) + "__"
    if not name.startswith(prefix) or len(name) == len(prefix):
        raise Refuse("tool name does not match the MCP server")
    return server, name[len(prefix) :]


def declared_contract(
    server: str, mcp_config: Mapping[str, Any], session_cwd: str | None
) -> dict[str, Any]:
    """MCP 설정에 선언된 로컬 서버를 실행 계약으로 옮긴다(실행 중 프로세스의 증명은 아니다)."""
    entry = (mcp_config.get("mcpServers") or {}).get(server)
    if not isinstance(entry, dict) or not isinstance(entry.get("command"), str):
        raise Refuse("server is not a local command server in the MCP config")
    cwd = entry.get("cwd") or session_cwd
    if not isinstance(cwd, str):
        raise Refuse("working directory is unknown")
    executable = shutil.which(entry["command"], path=(entry.get("env") or {}).get("PATH"))
    if executable is None:
        raise Refuse("server command was not found")
    argv = [str(item) for item in entry.get("args") or []]
    script = next(
        (
            path
            for item in argv
            if os.path.isfile(path := item if os.path.isabs(item) else os.path.join(cwd, item))
        ),
        None,
    )
    env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
    return {
        "schema_version": 1,
        "identity_kind": "stdio",
        "executable": executable,
        "argv": argv,
        "cwd": cwd,
        "executable_sha256": sha256_file(executable),
        "script_sha256": sha256_file(script) if script else None,
        "env": env,
        "secret_refs": {},
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_post(url: str, headers: dict[str, str], body: bytes, timeout: float, ca_file: str | None):
    import ssl

    context = ssl.create_default_context(cafile=ca_file) if url.startswith("https:") else None
    handlers: list[Any] = [_NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE + 1)


def decide(
    event: Mapping[str, Any],
    *,
    url: str,
    key: str,
    mcp_config: Mapping[str, Any],
    post: Post,
    http_timeout: float = HTTP_TIMEOUT,
) -> None:
    """허용이면 조용히 돌아오고, 그 밖에는 ``Refuse``를 던진다."""
    name = event.get("tool_name")
    if not isinstance(name, str) or not name.startswith("mcp__"):
        return  # MCP 호출이 아니면 이 훅의 대상이 아니다.
    server, tool = server_and_tool(event)
    arguments = event.get("tool_input")
    if not isinstance(arguments, dict):
        raise Refuse("tool arguments are not an object")
    payload = {
        "server": server,
        "tool": tool,
        "arguments": arguments,
        "contract": declared_contract(server, mcp_config, event.get("cwd")),
        "tool_use_id": event.get("tool_use_id"),
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        status, raw = post(
            url.rstrip("/") + DECIDE_PATH, headers, json.dumps(payload).encode(), http_timeout
        )
    except (OSError, ValueError) as exc:
        raise Refuse(f"decision service is unreachable ({type(exc).__name__})") from exc
    if status != 200:
        raise Refuse(f"decision service refused the request (HTTP {status})")
    try:
        answer = json.loads(raw) if len(raw) <= MAX_RESPONSE else None
    except ValueError:
        answer = None
    if not isinstance(answer, dict) or answer.get("decision") not in {"allow", "deny"}:
        raise Refuse("decision service sent an unreadable answer")
    if answer["decision"] == "deny":
        error = answer.get("error") if isinstance(answer.get("error"), dict) else {}
        raise Refuse(
            f"blocked by MINT: {error.get('code', 'denied')} reference={answer.get('reference')}"
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--mcp-config", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT)
    parser.add_argument("--deadline", type=float, default=HOOK_DEADLINE)
    args = parser.parse_args(argv)

    def give_up(message: str) -> None:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
        os._exit(2)

    watchdog = threading.Timer(args.deadline, give_up, ["MINT hook timed out; the call is blocked"])
    watchdog.daemon = True
    watchdog.start()
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise Refuse("hook input is not an object")
        with open(args.key_file, encoding="utf-8") as handle:
            key = handle.read().strip()
        with open(args.mcp_config, encoding="utf-8") as handle:
            mcp_config = json.load(handle)
        decide(
            event,
            url=args.url,
            key=key,
            mcp_config=mcp_config,
            post=lambda u, h, b, t: http_post(u, h, b, t, args.ca_file),
            http_timeout=args.http_timeout,
        )
    except Refuse as exc:
        give_up(str(exc))
    except BaseException as exc:  # 어떤 예외도 허용으로 새지 않는다.
        give_up(f"MINT hook failed: {type(exc).__name__}")
    watchdog.cancel()
    sys.exit(0)


if __name__ == "__main__":
    main()
