"""시작 횟수와 도구 실행 횟수를 따로 세는 시험용 stdio MCP 서버.

사용: python count_mcp.py LOG_FILE
시작할 때 ``start`` 줄 하나, 도구가 실제로 실행될 때마다 ``call`` 줄 하나를 LOG_FILE에 덧붙인다.
표준 라이브러리만 쓰고 줄 단위 JSON-RPC를 말한다. ``slow`` 도구는 실행 중 지연을 시험할 때 쓴다.
"""

import json
import os
import sys
import time

TOOLS = [
    {
        "name": "echo",
        "description": "Return the given text.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "slow",
        "description": "Return the given text after a delay in seconds.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}, "seconds": {"type": "number"}},
            "required": ["text"],
        },
    },
]


def record(path: str, event: str, **fields) -> None:
    line = json.dumps({"ev": event, "pid": os.getpid(), "ts": time.time(), **fields})
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")


def reply(message_id, result=None, error=None) -> None:
    body = {"jsonrpc": "2.0", "id": message_id}
    body["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(body) + "\n")
    sys.stdout.flush()


def handle(log: str, message: dict) -> None:
    method, message_id = message.get("method"), message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        reply(
            message_id,
            {
                "protocolVersion": params.get("protocolVersion", ""),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "count-mcp", "version": "0.1.0"},
            },
        )
    elif method == "tools/list":
        reply(message_id, {"tools": TOOLS})
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in {tool["name"] for tool in TOOLS}:
            reply(message_id, error={"code": -32602, "message": "unknown tool"})
            return
        record(log, "call", tool=name, args=args)
        if name == "slow":
            time.sleep(float(args.get("seconds", 1)))
        reply(message_id, {"content": [{"type": "text", "text": str(args.get("text", ""))}]})
    elif message_id is not None:
        reply(message_id, error={"code": -32601, "message": "method not found"})


def main() -> None:
    log = sys.argv[1]
    record(log, "start", argv=sys.argv[1:], cwd=os.getcwd())
    for raw in sys.stdin:
        raw = raw.strip()
        if raw:
            handle(log, json.loads(raw))


if __name__ == "__main__":
    main()
