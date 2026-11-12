"""공식 MCP SDK(FastMCP, Streamable HTTP)로 만든 통합 시험용 업스트림 서버.

제품 배포·승인 목록 밖에서 업스트림 호출 수를 세고 결정론적 장애를 주입하는 데만 쓴다.
MCP 포트(MCP_PORT)와 제어 포트(CONTROL_PORT)는 분리되어 있고, 제어 포트만 시험 호스트에 열린다.
같은 프로세스가 전송·판본 조합별 MCP 포트를 더 연다(``TRANSPORTS``). 조합마다 받은 초기화 판본,
요청 헤더의 판본, 응답 콘텐츠 유형을 따로 기록해 전송 회귀 시험이 대조한다.

계수는 세 지점에서 따로 한다.
  arrived    HTTP 본문을 읽어 tools/call 메시지를 확인한 시점(SDK에 넘기기 전)
  entered    SDK의 CallToolRequest 처리기에 들어온 시점
  completed  처리기가 결과를 돌려준 시점
"""

import asyncio
import json
import os
import weakref
from typing import Any

import uvicorn
from mcp import types
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import McpError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

INSTANCE = os.environ.get("INSTANCE_ID", "testserver")
MCP_PORT = int(os.environ.get("MCP_PORT", "9000"))
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "9001"))
# 조합 이름 -> (포트, 설명). 계수 프록시의 /e/ /f/ /g/ /h/ 경로가 각각 가리킨다.
TRANSPORTS = {
    "json-pinned": (9005, "Streamable HTTP, JSON 응답"),
    "sse-response": (9002, "Streamable HTTP, SSE 응답"),
    "legacy-sse": (9003, "구형 HTTP+SSE(별도 SSE 수신 연결과 POST 주소)"),
    "modern": (9004, "2026-07-28 요청별 봉투, SDK 없이 직접 구현"),
}
LEGACY_SSE_MOUNT = "/g"
MODERN_VERSION = "2026-07-28"

MUTABLE_VARIANTS = {
    "v1": "Returns the stored value (variant one).",
    "v2": "Returns the stored value repeated count times (variant two).",
}


class State:
    def __init__(self) -> None:
        self.sessions: weakref.WeakSet[Any] = weakref.WeakSet()
        self.reset()

    def reset(self) -> None:
        self.arrived_by_method: dict[str, int] = {}
        # 조합 이름 -> {"initialize": {판본: 수}, "protocol_header": {메서드: {헤더 값: 수}},
        #               "response_types": {콘텐츠 유형: 수}}
        self.seen: dict[str, dict[str, Any]] = {}
        self.modern_requests: list[dict[str, Any]] = []
        self.tools_call: dict[str, dict[str, int]] = {}
        self.list_changed_sent = 0
        self.faults: dict[str, Any] = {}
        self.variant = "v1"
        self.description = MUTABLE_VARIANTS["v1"]

    def bump(self, marker: str, field: str) -> None:
        row = self.tools_call.setdefault(marker, {"arrived": 0, "entered": 0, "completed": 0})
        row[field] += 1

    def note(self, label: str, kind: str, *keys: str) -> None:
        node = self.seen.setdefault(label, {}).setdefault(kind, {})
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = node.get(keys[-1], 0) + 1

    def totals(self) -> dict[str, int]:
        out = {"arrived": 0, "entered": 0, "completed": 0}
        for row in self.tools_call.values():
            for key, value in row.items():
                out[key] += value
        return out


state = State()


def rpc_messages(body: bytes) -> list[tuple[str, str, str]]:
    """본문의 JSON-RPC 메시지를 (method, marker, 초기화 판본) 목록으로 푼다. 못 풀면 빈 목록."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return []
    out: list[tuple[str, str, str]] = []
    for message in parsed if isinstance(parsed, list) else [parsed]:
        if not isinstance(message, dict) or "method" not in message:
            continue
        params = message.get("params") or {}
        arguments = params.get("arguments") if isinstance(params, dict) else None
        marker = arguments.get("marker", "") if isinstance(arguments, dict) else ""
        version = params.get("protocolVersion", "") if isinstance(params, dict) else ""
        out.append((str(message["method"]), str(marker), str(version)))
    return out


class Gate:
    """SDK 앞단에서 도착을 세고 HTTP 상태 코드·응답 중간 끊김 장애를 주입한다."""

    def __init__(self, app, label: str = "json"):
        self.app = app
        self.label = label

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        chunks, more = [], True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(chunks)
        calls = []
        header = dict(scope["headers"]).get(b"mcp-protocol-version", b"").decode()
        for method, marker, version in rpc_messages(body):
            state.arrived_by_method[method] = state.arrived_by_method.get(method, 0) + 1
            state.note(self.label, "protocol_header", method, header)
            if method == "initialize":
                state.note(self.label, "initialize", version)
            if method == "tools/call":
                state.bump(marker, "arrived")
                calls.append(marker)

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        faults = state.faults
        if calls and faults.get("http_status"):
            await send(
                {
                    "type": "http.response.start",
                    "status": int(faults["http_status"]),
                    "headers": [(b"content-length", b"0")],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return
        cut = faults.get("cut") if calls else None
        if cut:
            if cut == "after_exec":

                async def discard(message):
                    pass

                await self.app(scope, replay, discard)
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", b"4096"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"jsonrpc"', "more_body": True})
            # 응답 시작 뒤 예외를 던지면 uvicorn이 연결을 닫아 클라이언트가 중간 끊김을 본다.
            raise ConnectionAbortedError("injected cut")

        async def tap(message):
            if calls and message["type"] == "http.response.start":
                kind = dict(message.get("headers", [])).get(b"content-type", b"").decode()
                state.note(self.label, "response_types", kind.split(";")[0])
            await send(message)

        await self.app(scope, replay, tap)


def register_mutable(server: FastMCP) -> None:
    if state.variant == "v1":

        def mutable(text: str, marker: str = "") -> str:
            return text
    else:

        def mutable(text: str, count: int, marker: str = "") -> str:
            return text * count

    server.add_tool(mutable, name="mutable", description=state.description)


def build(json_response: bool = True) -> FastMCP:
    server = FastMCP(
        INSTANCE,
        host="",
        port=MCP_PORT,
        json_response=json_response,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @server.tool(description="Returns the given text together with the serving instance name.")
    def echo(text: str, marker: str = "") -> str:
        return f"{INSTANCE}:{text}"

    @server.tool(description="Waits for the given number of seconds, then returns.")
    async def slow(seconds: float, marker: str = "") -> str:
        await asyncio.sleep(seconds)
        return f"{INSTANCE}:slept"

    @server.prompt(description="A fixed greeting prompt.")
    def greeting() -> str:
        return "hello"

    @server.resource("note://hello", description="A fixed text resource.")
    def note() -> str:
        return "hello"

    register_mutable(server)

    low = server._mcp_server
    inner_call = low.request_handlers[types.CallToolRequest]
    inner_list = low.request_handlers[types.ListToolsRequest]

    async def counted_call(req):
        state.sessions.add(low.request_context.session)
        marker = str((req.params.arguments or {}).get("marker", ""))
        state.bump(marker, "entered")
        faults = state.faults
        if faults.get("delay_ms"):
            await asyncio.sleep(int(faults["delay_ms"]) / 1000)
        if faults.get("rpc_error"):
            raise McpError(types.ErrorData(code=-32001, message="injected rpc error"))
        if faults.get("tool_error"):
            state.bump(marker, "completed")
            return types.ServerResult(
                types.CallToolResult(
                    content=[types.TextContent(type="text", text="injected tool error")],
                    isError=True,
                )
            )
        result = await inner_call(req)
        state.bump(marker, "completed")
        return result

    async def listed(req):
        state.sessions.add(low.request_context.session)
        return await inner_list(req)

    low.request_handlers[types.CallToolRequest] = counted_call
    low.request_handlers[types.ListToolsRequest] = listed
    return server


async def notify_list_changed() -> int:
    sent = 0
    for session in list(state.sessions):
        try:
            await session.send_tool_list_changed()
            sent += 1
        except Exception:
            continue
    state.list_changed_sent += sent
    return sent


def modern_app() -> Starlette:
    """2026-07-28 요청별 봉투를 SDK 없이 받는 최소 서버(server/discover, tools/list, tools/call).

    요청 헤더(판본·메서드·이름)와 본문 값이 어긋나면 400으로 거절하고, 받은 요청의 헤더·본문 값을
    그대로 남겨 시험이 명세의 기대와 대조한다.
    """
    tool = {
        "name": "echo",
        "description": "Returns the given text together with the serving instance name.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}, "marker": {"type": "string"}},
            "required": ["text"],
        },
    }

    def fail(status: int, code: int, text: str, rid=None) -> JSONResponse:
        error = {"code": code, "message": text, "data": {"supported": [MODERN_VERSION]}}
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": error}, status_code=status)

    async def endpoint(request: Request):
        message = await request.json()
        params = message.get("params") or {}
        meta = params.get("_meta") or {}
        method, rid = message.get("method"), message.get("id")
        row = {
            "method": method,
            "header_version": request.headers.get("mcp-protocol-version"),
            "header_method": request.headers.get("mcp-method"),
            "header_name": request.headers.get("mcp-name"),
            "meta_version": meta.get("io.modelcontextprotocol/protocolVersion"),
            "body_name": params.get("name"),
            "accept": request.headers.get("accept"),
            "session_header": "mcp-session-id" in request.headers,
        }
        state.modern_requests.append(row)
        if rid is None:
            return Response(status_code=202)
        if row["header_version"] != MODERN_VERSION or row["meta_version"] != MODERN_VERSION:
            return fail(400, -32022, "Unsupported protocol version", rid)
        if row["header_method"] != method or (
            method == "tools/call" and row["header_name"] != row["body_name"]
        ):
            return fail(400, -32020, "Header mismatch", rid)
        done = {"resultType": "complete"}
        if method == "server/discover":
            result = {
                **done,
                "supportedVersions": [MODERN_VERSION],
                "capabilities": {"tools": {}},
                "cacheScope": "private",
                "ttlMs": 0,
            }
        elif method == "tools/list":
            result = {**done, "tools": [tool], "cacheScope": "private", "ttlMs": 0}
        elif method == "tools/call":
            arguments = params.get("arguments") or {}
            marker = str(arguments.get("marker", ""))
            state.bump(marker, "entered")
            text = f"{INSTANCE}:{arguments.get('text', '')}"
            result = {**done, "content": [{"type": "text", "text": text}]}
            state.bump(marker, "completed")
        else:
            return fail(404, -32601, "Method not found", rid)
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result})

    return Starlette(routes=[Route("/mcp", endpoint, methods=["POST"])])


def control_app(server: FastMCP) -> Starlette:
    async def health(_: Request):
        return JSONResponse({"ok": True, "instance": INSTANCE})

    async def counters(_: Request):
        return JSONResponse(
            {
                "instance": INSTANCE,
                "tools_call": state.totals(),
                "by_marker": state.tools_call,
                "by_method": state.arrived_by_method,
                "transports": state.seen,
                "modern_requests": state.modern_requests,
                "list_changed_sent": state.list_changed_sent,
                "variant": state.variant,
                "faults": state.faults,
            }
        )

    async def set_faults(request: Request):
        state.faults = await request.json() if request.method == "POST" else {}
        return JSONResponse(state.faults)

    async def reset(_: Request):
        state.reset()
        server.remove_tool("mutable")
        register_mutable(server)
        return JSONResponse({"ok": True})

    async def mutate(request: Request):
        body = await request.json()
        variant = body.get("variant", state.variant)
        if variant not in MUTABLE_VARIANTS:
            return JSONResponse({"error": "unknown variant"}, status_code=400)
        state.variant = variant
        state.description = body.get("description", MUTABLE_VARIANTS[variant])
        server.remove_tool("mutable")
        register_mutable(server)
        sent = await notify_list_changed()
        return JSONResponse({"variant": state.variant, "notified_sessions": sent})

    return Starlette(
        routes=[
            Route("/health", health),
            Route("/counters", counters),
            Route("/faults", set_faults, methods=["POST", "DELETE"]),
            Route("/reset", reset, methods=["POST"]),
            Route("/mutate", mutate, methods=["POST"]),
        ]
    )


async def main() -> None:
    server = build()
    mcp_app = Gate(server.streamable_http_app())
    apps = {
        "json-pinned": build().streamable_http_app(),
        "sse-response": build(json_response=False).streamable_http_app(),
        "legacy-sse": build().sse_app(mount_path=LEGACY_SSE_MOUNT),
        "modern": modern_app(),
    }
    extra = [
        uvicorn.Server(
            uvicorn.Config(
                Gate(app, label), host="", port=TRANSPORTS[label][0], log_level="warning"
            )
        )
        for label, app in apps.items()
    ]
    servers = [
        *extra,
        uvicorn.Server(uvicorn.Config(mcp_app, host="", port=MCP_PORT, log_level="warning")),
        uvicorn.Server(
            uvicorn.Config(control_app(server), host="", port=CONTROL_PORT, log_level="warning")
        ),
    ]
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
