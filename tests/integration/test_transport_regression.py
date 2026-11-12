"""전송·판본 조합 회귀: 지금 지원하는 MCP 전송 조합을 고정하고 2026-07-28 판본의 동작을 기록한다.

조합마다 (1) 승인이 없으면 판정 사건이 한 건 남고 업스트림 효과가 0이며, (2) 승인하면 사건이 한 건
남고 효과가 1이라는 것과, 시험 서버가 실제로 본 전송·판본(초기화 판본, 요청 헤더, 응답 형식)을 함께
확인한다. LiteLLM 판본을 올렸을 때 동작이 바뀌면 이 시험이 실패한다.

    들어오는 쪽(하네스 -> LiteLLM)              나가는 쪽(LiteLLM -> 업스트림)
    Streamable HTTP, 초기화 판본 2025-06-18     e: Streamable HTTP, JSON 응답, 2025-06-18
    (LiteLLM은 응답을 SSE로 돌려준다)           f: Streamable HTTP, SSE 응답, 2025-06-18
                                                g: 구형 HTTP+SSE, 2024-11-05
                                                h: 2026-07-28 요청별 봉투
    구형 HTTP+SSE(/mcp/sse + /mcp/sse/messages) e

2026-07-28 헤더로 들어오는 요청은 기본 설정에서 도구 호출 앞에서 거절된다. 광고 판본에 2026-07-28을
넣은 구성은 거절 여부를 단정하지 않고 판정 사건 없이 업스트림에 닿는 호출이 없음만 확인한다.
"""

import json
import re
import time
from pathlib import Path

import httpx
import pytest
import support
from mcp import ClientSession
from mcp.client.sse import sse_client
from scenario import decision, litellm_config
from support import run
from test_acceptance_core import code_of

LITELLM = support.url(support.LITELLM_PORTS[0])
CONFIG_DIR = Path(__file__).resolve().parent / "config"
BASE_CONFIG = CONFIG_DIR / "litellm.mint.yaml"
BLOCK = code_of("APPROVAL_ABSENT")
INSTANCE = "upstream-a"
LEGACY_VERSIONS = "2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25"
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "it", "version": "0"},
}


def messages_of(reply: httpx.Response) -> list[dict]:
    """JSON 또는 SSE로 온 응답 본문의 JSON-RPC 메시지들."""
    if reply.headers.get("content-type", "").startswith("text/event-stream"):
        data = [line[5:].strip() for line in reply.text.splitlines() if line.startswith("data:")]
        return [json.loads(d) for d in data if d]
    return [reply.json()] if reply.content else []


class Wire:
    """Streamable HTTP 하네스를 흉내 내는 원시 클라이언트. 초기화 판본과 헤더를 직접 정한다."""

    def __init__(self, key: str, version: str = "2025-06-18"):
        self.version = version
        self.http = httpx.Client(timeout=60)
        self.headers = {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        self.session: str | None = None
        self.next_id = 0

    def post(self, method: str, params: dict | None = None) -> httpx.Response:
        body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not method.startswith("notifications/"):
            self.next_id += 1
            body["id"] = self.next_id
        return self.http.post(f"{LITELLM}/mcp", headers=self.headers, content=json.dumps(body))

    def open(self) -> httpx.Response:
        reply = self.post(
            "initialize",
            {
                "protocolVersion": self.version,
                "capabilities": {},
                "clientInfo": {"name": "it", "version": "0"},
            },
        )
        self.session = reply.headers.get("mcp-session-id")
        self.headers["MCP-Protocol-Version"] = self.version
        if self.session:
            self.headers["Mcp-Session-Id"] = self.session
        self.post("notifications/initialized")
        return reply

    def call(self, tool: str, arguments: dict) -> httpx.Response:
        return self.post("tools/call", {"name": tool, "arguments": arguments})

    def close(self) -> None:
        if self.session:
            self.http.delete(f"{LITELLM}/mcp", headers=self.headers)
        self.http.close()


def streamable_call(key: str, server: str, mark: str) -> str:
    wire = Wire(key)
    try:
        opened = wire.open()
        assert opened.status_code == 200, opened.text
        reply = wire.call(f"{support.TOOL_PREFIX[server]}-echo", {"text": "hello", "marker": mark})
        return reply.text
    finally:
        wire.close()


async def _legacy_call(key: str, server: str, mark: str) -> str:
    headers = {"Authorization": f"Bearer {key}"}
    async with sse_client(support.url(support.LITELLM_PORTS[0], "/mcp/sse"), headers) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            try:
                result = await session.call_tool(
                    f"{support.TOOL_PREFIX[server]}-echo", {"text": "hello", "marker": mark}
                )
            except Exception as error:
                return str(error)
            return json.dumps(result.model_dump(), default=str)


def legacy_call(key: str, server: str, mark: str) -> str:
    return run(_legacy_call(key, server, mark))


# 경로 이름 -> (들어오는 쪽, 업스트림 서버)
PATHS = {
    "streamable-in__json-out": ("streamable", "e"),
    "streamable-in__sse-response-out": ("streamable", "f"),
    "streamable-in__legacy-sse-out": ("streamable", "g"),
    "streamable-in__2026-07-28-out": ("streamable", "h"),
    "legacy-sse-in__json-out": ("legacy", "e"),
}


def invoke(ingress: str, key: str, server: str, mark: str) -> str:
    return (legacy_call if ingress == "legacy" else streamable_call)(key, server, mark)


def decisions_of(world, subject, since, count: int) -> list[dict]:
    """주체가 남긴 판정 사건. ``count``건이 보일 때까지 기다린다."""
    support.wait_until(
        lambda: len(world.decisions_since(subject, since)) >= count, 10, 0.5, what="decision events"
    )
    return world.decisions_since(subject, since)


def seen(upstream, label: str) -> dict:
    return upstream.counters()["transports"].get(label, {})


@pytest.mark.parametrize("path", PATHS)
def test_each_path_blocks_without_approval_and_allows_with_it(world, evidence, path):
    ingress, server = PATHS[path]
    subject = world.subject((server,))
    relation = world.prepare(subject, server)

    since = world.now()
    blocked = support.marker()
    text = invoke(ingress, subject.key, server, blocked)
    assert BLOCK in text, text
    (event,) = decisions_of(world, subject, since, 1)
    payload = event["payload"]
    assert (payload["evaluated_decision"], payload["enforced_action"]) == ("block", "block")
    assert payload["stop"]["reason_code"] == "APPROVAL_ABSENT"
    evidence.assert_calls(blocked, 0, server)

    world.approve(subject, relation, tools="echo")
    since = world.now()
    allowed = support.marker()
    text = invoke(ingress, subject.key, server, allowed)
    assert f"{INSTANCE}:hello" in text, text
    (event,) = decisions_of(world, subject, since, 1)
    assert (event["payload"]["evaluated_decision"], event["payload"]["enforced_action"]) == (
        "allow",
        "allow",
    )
    evidence.assert_calls(allowed, 1, server)


def test_upstream_streamable_http_json_response_with_2025_06_18(world, evidence, upstreams):
    subject = world.subject(("e",))
    world.approve(subject, world.prepare(subject, "e"), tools="echo")
    mark = support.marker()
    assert f"{INSTANCE}:hello" in streamable_call(subject.key, "e", mark)
    wire = seen(upstreams["a"], "json-pinned")
    assert set(wire["initialize"]) == {"2025-06-18"}
    assert wire["protocol_header"]["tools/call"] == {"2025-06-18": 1}
    assert wire["response_types"] == {"application/json": 1}


def test_upstream_streamable_http_sse_response_with_2025_06_18(world, evidence, upstreams):
    subject = world.subject(("f",))
    world.approve(subject, world.prepare(subject, "f"), tools="echo")
    mark = support.marker()
    assert f"{INSTANCE}:hello" in streamable_call(subject.key, "f", mark)
    wire = seen(upstreams["a"], "sse-response")
    assert set(wire["initialize"]) == {"2025-06-18"}
    assert wire["protocol_header"]["tools/call"] == {"2025-06-18": 1}
    assert wire["response_types"] == {"text/event-stream": 1}


def test_upstream_legacy_http_sse_uses_separate_get_and_post(world, evidence, upstreams, proxy_log):
    subject = world.subject(("g",))
    world.approve(subject, world.prepare(subject, "g"), tools="echo")
    mark = support.marker()
    proxy_log.mark()
    assert f"{INSTANCE}:hello" in streamable_call(subject.key, "g", mark)
    evidence.assert_calls(mark, 1, "g")
    assert set(seen(upstreams["a"], "legacy-sse")["initialize"]) == {"2024-11-05"}
    support.wait_until(lambda: proxy_log.rows(http="GET", path="/g/sse"), 10, 0.5, what="sse GET")
    (row,) = proxy_log.tools_calls(mark, "g")
    assert (row["http"], row["path"]) == ("POST", "/g/messages/")


def test_upstream_2026_07_28_sends_matching_headers_and_envelope(world, evidence, upstreams):
    subject = world.subject(("h",))
    world.approve(subject, world.prepare(subject, "h"), tools="echo")
    mark = support.marker()
    assert f"{INSTANCE}:hello" in streamable_call(subject.key, "h", mark)
    requests = upstreams["a"].counters()["modern_requests"]
    assert {r["method"] for r in requests} <= {"server/discover", "tools/list", "tools/call"}
    (call,) = [r for r in requests if r["method"] == "tools/call"]
    assert call["header_version"] == call["meta_version"] == "2026-07-28"
    assert call["header_method"] == "tools/call"
    assert call["header_name"] == call["body_name"] == "echo"
    assert not any(r["session_header"] for r in requests)
    assert "initialize" not in seen(upstreams["a"], "modern")["protocol_header"]


def test_ingress_initialize_2025_06_18_is_negotiated_and_answered_as_sse(world):
    subject = world.subject(("e",))
    wire = Wire(subject.key)
    try:
        reply = wire.open()
        assert reply.status_code == 200, reply.text
        assert reply.headers["content-type"].startswith("text/event-stream")
        (message,) = messages_of(reply)
        assert message["result"]["protocolVersion"] == "2025-06-18"
        assert wire.session
    finally:
        wire.close()


@pytest.mark.parametrize(
    ("method", "name"),
    [("tools/call", "mcp_e-echo"), ("tools/list", None), ("server/discover", None)],
)
@pytest.mark.parametrize("version", ["2026-07-28", "2099-01-01"])
def test_ingress_unadvertised_revision_is_refused_before_any_call(
    world, evidence, method, name, version
):
    subject = world.subject(("e",))
    world.approve(subject, world.prepare(subject, "e"), tools="echo")
    since = world.now()
    mark = support.marker()
    params = {"_meta": MODERN_META}
    headers = {
        "Authorization": f"Bearer {subject.key}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }
    if name:
        params |= {"name": name, "arguments": {"text": "hello", "marker": mark}}
        headers["Mcp-Name"] = name
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    reply = httpx.post(f"{LITELLM}/mcp", headers=headers, content=json.dumps(body), timeout=30)
    assert reply.status_code == 400, reply.text
    error = reply.json()["error"]
    assert error["code"] == -32600
    assert error["message"] == (
        f"Unsupported MCP-Protocol-Version {version}; supported: {LEGACY_VERSIONS}"
    )
    evidence.assert_calls(mark, 0, "e")
    assert world.decisions_since(subject, since) == []


def test_legacy_sse_ingress_also_refuses_2026_07_28(world):
    subject = world.subject(("e",))
    headers = {
        "Authorization": f"Bearer {subject.key}",
        "Accept": "text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
    }
    with httpx.stream("GET", f"{LITELLM}/mcp/sse", headers=headers, timeout=15) as reply:
        assert reply.status_code == 400
        body = json.loads(reply.read())
    assert body["error"]["message"].startswith("Unsupported MCP-Protocol-Version 2026-07-28")


def test_advertising_2026_07_28_never_lets_a_call_reach_upstream_without_a_decision(
    world, evidence
):
    """광고 판본에 2026-07-28을 넣은 구성: 승인 없는 호출의 효과는 0, 효과는 허용 사건 수와 같다."""
    base = BASE_CONFIG.read_text(encoding="utf-8")
    name = "modern-advertised.generated.yaml"
    versions = json.dumps([*LEGACY_VERSIONS.split(", "), "2026-07-28"])
    path = CONFIG_DIR / name
    path.write_text(
        re.sub(
            r"(store_prompts_in_spend_logs: false\n)",
            rf"\1  mcp_advertised_versions: {versions}\n",
            base,
            count=1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    try:
        subject = world.subject(("e",))
        relation = world.prepare(subject, "e")
        with litellm_config(f"./config/{name}") as started:
            assert started.returncode == 0, started.stderr
            since = world.now()
            outcomes = []
            for approved in (False, True):
                if approved:
                    world.approve(subject, relation, tools="echo")
                mark = support.marker()
                headers = {
                    "Authorization": f"Bearer {subject.key}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "MCP-Protocol-Version": "2026-07-28",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "mcp_e-echo",
                }
                params = {
                    "name": "mcp_e-echo",
                    "arguments": {"text": "hello", "marker": mark},
                    "_meta": MODERN_META,
                }
                body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
                reply = httpx.post(
                    f"{LITELLM}/mcp", headers=headers, content=json.dumps(body), timeout=60
                )
                outcomes.append((approved, mark, reply.status_code, reply.text))
            time.sleep(2)
            allows = [
                e
                for e in world.decisions_since(subject, since)
                if decision(e)[:2] == ("allow", "allow")
            ]
            reached = sum(evidence.calls(mark, "e")[1] for _, mark, _, _ in outcomes)
            print([(a, status, text[:200]) for a, _, status, text in outcomes])
            assert evidence.calls(outcomes[0][1], "e") == (0, 0), outcomes[0]
            assert reached == len(allows), (reached, len(allows), outcomes)
    finally:
        path.unlink(missing_ok=True)
