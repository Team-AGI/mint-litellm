"""통합 시험 공용 도구: 스택 주소, LiteLLM 호출, 업스트림 계수·장애 스위치, 증거 판정."""

import asyncio
import contextlib
import json
import os
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

HERE = Path(__file__).resolve().parent
HOST = os.environ.get("MINT_E_HOST", "localhost")
MASTER_KEY = os.environ.get("MINT_E_MASTER_KEY", "sk-integration-master")
SERVER_ID = {
    "a": "e1000000000000000000000000000001",
    "b": "e1000000000000000000000000000002",
    "c": "e1000000000000000000000000000003",
    "d": "e1000000000000000000000000000004",
}


def sid(server: str) -> str:
    """시험 서버 약칭(a·b·c·d) 또는 LiteLLM 서버 식별자를 서버 식별자로 바꾼다."""
    return SERVER_ID.get(server, server)


TOOL_PREFIX = {"a": "mcp_a", "b": "mcp_b", "c": "mcp_c", "d": "mcp_d"}
# 서버 c·d는 업스트림 b·a를 다른 경로로 가리키는 별도 설정 서버이다.
UPSTREAM_OF = {"a": "a", "b": "b", "c": "b", "d": "a"}

# 같은 기계에서 다른 스택과 겹치지 않도록 compose의 MINT_E_PORT_PREFIX와 같은 접두를 붙인다.
PORT_PREFIX = os.environ.get("MINT_E_PORT_PREFIX", "")


def _port(base: int) -> int:
    return int(f"{PORT_PREFIX}{base}")


LITELLM_PORTS = (_port(4101), _port(4102))
PLAIN_PORT = _port(4103)
DB_PROXY_PORT = _port(4176)
CONTROL_ROUTES = [
    "/v1/mcp/server",
    "/key/info",
    "/team/info",
    "/user/info",
    "/key/list",
    "/team/list",
    "/guardrails/list",
]
PROXY_PORT = _port(4180)
UPSTREAM_CONTROL_PORT = {"a": _port(4191), "b": _port(4192)}
TOXIPROXY_PORT = _port(4174)
TOXIPROXY_DB_PORT = _port(4175)
OPA_PORT = _port(4181)
POSTGRES_PORT = _port(4132)

COMPOSE = os.environ.get(
    "MINT_E_COMPOSE", f"docker compose -p mint-e -f {shlex.quote(str(HERE / 'compose.yaml'))}"
)


def url(port: int, path: str = "") -> str:
    return f"http://{HOST}:{port}{path}"


def compose(*args: str, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = None
    if env:
        # WSL 안의 docker로 실행할 때 변수가 넘어가도록 WSLENV에 적는다(리눅스에서는 무해하다).
        names = ":".join([os.environ.get("WSLENV", ""), *env]).strip(":")
        merged = {**os.environ, **env, "WSLENV": names}
    return subprocess.run(
        [*shlex.split(COMPOSE), *args],
        env=merged,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=check,
        stdin=subprocess.DEVNULL,
    )


def marker() -> str:
    return "t-" + uuid.uuid4().hex[:12]


@dataclass
class Upstream:
    """시험 서버 한 대의 제어 면. 이름은 ``a`` 또는 ``b``."""

    name: str

    @property
    def base(self) -> str:
        return url(UPSTREAM_CONTROL_PORT[self.name])

    def counters(self) -> dict:
        return httpx.get(f"{self.base}/counters", timeout=5).json()

    def count(self, mark: str) -> dict:
        row = self.counters()["by_marker"].get(mark)
        return row or {"arrived": 0, "entered": 0, "completed": 0}

    def set_faults(self, **faults) -> None:
        httpx.post(f"{self.base}/faults", json=faults, timeout=5).raise_for_status()

    def reset(self) -> None:
        httpx.delete(f"{self.base}/faults", timeout=5).raise_for_status()
        httpx.post(f"{self.base}/reset", timeout=5).raise_for_status()

    def mutate(self, variant: str, description: str | None = None) -> dict:
        body = {"variant": variant}
        if description is not None:
            body["description"] = description
        return httpx.post(f"{self.base}/mutate", json=body, timeout=5).json()


class Toxics:
    """Toxiproxy 한 프록시의 독성(toxic) 주입. 끝나면 ``clear``로 모두 지운다."""

    def __init__(self, port: int, proxy: str):
        self.base = url(port)
        self.proxy = proxy

    def add(
        self, kind: str, stream: str = "downstream", toxicity: float = 1.0, **attributes
    ) -> str:
        name = f"{kind}-{stream}-{uuid.uuid4().hex[:6]}"
        body = {
            "name": name,
            "type": kind,
            "stream": stream,
            "toxicity": toxicity,
            "attributes": attributes,
        }
        httpx.post(
            f"{self.base}/proxies/{self.proxy}/toxics", json=body, timeout=5
        ).raise_for_status()
        return name

    def clear(self) -> None:
        listing = httpx.get(f"{self.base}/proxies/{self.proxy}/toxics", timeout=5).json()
        for toxic in listing:
            httpx.delete(f"{self.base}/proxies/{self.proxy}/toxics/{toxic['name']}", timeout=5)

    def disable(self) -> None:
        httpx.post(f"{self.base}/proxies/{self.proxy}", json={"enabled": False}, timeout=5)

    def enable(self) -> None:
        httpx.post(f"{self.base}/proxies/{self.proxy}", json={"enabled": True}, timeout=5)


class ProxyLog:
    """계수 프록시의 접근 기록(JSON 줄). 기준 시점 이후만 본다."""

    def __init__(self) -> None:
        self.offset = 0
        self.mark()

    def _lines(self) -> list[dict]:
        text = httpx.get(url(PROXY_PORT, "/__log"), timeout=5).text
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def mark(self) -> None:
        self.offset = len(self._lines())

    def rows(self, **match) -> list[dict]:
        return [
            r for r in self._lines()[self.offset :] if all(r.get(k) == v for k, v in match.items())
        ]

    def tools_calls(self, mark: str, upstream: str | None = None) -> list[dict]:
        rows = self.rows(rpc="tools/call", marker=mark)
        return [r for r in rows if upstream is None or r["path"].startswith(f"/{upstream}/")]


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.2, what: str = "condition"):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(interval)


def master_headers() -> dict:
    return {"Authorization": f"Bearer {MASTER_KEY}"}


def new_key(servers=("a", "b"), port: int = LITELLM_PORTS[0], **extra) -> str:
    body = {
        "key_alias": "it-" + uuid.uuid4().hex[:10],
        "object_permission": {"mcp_servers": [sid(s) for s in servers]},
        **extra,
    }
    reply = httpx.post(url(port, "/key/generate"), headers=master_headers(), json=body, timeout=30)
    reply.raise_for_status()
    return reply.json()["key"]


@contextlib.asynccontextmanager
async def mcp_session(key: str, port: int = LITELLM_PORTS[0], path: str = "/mcp"):
    client = create_mcp_http_client(headers={"Authorization": f"Bearer {key}"})
    async with client, streamable_http_client(url(port, path), http_client=client) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            yield session


async def call_tool(
    key: str, server: str, tool: str, arguments: dict, port: int = LITELLM_PORTS[0]
):
    async with mcp_session(key, port) as session:
        return await session.call_tool(f"{TOOL_PREFIX[server]}-{tool}", arguments)


def rest_call(
    key: str,
    server: str,
    tool: str,
    arguments: dict,
    port: int = LITELLM_PORTS[0],
    call_id: str | None = None,
) -> httpx.Response:
    headers = {"Authorization": f"Bearer {key}"}
    if call_id:
        headers["x-litellm-call-id"] = call_id
    body = {
        "server_id": sid(server),
        "name": f"{TOOL_PREFIX[server]}-{tool}",
        "arguments": arguments,
    }
    return httpx.post(url(port, "/mcp-rest/tools/call"), headers=headers, json=body, timeout=180)


class Evidence:
    """업스트림 호출 수의 증거. 프록시 기록과 시험 서버 진입 계수를 함께 대조한다."""

    def __init__(self, upstreams: dict[str, Upstream], log: ProxyLog):
        self.upstreams = upstreams
        self.log = log

    def positive_control(self) -> None:
        """계수 경로가 이번 실행에서 살아 있음을 확인한다. LiteLLM과 정책을 거치지 않는다."""
        mark = marker()
        for name, upstream in self.upstreams.items():
            before = len(self.log.tools_calls(mark, name))
            assert before == 0

            async def probe(name=name):
                async with streamable_http_client(url(PROXY_PORT, f"/{name}/mcp")) as (r, w):
                    async with ClientSession(r, w) as session:
                        await session.initialize()
                        await session.call_tool("echo", {"text": "control", "marker": mark})

            asyncio.run(probe())
            wait_until(lambda n=name: len(self.log.tools_calls(mark, n)) == 1, what="proxy row")
            row = upstream.count(mark)
            assert row == {"arrived": 1, "entered": 1, "completed": 1}, row

    def calls(self, mark: str, server: str = "a") -> tuple[int, int]:
        """(프록시 tools/call 행 수, 시험 서버 진입 수)."""
        return (
            len(self.log.tools_calls(mark, server)),
            self.upstreams[UPSTREAM_OF[server]].count(mark)["entered"],
        )

    def assert_calls(
        self, mark: str, expected: int, server: str = "a", settle: float = 1.0
    ) -> None:
        """기록이 안정된 뒤 두 지점의 호출 수가 모두 기대값과 같음을 확인한다."""
        time.sleep(settle)
        proxy, entered = self.calls(mark, server)
        assert (proxy, entered) == (expected, expected), (
            f"proxy rows={proxy} server entered={entered} expected={expected}"
        )


def run(coro):
    return asyncio.run(coro)


def mint_database_url() -> str:
    return os.environ.get(
        "MINT_E_MINT_DATABASE_URL",
        f"postgresql://postgres:{os.environ.get('MINT_E_DB_PASSWORD', 'integration-db')}"
        f"@{HOST}:{POSTGRES_PORT}/mint",
    )
