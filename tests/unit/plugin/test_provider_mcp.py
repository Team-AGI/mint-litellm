"""모델 요청에 담긴 공급자 쪽 MCP 차단: 판정 함수와 LiteLLM 사전 훅 사슬."""

import asyncio

import pytest

pytest.importorskip("litellm")
pytest.importorskip("fastapi")

from fastapi import HTTPException  # noqa: E402
from litellm.caching.caching import DualCache  # noqa: E402
from litellm.proxy._experimental.mcp_server.mcp_server_manager import (  # noqa: E402
    global_mcp_server_manager,
)
from litellm.proxy.utils import ProxyLogging  # noqa: E402
from litellm.types.mcp import MCPTransport  # noqa: E402
from litellm.types.mcp_server.mcp_server_manager import MCPServer  # noqa: E402
from test_plugin_hooks import auth, build_runtime  # noqa: E402

from mint_litellm.plugin.guardrail import MintGuardrail  # noqa: E402
from mint_litellm.plugin.provider_mcp import external_mcp  # noqa: E402
from mint_litellm.types.errors import MintError  # noqa: E402

EXTERNAL = "https://external.example.invalid/mcp"
CALL_TYPES = ["acompletion", "aresponses", "anthropic_messages", "pass_through_endpoint"]


def run(coro):
    return asyncio.run(coro)


def mcp_tool(url, **extra):
    return {"type": "mcp", "server_url": url, "require_approval": "never", **extra}


@pytest.fixture(autouse=True)
def isolated_callbacks(monkeypatch):
    import litellm

    monkeypatch.setattr(litellm, "callbacks", [])


@pytest.fixture
def registry(monkeypatch):
    """게이트웨이가 서빙하는 서버 하나(mslearn)를 전역 관리자에 임시로 올린다."""
    server = MCPServer(
        server_id="srv-1",
        name="mslearn",
        alias="mslearn",
        url="https://mcp.example/api",
        transport=MCPTransport.http,
    )
    monkeypatch.setitem(global_mcp_server_manager.registry, "srv-1", server)
    return server


class TestExternalMcp:
    @pytest.mark.parametrize(
        "data",
        [
            None,
            "text",
            {},
            {"messages": [{"role": "user", "content": "hi"}]},
            {"tools": None},
            {"tools": "mcp"},
            {"tools": [{"type": "function", "function": {"name": "f"}}]},
            {"tools": ["mcp", 3, None]},
            {"mcp_servers": []},
            {"mcp_servers": None},
        ],
    )
    def test_requests_without_provider_side_mcp_pass_without_asking_the_gateway(self, data):
        async def never(tools):
            raise AssertionError("the gateway must not be asked")

        assert run(external_mcp(data, never)) is None

    def test_an_external_server_url_is_found(self):
        data = {"tools": [{"type": "function"}, mcp_tool(EXTERNAL)]}
        assert run(external_mcp(data)) == "tools"

    def test_a_connector_without_a_server_url_is_found(self):
        data = {"tools": [{"type": "mcp", "server_label": "drive", "connector_id": "x"}]}
        assert run(external_mcp(data)) == "tools"

    def test_anthropic_mcp_servers_are_found_even_beside_other_tools(self):
        data = {"mcp_servers": [{"type": "url", "url": EXTERNAL, "name": "x"}], "tools": []}
        assert run(external_mcp(data)) == "mcp_servers"

    def test_one_external_tool_among_gateway_tools_is_enough(self):
        data = {"tools": [mcp_tool("litellm_proxy/mcp/docs"), mcp_tool(EXTERNAL)]}
        assert run(external_mcp(data)) == "tools"

    def test_gateway_addresses_pass(self, registry):
        for url in ("litellm_proxy", "litellm_proxy/mcp/docs", "https://gw.test/mcp/mslearn"):
            assert run(external_mcp({"tools": [mcp_tool(url)]})) is None

    def test_a_path_that_looks_like_the_gateway_but_names_no_registered_server_is_external(
        self, registry
    ):
        assert run(external_mcp({"tools": [mcp_tool("https://evil.test/mcp/unknown")]})) == "tools"


class TestPreCallChain:
    @pytest.fixture
    def rig(self, tmp_path, monkeypatch, registry):
        import litellm

        runtime, store, _ = build_runtime(tmp_path)
        guardrail = runtime.guardrail
        monkeypatch.setattr(litellm, "callbacks", [guardrail])
        assert isinstance(guardrail, MintGuardrail)
        return runtime, store, ProxyLogging(user_api_key_cache=DualCache())

    def send(self, rig, data, call_type, user=None):
        _, _, proxy = rig
        return run(
            proxy.pre_call_hook(
                user_api_key_dict=user if user is not None else auth(),
                data=data,
                call_type=call_type,
            )
        )

    @pytest.mark.parametrize("call_type", CALL_TYPES)
    @pytest.mark.parametrize(
        "body",
        [
            {"tools": [mcp_tool(EXTERNAL)]},
            {"mcp_servers": [{"type": "url", "url": EXTERNAL, "name": "x"}]},
        ],
        ids=["tools", "mcp_servers"],
    )
    def test_an_external_mcp_is_refused_before_it_is_sent_and_leaves_one_event(
        self, rig, call_type, body
    ):
        _, store, _ = rig
        data = {"model": "m", "messages": [], **body}
        with pytest.raises(HTTPException) as raised:
            self.send(rig, data, call_type)
        assert raised.value.status_code == 403
        error = MintError.from_detail(raised.value.detail)
        assert error.code == "MINT-EXTERNAL-MCP-FORBIDDEN"
        assert error.dispatch_state.value == "not_dispatched" and error.retry_safe is False
        (event,) = store.of_kind("decision_evaluated")
        payload = event.payload
        assert payload["operation"] == "llm_request"
        assert payload["enforced_action"] == "block" and payload["decision_ref"] == error.reference
        assert payload["stop"]["reason_code"] == "EXTERNAL_MCP_FORBIDDEN"
        assert payload["tool"] is None and payload["resolved_server_id"] is None
        assert "external.example" not in str(payload)

    def test_the_master_key_gets_the_same_refusal(self, rig):
        from mint_litellm.compat import litellm_1_106 as compat

        user = auth()
        user.token = compat.master_key_alias()
        with pytest.raises(HTTPException) as raised:
            self.send(rig, {"tools": [mcp_tool(EXTERNAL)]}, "acompletion", user)
        assert MintError.from_detail(raised.value.detail).code == "MINT-EXTERNAL-MCP-FORBIDDEN"

    @pytest.mark.parametrize("call_type", CALL_TYPES)
    def test_requests_without_provider_side_mcp_pass_untouched_and_leave_no_event(
        self, rig, call_type
    ):
        _, store, _ = rig
        for body in (
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            {"model": "m", "tools": [{"type": "function", "function": {"name": "f"}}]},
        ):
            assert self.send(rig, dict(body), call_type)["model"] == "m"
        assert store.events == {}

    @pytest.mark.parametrize("call_type", CALL_TYPES)
    def test_a_gateway_address_passes(self, rig, call_type):
        _, store, _ = rig
        data = {"model": "m", "tools": [mcp_tool("litellm_proxy/mcp/mslearn")]}
        assert self.send(rig, data, call_type)["model"] == "m"
        assert store.events == {}

    def test_an_unverified_worker_refuses_the_request_too(self, tmp_path, monkeypatch, registry):
        import litellm

        runtime, _, _ = build_runtime(tmp_path, verified=False)
        monkeypatch.setattr(litellm, "callbacks", [runtime.guardrail])
        rig = runtime, None, ProxyLogging(user_api_key_cache=DualCache())
        with pytest.raises(HTTPException) as raised:
            self.send(rig, {"tools": [mcp_tool(EXTERNAL)]}, "aresponses")
        assert MintError.from_detail(raised.value.detail).code == "MINT-ENFORCEMENT-UNVERIFIED"

    def test_a_judgment_that_fails_blocks_instead_of_passing(self, rig, monkeypatch):
        runtime, _, _ = rig

        async def broken(*args):
            raise RuntimeError("boom")

        monkeypatch.setattr(runtime, "judge_external_mcp", broken)
        with pytest.raises(HTTPException) as raised:
            self.send(rig, {"tools": [mcp_tool(EXTERNAL)]}, "acompletion")
        assert raised.value.status_code == 403
        assert MintError.from_detail(raised.value.detail).code == "MINT-SCHEMA-ERROR"
