"""모델 요청에 담긴 공급자 쪽 MCP 차단: 판정 함수와 LiteLLM 사전 훅 사슬."""

import asyncio
from dataclasses import replace

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
from mint_litellm.plugin.provider_mcp import external_mcp, is_realtime  # noqa: E402
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
            {"input": "{not json", "metadata": {"a": "[1, 2"}},
            {"input": [{"type": "mcp_call", "name": "x"}]},
        ],
    )
    def test_requests_without_provider_side_mcp_pass(self, data):
        assert external_mcp(data, "acompletion") is None

    def test_an_external_server_url_is_found(self):
        data = {"tools": [{"type": "function"}, mcp_tool(EXTERNAL)]}
        assert external_mcp(data, "acompletion") == "tools"

    def test_a_connector_without_a_server_url_is_found(self):
        data = {"tools": [{"type": "mcp", "server_label": "drive", "connector_id": "x"}]}
        assert external_mcp(data, "aresponses") == "tools"

    def test_anthropic_mcp_servers_are_found_even_beside_other_tools(self):
        data = {"mcp_servers": [{"type": "url", "url": EXTERNAL, "name": "x"}], "tools": []}
        assert external_mcp(data, "anthropic_messages") == "mcp_servers"

    def test_one_external_tool_among_gateway_tools_is_enough(self):
        data = {"tools": [mcp_tool("litellm_proxy/mcp/docs"), mcp_tool(EXTERNAL)]}
        assert external_mcp(data, "acompletion") == "tools"

    def test_only_the_litellm_proxy_form_in_top_level_tools_passes(self):
        for url in ("litellm_proxy", "litellm_proxy/mcp/docs"):
            assert external_mcp({"tools": [mcp_tool(url)]}, "aresponses") is None
        for url in ("litellm_proxyx", "https://gw.test/mcp/mslearn", "https://evil.test/mcp/x"):
            assert external_mcp({"tools": [mcp_tool(url)]}, "aresponses") == "tools"

    def test_the_copy_litellm_keeps_of_the_body_is_not_scanned_twice(self):
        tool = mcp_tool("litellm_proxy/mcp/docs")
        data = {"tools": [tool], "proxy_server_request": {"body": {"tools": [dict(tool)]}}}
        assert external_mcp(data, "aresponses") is None

    def test_nested_places_and_stringified_json_are_scanned(self):
        import json

        assert external_mcp({"extra_body": {"tools": [mcp_tool(EXTERNAL)]}}) == "tools"
        assert external_mcp({"input": [{"content": [mcp_tool(EXTERNAL)]}]}) == "tools"
        stringified = json.dumps({"mcp_servers": [{"url": EXTERNAL}]})
        assert external_mcp({"x": stringified}) == "mcp_servers"
        assert external_mcp({"x": json.dumps([json.dumps({"type": "mcp"})])}) == "tools"

    def test_limits_make_the_body_unjudgeable(self):
        deep: dict = {}
        node = deep
        for _ in range(100):
            node["a"] = {}
            node = node["a"]
        assert external_mcp({"x": deep}) == "limit"
        assert external_mcp({"x": [0] * 200_000}) == "limit"
        assert external_mcp({"x": "[" + "0," * 600_000 + "0]"}) == "limit"

    def test_passthrough_has_no_gateway_exception(self):
        data = {"tools": [mcp_tool("litellm_proxy")]}
        assert external_mcp(data, "pass_through_endpoint") == "tools"

    @pytest.mark.parametrize(
        ("call_type", "expected"),
        [("acreate_realtime_client_secret", True), ("_arealtime", True), ("acompletion", False),
         (None, False)],
    )
    def test_realtime_call_types(self, call_type, expected):
        assert is_realtime(call_type) is expected


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

    @pytest.mark.parametrize("call_type", ["acompletion", "aresponses", "anthropic_messages"])
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

        monkeypatch.setattr(runtime, "judge_refused_request", broken)
        with pytest.raises(HTTPException) as raised:
            self.send(rig, {"tools": [mcp_tool(EXTERNAL)]}, "acompletion")
        assert raised.value.status_code == 403
        assert MintError.from_detail(raised.value.detail).code == "MINT-SCHEMA-ERROR"


class TestBypassesFoundInReview:
    """요청 본문의 다른 자리·다른 호출 유형·실시간 경로로 돌아가는 우회."""

    @pytest.fixture
    def rig(self, tmp_path, monkeypatch, registry):
        import litellm

        runtime, store, _ = build_runtime(tmp_path)
        monkeypatch.setattr(litellm, "callbacks", [runtime.guardrail])
        return runtime, store, ProxyLogging(user_api_key_cache=DualCache())

    send = TestPreCallChain.send

    def refused(self, rig, data, call_type, code="MINT-EXTERNAL-MCP-FORBIDDEN"):
        with pytest.raises(HTTPException) as raised:
            self.send(rig, data, call_type)
        assert MintError.from_detail(raised.value.detail).code == code

    @pytest.mark.parametrize("call_type", ["acompletion", "aresponses", "pass_through_endpoint"])
    def test_extra_body_tools_are_refused(self, rig, call_type):
        data = {"model": "m", "input": "hi", "extra_body": {"tools": [mcp_tool(EXTERNAL)]}}
        self.refused(rig, data, call_type)

    def test_extra_body_mcp_servers_are_refused(self, rig):
        data = {"model": "m", "extra_body": {"mcp_servers": [{"url": EXTERNAL}]}}
        self.refused(rig, data, "aresponses")

    def test_a_gateway_address_inside_extra_body_is_still_refused(self, rig):
        data = {"model": "m", "extra_body": {"tools": [mcp_tool("litellm_proxy/mcp/mslearn")]}}
        self.refused(rig, data, "aresponses")

    def test_mcp_objects_in_input_session_and_stringified_json_are_refused(self, rig):
        import json

        for data in (
            {"input": [{"role": "user", "content": [mcp_tool(EXTERNAL)]}]},
            {"session": {"type": "realtime", "tools": [mcp_tool(EXTERNAL)]}},
            {"metadata": {"x": json.dumps({"tools": [mcp_tool(EXTERNAL)]})}},
            {"extra_body": json.dumps({"mcp_servers": [{"url": EXTERNAL}]})},
        ):
            self.refused(rig, data, "aresponses")

    def test_a_path_that_names_a_registered_server_on_another_host_is_external(self, rig):
        data = {"tools": [mcp_tool("https://evil.example/mcp/mslearn")]}
        self.refused(rig, data, "aresponses")

    @pytest.mark.parametrize("url", ["litellm_proxy/mcp/mslearn", "litellm_proxy"])
    def test_passthrough_refuses_every_mcp_tool_even_in_the_gateway_form(self, rig, url):
        self.refused(rig, {"tools": [mcp_tool(url)]}, "pass_through_endpoint")

    def test_a_body_beyond_the_scan_limits_is_refused(self, rig):
        deep: dict = {}
        node = deep
        for _ in range(200):
            node["a"] = {}
            node = node["a"]
        self.refused(rig, {"extra_body": deep}, "aresponses")
        self.refused(rig, {"extra_body": [{}] * 200_000}, "aresponses")

    @pytest.mark.parametrize(
        "call_type",
        [
            "acreate_realtime_client_secret",
            "arealtime_calls",
            "acreate_realtime_transcription_session",
            "_arealtime",
        ],
    )
    def test_realtime_requests_are_refused_unless_the_operator_allows_them(
        self, rig, call_type
    ):
        runtime, store, _ = rig
        self.refused(rig, {"model": "m"}, call_type, "MINT-REALTIME-FORBIDDEN")
        assert len(store.of_kind("decision_evaluated")) == 1
        runtime.config = replace(runtime.config, allow_realtime=True)
        assert self.send(rig, {"model": "m"}, call_type)["model"] == "m"
        # 허용해도 본문의 외부 MCP는 막힌다.
        self.refused(rig, {"session": {"tools": [mcp_tool(EXTERNAL)]}}, call_type)
