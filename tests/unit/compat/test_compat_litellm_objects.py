"""고정 판본의 실제 LiteLLM 객체를 쓰는 접점 시험. LiteLLM이 설치되지 않으면 건너뛴다."""

import asyncio
from unittest import mock

import pytest

pytest.importorskip("litellm")
pytest.importorskip("fastapi")

from litellm.constants import LITELLM_PROXY_MASTER_KEY_ALIAS  # noqa: E402
from litellm.proxy._experimental.mcp_server.mcp_server_manager import (  # noqa: E402
    MCPServerManager,
    global_mcp_server_manager,
)
from litellm.proxy._experimental.mcp_server.utils import (  # noqa: E402
    add_server_prefix_to_name,
    normalize_server_name,
)
from litellm.proxy._types import UserAPIKeyAuth  # noqa: E402
from litellm.types.mcp import MCPAuth, MCPTransport  # noqa: E402
from litellm.types.mcp_server.mcp_server_manager import MCPServer  # noqa: E402

from mint_litellm.compat import litellm_1_106 as compat  # noqa: E402
from mint_litellm.types.decision import url_sha256  # noqa: E402
from mint_litellm.types.identity import PrincipalType  # noqa: E402

RAW_KEY = "sk-" + "t" * 40


def mcp_server(server_id, name, url="https://learn.test/api/mcp", **kw):
    return MCPServer(
        server_id=server_id,
        name=name,
        url=url,
        transport=kw.pop("transport", MCPTransport.http),
        **kw,
    )


def test_every_symbol_the_layer_uses_exists_in_the_pinned_release():
    assert compat.missing_symbols() == []
    assert compat.installed_litellm_version() in compat.SUPPORTED_LITELLM_VERSIONS


def test_the_version_check_accepts_every_supported_release_and_rejects_others():
    for version in compat.SUPPORTED_LITELLM_VERSIONS:
        with mock.patch.object(compat, "installed_litellm_version", return_value=version):
            assert compat.missing_symbols(env={}) == []
    with mock.patch.object(compat, "installed_litellm_version", return_value="1.107.0"):
        assert any("1.107.0" in m for m in compat.missing_symbols(env={}))


def test_the_local_name_normalizer_matches_litellm():
    for name in ["mslearn", "my server", " lead", "a b  c", "한 글"]:
        assert compat.normalize_server_name(name) == normalize_server_name(name)


def test_the_global_manager_is_the_one_the_layer_reads():
    assert compat.global_manager() is global_mcp_server_manager


def test_master_key_alias_constant():
    assert compat.master_key_alias() == LITELLM_PROXY_MASTER_KEY_ALIAS


class TestRealAuthObjects:
    def test_a_virtual_key_is_hashed_and_its_token_is_the_key_id(self):
        auth = UserAPIKeyAuth(api_key=RAW_KEY, user_id="u1", team_id="t1")
        principal = compat.principal_from_auth(auth, instance_id="inst")
        assert principal.principal_type is PrincipalType.USER
        assert principal.key_id == auth.token and principal.key_id != RAW_KEY
        assert len(principal.key_id) == 64

    def test_the_master_key_object_is_recognized(self):
        auth = UserAPIKeyAuth(api_key=LITELLM_PROXY_MASTER_KEY_ALIAS, user_id="default_user_id")
        principal = compat.principal_from_auth(auth, instance_id="inst")
        assert principal.principal_type is PrincipalType.MASTER_KEY

    def test_a_team_key_and_a_service_account_marker(self):
        team = UserAPIKeyAuth(api_key=RAW_KEY, team_id="t1")
        assert compat.principal_from_auth(team, instance_id="i").principal_type is (
            PrincipalType.TEAM_KEY
        )
        bot = UserAPIKeyAuth(api_key=RAW_KEY, team_id="t1", metadata={"service_account_id": "bot"})
        assert compat.principal_from_auth(bot, instance_id="i").principal_type is (
            PrincipalType.SERVICE_ACCOUNT
        )

    def test_the_end_user_header_value_becomes_a_claim(self):
        auth = UserAPIKeyAuth(api_key=RAW_KEY, user_id="u1", end_user_id="visitor")
        principal = compat.principal_from_auth(auth, instance_id="i")
        assert principal.claimed_end_user_id == "visitor"

    def test_a_key_with_neither_user_nor_team_is_anonymous(self):
        auth = UserAPIKeyAuth(api_key=RAW_KEY)
        assert compat.principal_from_auth(auth, instance_id="i").principal_type is (
            PrincipalType.ANONYMOUS
        )


class TestJwtAuthObjects:
    """LiteLLM JWT 경로가 만드는 객체. handle_jwt.py의 user_api_key_auth_from_result는
    api_key=None으로 만들고 user_id·team_id·org_id·end_user_id·jwt_claims를 채운다."""

    def jwt_auth(self, **kw):
        args = {
            "api_key": None,
            "user_id": "entra-oid-1",
            "team_id": "t1",
            "org_id": "o1",
            "end_user_id": "visitor",
            "jwt_claims": {"sub": "entra-oid-1"},
        }
        args.update(kw)
        return UserAPIKeyAuth(**args)

    def test_a_jwt_user_without_a_virtual_key_is_that_user(self):
        auth = self.jwt_auth()
        assert auth.token is None
        principal = compat.principal_from_auth(auth, instance_id="i")
        assert principal.principal_type is PrincipalType.USER
        assert principal.principal_id == "entra-oid-1" and principal.user_id == "entra-oid-1"
        assert principal.key_id is None and principal.team_id == "t1"
        assert principal.claimed_end_user_id == "visitor"

    def test_a_jwt_without_a_user_id_is_anonymous_even_with_a_team(self):
        auth = self.jwt_auth(user_id=None)
        assert compat.principal_from_auth(auth, instance_id="i").principal_type is (
            PrincipalType.ANONYMOUS
        )

    def test_a_keyless_user_without_a_server_side_marker_is_anonymous(self):
        auth = UserAPIKeyAuth(api_key=None, user_id="u1", team_id="t1")
        assert compat.principal_from_auth(auth, instance_id="i").principal_type is (
            PrincipalType.ANONYMOUS
        )

    def test_a_managed_agent_context_counts_as_a_verified_keyless_subject(self):
        from litellm.types.proxy.agent_identity import ManagedAgentContext

        auth = UserAPIKeyAuth(api_key=None, user_id="agent-user")
        auth.managed_agent_context = ManagedAgentContext(
            agent_id="a1", mode="delegated", user_id="agent-user"
        )
        principal = compat.principal_from_auth(auth, instance_id="i")
        assert principal.principal_type is PrincipalType.USER
        assert principal.principal_id == "agent-user"

    def test_a_gateway_admitted_user_counts_as_a_verified_keyless_subject(self):
        auth = UserAPIKeyAuth(api_key=None, user_id="u9")
        auth.mcp_admitted_user_subject = True
        assert compat.principal_from_auth(auth, instance_id="i").principal_id == "u9"

    def test_the_marker_cannot_be_set_from_constructor_input(self):
        auth = UserAPIKeyAuth(api_key=None, user_id="u9", mcp_admitted_user_subject=True)
        assert compat.principal_from_auth(auth, instance_id="i").principal_type is (
            PrincipalType.ANONYMOUS
        )

    def test_a_virtual_key_still_wins(self):
        auth = self.jwt_auth(api_key=RAW_KEY)
        assert compat.principal_from_auth(auth, instance_id="i").key_id == auth.token


def manager_with(*servers, tools=None):
    manager = MCPServerManager()
    for server in servers:
        manager.registry[server.server_id] = server
    for tool, owner in (tools or {}).items():
        manager.tool_name_to_mcp_server_name_mapping[tool] = owner
    return manager


class TestRealManager:
    def test_resolution_matches_the_execution_stage_for_a_listed_tool(self):
        server = mcp_server("srv-a", "mslearn", alias="mslearn", auth_type=MCPAuth.bearer_token)
        manager = manager_with(server, tools={"search": "mslearn"})
        hook = compat.parse_hook_data({"mcp_server_name": "mslearn", "mcp_tool_name": "search"})
        resolved = compat.resolve_server(hook, manager=manager)
        assert resolved.server_id == "srv-a"
        assert resolved.transport == "http" and resolved.auth_type == "bearer_token"
        assert resolved.url_sha256 == url_sha256("https://learn.test/api/mcp")

    def test_a_server_without_auth_type_resolves_to_none(self):
        manager = manager_with(mcp_server("srv-a", "mslearn"), tools={"search": "mslearn"})
        hook = compat.parse_hook_data({"mcp_server_name": "mslearn", "mcp_tool_name": "search"})
        assert compat.resolve_server(hook, manager=manager).auth_type == "none"

    def test_an_unlisted_tool_is_unresolved_by_the_execution_resolver(self):
        manager = manager_with(mcp_server("srv-a", "mslearn"))
        hook = compat.parse_hook_data({"mcp_server_name": "mslearn", "mcp_tool_name": "search"})
        with pytest.raises(compat.ServerResolutionError):
            compat.resolve_server(hook, manager=manager)

    def test_listing_resolves_before_the_tool_table_is_filled(self):
        manager = manager_with(mcp_server("srv-a", "mslearn"))
        hook = compat.parse_hook_data({"mcp_server_name": "mslearn", "mcp_tool_name": "search"})
        assert compat.resolve_listed_server(hook, manager=manager).server_id == "srv-a"

    def test_two_servers_with_the_same_alias_are_counted(self):
        first = mcp_server("srv-config", "mslearn", alias="mslearn", url="https://one.test/")
        second = mcp_server("srv-db", "other", alias="mslearn", url="https://two.test/")
        manager = manager_with(first, second, tools={"search": "mslearn"})
        hook = compat.parse_hook_data({"mcp_server_name": "mslearn", "mcp_tool_name": "search"})
        resolved = compat.resolve_server(hook, manager=manager)
        assert resolved.candidates_with_same_name == 2

    def test_registry_entries_read_the_real_registry(self):
        manager = manager_with(mcp_server("srv-a", "mslearn", allow_all_keys=True))
        (entry,) = compat.registry_entries(manager=manager)
        assert entry.server_id == "srv-a" and entry.allow_all_keys is True
        assert entry.transport == "http" and entry.auth_type == "none"


def test_the_judgment_hook_is_defined_on_the_guardrail_class_and_not_on_the_logger():
    # LiteLLM runs a pre-call hook only when the leaf class defines it.
    from mint_litellm.plugin.guardrail import MintGuardrail
    from mint_litellm.plugin.logger import MintLogger

    assert "async_pre_call_hook" in vars(MintGuardrail)
    assert "async_pre_call_hook" not in vars(MintLogger)


async def no_unmanaged():
    return set()


class TestRegisterContractTools:
    def manager(self, *servers):
        manager = MCPServerManager()
        for server in servers:
            manager.registry[server.server_id] = server
        return manager

    def test_contract_tools_are_mapped_to_their_server_and_nothing_else(self):
        a = mcp_server("sa", "alpha", alias="alpha")
        manager = self.manager(a)
        added = compat.register_contract_tools({"sa": ("read", "wipe")}, manager=manager)
        mapping = manager.tool_name_to_mcp_server_name_mapping
        assert added > 0
        assert mapping[add_server_prefix_to_name("wipe", "alpha")] == "alpha"
        assert mapping[add_server_prefix_to_name("read", "alpha")] == "alpha"
        assert not any("other" in spelling for spelling in mapping)
        assert manager.server_exposes_tool(a, "wipe")
        assert manager._resolve_mcp_server_for_tool_call("alpha", "wipe") is a

    def test_a_second_run_changes_nothing(self):
        manager = self.manager(mcp_server("sa", "alpha", alias="alpha"))
        compat.register_contract_tools({"sa": ("read",)}, manager=manager)
        before = dict(manager.tool_name_to_mcp_server_name_mapping)
        assert compat.register_contract_tools({"sa": ("read",)}, manager=manager) == 0
        assert manager.tool_name_to_mcp_server_name_mapping == before

    def test_a_spelling_owned_by_another_server_is_left_alone(self):
        manager = self.manager(
            mcp_server("sa", "alpha", alias="alpha"), mcp_server("sb", "beta", alias="beta")
        )
        manager.tool_name_to_mcp_server_name_mapping["read"] = "beta"
        compat.register_contract_tools({"sa": ("read",)}, manager=manager)
        mapping = manager.tool_name_to_mcp_server_name_mapping
        assert mapping["read"] == "beta"
        assert mapping[add_server_prefix_to_name("read", "alpha")] == "alpha"

    def test_servers_without_contract_names_add_nothing(self):
        manager = self.manager(mcp_server("sa", "alpha", alias="alpha"))
        assert compat.register_contract_tools({"unknown": ("read",)}, manager=manager) == 0
        assert manager.tool_name_to_mcp_server_name_mapping == {}
        with pytest.raises(ValueError, match="not found"):
            manager._resolve_mcp_server_for_tool_call("alpha", "wipe")

    def test_a_server_without_contracts_gets_the_called_tool_mapped_for_the_hook(self):
        manager = self.manager(
            mcp_server("sa", "alpha", alias="alpha"), mcp_server("sb", "beta", alias="beta")
        )
        seen = []

        async def original(server_name, name, **kwargs):
            seen.append(manager._resolve_mcp_server_for_tool_call(server_name, name).server_id)

        async def reload():
            return None

        async def load():
            return {}

        async def unmanaged():
            return {"sa"}

        manager.call_tool = original
        manager.reload_servers_from_database = reload
        compat.install_contract_retry(load, unmanaged, manager=manager)
        asyncio.run(manager.call_tool(server_name="alpha", name="slow"))
        assert seen == ["sa"]
        with pytest.raises(ValueError, match="not found"):  # 계약이 있는 서버는 그대로 거절
            asyncio.run(manager.call_tool(server_name="beta", name="slow"))

    def test_a_call_to_an_unmapped_contract_tool_reads_the_names_once_and_proceeds(self):
        manager = self.manager(mcp_server("sa", "alpha", alias="alpha"))
        seen = []

        async def original(server_name, name, **kwargs):
            seen.append(manager._resolve_mcp_server_for_tool_call(server_name, name).server_id)
            return "ok"

        manager.call_tool = original
        reloads = []

        async def reload():
            reloads.append(1)

        manager.reload_servers_from_database = reload
        loads = []

        async def load():
            loads.append(1)
            return {"sa": ("wipe",)}

        compat.install_contract_retry(load, no_unmanaged, manager=manager)
        compat.install_contract_retry(load, no_unmanaged, manager=manager)  # 다시 감싸지 않는다
        for _ in range(2):
            assert asyncio.run(manager.call_tool(server_name="alpha", name="wipe")) == "ok"
        assert seen == ["sa", "sa"] and loads == [1] and reloads == [1]

    def test_a_failed_read_leaves_litellms_own_rejection(self):
        manager = self.manager(mcp_server("sa", "alpha", alias="alpha"))

        async def original(server_name, name, **kwargs):
            manager._resolve_mcp_server_for_tool_call(server_name, name)

        manager.call_tool = original

        async def load():
            raise RuntimeError("database down")

        compat.install_contract_retry(load, no_unmanaged, manager=manager)
        with pytest.raises(ValueError, match="not found"):
            asyncio.run(manager.call_tool(server_name="alpha", name="wipe"))
