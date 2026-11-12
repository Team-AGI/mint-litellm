"""사전 훅 ``data``와 서버 해석의 형태.

LiteLLM 1.106.6이 도구 호출에 실제로 넘기는 값의 고정 사본을 쓴다.
"""

from enum import Enum
from types import SimpleNamespace

import pytest

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.compat.litellm_1_106 import ServerResolutionError
from mint_litellm.types.decision import normalize_auth_type, url_sha256
from mint_litellm.types.identity import PrincipalType
from mint_litellm.types.reason_codes import Reason

MASTER = "litellm_proxy_master_key"
TOKEN = "a1" * 32


class Transport(str, Enum):  # noqa: UP042
    http = "http"
    sse = "sse"


class AuthType(str, Enum):  # noqa: UP042
    none = "none"
    bearer_token = "bearer_token"


def logging_obj(call_id="call-1"):
    return SimpleNamespace(litellm_call_id=call_id, model_call_details={})


def synthesized(**override):
    """합성 단계 ``data``. 로거와 가드레일 사전 훅이 같은 열세 개 키를 받는다."""
    data = {
        "incoming_bearer_token": None,
        "litellm_logging_obj": logging_obj(),
        "mcp_arguments": {"query": "azure functions"},
        "mcp_server_name": "mslearn",
        "mcp_tool_name": "microsoft_docs_search",
        "messages": [
            {
                "role": "user",
                "content": "Tool: microsoft_docs_search\nArguments: {'query': 'azure functions'}",
            }
        ],
        "metadata": {"headers": {}, "user_api_key_user_id": "user-a"},
        "model": "mcp-tool-call",
        "user_api_key_end_user_id": None,
        "user_api_key_hash": None,
        "user_api_key_request_route": None,
        "user_api_key_team_id": None,
        "user_api_key_user_id": "user-a",
    }
    data.update(override)
    return data


def rest_body_stage():
    """REST 호출의 첫 번째 로거 호출. 서버 이름과 도구 이름이 없다."""
    return {
        "arguments": {"query": "x"},
        "litellm_call_id": "call-1",
        "litellm_logging_obj": logging_obj(),
        "metadata": {},
        "model": "mcp-tool-call",
        "name": "microsoft_docs_search",
        "proxy_server_request": {},
        "secret_fields": {},
        "server_id": "some-server",
    }


def server(
    server_id="srv-1", name="mslearn", alias=None, server_name=None, url="https://x.test/mcp", **kw
):
    return SimpleNamespace(
        server_id=server_id,
        name=name,
        alias=alias,
        server_name=server_name,
        url=url,
        transport=kw.get("transport", Transport.http),
        auth_type=kw.get("auth_type"),
        allow_all_keys=kw.get("allow_all_keys", False),
        **{k: v for k, v in kw.items() if k not in ("transport", "auth_type", "allow_all_keys")},
    )


class Manager:
    def __init__(self, servers, chosen=None, error=None):
        self.registry = {s.server_id: s for s in servers}
        self.chosen = chosen
        self.error = error
        self.calls = []

    def get_registry(self):
        return self.registry

    def _resolve_mcp_server_for_tool_call(self, server_name, name):
        self.calls.append((server_name, name))
        if self.error:
            raise self.error
        return self.chosen or next(iter(self.registry.values()))


class TestHookData:
    def test_a_synthesized_call_carries_server_tool_and_arguments(self):
        hook = compat.parse_hook_data(synthesized())
        assert (hook.server_name, hook.tool_name) == ("mslearn", "microsoft_docs_search")
        assert hook.arguments == {"query": "azure functions"}
        assert hook.litellm_call_id == "call-1"

    def test_the_rest_request_body_stage_has_no_server_name(self):
        hook = compat.parse_hook_data(rest_body_stage())
        assert hook.server_name is None

    def test_modified_arguments_win_when_truthy_and_empty_ones_are_ignored(self):
        assert compat.parse_hook_data(
            synthesized(modified_arguments={"query": "masked"})
        ).arguments == {"query": "masked"}
        assert compat.parse_hook_data(synthesized(modified_arguments={})).arguments == {
            "query": "azure functions"
        }

    def test_a_missing_arguments_key_is_an_empty_object_and_other_non_objects_are_not_ok(self):
        data = synthesized()
        del data["mcp_arguments"]
        assert compat.parse_hook_data(data).arguments_ok
        assert compat.parse_hook_data(data).arguments == {}
        for odd in (None, "", [], 0, "text", [1]):
            hook = compat.parse_hook_data(synthesized(mcp_arguments=odd))
            assert not hook.arguments_ok and hook.arguments == {}, odd
        assert compat.parse_hook_data(synthesized(mcp_arguments={})).arguments_ok

    def test_a_non_object_replacement_is_not_ok_only_when_it_is_not_empty(self):
        assert not compat.parse_hook_data(synthesized(modified_arguments="abc")).arguments_ok
        for empty in ("", [], 0, None, {}):
            hook = compat.parse_hook_data(synthesized(modified_arguments=empty))
            assert hook.arguments_ok and hook.arguments == {"query": "azure functions"}, empty

    def test_missing_or_odd_arguments_become_empty(self):
        assert compat.parse_hook_data(synthesized(mcp_arguments=None)).arguments == {}
        assert compat.parse_hook_data(synthesized(mcp_arguments="text")).arguments == {}

    def test_effective_arguments_tell_a_missing_value_from_one_that_is_not_an_object(self):
        assert compat.effective_arguments(synthesized(mcp_arguments=None)) is None
        assert compat.effective_arguments(synthesized(mcp_arguments=[])) is None
        assert compat.effective_arguments(synthesized(mcp_arguments={})) == {}
        assert compat.effective_arguments(synthesized(mcp_arguments="text")) is None
        odd = synthesized(mcp_arguments={}, modified_arguments=["x"])
        assert compat.effective_arguments(odd) is None
        assert compat.effective_arguments(synthesized(modified_arguments=0)) == {
            "query": "azure functions"
        }

    def test_arguments_are_confirmed_against_the_original_kept_in_the_first_message(self):
        assert compat.parse_hook_data(synthesized()).arguments_confirmed
        replaced = synthesized(mcp_arguments={"query": "masked"})
        replaced["messages"] = synthesized()["messages"]
        assert not compat.parse_hook_data(replaced).arguments_confirmed
        # 참인 수정본이 있으면 전송 인자는 그것이라 원래 인자와 맞출 필요가 없다.
        assert compat.parse_hook_data(
            {**replaced, "modified_arguments": {"a": 1}}
        ).arguments_confirmed
        for messages in (None, [], [{}], [{"content": None}], [{"content": "Tool: t"}]):
            assert not compat.parse_hook_data(synthesized(messages=messages)).arguments_confirmed

    def test_the_message_witness_matches_the_real_converter_of_the_supported_version(self):
        pytest.importorskip("litellm")
        assert compat.arguments_witness_problem() is None

    @pytest.mark.parametrize("both", [False, True], ids=["arguments-only", "arguments-and-message"])
    def test_the_startup_probe_compares_with_the_known_original_input(self, monkeypatch, both):
        pytest.importorskip("litellm")
        from litellm.proxy.utils import ProxyLogging

        real = ProxyLogging.convert_mcp_to_llm_format

        def altered(self, request, kwargs):
            data = real(self, request, kwargs)
            data["mcp_arguments"] = {"changed": 1}
            if both:
                # 변환기가 두 곳을 함께 바꿔도 알려진 원래 입력과 다르면 잡혀야 한다.
                data["messages"][0]["content"] = "Tool: probe\nArguments: {'changed': 1}"
            return data

        monkeypatch.setattr(ProxyLogging, "convert_mcp_to_llm_format", altered)
        assert compat.arguments_witness_problem() is not None

    def test_the_call_id_is_read_from_the_logging_object_first(self):
        data = synthesized(litellm_call_id="from-data")
        assert compat.parse_hook_data(data).litellm_call_id == "call-1"
        data["litellm_logging_obj"] = None
        assert compat.parse_hook_data(data).litellm_call_id == "from-data"

    def test_listing_scan_data_has_no_call_id(self):
        data = synthesized(litellm_logging_obj=None)
        assert compat.parse_hook_data(data).litellm_call_id is None

    def test_logging_details_is_the_shared_dictionary(self):
        obj = logging_obj()
        assert compat.logging_details(obj) is obj.model_call_details
        assert compat.logging_details(None) is None
        assert compat.logging_details(SimpleNamespace(model_call_details=None)) is None


class TestPrincipal:
    def auth(self, **override):
        base = {
            "token": TOKEN,
            "api_key": TOKEN,
            "user_id": "user-a",
            "team_id": "team-a",
            "metadata": {},
            "end_user_id": None,
        }
        base.update(override)
        return SimpleNamespace(**base)

    def classify(self, auth):
        return compat.principal_from_auth(auth, instance_id="inst", master_alias=MASTER)

    def test_a_user_key_uses_the_token_as_key_id_not_the_data_hash(self):
        principal = self.classify(self.auth())
        assert principal.principal_type is PrincipalType.USER
        assert principal.key_id == TOKEN and principal.principal_id == "user-a"
        assert principal.team_id == "team-a"

    def test_a_team_key_has_no_user(self):
        principal = self.classify(self.auth(user_id=None))
        assert principal.principal_type is PrincipalType.TEAM_KEY
        assert principal.principal_id == TOKEN

    def test_the_service_account_marker_is_classified_but_not_proven(self):
        marked = self.auth(user_id=None, metadata={"service_account_id": "ci-bot"})
        assert self.classify(marked).principal_type is PrincipalType.SERVICE_ACCOUNT
        with_user = self.auth(metadata={"service_account_id": "ci-bot"})
        assert self.classify(with_user).principal_type is PrincipalType.USER

    def test_the_master_key_alias_is_recognized(self):
        principal = self.classify(
            self.auth(token=MASTER, api_key=MASTER, user_id="default_user_id")
        )
        assert principal.principal_type is PrincipalType.MASTER_KEY

    def test_a_key_without_user_or_team_is_anonymous(self):
        principal = self.classify(self.auth(user_id=None, team_id=None))
        assert principal.principal_type is PrincipalType.ANONYMOUS

    def test_no_auth_object_is_anonymous(self):
        assert self.classify(None).principal_type is PrincipalType.ANONYMOUS

    def test_the_end_user_is_a_claim(self):
        principal = self.classify(self.auth(end_user_id="visitor"))
        assert principal.claimed_end_user_id == "visitor"
        assert principal.provenance["claimed_end_user_id"].value == "claimed_by_caller"

    def test_a_non_mapping_metadata_is_ignored(self):
        assert self.classify(self.auth(user_id=None, metadata="x")).principal_type is (
            PrincipalType.TEAM_KEY
        )


class TestServerResolution:
    def test_the_execution_stage_resolver_is_called_with_the_hook_names(self):
        target = server(auth_type=AuthType.bearer_token, transport=Transport.sse)
        manager = Manager([target])
        resolved = compat.resolve_server(compat.parse_hook_data(synthesized()), manager=manager)
        assert manager.calls == [("mslearn", "microsoft_docs_search")]
        assert resolved.server_id == "srv-1"
        assert resolved.url_sha256 == url_sha256("https://x.test/mcp")
        assert resolved.transport == "sse" and resolved.auth_type == "bearer_token"
        assert resolved.candidates_with_same_name == 1

    def test_a_server_without_authentication_has_the_auth_type_none(self):
        manager = Manager([server(auth_type=None)])
        resolved = compat.resolve_server(compat.parse_hook_data(synthesized()), manager=manager)
        assert resolved.auth_type == normalize_auth_type(None) == "none"

    def test_the_url_hash_has_no_normalization(self):
        a = compat.resolve_server(
            compat.parse_hook_data(synthesized()),
            manager=Manager([server(url="https://x.test/mcp")]),
        )
        b = compat.resolve_server(
            compat.parse_hook_data(synthesized()),
            manager=Manager([server(url="https://x.test/mcp/")]),
        )
        assert a.url_sha256 != b.url_sha256

    def test_the_resolver_chooses_among_servers_that_share_a_name(self):
        config_server = server("srv-config", url="https://config.test/")
        db_server = server("srv-db", url="https://db.test/")
        manager = Manager([config_server, db_server], chosen=config_server)
        resolved = compat.resolve_server(compat.parse_hook_data(synthesized()), manager=manager)
        assert resolved.server_id == "srv-config" and resolved.candidates_with_same_name == 2

    def test_names_match_across_alias_server_name_and_name(self):
        servers = [
            server("a", name="x", alias="mslearn"),
            server("b", name="y", server_name="mslearn"),
            server("c", name="mslearn"),
            server("d", name="other"),
        ]
        resolved = compat.resolve_server(
            compat.parse_hook_data(synthesized()), manager=Manager(servers)
        )
        assert resolved.candidates_with_same_name == 3

    def test_spaces_in_names_are_normalized_like_the_resolver(self):
        manager = Manager([server("a", name="my server")])
        hook = compat.parse_hook_data(synthesized(mcp_server_name="my_server"))
        assert compat.resolve_server(hook, manager=manager).candidates_with_same_name == 1

    @pytest.mark.parametrize("error", [ValueError("Tool x not found"), RuntimeError("boom")])
    def test_a_resolution_error_is_reported_as_unresolved(self, error):
        manager = Manager([server()], error=error)
        with pytest.raises(ServerResolutionError) as raised:
            compat.resolve_server(compat.parse_hook_data(synthesized()), manager=manager)
        assert raised.value.reason is Reason.SERVER_UNRESOLVED
        assert raised.value.detail == type(error).__name__

    def test_a_server_without_a_url_is_unsupported_not_unresolved(self):
        manager = Manager([server(url=None)])
        with pytest.raises(ServerResolutionError) as raised:
            compat.resolve_server(compat.parse_hook_data(synthesized()), manager=manager)
        assert raised.value.reason is Reason.UNSUPPORTED
        assert raised.value.detail == "server_without_url"

    def test_listing_a_server_without_a_url_is_unsupported_too(self):
        with pytest.raises(ServerResolutionError) as raised:
            compat.resolve_listed_server(
                compat.parse_hook_data(synthesized()), manager=Manager([server(url=None)])
            )
        assert raised.value.reason is Reason.UNSUPPORTED

    def test_a_request_body_stage_cannot_be_resolved(self):
        with pytest.raises(ServerResolutionError):
            compat.resolve_server(
                compat.parse_hook_data(rest_body_stage()), manager=Manager([server()])
            )

    def test_listing_resolves_by_registry_name_without_the_tool_table(self):
        manager = Manager([server("a", name="mslearn"), server("b", name="other")])
        resolved = compat.resolve_listed_server(
            compat.parse_hook_data(synthesized()), manager=manager
        )
        assert resolved.server_id == "a" and manager.calls == []

    def test_listing_with_a_shared_name_reports_the_candidate_count(self):
        manager = Manager([server("a", name="mslearn"), server("b", name="x", alias="mslearn")])
        resolved = compat.resolve_listed_server(
            compat.parse_hook_data(synthesized()), manager=manager
        )
        assert resolved.candidates_with_same_name == 2

    def test_listing_an_unknown_name_is_unresolved(self):
        with pytest.raises(ServerResolutionError):
            compat.resolve_listed_server(
                compat.parse_hook_data(synthesized(mcp_server_name="nothing")),
                manager=Manager([server()]),
            )

    def test_registry_entries_expose_the_contract_and_access_flag(self):
        entries = compat.registry_entries(
            manager=Manager(
                [server(alias="ms", allow_all_keys=True, auth_type=AuthType.bearer_token)]
            )
        )
        (entry,) = entries
        assert entry.names == ("ms", "mslearn") and entry.allow_all_keys is True
        assert entry.auth_type == "bearer_token" and entry.transport == "http"
        assert entry.url_sha256 == url_sha256("https://x.test/mcp")

    def test_registry_entries_expose_the_values_policy_checks_read(self):
        oauth = server(
            auth_type="oauth2",
            needs_user_oauth_token=True,
            delegate_auth_to_upstream=False,
            oauth_identity_binding=SimpleNamespace(mode="enforce"),
            issuer="https://issuer.test",
            timeout=30.0,
            authentication_token="secret-token",
        )
        (entry,) = compat.registry_entries(manager=Manager([oauth]))
        assert entry.discovery_oauth and entry.per_user_oauth and entry.binding_mode == "enforce"
        assert entry.timeout == 30.0 and entry.facts().issuer == "https://issuer.test"
        assert entry.credential and "secret-token" not in entry.credential
        assert entry.in_database  # 대역 관리자의 registry에 있는 서버는 DB 서버이다

    def test_static_header_credentials_count_as_the_same_credential_as_a_token(self):
        by_token = server(authentication_token="shared-secret")
        by_header = server(
            "srv-2", static_headers={"Authorization": "Bearer shared-secret", "X-Trace": "t"}
        )
        first, second = compat.registry_entries(manager=Manager([by_token, by_header]))
        assert first.credential in second.header_credentials
        assert len(second.header_credentials) == 1  # 자격을 싣지 않는 헤더는 보지 않는다
        assert "shared-secret" not in repr(second)

    def test_config_servers_are_not_database_servers(self):
        manager = Manager([server()])
        manager.config_mcp_servers = {"srv-1": manager.registry.pop("srv-1")}
        manager.get_registry = lambda: manager.config_mcp_servers
        (entry,) = compat.registry_entries(manager=manager)
        assert not entry.in_database


class TestResultHelpers:
    def test_tool_result_size_counts_text_bytes(self):
        block = SimpleNamespace(text="한글abc")
        assert compat.tool_result_size(SimpleNamespace(content=[block])) == len("한글abc".encode())
        assert compat.tool_result_size(SimpleNamespace(content="nope")) is None
        assert compat.tool_result_size(None) is None

    def test_failure_helpers(self):
        class MCPToolResultError(Exception):
            pass

        class Timeout(Exception):
            status_code = 504

        assert compat.is_tool_result_error(MCPToolResultError("x"))
        assert not compat.is_tool_result_error(Timeout())
        assert not compat.is_tool_result_error(None)
        assert compat.exception_status(Timeout()) == 504
        assert compat.exception_status(ValueError()) is None
        assert compat.failure_exception({"exception": Timeout()}).status_code == 504
        assert compat.failure_exception({"exception": "text"}) is None

    def test_strict_modes_default_to_true_unless_explicitly_false(self):
        pytest.importorskip("litellm")
        assert compat.strict_guardrail_modes_enabled({}) is True
        assert (
            compat.strict_guardrail_modes_enabled({"LITELLM_STRICT_GUARDRAIL_MODES": "false"})
            is False
        )
        assert (
            compat.strict_guardrail_modes_enabled({"LITELLM_STRICT_GUARDRAIL_MODES": "true"})
            is True
        )
        assert (
            compat.strict_guardrail_modes_enabled({"LITELLM_STRICT_GUARDRAIL_MODES": "weird"})
            is True
        )


def test_missing_symbols_reports_unimportable_modules():
    def importer(name):
        raise ImportError(name)

    missing = compat.missing_symbols(importer=importer)
    assert len(missing) >= 10 and all(":" in m or "==" in m for m in missing)
