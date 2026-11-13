"""관리 API 클라이언트: 읽기 전용, 자격 열 폐기, 오류 해석."""

import pytest
from litellm_stub import CONTROL_KEY, fixture

from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin, LiteLLMError, scrub
from mint_litellm.types.cli_commands import LITELLM_CREDENTIAL_FIELDS


def test_scrub_removes_every_credential_field_at_any_depth():
    value = {
        "a": {name: "secret" for name in LITELLM_CREDENTIAL_FIELDS},
        "list": [{"credentials": {"x": 1}, "keep": 2}],
        "keep": 1,
    }
    assert scrub(value) == {"a": {}, "list": [{"keep": 2}], "keep": 1}


def test_credentials_are_dropped_on_receipt(stub, litellm):
    body = dict(fixture("server_get"), credentials={"auth_value": "x"}, env_vars={"K": "V"})
    stub.set("/v1/mcp/server/ctl-everything", body)
    entry = litellm.get_server("ctl-everything")
    assert "credentials" not in entry and "env_vars" not in entry
    assert entry["server_id"] == "ctl-everything"


def test_get_server_user_key_team_lookups(litellm):
    assert litellm.get_server("nonexistent") is None
    assert litellm.get_user("nobody") is None
    assert litellm.get_user("human-1")["user_role"] == "internal_user"
    assert litellm.get_team("team-op")["object_permission"]["mcp_servers"] == ["everything"]
    assert litellm.get_key("unknown-key") is None


def test_every_request_is_a_get_with_the_control_key_only(stub, litellm):
    litellm.list_servers()
    litellm.list_teams()
    litellm.list_guardrails()
    litellm.list_keys()
    paths = [p for p, _, _ in stub.requests]
    assert paths == ["/v1/mcp/server", "/team/list", "/guardrails/list", "/key/list"]
    assert {auth for _, _, auth in stub.requests} == {f"Bearer {CONTROL_KEY}"}
    assert stub.requests[-1][1]["return_full_object"] == "true"


def test_unauthorized_responses_explain_the_key_requirements(stub, litellm):
    stub.set("/team/list", {"error": "no"}, 403)
    with pytest.raises(LiteLLMError, match="allowed_routes"):
        litellm.list_teams()
    stub.set("/team/list", {"error": "boom"}, 500)
    with pytest.raises(ControlError, match="HTTP 500"):
        litellm.list_teams()


def test_unreachable_api_is_a_control_error():
    client = LiteLLMAdmin("http://localhost:9", "k", timeout=0.5)
    with pytest.raises(ControlError, match="연결할 수 없습니다"):
        client.list_servers()


def test_scrub_keeps_only_the_oauth_scopes_of_credentials():
    value = {"credentials": {"auth_value": "secret", "scopes": ["read", 3]}}
    assert scrub(value) == {"credentials": {"scopes": ["read"]}}
    assert scrub({"credentials": {"auth_value": "secret"}}) == {}
