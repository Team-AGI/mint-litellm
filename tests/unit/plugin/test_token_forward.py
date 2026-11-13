"""호출자 토큰을 업스트림에 그대로 전달하는 서버(POL-R-06)와 토큰 대상 설정(POL-R-05)."""

import asyncio
from dataclasses import replace

import pytest
from plugin_helpers import (
    approval,
    evaluator,
    harness,
    request,
    resolved_server,
    server_row,
    snapshot,
)

from mint_litellm.control.approvals import build_conditions
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.types.reuse_policy import (
    KEY_FORWARD,
    KEY_RESOURCE,
    ServerFacts,
    forwarding_violation,
    forwards_client_token,
    reuse_violations,
)
from mint_litellm.types.settings import Mode


def decide(tmp_path, auth_type, conditions=None, observe=False):
    snap = snapshot(
        server=server_row(auth_type=auth_type),
        approvals=(approval(conditions=conditions or {}),),
    )
    h = harness(tmp_path, snap, evaluate=evaluator())
    if observe:
        h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    return asyncio.run(
        evaluate_request(request(resolved=resolved_server(auth_type=auth_type)), h.deps)
    )


@pytest.mark.parametrize("auth_type", ["true_passthrough", "oauth_delegate"])
def test_a_forwarding_server_is_blocked_without_the_approval_condition(tmp_path, auth_type):
    out = decide(tmp_path, auth_type)
    assert not out.allowed
    assert out.error.code == "MINT-TOKEN-FORWARD-FORBIDDEN"
    assert not decide(tmp_path, auth_type, {"allow_token_forward": False}).allowed
    assert not decide(tmp_path, auth_type, {"allow_token_forward": "yes"}).allowed


def test_the_block_is_not_converted_in_observe_mode(tmp_path):
    assert not decide(tmp_path, "true_passthrough", observe=True).allowed


@pytest.mark.parametrize("auth_type", ["true_passthrough", "oauth_delegate"])
def test_the_approval_condition_lets_a_forwarding_server_through(tmp_path, auth_type):
    assert decide(tmp_path, auth_type, {"allow_token_forward": True}).allowed


@pytest.mark.parametrize("auth_type", ["none", "oauth2", "bearer_token", "api_key"])
def test_other_servers_are_not_affected(tmp_path, auth_type):
    assert decide(tmp_path, auth_type).allowed


def test_the_condition_is_written_only_when_asked():
    kwargs = dict(high_risk_tools=None, business_hours_only=False, business_hours=None,
                  require_consent=None)
    assert build_conditions(**kwargs) == {}
    assert build_conditions(**kwargs, allow_token_forward=True) == {"allow_token_forward": True}


def facts(name="s", **kw):
    return ServerFacts(name, False, False, None, None, 60.0, None, 1, 1, **kw)


def test_forwarding_configurations_are_recognized():
    assert forwards_client_token("true_passthrough", None, None)
    assert forwards_client_token("oauth_delegate", None, None)
    assert forwards_client_token("oauth2", True, None)
    assert forwards_client_token("none", None, ["Authorization"])
    assert forwards_client_token("none", None, ["x-api-key"])
    assert not forwards_client_token("oauth2", False, ["X-Request-Id"])
    assert not forwards_client_token("none", None, None)
    assert forwarding_violation([facts(), facts("a", forwards_token=False)]) is None
    found = forwarding_violation([facts("fwd", forwards_token=True)])
    assert found and found.key == KEY_FORWARD and "fwd" in found.message


def test_a_gateway_oauth_server_without_upstream_resource_is_a_violation():
    def keys(**kw):
        return [v.key for v in reuse_violations(
            general={"disable_env_credential_login": True}, allowed_hosts=[], ssl_verify=True,
            env={"PROXY_BASE_URL": "https://g.test"}, servers=[facts(**kw)],
            default_timeout=60.0)]

    assert KEY_RESOURCE in keys(gateway_oauth=True)
    assert KEY_RESOURCE not in keys(gateway_oauth=True, upstream_resource="auto")
    assert KEY_RESOURCE not in keys(gateway_oauth=True, upstream_resource="")
    assert KEY_RESOURCE not in keys(gateway_oauth=True, in_database=True)
    assert KEY_RESOURCE not in keys(gateway_oauth=False)
