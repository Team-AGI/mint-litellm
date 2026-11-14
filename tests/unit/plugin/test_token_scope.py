"""전달되는 호출자 토큰의 범위 확인(POL-O-15)."""

import asyncio
import base64
import json
import logging
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

from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.token_scope import exceeded_scopes, token_scopes

SECRET = "sig-must-not-leak"


def jwt(claims) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64(claims)}.{SECRET}"


@pytest.mark.parametrize(
    ("claims", "scopes"),
    [
        ({"scope": "read write"}, {"read", "write"}),
        ({"scp": ["read", "admin"]}, {"read", "admin"}),
        ({"scp": "read  admin"}, {"read", "admin"}),
        ({"scope": "read", "scp": ["write"]}, {"read", "write"}),
        ({"sub": "x"}, set()),
        ({"scope": 7, "scp": [1, None]}, set()),
    ],
)
def test_scope_string_and_list_forms(claims, scopes):
    assert token_scopes(jwt(claims)) == scopes


def test_subset_passes_and_extra_names_are_listed_sorted():
    assert exceeded_scopes(jwt({"scope": "read"}), ["read", "write"]) == ()
    assert exceeded_scopes(jwt({"scope": "read write"}), ["read", "write"]) == ()
    assert exceeded_scopes(jwt({"scope": "z a read"}), ["read"]) == ("a", "z")


@pytest.mark.parametrize("token", ["sk-opaque", "a.b.c", ""])
def test_opaque_tokens_are_not_checked(token):
    assert token_scopes(token) is None
    assert exceeded_scopes(token, ["read"]) is None


def decide(tmp_path, token, mode, approved=("read", "write"), auth="true_passthrough"):
    snap = snapshot(
        server=server_row(auth_type=auth, approved_oauth_scopes=approved),
        approvals=(approval(conditions={"allow_token_forward": True}),),
    )
    h = harness(tmp_path, snap, evaluate=evaluator())
    h.deps.config = replace(h.deps.config, token_scope=mode)
    req = request(resolved=resolved_server(auth_type=auth))
    req = replace(req, hook=replace(req.hook, bearer=token))
    return asyncio.run(evaluate_request(req, h.deps))


def test_enforce_blocks_a_token_wider_than_the_approved_scopes(tmp_path):
    out = decide(tmp_path, jwt({"scope": "read admin"}), "enforce")
    assert not out.allowed
    assert out.error.code == "MINT-TOKEN-SCOPE-EXCEEDED"
    assert out.context["scope_exceeded"] == ["admin"]


def test_observe_lets_it_through_and_names_only_the_extra_scopes(tmp_path):
    out = decide(tmp_path, jwt({"scp": ["read", "admin", "root"]}), "observe")
    assert out.allowed
    assert out.context["scope_exceeded"] == ["admin", "root"]
    assert out.context["scope_unchecked_reason"] is None
    assert SECRET not in json.dumps(out.context, default=str)


def test_a_subset_passes_in_both_modes(tmp_path):
    for mode in ("observe", "enforce"):
        out = decide(tmp_path, jwt({"scope": "read"}), mode)
        assert out.allowed and out.context["scope_exceeded"] == []


@pytest.mark.parametrize("approved", [None, ()])
def test_missing_approved_scopes_skip_with_a_reason(tmp_path, approved):
    out = decide(tmp_path, jwt({"scope": "admin"}), "enforce", approved=approved)
    assert out.allowed
    assert out.context["scope_exceeded"] == []
    assert out.context["scope_unchecked_reason"] == "no_approved_scopes"


def test_opaque_token_passes_with_reason_in_both_modes(tmp_path):
    for mode in ("observe", "enforce"):
        out = decide(tmp_path, "sk-opaque", mode)
        assert out.allowed and out.context["scope_unchecked_reason"] == "opaque"


def test_off_marks_forwarding_calls_unchecked(tmp_path):
    out = decide(tmp_path, jwt({"scope": "admin"}), "off")
    assert out.allowed
    assert out.context["scope_unchecked_reason"] == "not_forwarded"
    assert out.context["scope_exceeded"] == []


def _config(mode):
    base = {
        "MINT_INSTANCE_ID": "i1",
        "MINT_DATABASE_URL": "postgresql://x",
        "MINT_OPA_URL": "http://o",
    }
    return PluginConfig.from_env({**base, "MINT_TOKEN_SCOPE": mode} if mode else base)


def test_setting_defaults_to_observe_and_rejects_other_values():
    assert _config(None).token_scope == "observe"
    assert _config(" Enforce ").token_scope == "enforce"
    with pytest.raises(RuntimeError):
        _config("block")


def test_missing_token_passthrough_turns_the_check_off_or_refuses_enforce(caplog):
    from mint_litellm.plugin.selfcheck import _scope_capability

    problem = "bearer passthrough: token not carried"
    assert _scope_capability(_config("observe"), lambda: None).token_scope == "observe"
    with caplog.at_level(logging.WARNING):
        assert _scope_capability(_config("observe"), lambda: problem).token_scope == "off"
    assert "범위" in caplog.text
    with pytest.raises(RuntimeError, match="enforce"):
        _scope_capability(_config("enforce"), lambda: problem)
