"""전달되는 호출자 토큰의 대상(aud) 확인(POL-R-05)."""

import asyncio
import base64
import json
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

from mint_litellm.compat.litellm_1_106 import parse_hook_data
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.token_audience import MISMATCH, OK, UNCHECKED, audience_verdict

URL = "http://u.test/mcp"


def jwt(claims) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


@pytest.mark.parametrize(
    ("claims", "verdict"),
    [
        ({"aud": URL}, OK),
        ({"aud": URL + "/"}, OK),
        ({"aud": ["other", URL]}, OK),
        ({"aud": "http://other.test/mcp"}, MISMATCH),
        ({"aud": ["a", "b"]}, MISMATCH),
        ({"sub": "x"}, MISMATCH),
        ({"aud": 7}, MISMATCH),
    ],
)
def test_jwt_audience_string_list_and_missing(claims, verdict):
    assert audience_verdict(jwt(claims), [URL]) == verdict


@pytest.mark.parametrize("token", ["sk-opaque", "a.b.c", "a..c", "", "x.e30.y.z"])
def test_opaque_tokens_are_not_checked(token):
    assert audience_verdict(token, [URL]) == UNCHECKED


def test_hook_data_carries_the_bearer_without_showing_it():
    hook = parse_hook_data({"incoming_bearer_token": "secret-token"})
    assert hook.bearer == "secret-token"
    assert "secret-token" not in repr(hook)
    assert parse_hook_data({}).bearer is None


def decide(tmp_path, token, mode):
    conditions = {"allow_token_forward": True}
    snap = snapshot(
        server=server_row(auth_type="true_passthrough"),
        approvals=(approval(conditions=conditions),),
    )
    h = harness(tmp_path, snap, evaluate=evaluator())
    h.deps.config = replace(h.deps.config, token_audience=mode)
    server = resolved_server(auth_type="true_passthrough").model_copy(update={"audiences": (URL,)})
    req = request(resolved=server)
    req = replace(req, hook=replace(req.hook, bearer=token))
    return asyncio.run(evaluate_request(req, h.deps))


def test_enforce_blocks_a_token_for_another_audience(tmp_path):
    out = decide(tmp_path, jwt({"aud": "http://other.test"}), "enforce")
    assert not out.allowed
    assert out.error.code == "MINT-TOKEN-AUDIENCE-MISMATCH"


def test_observe_lets_it_through_and_marks_the_event(tmp_path):
    out = decide(tmp_path, jwt({"aud": "http://other.test"}), "observe")
    assert out.allowed
    assert out.context["aud_mismatch"] is True and out.context["aud_unchecked"] is False


def test_opaque_and_matching_tokens_pass_in_both_modes(tmp_path):
    for mode in ("observe", "enforce"):
        opaque = decide(tmp_path, "sk-opaque", mode)
        assert opaque.allowed and opaque.context["aud_unchecked"] is True
        assert opaque.context["aud_mismatch"] is False
        good = decide(tmp_path, jwt({"aud": URL}), mode)
        assert good.allowed and not good.context["aud_unchecked"]


def test_setting_defaults_to_observe_and_rejects_other_values():
    base = {
        "MINT_INSTANCE_ID": "i1",
        "MINT_DATABASE_URL": "postgresql://x",
        "MINT_OPA_URL": "http://o",
    }
    assert PluginConfig.from_env(base).token_audience == "observe"
    assert PluginConfig.from_env({**base, "MINT_TOKEN_AUDIENCE": " Enforce "}).token_audience == (
        "enforce"
    )
    with pytest.raises(RuntimeError):
        PluginConfig.from_env({**base, "MINT_TOKEN_AUDIENCE": "block"})
