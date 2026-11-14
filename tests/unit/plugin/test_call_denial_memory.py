"""거부된 호출별 승인은 같은 호출의 재시도를 새 요청 없이 사유와 함께 거절한다."""

import asyncio
import json

from plugin_helpers import config, evaluator, harness, request

from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.types.reason_codes import Reason
from mint_litellm.types.settings import Mode


def setup(tmp_path, prior, **cfg):
    h = harness(tmp_path, evaluate=evaluator("RequireApproval", policy_ids=("R2",)),
                cfg=config(tmp_path, mode_ceiling=Mode.ENFORCE, **cfg))
    h.snapshots.opened, h.snapshots.asked = [], []

    async def outcome(params):
        h.snapshots.asked.append(params)
        return prior

    async def create(params):
        h.snapshots.opened.append(params)
        return "call-1"

    h.snapshots.recent_call_outcome = outcome
    h.snapshots.request_call_approval = create
    return h


def test_a_denied_retry_is_refused_with_the_reason_and_opens_nothing(tmp_path):
    h = setup(tmp_path, ("rejected", "범위 밖 요청"))
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_DENIED
    body = json.loads(result.error.detail())
    assert body["code"] == "MINT-CALL-APPROVAL-DENIED" and body["denial_reason"] == "범위 밖 요청"
    assert body["retry_safe"] is False and "approval_requested" not in body
    assert h.snapshots.opened == []
    assert h.snapshots.asked[0]["minutes"] == 30


def test_without_a_prior_denial_a_new_request_opens_as_before(tmp_path):
    h = setup(tmp_path, None)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    assert len(h.snapshots.opened) == 1
    assert json.loads(result.error.detail())["approval_requested"] is True


def test_an_expired_prior_approval_is_reported_while_a_new_request_opens(tmp_path):
    h = setup(tmp_path, ("expired", None))
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    body = json.loads(result.error.detail())
    assert body["previous_expired"] is True and body["approval_requested"] is True
    assert len(h.snapshots.opened) == 1


def test_the_memory_can_be_turned_off(tmp_path):
    h = setup(tmp_path, ("rejected", "x"), call_denial_minutes=0)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    assert h.snapshots.asked == [] and len(h.snapshots.opened) == 1


def test_a_failing_lookup_does_not_change_the_block(tmp_path):
    h = setup(tmp_path, None)

    async def broken(params):
        raise RuntimeError("down")

    h.snapshots.recent_call_outcome = broken
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED


def test_the_window_comes_from_the_environment():
    env = {"MINT_INSTANCE_ID": "i1", "MINT_DATABASE_URL": "postgresql://x/y",
           "MINT_OPA_URL": "http://opa:8181"}
    assert PluginConfig.from_env(env).call_denial_minutes == 30
    assert PluginConfig.from_env({**env, "MINT_CALL_DENIAL_MINUTES": "5"}).call_denial_minutes == 5
