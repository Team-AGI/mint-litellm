"""승인이 없어 막힌 호출은 호출별 승인 요청을 열고, 호출자 오류에 그 사실이 담긴다."""

import asyncio
import json

from plugin_helpers import config, evaluator, harness, request

from mint_litellm.plugin.pipeline import AUTO_REQUESTER, evaluate_request
from mint_litellm.types.errors import MintError
from mint_litellm.types.reason_codes import Reason
from mint_litellm.types.settings import Mode


def setup(tmp_path, snap=None, opened="call-1"):
    h = harness(tmp_path, snap, evaluate=evaluator("RequireApproval", policy_ids=("R2",)),
                cfg=config(tmp_path, mode_ceiling=Mode.ENFORCE))
    h.snapshots.requests = []

    async def create(params):
        h.snapshots.requests.append(params)
        return opened

    h.snapshots.request_call_approval = create
    return h


def test_blocked_call_opens_a_pending_request_and_tells_the_caller(tmp_path):
    h = setup(tmp_path)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    (params,) = h.snapshots.requests
    assert params["requested_by"] == AUTO_REQUESTER and params["tool"] == "search"
    assert len(params["args_fp"]) == 64
    body = json.loads(result.error.detail())
    assert body["approval_requested"] is True and body["reference"]
    assert body["retry_safe"] is True and "다시 요청하십시오" in body["guidance"]
    assert MintError.from_detail(result.error.detail()).approval_requested


def test_a_request_that_cannot_be_opened_still_blocks_without_the_flag(tmp_path):
    h = setup(tmp_path, opened=None)
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert not result.allowed
    assert "approval_requested" not in json.loads(result.error.detail())


def test_a_store_without_the_request_hook_does_not_change_the_block(tmp_path):
    h = setup(tmp_path)

    async def broken(params):
        raise RuntimeError("down")

    h.snapshots.request_call_approval = broken
    result = asyncio.run(evaluate_request(request(), h.deps))
    assert result.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    assert "approval_requested" not in json.loads(result.error.detail())


def test_the_announcing_job_uses_the_same_requester_marker():
    from mint_litellm.control.services import expiry

    assert expiry.AUTO_REQUESTER == AUTO_REQUESTER
