"""에이전트가 읽는 거부 응답 세 갈래와, 정책 엔진 장애 중 직전에 허용된 호출의 통과."""

import asyncio
import json

from plugin_helpers import (
    NOW,
    approval,
    buffered,
    denial,
    evaluator,
    harness,
    resolved_server,
    server_row,
    snapshot,
    user_principal,
)

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.plugin.pipeline import build_request, evaluate_request
from mint_litellm.plugin.snapshot import ToolContractRow
from mint_litellm.types.decision import OperationType, Reason, StageResult
from mint_litellm.types.errors import Dependency, error_for_reason

SERVER = server_row(contract_status="managed", last_observed_at=NOW)
CONTRACTS = (ToolContractRow("c1", "server", "search", "none", 1, input_keys=("q",)),)
REF = "00000000-0000-0000-0000-000000000001:1"


def body(code, **kw):
    return json.loads(error_for_reason(code, REF, **kw).detail())


def test_the_three_refusal_kinds_tell_the_agent_what_to_do():
    pending = body("CALL_APPROVAL_REQUIRED")
    assert pending["retry_safe"] is True and pending["retry_after"] > 0
    assert "승인 대기 중" in pending["guidance"] and "Approval pending" in pending["guidance"]
    blocked = body("SERVER_NOT_APPROVED")
    assert blocked["retry_safe"] is False and "retry_after" not in blocked
    assert "재시도하지 마십시오" in blocked["guidance"] and "do not retry" in blocked["guidance"]
    admin = body("DENIED")
    assert admin["retry_safe"] is True and admin["retry_after"] <= 5
    assert "관리자가 막은 도구" in admin["guidance"] and len(admin["guidance"].split(".")[0]) < 40
    transient = body("DEPENDENCY_FAILURE", dependency=Dependency.OPA)
    assert transient["retry_safe"] is True and transient["retry_after"] > 0
    assert "일시 오류" in transient["guidance"] and "Temporary error" in transient["guidance"]
    assert transient["reference"] == pending["reference"] == blocked["reference"] == REF


def call(h):
    data = {
        "mcp_server_name": "mslearn",
        "mcp_tool_name": "search",
        "mcp_arguments": {"q": "x"},
        "messages": [{"role": "user", "content": "call\nArguments: {'q': 'x'}"}],
    }
    request = build_request(
        data,
        None,
        operation=OperationType.TOOL_CALL,
        instance_id="inst",
        hook_parser=compat.parse_hook_data,
        resolver=lambda hook: resolved_server(),
        principal_factory=lambda auth, instance_id: user_principal(),
    )
    return asyncio.run(evaluate_request(request, h.deps))


def ready(tmp_path, **kw):
    return harness(
        tmp_path,
        snapshot(server=SERVER, tool_contracts=CONTRACTS, approvals=(approval(),)),
        evaluate=kw.get("evaluate", evaluator()),
    )


def test_an_approved_call_passes_while_the_policy_engine_is_down_even_the_first_time(tmp_path):
    h = ready(tmp_path, evaluate=evaluator(failure=StageResult.stop(Reason.DEPENDENCY_FAILURE)))
    outage = call(h)
    assert outage.allowed and outage.snapshot.policy_degraded is True
    assert json.loads(outage.snapshot.model_dump_json())["policy_degraded"] is True


def test_a_denied_call_is_still_blocked_while_the_policy_engine_is_down(tmp_path):
    h = harness(
        tmp_path,
        snapshot(server=SERVER, tool_contracts=CONTRACTS, denials=(denial(),)),
        evaluate=evaluator(failure=StageResult.stop(Reason.DEPENDENCY_FAILURE)),
    )
    assert not call(h).allowed


def test_the_last_good_snapshot_decides_while_the_database_is_down(tmp_path):
    h = ready(tmp_path)
    assert call(h).allowed
    h.snapshots.snap = RuntimeError("db down")
    outage = call(h)
    assert outage.allowed and outage.snapshot.snapshot_stale is True


def test_a_call_with_no_good_snapshot_yet_is_a_transient_error(tmp_path):
    h = ready(tmp_path)
    h.snapshots.snap = RuntimeError("db down")
    outage = call(h)
    assert not outage.allowed and outage.error.code == "MINT-DEPENDENCY-DB"
    assert outage.error.retry_safe


def test_an_allowed_call_is_buffered_when_the_event_cannot_be_stored(tmp_path):
    h = ready(tmp_path)
    h.store.fail = RuntimeError("db down")
    outcome = call(h)
    assert outcome.allowed and outcome.evidence.value == "buffer"
    assert buffered(h)


def test_a_litellm_admin_outage_only_retries_the_sync_job():
    from types import SimpleNamespace

    import pytest

    from mint_litellm.control.litellm_write import LiteLLMUnreachable
    from mint_litellm.control.sync_jobs import _reachable

    def handler(ctx):
        raise LiteLLMUnreachable("down")

    with pytest.raises(LiteLLMUnreachable):
        _reachable(handler)(SimpleNamespace(instance_id="avl-test", conn=None))
