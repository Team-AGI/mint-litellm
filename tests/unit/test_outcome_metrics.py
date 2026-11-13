"""결과 분류, 판정 참조 검색, 지표 출력."""

import asyncio
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from mint_litellm.control.services import metrics, reads
from mint_litellm.plugin.result import ResultDeps, observe_response, observe_unknown_outcome
from mint_litellm.types.errors import error_for_reason
from mint_litellm.types.events import EventKind
from mint_litellm.types.outcome import Outcome, decision_outcome, response_outcome


@pytest.mark.parametrize(
    ("allowed", "reason", "findings", "expected"),
    [
        (True, None, False, Outcome.ALLOWED),
        (True, "SERVER_NOT_APPROVED", True, Outcome.OBSERVED),
        (False, "DENIED", False, Outcome.BLOCKED),
        (False, "SERVER_NOT_APPROVED", True, Outcome.BLOCKED),
        (False, "CALL_APPROVAL_REQUIRED", False, Outcome.PENDING_APPROVAL),
        (False, "CONTRACT_DRIFT_input_schema", False, Outcome.CONTRACT_DRIFT),
        (False, "DEPENDENCY_FAILURE", False, Outcome.DEPENDENCY_FAILURE),
        (False, "AUDIT_FAILURE", False, Outcome.DEPENDENCY_FAILURE),
    ],
)
def test_decision_outcome(allowed, reason, findings, expected):
    assert decision_outcome(allowed=allowed, reason_code=reason, has_findings=findings) is expected


def test_response_outcome():
    assert response_outcome(is_error=False, output_blocked=False) is Outcome.SUCCESS
    assert response_outcome(is_error=True, output_blocked=False) is Outcome.TOOL_ERROR
    assert response_outcome(is_error=False, output_blocked=True) is Outcome.OUTPUT_BLOCKED


class _Recorder:
    def __init__(self):
        self.events = []

    async def record(self, event):
        self.events.append(event)


class _Database:
    async def read_epoch(self, instance_id):
        return 1


def _deps():
    config = SimpleNamespace(instance_id="i", decision_budget_seconds=1.0)
    return ResultDeps(config=config, database=_Database(), recorder=_Recorder())


def _ctx():
    return {
        "invocation_id": str(uuid4()), "attempt_id": 1, "decision_ref": "x:1", "allowed": True,
        "state_epoch": 1, "server_id": "s", "tool": "t",
    }


def test_result_events_carry_outcome():
    deps = _deps()

    async def run():
        await observe_response(_ctx(), is_error=True, size_bytes=None, deps=deps)
        await observe_unknown_outcome(_ctx(), exception_type="X", http_status=504, deps=deps)

    asyncio.run(run())
    response, unknown = deps.recorder.events
    assert response.kind is EventKind.CALL_RESPONSE_RECEIVED
    assert response.payload["outcome"] == "tool_error"
    assert unknown.payload["outcome"] == "unknown"


def test_block_error_carries_reference_only():
    ref = f"{uuid4()}:1"
    detail = json.loads(error_for_reason("DENIED", ref).detail())
    assert detail["reference"] == ref
    assert set(detail) == {"code", "dispatch_state", "retry_safe", "reference"}


def test_ledger_reference_filter():
    invocation = uuid4()
    assert reads.parse_ref(f" {invocation}:2 ") == (invocation, 2)
    assert reads.parse_ref(str(invocation)) == (invocation, None)
    for bad in ("nope", f"{invocation}:0", f"{invocation}:x"):
        with pytest.raises(ValueError):
            reads.parse_ref(bad)
    where, params = reads._ledger_where(
        "i", since=None, until=None, kind=None, actor=None, server_id=None, result=None,
        ref=f"{invocation}:2",
    )
    assert "invocation_id = %s" in where and "attempt_id = %s" in where
    assert "inserted_at >= %s" not in where  # 참조로 찾을 때는 기본 기간이 없다
    assert params == ["i", invocation, 2]


def test_metrics_render():
    data = {
        "decisions": [
            {"server_id": "a", "result": "blocked", "n": 3},
            {"server_id": "", "result": "allowed", "n": 5},
        ],
        "results": [{"result": "unknown", "n": 1}],
        "latency": {"n": 4, "total": 6000, **{f"b{i}": 4 for i in range(len(metrics.BUCKETS))}},
        "jobs": [{"kind": "observe", "n": 2, "oldest": 12.5}],
        "observed": [{"server_id": 'we"ird', "age": 30}],
        "alerts": [{"kind": "call_spike", "severity": "high", "n": 1}],
    }
    text = metrics.render(data)
    assert 'mint_decisions_total{result="blocked",server_id="a"} 3' in text
    assert 'mint_decision_seconds_bucket{le="+Inf"} 4' in text
    assert "mint_decision_seconds_sum 0.006" in text
    assert 'mint_jobs_oldest_pending_seconds{kind="observe"} 12.5' in text
    assert 'server_id="we\\"ird"' in text
    assert 'mint_alerts_open{kind="call_spike",severity="high"} 1' in text
    assert text.endswith("\n")
    for banned in ("user", "args", "tool="):
        assert banned not in text
