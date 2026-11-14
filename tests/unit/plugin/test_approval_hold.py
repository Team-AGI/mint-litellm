"""승인을 기다리며 호출을 붙잡아 두는 동작: 결정 대기, 판정 재실행, 취소, 요청 재사용."""

import asyncio
from dataclasses import replace

import pytest
from plugin_helpers import call_approval, config, evaluator, harness, request, snapshot

from mint_litellm.plugin.approval_hold import hold_for_decision, hold_if_pending
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.types.reason_codes import Reason
from mint_litellm.types.settings import Mode


class Clock:
    """가짜 시계. sleep이 시간을 흘려보낸다."""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def statuses(*values):
    queue = list(values)

    async def status(call_id):
        return queue.pop(0) if len(queue) > 1 else queue[0]

    return status


def hold(seconds, status, clock):
    return asyncio.run(hold_for_decision("call-1", seconds, status, sleep=clock.sleep, clock=clock))


def test_approval_during_the_hold_ends_it_early():
    clock = Clock()
    result, ms = hold(120, statuses("pending", "pending", "approved"), clock)
    assert result == "approved" and len(clock.sleeps) == 3 and 0 < ms < 5000


@pytest.mark.parametrize(
    ("state", "expected"),
    [("rejected", "denied"), ("cancelled", "denied"), ("expired", "expired"), (None, "expired")],
)
def test_a_closed_request_ends_the_hold_with_its_outcome(state, expected):
    assert hold(120, statuses("pending", state), Clock())[0] == expected


def test_no_decision_times_out_and_polls_with_backoff():
    clock = Clock()
    result, ms = hold(10, statuses("pending"), clock)
    assert result == "timed_out" and ms == 10000
    assert clock.sleeps[0] < clock.sleeps[3] <= 2.0 and sum(clock.sleeps) == pytest.approx(10)


def test_a_failed_status_read_keeps_waiting():
    calls = []

    async def status(call_id):
        calls.append(call_id)
        if len(calls) == 1:
            raise RuntimeError("down")
        return "approved"

    assert hold(120, status, Clock())[0] == "approved" and len(calls) == 2


def test_cancellation_stops_waiting_and_is_not_swallowed():
    clock = Clock()

    async def go():
        task = asyncio.create_task(
            hold_for_decision("call-1", 120, statuses("pending"), clock=clock)
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(go())


def setup(tmp_path, snap=None, opened="call-1"):
    h = harness(
        tmp_path,
        snap,
        evaluate=evaluator("RequireApproval", policy_ids=("R2",)),
        cfg=config(tmp_path, mode_ceiling=Mode.ENFORCE),
    )
    h.snapshots.requests = []

    async def create(params):
        h.snapshots.requests.append(params)
        return opened

    h.snapshots.request_call_approval = create
    return h


def run_hold(h, seconds, status, clock):
    async def go():
        first = await evaluate_request(request(), h.deps)

        async def again(held):
            return await evaluate_request(replace(request(), hold=held), h.deps)

        return first, await hold_if_pending(
            first, seconds, status, again, sleep=clock.sleep, clock=clock
        )

    return asyncio.run(go())


def test_approval_during_the_hold_reruns_the_decision_and_consumes_it(tmp_path):
    h = setup(tmp_path)
    clock = Clock()

    async def status(call_id):
        h.snapshots.snap = snapshot(call_approvals=(call_approval(),))
        return "approved"

    first, final = run_hold(h, 120, status, clock)
    assert not first.allowed and first.approval_request_id == "call-1"
    assert final.allowed and final.snapshot.approval_hold == "approved"
    assert final.snapshot.invocation_id != first.snapshot.invocation_id
    assert [str(c.call_approval_id) for c in h.store.consumed] == [
        "00000000-0000-0000-0000-0000000000c1"
    ]
    assert len(h.snapshots.requests) == 1  # 다시 돌린 판정은 새 요청을 열지 않는다


@pytest.mark.parametrize(
    ("state", "label"), [("rejected", "denied"), ("expired", "expired"), ("pending", "timed_out")]
)
def test_refusal_outcomes_return_the_existing_refusal(tmp_path, state, label):
    h = setup(tmp_path)
    final = run_hold(h, 3, statuses(state), Clock())[1]
    assert not final.allowed and final.error is not None
    assert final.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
    assert final.snapshot.approval_hold == label and h.store.consumed == []


def test_an_approval_that_no_longer_fits_the_call_is_refused_again(tmp_path):
    h = setup(tmp_path)

    async def status(call_id):
        h.snapshots.snap = snapshot(call_approvals=(call_approval(tool="other"),))
        return "approved"

    final = run_hold(h, 120, status, Clock())[1]
    assert not final.allowed and final.snapshot.approval_hold == "approved"
    assert h.store.consumed == []


@pytest.mark.parametrize("opened", [None])
def test_no_pending_request_means_no_hold(tmp_path, opened):
    h = setup(tmp_path, opened=opened)
    clock = Clock()
    first, final = run_hold(h, 120, statuses("approved"), clock)
    assert final is first and clock.sleeps == []


def test_zero_seconds_disables_the_hold(tmp_path):
    h = setup(tmp_path)
    clock = Clock()
    first, final = run_hold(h, 0, statuses("approved"), clock)
    assert final is first and clock.sleeps == [] and first.approval_request_id == "call-1"


def test_an_allowed_call_is_returned_untouched(tmp_path):
    h = harness(tmp_path)
    clock = Clock()
    first, final = run_hold(h, 120, statuses("approved"), clock)
    assert first.allowed and final is first and clock.sleeps == []


def test_the_config_bounds_the_hold(tmp_path):
    env = {
        "MINT_INSTANCE_ID": "i1",
        "MINT_DATABASE_URL": "postgresql://x",
        "MINT_OPA_URL": "http://o",
    }
    assert PluginConfig.from_env(env).approval_hold_seconds == 120
    off = PluginConfig.from_env({**env, "MINT_APPROVAL_HOLD_SECONDS": "0"})
    assert off.approval_hold_seconds == 0
    for bad in ("-1", "301", "x"):
        with pytest.raises(RuntimeError):
            PluginConfig.from_env({**env, "MINT_APPROVAL_HOLD_SECONDS": bad})
