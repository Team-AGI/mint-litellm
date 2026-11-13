"""정책 시험 적용: 호출 판정은 그대로이고, 오류는 삼키고, 부하는 상한으로 막는다."""

import asyncio

from plugin_helpers import BUNDLE, evaluator, harness, request

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.policy.opa_client import Evaluation
from mint_litellm.plugin.shadow import MAX_INFLIGHT, MAX_KEYS, Bucket, ShadowTarget, ShadowWatch
from mint_litellm.types.decision import StageResult
from mint_litellm.types.reason_codes import Reason


class FakeConn:
    def __init__(self, row=None):
        self.statements = []
        self.row = row

    async def execute(self, sql, params=()):
        self.statements.append((sql, params))
        return self

    async def fetchone(self):
        return self.row

    def transaction(self):
        conn = self

        class Tx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False

        return Tx()


class FakeDatabase:
    def __init__(self, row=None, fail=False):
        self.conn = FakeConn(row)
        self.fail = fail

    async def _run(self, work):
        if self.fail:
            raise OSError("down")
        return await work(self.conn)


def watch(evaluate=None, **kw) -> ShadowWatch:
    evaluate = evaluate or evaluator("Block", policy_ids=("R9",))
    w = ShadowWatch("inst", kw.pop("database", FakeDatabase()), evaluate, **kw)
    w.target = ShadowTarget("pv1", BUNDLE)
    return w


def submit(w: ShadowWatch, decision="Allow", ids=(), invocation="i-1") -> None:
    w.submit(
        {"arguments": {}}, invocation_id=invocation, server_id="s1", tool="t1",
        decision=decision, policy_ids=ids,
    )


async def settle(w: ShadowWatch) -> None:
    await asyncio.gather(*list(w._tasks))


def run(coro):
    return asyncio.run(coro)


def test_without_a_target_nothing_is_evaluated():
    async def go():
        calls = []
        w = watch(evaluator("Block", calls=calls))
        w.target = None
        submit(w)
        await settle(w)
        assert calls == [] and w.pending == {}

    run(go())


def test_a_differing_decision_is_counted_with_a_bounded_sample_of_invocations():
    async def go():
        w = watch()
        for n in range(8):
            submit(w, "Allow", invocation=f"i-{n}")
        await settle(w)
        bucket = w.pending["pv1"]
        assert (bucket.evaluated, bucket.same, bucket.errors) == (8, 0, 0)
        ((key, (count, samples)),) = bucket.results.items()
        assert key == ("s1", "t1", "Allow", "Block", "", "R9")
        assert count == 8 and samples == ["i-0", "i-1", "i-2", "i-3", "i-4"]

    run(go())


def test_same_decision_and_reasons_are_counted_as_same_only():
    async def go():
        w = watch()
        submit(w, "Block", ("R9",))
        await settle(w)
        assert (w.pending["pv1"].evaluated, w.pending["pv1"].same) == (1, 1)
        assert w.pending["pv1"].results == {}

    run(go())


def test_same_decision_with_other_reasons_is_a_difference():
    async def go():
        w = watch()
        submit(w, "Block", ("R1",))
        await settle(w)
        assert list(w.pending["pv1"].results) == [("s1", "t1", "Block", "Block", "R1", "R9")]

    run(go())


def test_shadow_errors_are_swallowed_and_counted():
    async def boom(*args, **kwargs):
        raise RuntimeError("down")

    async def empty(*args, **kwargs):  # 엔진 실패
        return Evaluation()

    async def go(evaluate):
        w = watch(evaluate)
        submit(w)
        await settle(w)
        assert w.pending["pv1"].errors == 1 and w.pending["pv1"].evaluated == 0

    run(go(boom))
    run(go(empty))


def test_submit_never_raises_even_without_a_running_loop():
    w = watch()
    submit(w)  # 이벤트 루프가 없다
    assert w.pending["pv1"].errors == 1


def test_per_second_cap_skips_the_rest():
    async def go():
        now = [100.2]
        w = watch(max_per_second=3, clock=lambda: now[0])
        for n in range(10):
            submit(w, invocation=f"i-{n}")
        await settle(w)
        assert (w.pending["pv1"].evaluated, w.pending["pv1"].skipped) == (3, 7)
        now[0] = 101.1  # 다음 초에는 다시 평가한다
        submit(w)
        await settle(w)
        assert w.pending["pv1"].evaluated == 4

    run(go())


def test_in_flight_evaluations_are_bounded():
    async def go():
        gate = asyncio.Event()

        async def slow(*args, **kwargs):
            await gate.wait()
            return await evaluator("Block", policy_ids=("R9",))(*args, **kwargs)

        w = watch(slow, max_per_second=1000)
        for _ in range(MAX_INFLIGHT + 5):
            submit(w)
        assert len(w._tasks) == MAX_INFLIGHT and w.pending["pv1"].skipped == 5
        gate.set()
        await settle(w)

    run(go())


def test_sample_rate_skips_calls():
    async def go():
        w = watch(sample_percent=30, rand=iter([0.1, 0.5, 0.29, 0.3]).__next__)
        for _ in range(4):
            submit(w)
        await settle(w)
        assert (w.pending["pv1"].evaluated, w.pending["pv1"].skipped) == (2, 2)

    run(go())


def test_result_keys_are_bounded():
    bucket = Bucket()
    for n in range(MAX_KEYS + 3):
        bucket.differ((f"s{n}", "t", "Allow", "Block", "", ""), "i")
    assert len(bucket.results) == MAX_KEYS and bucket.skipped == 3


def test_flush_adds_counts_and_failures_keep_them_for_the_next_round():
    async def go():
        db = FakeDatabase(fail=True)
        w = watch(database=db)
        submit(w)
        submit(w, "Block", ("R9",))
        await settle(w)
        await w.flush()  # 쓰지 못해도 값은 남는다
        assert w.pending["pv1"].evaluated == 2
        db.fail = False
        await w.flush()
        assert w.pending == {}
        stats, result = db.conn.statements
        assert stats[1] == ("inst", "pv1", 2, 1, 0, 0)
        assert result[1] == ("inst", "pv1", "s1", "t1", "Allow", "Block", "", "R9", 1, ["i-1"])

    run(go())


def test_refresh_reads_the_shadow_version_and_keeps_the_old_one_on_failure():
    async def go():
        db = FakeDatabase(row=("pv2", "b" * 64))
        w = watch(database=db)
        await w.refresh()
        assert w.target == ShadowTarget("pv2", "b" * 64)
        db.fail = True
        await w.refresh()
        assert w.target == ShadowTarget("pv2", "b" * 64)
        db.fail, db.conn.row = False, (None, None)
        await w.refresh()
        assert w.target is None

    run(go())


def test_the_real_decision_is_unchanged_by_shadow(tmp_path):
    async def go(shadow):
        h = harness(tmp_path / "x")
        h.deps.shadow = shadow
        outcome = await evaluate_request(request(), h.deps)
        return outcome, h

    async def with_watch():
        w = watch()
        outcome, h = await go(w.submit)
        await settle(w)
        return outcome, w

    baseline, _ = run(go(None))
    outcome, w = run(with_watch())
    assert outcome.allowed and baseline.allowed
    assert outcome.snapshot.enforced_action == baseline.snapshot.enforced_action
    assert w.pending["pv1"].evaluated == 1
    assert list(w.pending["pv1"].results)[0][2:4] == ("Allow", "Block")


def test_a_failing_shadow_hook_does_not_affect_the_call(tmp_path):
    def broken(*args, **kwargs):
        raise RuntimeError("shadow bug")

    h = harness(tmp_path)
    h.deps.shadow = broken
    outcome = run(evaluate_request(request(), h.deps))
    assert outcome.allowed
    assert len(h.store.of_kind("decision_evaluated")) == 1


def test_a_stopped_policy_stage_is_not_compared(tmp_path):
    seen = []
    failure = StageResult.stop(Reason.DEPENDENCY_FAILURE)
    h = harness(tmp_path, evaluate=evaluator(failure=failure))
    h.deps.shadow = lambda *a, **k: seen.append(k)
    outcome = run(evaluate_request(request(), h.deps))
    assert not outcome.allowed and seen == []
