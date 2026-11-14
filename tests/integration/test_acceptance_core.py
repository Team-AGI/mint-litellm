"""1단계 인수시험: 승인 수명주기, 상태 집행, 증거 불변식.

모든 시험은 사건 행(``decision_evaluated``)과 업스트림 호출 수(프록시 기록 + 시험 서버 진입 계수)를
함께 확인한다. 차단 시험은 같은 실행에서 양성 대조를 먼저 통과해야 한다.
"""

import concurrent.futures
import json
import os
import statistics
import threading
import time
from datetime import timedelta

import pytest
import support
from scenario import decision, iso


def code_of(reason: str) -> str:
    return "MINT-" + reason.replace("_", "-")


def assert_blocked(world, evidence, outcome, reason: str, server: str = "a") -> None:
    assert outcome.status == 403, outcome.body
    assert outcome.code == code_of(reason), outcome.body
    events = world.events(outcome.mark)
    assert len(events) == 1
    evaluated, enforced, found = decision(events[0])
    assert (evaluated, enforced, found) == ("block", "block", reason)
    evidence.assert_calls(outcome.mark, 0, server)


def assert_allowed(world, evidence, outcome, server: str = "a") -> dict:
    assert outcome.allowed, outcome.body
    events = world.events(outcome.mark)
    assert len(events) == 1
    assert decision(events[0])[:2] == ("allow", "allow")
    evidence.assert_calls(outcome.mark, 1, server)
    return events[0]["payload"]


@pytest.fixture
def approved(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    approval = world.approve(subject, relation)
    return subject, relation, approval


def test_approved_call_is_allowed_once(world, evidence, approved):
    subject, _, approval = approved
    payload = assert_allowed(world, evidence, world.call(subject))
    assert payload["selected_approval_id"] == approval


def test_call_without_approval_is_blocked(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    world.prepare(subject)
    assert_blocked(world, evidence, world.call(subject), "APPROVAL_ABSENT")


def test_approval_is_effective_immediately(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    assert_blocked(world, evidence, world.call(subject), "APPROVAL_ABSENT")
    world.approve(subject, relation)
    assert_allowed(world, evidence, world.call(subject))


def test_sole_approval_revoked_blocks_later_calls(world, evidence, approved):
    subject, _, approval = approved
    assert_allowed(world, evidence, world.call(subject))
    world.mint.run("revoke", approval, "--reason", "it")
    assert_blocked(world, evidence, world.call(subject), "APPROVAL_REVOKED")


def test_revoke_with_deny_wins_over_other_approvals(world, evidence, approved):
    subject, relation, approval = approved
    world.approve(subject, relation)
    world.mint.run("revoke", approval, "--reason", "it", "--deny")
    assert_blocked(world, evidence, world.call(subject), "DENIED")


def test_revoking_narrow_approval_keeps_broad_one(world, evidence, approved):
    subject, relation, broad = approved
    narrow = world.approve(subject, relation, tools="echo")
    world.mint.run("revoke", narrow, "--reason", "it")
    payload = assert_allowed(world, evidence, world.call(subject))
    assert payload["selected_approval_id"] == broad


def test_denial_blocks_even_with_approval(world, evidence, approved):
    subject, _, _ = approved
    world.mint.run(
        "deny",
        "--scope",
        "key",
        "--scope-id",
        subject.key_id,
        "--server",
        support.SERVER_ID["a"],
        "--reason",
        "it",
    )
    assert_blocked(world, evidence, world.call(subject), "DENIED")


def test_suspended_server_blocks_and_resume_restores(world, evidence, approved):
    subject, _, _ = approved
    world.mint.run("server", "suspend", support.SERVER_ID["a"])
    try:
        assert_blocked(world, evidence, world.call(subject), "SERVER_SUSPENDED")
    finally:
        world.mint.run("server", "resume", support.SERVER_ID["a"])
    assert_allowed(world, evidence, world.call(subject))


def test_terminated_relation_blocks(world, evidence, approved):
    subject, relation, _ = approved
    world.mint.run("relation", "terminate", relation)
    assert_blocked(world, evidence, world.call(subject), "RELATION_TERMINATED")


def test_expired_approval_blocks(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    world.approve(subject, relation, valid=timedelta(seconds=4))
    assert world.call(subject).allowed
    time.sleep(5)
    assert_blocked(world, evidence, world.call(subject), "APPROVAL_EXPIRED")


def test_approval_not_yet_valid_blocks(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    world.approve(subject, relation, valid_from=timedelta(hours=1), valid=timedelta(hours=2))
    assert_blocked(world, evidence, world.call(subject), "APPROVAL_ABSENT")


def test_allowlist_expiry_blocks(world, evidence):
    evidence.positive_control()
    subject = world.subject(("c",))
    relation = world.prepare(subject, "c")
    entry = world.mint.data(
        "allowlist",
        "add",
        "--kind",
        "provider",
        "--value",
        "integration-provider",
        "--valid-until",
        iso(timedelta(seconds=6)),
    )["id"]
    world.approve(subject, relation, extra=("--allowlist-ref", entry))
    assert_allowed(world, evidence, world.call(subject, "c"), "c")
    time.sleep(7)
    assert_blocked(world, evidence, world.call(subject, "c"), "ALLOWLIST_EXPIRED", "c")


def test_other_organization_approval_is_not_reused(world, evidence, approved):
    other = world.subject()
    world.prepare(other)
    assert_blocked(world, evidence, world.call(other), "APPROVAL_ABSENT")


def test_same_decision_on_both_replicas(world, evidence, approved):
    subject, _, _ = approved
    for port in support.LITELLM_PORTS:
        assert_allowed(world, evidence, world.call(subject, port=port))


def test_each_path_records_exactly_one_decision_event(world, evidence, approved):
    subject, _, approval = approved
    allowed = world.call(subject)
    world.mint.run("revoke", approval, "--reason", "it")
    blocked = world.call(subject)
    for outcome in (allowed, blocked):
        assert len(world.events(outcome.mark)) == 1
        time.sleep(0.5)
        assert len(world.events(outcome.mark, wait=0)) == 1


def test_per_call_approval_single_consumption_under_concurrent_resubmit(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    world.approve(subject, relation, extra=("--high-risk-tools", "echo"))
    mark = support.marker()
    arguments = {"text": "x", "marker": mark}
    blocked_first = world.call(subject, mark=support.marker(), arguments=arguments)
    assert blocked_first.code == code_of("CALL_APPROVAL_REQUIRED")
    world.call_approval(subject, arguments)
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(
            pool.map(
                lambda port: world.call(subject, port=port, mark=mark, arguments=arguments),
                support.LITELLM_PORTS,
            )
        )
    allowed = [r for r in results if r.allowed]
    blocked = [r for r in results if not r.allowed]
    assert len(allowed) == 1 and len(blocked) == 1
    # 소비 경쟁에서 진 호출은 의존 장애가 아니라 호출별 승인 요구로 막힌다.
    assert blocked[0].code == code_of("CALL_APPROVAL_REQUIRED")
    evidence.assert_calls(mark, 1)
    support.wait_until(
        lambda: len(world.events(mark, wait=0)) == 2, 30, what="both decision events"
    )
    events = world.events(mark)
    consumed = [e for e in events if e["payload"].get("consumed_call_approval_id")]
    assert len(consumed) == 1


OBSERVE_CASES = [
    ("no_history", "block", "allow"),
    ("revoked_history", "block", "block"),
    ("denied", "block", "block"),
]


@pytest.mark.parametrize(("case", "evaluated", "enforced"), OBSERVE_CASES)
def test_observe_mode_matrix(world, evidence, case, evaluated, enforced):
    evidence.positive_control()
    world.mint.run("settings", "mode", "observe")
    try:
        subject = world.subject()
        relation = world.prepare(subject)
        if case == "revoked_history":
            world.mint.run("revoke", world.approve(subject, relation), "--reason", "it")
        if case == "denied":
            world.mint.run(
                "deny",
                "--scope",
                "key",
                "--scope-id",
                subject.key_id,
                "--server",
                support.SERVER_ID["a"],
                "--reason",
                "it",
            )
        outcome = world.call(subject)
        events = world.events(outcome.mark)
        assert len(events) == 1
        assert decision(events[0])[:2] == (evaluated, enforced)
        evidence.assert_calls(outcome.mark, 1 if enforced == "allow" else 0)
    finally:
        world.mint.run("settings", "mode", "enforce")


def buffered_rows(mark: str) -> int:
    done = support.compose(
        "exec",
        "-T",
        "litellm1",
        "sh",
        "-c",
        f"cat /var/lib/mint/buffer/* 2>/dev/null | grep -c '{mark}'",
        check=False,
    )
    return int(done.stdout.strip() or 0)


@pytest.mark.parametrize("dependency", ["postgres", "opa"])
def test_dependency_down_blocks_and_buffers_one_event(world, evidence, toxics, dependency):
    evidence.positive_control()
    subject = world.subject()
    world.approve(subject, world.prepare(subject))
    if dependency == "postgres":
        toxics["postgres"].disable()
    else:
        support.compose("stop", "opa")
    try:
        outcome = world.call(subject)
        assert outcome.status == 403
        assert outcome.code == "MINT-DEPENDENCY-" + ("DB" if dependency == "postgres" else "OPA")
        evidence.assert_calls(outcome.mark, 0)
        if dependency == "postgres":
            assert buffered_rows(outcome.mark) == 1
    finally:
        toxics["postgres"].enable()
        support.compose("start", "opa", check=False)
    if dependency == "opa":
        support.wait_until(lambda: len(world.events(outcome.mark, wait=0)) == 1, 20, what="event")


def test_buffer_overflow_keeps_blocking_and_records_marker(world, evidence, toxics):
    evidence.positive_control()
    subject = world.subject()
    world.approve(subject, world.prepare(subject))
    done = support.compose(
        "up",
        "-d",
        "--wait",
        "--force-recreate",
        "litellm1",
        env={"MINT_E_BUFFER_MAX_BYTES": "4096"},
    )
    assert done.returncode == 0
    since = world.now()
    toxics["postgres"].disable()
    try:
        outcomes = [world.call(subject) for _ in range(14)]
        assert all(o.status == 403 for o in outcomes)
        for outcome in outcomes:
            evidence.assert_calls(outcome.mark, 0, settle=0)
    finally:
        toxics["postgres"].enable()
    try:
        # 데이터베이스가 돌아온 뒤의 첫 DB 접근이 버퍼 재적재를 시작하고 넘침 사건이 적재된다.
        support.wait_until(lambda: world.call(subject).allowed, 30, 1, what="recovery")
        support.wait_until(
            lambda: world.count_since(since, "buffer_overflow") >= 1, 60, what="buffer_overflow"
        )
    finally:
        support.compose("up", "-d", "--wait", "--force-recreate", "litellm1")


def test_ledger_write_failure_before_allow_blocks(world, evidence, toxics):
    evidence.positive_control()
    subject = world.subject()
    world.approve(subject, world.prepare(subject))
    toxics["postgres"].add("limit_data", stream="upstream", bytes=0)
    outcome = world.call(subject)
    assert outcome.status == 403, outcome.body
    assert outcome.code in (code_of("AUDIT_FAILURE"), "MINT-DEPENDENCY-DB"), outcome.body
    evidence.assert_calls(outcome.mark, 0)


def test_operator_separation_of_duties_rejected(world, approved):
    subject, relation, _ = approved
    done = world.mint.run(
        "approve",
        "--relation",
        relation,
        "--scope",
        "key",
        "--scope-id",
        subject.key_id,
        "--tools",
        "echo",
        "--valid-until",
        iso(timedelta(days=1)),
        "--basis",
        "self-approval",
        "--requested-by",
        world.admin_user,
        check=False,
    )
    assert done.returncode == 1, done.stdout


def test_approver_without_user_binding_is_rejected(world):
    done = world.mint.run("operator", "add", "it-unbound", "--role", "approver", check=False)
    assert done.returncode == 1


def percentiles(samples: list[float]) -> tuple[float, float, float]:
    samples = sorted(samples)
    return tuple(samples[max(0, int(len(samples) * q) - 1)] for q in (0.5, 0.95, 0.99))


def timed_calls(
    key: str, ports: tuple[int, ...], count: int, workers: int, strict: bool = True
) -> list[float]:
    def one(index: int):
        started = time.perf_counter()
        reply = support.rest_call(key, "a", "echo", {"text": "x"}, port=ports[index % len(ports)])
        if strict:
            assert reply.status_code == 200, reply.text
        return (time.perf_counter() - started) * 1000

    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        return list(pool.map(one, range(count)))


def measure(
    label: str, key: str, plain: int, mint_ports: tuple[int, ...], workers: int, count: int
):
    base = percentiles(timed_calls(key, (plain,), count, workers))
    mint = percentiles(timed_calls(key, mint_ports, count, workers))
    print(
        f"latency_ms {label} (p50, p95, p99) plain={tuple(round(v, 1) for v in base)} "
        f"mint={tuple(round(v, 1) for v in mint)}"
    )
    return [m - b for b, m in zip(base, mint, strict=True)]


def test_mint_overhead_percentiles(world, evidence, plain, approved):
    """같은 스택에서 플러그인 적재와 순정 이미지의 종단 지연 차이를 세 조건에서 잰다.

    판정 대상은 복제본 2·동시 8 조건이다(순정 이미지도 같은 동시 8을 같은 업스트림으로 보낸다).
    순차 호출과 복제본 1·동시 8 조건은 원 측정값만 출력한다.
    """
    subject, _, _ = approved
    key = subject.key
    # 다시 시작한 직후의 첫 동시 호출은 데이터베이스 연결이 모자라 막힐 수 있어 단계적으로 데운다.
    for workers in (1, 2, 4, 8):
        timed_calls(key, (plain,), 8, workers, strict=False)
        timed_calls(key, support.LITELLM_PORTS, 8, workers, strict=False)
    first = support.LITELLM_PORTS[:1]
    measure("sequential", key, plain, first, 1, 60)
    measure("one-replica-concurrent-8", key, plain, first, 8, 160)
    rounds = [
        measure("two-replicas-concurrent-8", key, plain, support.LITELLM_PORTS, 8, 200)
        for _ in range(3)
    ]
    overhead = [statistics.median(r[i] for r in rounds) for i in range(3)]
    print("overhead_ms (p50, p95, p99, median of 3 rounds)", tuple(round(v, 1) for v in overhead))
    limits = [
        float(os.environ.get(n, d))
        for n, d in (("MINT_E_P50_MS", "30"), ("MINT_E_P95_MS", "100"), ("MINT_E_P99_MS", "300"))
    ]
    assert all(o <= limit for o, limit in zip(overhead, limits, strict=True)), overhead


def test_check_passes_on_clean_stack(world):
    done = world.mint.run("check", check=False)
    report = json.loads(done.stdout)
    assert done.returncode == 0, [f for f in report["findings"] if f["level"] == "FAIL"]


def test_a_held_call_returns_the_tool_result_once_an_admin_approves(world, evidence):
    """승인이 필요한 호출은 승인을 기다리며 붙잡혀 있다가 승인되면 같은 호출로 결과를 받는다.

    같은 호출을 다시 보내도 승인 요청은 하나이고, 승인 소비는 한 번이다.
    """
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    world.approve(subject, relation, extra=("--high-risk-tools", "echo"))
    support.compose(
        "up", "-d", "--wait", "--force-recreate", "litellm1",
        env={"MINT_E_APPROVAL_HOLD_SECONDS": "60"},
    )
    try:
        mark = support.marker()
        arguments = {"text": "x", "marker": mark}
        result: dict = {}

        def held_call():
            started = time.monotonic()
            result["outcome"] = world.call(subject, mark=mark, arguments=arguments)
            result["seconds"] = time.monotonic() - started

        pending = (
            "select id from mint.call_approvals where principal_id = %s and status = 'pending'"
        )
        worker = threading.Thread(target=held_call)
        worker.start()
        support.wait_until(
            lambda: world.query(pending, (subject.user_id,)), 30, what="the pending request"
        )
        worker.join(2)
        assert worker.is_alive(), "호출이 승인 결정을 기다리지 않고 반환됐다"
        (request,) = world.query(pending, (subject.user_id,))
        world.mint.run("call-approval", "approve", str(request["id"]))
        worker.join(30)
        assert not worker.is_alive()
        outcome = result["outcome"]
        assert outcome.allowed, outcome.body
        evidence.assert_calls(mark, 1)
        events = world.events(mark, wait=10)
        held = [e for e in events if e["payload"].get("approval_hold") == "approved"]
        assert len(held) == 1 and held[0]["payload"]["consumed_call_approval_id"]
        count = world.query(
            "select count(*) as n from mint.call_approvals where principal_id = %s",
            (subject.user_id,),
        )[0]["n"]
        assert count == 1
    finally:
        support.compose("up", "-d", "--wait", "--force-recreate", "litellm1")
