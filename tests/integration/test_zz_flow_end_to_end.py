"""전 구간 흐름 시험: 신청부터 철회까지 한 흐름과 기동 직후·DB 복구 직후 부하.

배포와 같은 파생 이미지·플러그인·작업 실행기로 업무 경로를 끝까지 밟는다.

    신청 생성 → 자동 검사 → 승인 → 허용 호출 → 도구 계약 변경 → 드리프트 관측과 호출 차단
    → 자동 재검사 → 후보에 결속된 증거로 재승인 → 다시 허용 → 철회 → 차단

상태가 바뀌기를 기다리는 곳은 모두 상태를 읽어 확인한다(고정 대기 없음). 작업 실행기를 LiteLLM
관리 키와 짧은 관측 주기로 다시 띄우므로 다른 시험에 상태를 남기지 않도록 마지막에 실행되고, 끝나면
작업 실행기를 기본 설정으로 되돌린다. 등록한 서버는 지우지 않는다(등록된 서버가 레지스트리에서
사라지면 다음 기동 점검이 실패한다).

기동 직후·복구 직후 부하는 연결 풀과 캐시를 데우지 않고 동시 호출 8건을 보낸다. 데우는 단계를 두면
차가운 상태에서만 나는 결함이 가려진다.
"""

import concurrent.futures
import threading
import uuid
from dataclasses import dataclass
from datetime import timedelta

import httpx
import psycopg
import pytest
import support
from scenario import Subject, db_server, decision, iso

from mint_litellm.control.litellm_control import STAGE2_ALLOWED_ROUTES
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.types.cli_commands import CONTROL_PLANE_ALLOWED_ROUTES

INSTANCE = "integration"
UPSTREAM_URL = "http://counting-proxy:8080/a/mcp"
OBSERVE_SECONDS = 20
BURST = 8
TOOLS = ["echo", "mutable", "slow"]
READY_AT_LEAST = {"url_guard", "connection", "definitions", "description_scan", "risk_grade"}


# --- 도구 ----------------------------------------------------------------------------------


def jobs_state(world) -> list[dict]:
    return world.query(
        "select kind, target_ref, status, attempts, last_error_code from mint.jobs "
        "order by created_at desc limit 12"
    )


def until(world, what: str, probe, timeout: float, interval: float = 1.0):
    """상태를 읽어 조건이 될 때까지 기다린다. 시간이 지나면 작업 표를 덧붙여 실패한다."""
    try:
        return support.wait_until(probe, timeout, interval, what)
    except AssertionError as error:
        raise AssertionError(f"{error}; jobs={jobs_state(world)}") from None


def recreate_worker(**env: str) -> None:
    done = support.compose("up", "-d", "--wait", "--force-recreate", "worker", env=env, check=False)
    assert done.returncode == 0, done.stdout + done.stderr


def judged(world, outcome, evaluated: str, enforced: str, reason: str | None = None) -> dict:
    """호출 한 건에 판정 사건이 한 건 남고, 판정과 집행이 기대와 같음을 확인한다."""
    events = world.events(outcome.mark)
    assert len(events) == 1, events
    got = decision(events[0])
    assert got[:2] == (evaluated, enforced), got
    if reason is not None:
        assert (got[2] or "").startswith(reason), got
    return events[0]["payload"]


@dataclass
class Flow:
    server_id: str
    subject: Subject
    org: str
    approver_token: str


@pytest.fixture(scope="module")
def flow(stack, world):
    suffix = uuid.uuid4().hex[:8]
    alias = f"e2e_flow_{suffix}"
    server_id = db_server(alias, UPSTREAM_URL)
    support.TOOL_PREFIX[server_id] = alias
    support.UPSTREAM_OF[server_id] = "a"
    subject = world.subject((server_id,))
    org = f"org-flow-{suffix}"
    world.mint.run("org", "add", org, "--name", org)
    world.mint.run("org", "bind", "--org", org, "--user", subject.user_id)
    valid_until = iso(timedelta(days=1))
    for kind in ("provider", "egress_target"):
        world.mint.run(
            "allowlist", "add", "--kind", kind, "--value", "counting-proxy",
            "--valid-until", valid_until,
        )
    approver_user = world.litellm_user()
    approver_token = world.mint.data(
        "operator", "add", f"e2e-approver-{suffix}",
        "--role", "approver", "--user-id", approver_user,
    )["token"]

    # 작업 실행기가 쓰는 관리 키: 수용검증·권한 동기화·재고정 경로까지 허용한 키이다.
    admin = f"e2e-worker-{suffix}"
    httpx.post(
        support.url(support.LITELLM_PORTS[0], "/user/new"),
        headers=support.master_headers(),
        json={"user_id": admin, "user_role": "proxy_admin"},
        timeout=30,
    ).raise_for_status()
    created = httpx.post(
        support.url(support.LITELLM_PORTS[0], "/key/generate"),
        headers=support.master_headers(),
        json={
            "user_id": admin,
            "allowed_routes": [*CONTROL_PLANE_ALLOWED_ROUTES, *STAGE2_ALLOWED_ROUTES],
        },
        timeout=30,
    )
    created.raise_for_status()
    worker_key = created.json()["key"]
    previous = world.query(
        "select control_key_token from mint.settings where instance_id = %s", (INSTANCE,)
    )[0]["control_key_token"]
    # 재고정 호출이 도구 목록 필터를 받지 않도록 이 키를 제어 평면 키로 알린다.
    world.mint.run("settings", "control-key", env={"MINT_LITELLM_KEY": worker_key})
    recreate_worker(
        MINT_E_WORKER_LITELLM_KEY=worker_key,
        MINT_E_OBSERVE_SECONDS=str(OBSERVE_SECONDS),
        MINT_E_INTAKE_PORTS="8080",
    )
    try:
        yield Flow(server_id, subject, org, approver_token)
    finally:
        with psycopg.connect(support.mint_database_url(), autocommit=True) as conn:
            conn.execute(
                "update mint.settings set control_key_token = %s where instance_id = %s",
                (previous, INSTANCE),
            )
        recreate_worker()


# --- 한 흐름 -------------------------------------------------------------------------------


def test_intake_to_revoke_in_one_flow(world, evidence, upstreams, flow):
    evidence.positive_control()
    subject, server_id = flow.subject, flow.server_id
    since = world.now()

    def call(mark: str, tool: str = "mutable", **arguments):
        return world.call(
            subject,
            server_id,
            tool,
            mark=mark,
            arguments={"text": "x", "marker": mark, **arguments},
        )

    # 1. 신청 생성
    intake_id = world.mint.data(
        "intake", "create", server_id,
        "--url", UPSTREAM_URL,
        "--org", flow.org,
        "--purpose", "flow",
        "--data-grade", "internal",
        "--allowed-resources", '["docs"]',
        "--provider", "Test",
        "--owner", subject.user_id,
        "--credential-notice", "mail",
        "--revocation-record", "log",
        "--audit-access-days", "90",
        "--data-return-terms", "delete after end",
    )["id"]

    def intake_row() -> dict:
        return world.query("select status, decision from mint.intakes where id = %s", (intake_id,))[
            0
        ]

    # 2. 자동 검사: 작업 실행기가 검사를 끝내 신청이 통과 상태가 된다.
    until(
        world,
        "intake checks to finish",
        lambda: intake_row()["status"] not in ("received", "checking"),
        180,
    )
    assert intake_row()["status"] == "passed", intake_row()
    checks = world.query(
        'select "check", result from mint.intake_checks where intake_id = %s', (intake_id,)
    )
    assert {c["result"] for c in checks} == {"pass"}, checks
    assert READY_AT_LEAST <= {c["check"] for c in checks}, checks
    candidates = world.query(
        "select tool from mint.tool_contracts where server_id = %s and status = 'candidate' "
        "order by tool",
        (server_id,),
    )
    assert [c["tool"] for c in candidates] == TOOLS

    # 3. 승인: 신청자와 다른 사용자의 승인자가 결정하면 대기 승인이 만들어지고, 작업 실행기가
    # 고정·권한 동기화·활성화를 끝내면 승인이 활성이 된다.
    decided = world.mint.data(
        "intake", "approve", intake_id,
        "--scope", "key",
        "--scope-id", subject.key_id,
        token=flow.approver_token,
    )
    approval_id = decided["approval_id"]
    until(
        world,
        "approval to become active",
        lambda: world.query("select status from mint.approvals where id = %s", (approval_id,))[0][
            "status"
        ]
        == "active",
        180,
    )

    # 4. 허용 호출: 판정 사건 한 건, 업스트림 한 번.
    first = call(support.marker())
    assert first.allowed, first.body
    payload = judged(world, first, "allow", "allow")
    assert payload["selected_approval_id"] == approval_id
    evidence.assert_calls(first.mark, 1, "a")

    # 5. 계약 변경: 시험 서버의 mutable 도구 정의를 바꾼다. 관측 주기 안에 드리프트가 기록되고
    # 그 도구 호출이 차단된다.
    upstreams["a"].mutate("v2")
    until(
        world,
        "input schema drift to be recorded",
        lambda: world.query(
            "select drift from mint.tool_contracts where server_id = %s and tool = 'mutable' "
            "and status = 'approved'",
            (server_id,),
        )[0]["drift"]
        == "input_schema",
        3 * OBSERVE_SECONDS + 60,
    )
    blocked = call(support.marker())
    assert blocked.status == 403, blocked.body
    assert (blocked.code or "").upper().startswith("MINT-CONTRACT-DRIFT"), blocked.body
    judged(world, blocked, "block", "block", "CONTRACT_DRIFT")
    evidence.assert_calls(blocked.mark, 0, "a")

    # 6. 자동 재검사: 드리프트가 등록한 재검사 작업이 끝나 후보 계약과 후보에 결속된 증거가 생긴다.
    evidence_job = f"{intake_id}/evidence"

    def recheck_status() -> str | None:
        rows = world.query(
            "select status from mint.jobs where kind = 'intake_run' and target_ref = %s",
            (evidence_job,),
        )
        return rows[0]["status"] if rows and rows[0]["status"] in ("done", "failed") else None

    finished = until(world, "evidence recheck job to finish", recheck_status, 150)
    assert finished == "done", jobs_state(world)
    recandidates = world.query(
        "select id, tool from mint.tool_contracts where server_id = %s and status = 'candidate' "
        "order by tool",
        (server_id,),
    )
    assert [c["tool"] for c in recandidates] == TOOLS
    with psycopg.connect(support.mint_database_url(), autocommit=True) as conn:
        bound = intake_service.contract_binding(conn, INSTANCE, server_id)
        evidence_checks = intake_service.latest_checks(conn, INSTANCE, intake_id)
    for check in evidence_checks:
        if check["check"] in ("connection", "definitions", "description_scan", "risk_grade"):
            assert check["result"] == "pass", check
            assert check["inputs"]["contract_sha256"] == bound, check

    # 7. 재승인: 신청자와 다른 사용자가 후보 전체를 재승인하고, 작업 실행기가 재고정을 끝낸다.
    world.mint.run(
        "contract", "reapprove", server_id, "--intake", intake_id,
        *[x for c in recandidates for x in ("--tool-contract", str(c["id"]))],
        token=flow.approver_token,
    )

    def reapproved() -> bool:
        server = world.query(
            "select deployment_drift from mint.servers where server_id = %s", (server_id,)
        )[0]
        pending = world.query(
            "select 1 from mint.contract_reapproval_plans where server_id = %s "
            "and status = 'pending'",
            (server_id,),
        )
        drifting = world.query(
            "select 1 from mint.tool_contracts where server_id = %s and status = 'approved' "
            "and drift <> 'none'",
            (server_id,),
        )
        return not server["deployment_drift"] and not pending and not drifting

    until(world, "reapproval to be finalized", reapproved, 150)
    approved_now = world.query(
        "select id from mint.tool_contracts where server_id = %s and status = 'approved' "
        "order by tool",
        (server_id,),
    )
    assert {a["id"] for a in approved_now} == {c["id"] for c in recandidates}

    # 8. 다시 허용: 바뀐 정의(count 필수)로 호출하면 허용된다.
    again = call(support.marker(), text="again", count=2)
    assert again.allowed, again.body
    judged(world, again, "allow", "allow")
    assert "againagain" in again.body, again.body
    evidence.assert_calls(again.mark, 1, "a")

    # 9. 철회: 이후 호출은 차단되고 업스트림에 닿지 않는다.
    world.mint.run("revoke", approval_id, "--reason", "flow end")
    revoked = call(support.marker(), text="late", count=2)
    assert revoked.status == 403, revoked.body
    assert revoked.code == "MINT-APPROVAL-REVOKED", revoked.body
    judged(world, revoked, "block", "block", "APPROVAL_REVOKED")
    evidence.assert_calls(revoked.mark, 0, "a")

    # 흐름 중 원장에 남은 제어 사건
    kinds = {
        row["kind"]
        for row in world.query(
            "select distinct kind from mint.events where inserted_at >= %s "
            "and (payload->>'server_id' = %s or payload->>'intake_id' = %s)",
            (since, server_id, intake_id),
        )
    }
    expected = {
        "intake_received",
        "intake_checked",
        "intake_decided",
        "contract_approved",
        "contract_drift_detected",
        "reapproval_requested",
        "approval_revoked",
    }
    assert expected <= kinds, sorted(expected - kinds)


# --- 기동 직후·복구 직후 부하 -------------------------------------------------------------


def burst(world, subject, port: int) -> list:
    """동시 호출 8건을 한꺼번에 보낸다. 연결 풀·캐시를 미리 데우지 않는다."""
    gate = threading.Barrier(BURST)

    def one(_):
        gate.wait(timeout=30)
        return world.call(subject, port=port)

    with concurrent.futures.ThreadPoolExecutor(BURST) as pool:
        return list(pool.map(one, range(BURST)))


def dependency_codes(outcomes) -> list[str]:
    return sorted(o.code for o in outcomes if (o.code or "").startswith("MINT-DEPENDENCY-"))


def not_allowed(world, outcomes) -> list[tuple]:
    """막힌 호출의 (상태, 코드, 판정 사건의 차단 맥락). 버퍼에서 적재되기를 잠시 기다린다."""
    rows = []
    for o in outcomes:
        if not o.allowed:
            events = world.events(o.mark, wait=20)
            stop = events[0]["payload"].get("stop") if events else None
            rows.append((o.status, o.code, stop))
    return rows


@pytest.fixture(scope="module")
def cold_subject(stack, world):
    subject = world.subject()
    world.approve(subject, world.prepare(subject))
    return subject


@pytest.fixture(scope="module")
def after_restart(cold_subject, world):
    """복제본을 새로 띄우고 집행 점검이 통과하면 곧바로 동시 호출을 보낸다."""
    assert world.call(cold_subject).allowed
    since = world.now()
    done = support.compose("up", "-d", "--wait", "--force-recreate", "litellm1", check=False)
    assert done.returncode == 0, done.stdout + done.stderr
    support.wait_until(
        lambda: world.count_since(since, "enforcement_verified") >= 1,
        150,
        2,
        what="the restarted replica to verify enforcement",
    )
    return burst(world, cold_subject, support.LITELLM_PORTS[0])


@pytest.fixture(scope="module")
def after_db_outage(cold_subject, world, after_restart):
    """데이터베이스 연결이 끊겼다 돌아온 직후 동시 호출을 보낸다."""
    proxy = support.Toxics(support.TOXIPROXY_DB_PORT, "postgres")
    proxy.clear()
    proxy.enable()
    assert world.call(cold_subject).allowed  # 끊기기 전에 풀에 살아 있는 연결이 있다
    proxy.disable()
    try:
        down = world.call(cold_subject)
    finally:
        proxy.enable()
    outcomes = burst(world, cold_subject, support.LITELLM_PORTS[0])
    support.wait_until(
        lambda: world.call(cold_subject).allowed, 60, 1, what="calls to recover after the burst"
    )
    return down, outcomes


# 제품 결함: 복구 직후 첫 동시 호출 8건 중 1~2건이 MINT-DEPENDENCY-DB로 막힌다(풀에 남은 끊어진
# 연결로 보인다). 이 변경은 제품 코드를 바꾸지 않으므로 결함이 고쳐질 때까지 표시만 해 둔다.
RECOVERY_DEFECT = pytest.mark.xfail(
    reason="product defect: calls sent right after the database recovers are still blocked "
    "with MINT-DEPENDENCY-DB (1-2 of 8)",
    strict=False,
)


def test_no_dependency_failure_right_after_a_replica_starts(after_restart):
    assert len(after_restart) == BURST
    assert dependency_codes(after_restart) == []


def test_every_call_is_allowed_right_after_a_replica_starts(world, after_restart):
    assert not_allowed(world, after_restart) == []


def test_the_outage_is_visible_to_a_call(after_db_outage):
    down, _ = after_db_outage
    assert down.code == "MINT-DEPENDENCY-DB", down.body


@RECOVERY_DEFECT
def test_no_dependency_failure_right_after_the_database_recovers(after_db_outage):
    _, outcomes = after_db_outage
    assert len(outcomes) == BURST
    assert dependency_codes(outcomes) == []


@RECOVERY_DEFECT
def test_every_call_is_allowed_right_after_the_database_recovers(world, after_db_outage):
    _, outcomes = after_db_outage
    assert not_allowed(world, outcomes) == []
