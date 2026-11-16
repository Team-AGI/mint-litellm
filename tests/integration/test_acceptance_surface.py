"""1단계 인수시험: LiteLLM 접점, 서버 식별, 설정 점검, 조직 경계, 증거 위치, 정책 전환.

각 시험은 사건 행과 업스트림 호출 수(프록시 기록 + 시험 서버 진입 계수)를 함께 확인한다.
"""

import json
import re
import threading
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import support
from scenario import (
    db_server,
    decision,
    insert_is_sleeping,
    iso,
    litellm_config,
    slow_decision_insert,
)
from support import mcp_session, run
from test_acceptance_core import assert_allowed, assert_blocked, buffered_rows, code_of

CONFIG_DIR = Path(__file__).resolve().parent / "config"
BASE_CONFIG = CONFIG_DIR / "litellm.mint.yaml"
LITELLM = support.url(support.LITELLM_PORTS[0])
DB_SERVER_URL = "http://counting-proxy:8080/a/mcp"


@pytest.fixture
def approved(world, evidence):
    evidence.positive_control()
    subject = world.subject(("a", "b"))
    relation = world.prepare(subject)
    world.approve(subject, relation)
    world.approve(subject, world.relate(subject, "b"))
    return subject, relation


@pytest.fixture
def variant():
    """기본 설정을 고친 설정 파일을 만들고 시험이 끝나면 지운다."""
    made: list[Path] = []

    def make(name: str, edit) -> str:
        path = CONFIG_DIR / f"{name}.generated.yaml"
        path.write_text(
            edit(BASE_CONFIG.read_text(encoding="utf-8")), encoding="utf-8", newline="\n"
        )
        made.append(path)
        return f"./config/{path.name}"

    yield make
    for path in made:
        path.unlink(missing_ok=True)


def in_control(path: str) -> str:
    return "/work/config/" + Path(path).name


def test_tools_list_records_one_event_per_tool_and_one_upstream_list_per_server(
    world, approved, proxy_log
):
    subject, _ = approved
    since = world.now()
    proxy_log.mark()

    async def listing():
        async with mcp_session(subject.key) as session:
            return (await session.list_tools()).tools

    tools = run(listing())
    assert len(tools) == 6  # 승인된 도구 3개 × 서버 2
    # 판정은 상류 도구마다 하나(승인 밖 leak 포함, 서버당 4개). LiteLLM은 그 뒤에 거른다.
    support.wait_until(
        lambda: world.count_since(since, "discovery_evaluated") == 8, what="discovery"
    )
    for server in ("a", "b"):
        lists = [r for r in proxy_log.rows(rpc="tools/list") if r["path"].startswith(f"/{server}/")]
        assert len(lists) == 1


def test_rest_call_records_exactly_one_decision(world, evidence, approved):
    subject, _ = approved
    assert_allowed(world, evidence, world.call(subject))


def test_duplicate_call_id_yields_two_events_with_distinct_invocations(world, evidence, approved):
    subject, _ = approved
    mark = support.marker()
    first = world.call(subject, mark=mark)
    second = world.call(subject, mark=mark)
    assert first.allowed and second.allowed
    events = world.events(mark)
    assert len(events) == 2
    assert len({e["payload"]["invocation_id"] for e in events}) == 2


def test_prompts_and_resources_leave_no_event_and_are_not_blocked(world, evidence):
    subject = world.subject(("a",))
    world.approve(subject, world.prepare(subject))
    since = world.now()

    async def touch():
        async with mcp_session(subject.key) as session:
            prompts = (await session.list_prompts()).prompts
            await session.get_prompt(
                next(p.name for p in prompts if p.name.endswith("greeting")), {}
            )
            resources = (await session.list_resources()).resources
            await session.read_resource(resources[0].uri)

    run(touch())
    time.sleep(1)
    for kind in ("decision_evaluated", "discovery_evaluated"):
        assert world.count_since(since, kind) == 0


def test_master_key_call_is_forbidden(world, evidence):
    evidence.positive_control()
    mark = support.marker()
    reply = support.rest_call(
        support.MASTER_KEY, "a", "echo", {"text": "x", "marker": mark}, call_id=mark
    )
    assert reply.status_code == 403
    assert code_of("MASTER_KEY_FORBIDDEN") in reply.text
    evidence.assert_calls(mark, 0)


@pytest.mark.parametrize(
    "metadata",
    [
        {"opted_out_global_guardrails": ["mint"]},
        {"disable_global_guardrails": True},
    ],
    ids=["opted-out-key", "global-guardrails-disabled"],
)
def test_guardrail_optout_key_is_still_judged(world, evidence, metadata):
    evidence.positive_control()
    subject = world.subject(("a",), metadata=metadata)
    relation = world.prepare(subject)
    assert_blocked(world, evidence, world.call(subject), "APPROVAL_ABSENT")
    world.approve(subject, relation)
    assert_allowed(world, evidence, world.call(subject))


def test_parallel_block_becomes_rest_403_and_mcp_error_result(world, evidence):
    evidence.positive_control()
    subject = world.subject(("a",))
    world.prepare(subject)
    since = world.now()
    rest = world.call(subject)
    assert rest.status == 403 and rest.code == code_of("APPROVAL_ABSENT")
    mark = support.marker()

    async def through_mcp():
        async with mcp_session(subject.key) as session:
            return await session.call_tool("mcp_a-echo", {"text": "x", "marker": mark})

    try:
        result = run(through_mcp())
    except Exception as error:
        assert code_of("APPROVAL_ABSENT") in str(error)
    else:
        assert result.is_error
        assert code_of("APPROVAL_ABSENT") in json.dumps(result.model_dump(), default=str)
    evidence.assert_calls(mark, 0)
    assert len(world.decisions_since(subject, since)) == 2


def test_tools_list_hides_tools_of_unapproved_subject(world, evidence):
    subject = world.subject(("a", "b"))
    relation = world.prepare(subject)
    world.approve(subject, relation)

    async def names():
        async with mcp_session(subject.key) as session:
            return {t.name for t in (await session.list_tools()).tools}

    visible = run(names())
    assert visible and all(n.startswith("mcp_a-") for n in visible)


def run_check(world, *extra: str) -> tuple[int, dict]:
    done = world.mint.run("check", *extra, check=False)
    return done.returncode, json.loads(done.stdout)


def finding(report: dict, item: str) -> list[dict]:
    return [f for f in report["findings"] if f["item"] == item]


def test_check_observes_spend_log_arguments(world):
    _, report = run_check(world)
    assert report["observations"]["spend_log_arguments_stored"] == "true"


def test_check_fails_when_prompts_are_stored_in_spend_logs(world, variant):
    path = variant(
        "spend",
        lambda text: text.replace(
            "store_prompts_in_spend_logs: false", "store_prompts_in_spend_logs: true"
        ),
    )
    code, report = run_check(world, "--config", in_control(path))
    assert code == 1
    assert any(
        "store_prompts_in_spend_logs" in f["item"]
        for f in report["findings"]
        if f["level"] == "FAIL"
    )


def test_check_warns_once_without_personal_key_role_restriction(world, variant):
    path = variant(
        "norole",
        lambda text: re.sub(r"(?ms)^  key_generation_settings:.*?(?=^\S|\Z)", "", text),
    )
    _, report = run_check(world, "--config", in_control(path))
    warnings = [
        f for f in report["findings"] if f["level"] == "WARN" and "allowed_user_roles" in f["item"]
    ]
    assert len(warnings) == 1


def test_check_counts_optout_subjects_and_unbound_keys(world):
    before = run_check(world)[1]["observations"]
    support.new_key(("a",), metadata={"opted_out_global_guardrails": ["other"]})
    support.new_key(("a",))
    after = run_check(world)[1]["observations"]
    assert after["guardrail_optout_subjects"] == before["guardrail_optout_subjects"] + 1
    assert after["unbound_keys"] >= before["unbound_keys"] + 2


def test_unbound_key_is_blocked_as_anonymous(world, evidence):
    evidence.positive_control()
    key = support.new_key(("a",))
    mark = support.marker()
    reply = support.rest_call(key, "a", "echo", {"text": "x", "marker": mark}, call_id=mark)
    assert reply.status_code == 403 and code_of("ANONYMOUS") in reply.text
    evidence.assert_calls(mark, 0)
    assert len(world.events(mark)) == 1


def test_control_plane_key_reaches_only_its_routes(world):
    headers = {"Authorization": f"Bearer {world.control_key}"}
    assert httpx.get(f"{LITELLM}/v1/mcp/server", headers=headers).status_code == 200
    assert httpx.post(f"{LITELLM}/key/generate", headers=headers, json={}).status_code == 403
    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    assert httpx.post(f"{LITELLM}/mcp", headers=headers, json=initialize).status_code == 403
    world.mint.run("check", check=False)
    world.mint.run("server", "register", support.SERVER_ID["a"])
    world.mint.run("operator", "add", "it-viewer", "--role", "viewer")


def test_team_without_binding_and_no_default_org_is_org_boundary(world, evidence):
    evidence.positive_control()
    subject = world.subject(team=True)
    world.mint.run("settings", "default-org", "--clear")
    try:
        assert_blocked(world, evidence, world.call(subject), "ORG_BOUNDARY")
    finally:
        world.mint.run("settings", "default-org", "--org", "default")


def test_approval_of_another_organization_is_org_boundary(world, evidence):
    evidence.positive_control()
    subject = world.subject(team=True)
    world.approve(subject, world.prepare(subject))
    assert world.call(subject).allowed
    world.mint.run("org", "unbind", "--team", subject.team_id)
    world.mint.run("org", "add", "org-elsewhere", "--name", "elsewhere", check=False)
    world.mint.run("org", "bind", "--org", "org-elsewhere", "--team", subject.team_id)
    assert_blocked(world, evidence, world.call(subject), "ORG_BOUNDARY")


def test_binding_one_team_to_two_organizations_is_rejected(world):
    subject = world.subject(team=True)
    world.prepare(subject)
    world.mint.run("org", "add", "org-second", "--name", "second", check=False)
    done = world.mint.run(
        "org", "bind", "--org", "org-second", "--team", subject.team_id, check=False
    )
    assert done.returncode == 1


def permit(*server_ids: str) -> str:
    key = support.new_key(())
    httpx.post(
        f"{LITELLM}/key/update",
        headers=support.master_headers(),
        json={"key": key, "object_permission": {"mcp_servers": list(server_ids)}},
        timeout=30,
    ).raise_for_status()
    return key


def test_same_alias_in_db_server_is_identity_ambiguous(world, evidence):
    evidence.positive_control()
    server_id = db_server("mcp_a", "http://counting-proxy:8080/a/mcp")
    try:
        key = permit(server_id, support.SERVER_ID["a"])
        mark = support.marker()
        reply = support.rest_call(key, "a", "echo", {"text": "x", "marker": mark}, call_id=mark)
        assert reply.status_code == 403
        assert code_of("SERVER_IDENTITY_AMBIGUOUS") in reply.text
        evidence.assert_calls(mark, 0)
    finally:
        httpx.delete(
            f"{LITELLM}/v1/mcp/server/{server_id}", headers=support.master_headers(), timeout=30
        )


def test_changed_db_server_url_is_identity_mismatch(world, evidence):
    evidence.positive_control()
    base = f"{LITELLM}/v1/mcp/server"
    server_id = db_server("mcp_db", "http://counting-proxy:8080/a/mcp")
    try:
        subject = world.subject((server_id,))
        relation = world.prepare(subject, server_id, url="http://counting-proxy:8080/a/mcp")
        world.approve(subject, relation, tools="echo")

        def call(mark: str):
            return httpx.post(
                f"{LITELLM}/mcp-rest/tools/call",
                headers={"Authorization": f"Bearer {subject.key}", "x-litellm-call-id": mark},
                timeout=60,
                json={
                    "server_id": server_id,
                    "name": "mcp_db-echo",
                    "arguments": {"text": "x", "marker": mark},
                },
            )

        async def listing():
            async with mcp_session(subject.key) as session:
                return {t.name for t in (await session.list_tools()).tools}

        assert "mcp_db-echo" in run(listing())
        first = support.marker()
        assert call(first).status_code == 200
        evidence.assert_calls(first, 1, "a")
        httpx.put(
            base,
            headers=support.master_headers(),
            timeout=30,
            json={"server_id": server_id, "url": "http://counting-proxy:8080/b/mcp"},
        ).raise_for_status()
        mark = support.marker()
        reply = call(mark)
        assert reply.status_code == 403, reply.text
        assert code_of("SERVER_IDENTITY_MISMATCH") in reply.text
        evidence.assert_calls(mark, 0, "a")
        evidence.assert_calls(mark, 0, "b")
    finally:
        # 서버는 지우지 않는다(등록된 서버가 레지스트리에서 사라지면 다음 기동 점검이 실패한다).
        # 바뀐 URL로 다시 등록해 계약 값을 맞춰 둔다.
        world.mint.run("server", "register", server_id, "--url", "http://counting-proxy:8080/b/mcp")


def test_alias_form_permission_is_rejected_by_approve(world):
    subject = world.subject(("a",))
    relation = world.prepare(subject)
    key = support.new_key(())
    httpx.post(
        f"{LITELLM}/key/update",
        headers=support.master_headers(),
        json={"key": key, "object_permission": {"mcp_servers": ["mcp_a"]}},
        timeout=30,
    ).raise_for_status()
    key_id = __import__("hashlib").sha256(key.encode()).hexdigest()
    done = world.mint.run(
        "approve",
        "--relation",
        relation,
        "--scope",
        "key",
        "--scope-id",
        key_id,
        "--tools",
        "echo",
        "--valid-until",
        iso(timedelta(days=1)),
        "--basis",
        "alias-form",
        "--requested-by",
        subject.user_id,
        check=False,
    )
    assert done.returncode == 1
    httpx.post(
        f"{LITELLM}/key/delete",
        headers=support.master_headers(),
        json={"keys": [key]},
        timeout=30,
    )


def test_config_server_url_change_after_start_blocks_calls_and_records_mismatch(
    world, evidence, variant
):
    evidence.positive_control()
    subject = world.subject(("d",))
    world.approve(subject, world.prepare(subject, "d"))
    assert_allowed(world, evidence, world.call(subject, "d"), "d")
    # 서버 c도 승인 상태로 두고 한 번의 기동 점검에서 서버 둘의 URL이 어긋나게 한다.
    other = world.subject(("c",))
    world.approve(other, world.prepare(other, "c"))

    def change(text: str) -> str:
        for name in ("d", "c"):
            text = text.replace(
                f"http://counting-proxy:8080/{name}/mcp", "http://counting-proxy:8080/a/mcp"
            )
        return text

    path = variant("urlchange", change)
    since = world.now()
    with litellm_config(path) as started:
        assert started.returncode == 0, started.stderr
        outcome = world.call(subject, "d")
        assert outcome.status == 403
        assert outcome.code == code_of("SERVER_IDENTITY_MISMATCH"), outcome.body
        evidence.assert_calls(outcome.mark, 0, "a")
        support.wait_until(
            lambda: len(mismatch_servers(world, since)) >= 2, 30, what="mismatch events"
        )
        assert mismatch_servers(world, since) == {
            support.SERVER_ID["c"],
            support.SERVER_ID["d"],
        }
        events = world.query(
            "select payload from mint.events where kind = 'server_identity_mismatch_observed' "
            "and inserted_at >= %s",
            (since,),
        )
        assert all("url_sha256" in e["payload"]["fields"] for e in events)


def mismatch_servers(world, since) -> set[str]:
    rows = world.query(
        "select distinct payload->>'server_id' as server from mint.events "
        "where kind = 'server_identity_mismatch_observed' and inserted_at >= %s",
        (since,),
    )
    return {row["server"] for row in rows}


def buffer_rows_in(service: str, mark: str) -> int:
    done = support.compose(
        "exec",
        "-T",
        service,
        "sh",
        "-c",
        f"cat /var/lib/mint/buffer/* 2>/dev/null | grep -c '{mark}'",
        check=False,
    )
    return int(done.stdout.strip() or 0)


def test_evidence_normal_path_has_db_row_and_no_buffer_row(world, evidence, approved):
    subject, _ = approved
    outcome = world.call(subject)
    assert len(world.events(outcome.mark)) == 1
    assert buffered_rows(outcome.mark) == 0


def test_evidence_database_down_leaves_one_buffer_row(world, evidence, approved, toxics):
    subject, _ = approved
    toxics["postgres"].disable()
    try:
        outcome = world.call(subject)
        assert outcome.status == 403
        assert buffered_rows(outcome.mark) == 1
        assert world.events(outcome.mark, wait=0) == []
    finally:
        toxics["postgres"].enable()


def test_evidence_commit_result_unknown_keeps_first_attempt_and_records_block_as_next(
    world, evidence, approved, toxics
):
    """커밋은 끝났지만 결과를 받지 못한 호출: 호출은 막히고 최종 집행은 다음 시도의 차단이다."""
    subject, _ = approved
    assert world.call(subject).allowed
    mark = "slow-" + support.marker()
    result: dict = {}
    with slow_decision_insert("slow-", 6):
        worker = threading.Thread(
            target=lambda: result.update(outcome=world.call(subject, mark=mark))
        )
        worker.start()
        support.wait_until(insert_is_sleeping, 15, 0.1, what="sleeping insert")
        # 삽입이 끝나 커밋되는 동안 응답과 취소 요청을 모두 막아 호출 쪽이 결과를 알 수 없게 한다.
        toxics["postgres"].add("timeout", stream="downstream", timeout=0)
        toxics["postgres"].add("timeout", stream="upstream", timeout=0)
        time.sleep(8)
        toxics["postgres"].clear()
        worker.join(90)
    assert not worker.is_alive()
    outcome = result["outcome"]
    assert outcome.status == 403, outcome.body
    evidence.assert_calls(mark, 0)
    # 데이터베이스를 다시 쓰는 첫 호출이 버퍼의 다음 시도 사건을 적재한다.
    support.wait_until(lambda: world.call(subject).allowed, 30, 1, what="recovery")
    support.wait_until(lambda: len(world.events(mark, wait=0)) >= 2, 60, what="both attempts")
    events = world.events(mark)
    attempts = sorted((e["attempt_id"], decision(e)[1]) for e in events)
    assert attempts[0] == (1, "allow")
    assert attempts[-1][0] >= 2 and attempts[-1][1] == "block"
    assert len({e["payload"]["invocation_id"] for e in events}) == 1


def test_silent_database_does_not_hold_the_call_beyond_the_budget(
    world, evidence, approved, toxics
):
    subject, _ = approved
    result: dict = {}

    def go():
        started = time.monotonic()
        result["outcome"] = world.call(subject)
        result["seconds"] = time.monotonic() - started

    toxics["postgres"].add("timeout", stream="downstream", timeout=0)
    worker = threading.Thread(target=go)
    worker.start()
    worker.join(10)
    held = worker.is_alive()
    toxics["postgres"].clear()
    worker.join(60)
    assert not held, "호출이 판정 예산(2초)을 크게 넘겨 10초가 지나도 반환되지 않았다"
    assert result["outcome"].status == 403
    assert result["outcome"].code == "MINT-DEPENDENCY-DB", result["outcome"].body


def test_evidence_database_down_and_buffer_read_only_goes_to_stderr(
    world, evidence, approved, toxics
):
    subject, _ = approved
    support.compose(
        "up", "-d", "--wait", "--force-recreate", "litellm1", env={"MINT_E_BUFFER1_MODE": ":ro"}
    )
    toxics["postgres"].disable()
    try:
        outcome = world.call(subject)
        assert outcome.status == 403
        logs = support.compose("logs", "--no-log-prefix", "litellm1").stdout
        lines = [x for x in logs.splitlines() if "decision_evaluated" in x and outcome.mark in x]
        assert len(lines) == 1
    finally:
        toxics["postgres"].enable()
        support.compose("up", "-d", "--wait", "--force-recreate", "litellm1")


def observed_subject(world, *extra: str):
    subject = world.subject()
    relation = world.prepare(subject)
    world.approve(
        subject,
        relation,
        extra=("--business-hours-only", "--business-hours", "UTC,1-7,00:00,00:01", *extra),
    )
    return subject


def test_observe_mode_converts_only_observable_policy_block(world, evidence):
    """업무 시간 밖 규칙만 걸린 호출은 관측 가능 정책이면 허용으로 전환되고 판정은 차단이다."""
    evidence.positive_control()
    subject = observed_subject(world)
    world.mint.run("settings", "mode", "observe")
    world.mint.run("settings", "observable", "--policy-ids", "R1,R3")
    try:
        outcome = world.call(subject)
        events = world.events(outcome.mark)
        assert len(events) == 1
        assert events[0]["payload"]["policy_ids"] == ["R3"]
        assert decision(events[0])[:2] == ("block", "allow")
        evidence.assert_calls(outcome.mark, 1)
    finally:
        world.mint.run("settings", "mode", "enforce")


def test_observe_mode_with_high_risk_tool_needs_per_call_approval(world, evidence):
    """고위험 도구와 업무 시간 밖이 겹치면 호출별 승인이 없을 때 차단, 있으면 허용하고 기록한다."""
    evidence.positive_control()
    subject = observed_subject(world, "--high-risk-tools", "echo")
    world.mint.run("settings", "mode", "observe")
    world.mint.run("settings", "observable", "--policy-ids", "R1,R3")
    try:
        mark = support.marker()
        without = world.call(subject, mark=mark, arguments={"text": "x", "marker": mark})
        assert without.code == code_of("CALL_APPROVAL_REQUIRED")
        evidence.assert_calls(mark, 0)
        mark2 = support.marker()
        arguments2 = {"text": "x", "marker": mark2}
        world.call_approval(subject, arguments2)
        with_approval = world.call(subject, mark=mark2, arguments=arguments2)
        assert with_approval.allowed, with_approval.body
        event = world.events(mark2)[0]
        assert event["payload"]["policy_ids"] == ["R3"]
        assert any(f["reason_code"] == "POLICY_DETECT_R3" for f in event["payload"]["findings"])
        evidence.assert_calls(mark2, 1)
    finally:
        world.mint.run("settings", "mode", "enforce")
