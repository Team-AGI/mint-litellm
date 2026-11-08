"""1단계 인수시험: 병렬 가드레일 판정, 전송 인자 기준 판정, 취소·결과 불명 기록, 기동 점검.

지원 이미지 위에서 LiteLLM이 실제로 가드레일 순서·차단 변환·취소를 처리하는 방식을 확인한다.
"""

import asyncio
import json
import re
import time
from pathlib import Path

import anyio
import httpx
import pytest
import support
from scenario import decision, litellm_config
from support import mcp_session, run
from test_acceptance_core import assert_allowed, assert_blocked, code_of

CONFIG_DIR = Path(__file__).resolve().parent / "config"
BASE_CONFIG = CONFIG_DIR / "litellm.mint.yaml"
LITELLM = support.url(support.LITELLM_PORTS[0])
SEQUENTIAL = (
    "guardrails:\n"
    "  - guardrail_name: it-sequential\n"
    "    litellm_params:\n"
    "      guardrail: it_guardrails.{cls}\n"
    "      mode: [pre_mcp_call]\n"
    "      default_on: true\n"
)


@pytest.fixture
def variant():
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


def with_sequential(cls: str):
    def edit(text: str) -> str:
        head = SEQUENTIAL.format(cls=cls)
        return text.replace("guardrails:\n", head, 1)

    return edit


def approved_subject(world, evidence, **approve):
    evidence.positive_control()
    subject = world.subject(("a",))
    relation = world.prepare(subject)
    world.approve(subject, relation, **approve)
    return subject, relation


def test_sequential_guardrail_rewrite_is_judged_and_consumed_as_sent(world, evidence, variant):
    path = variant("rewrite", with_sequential("RewriteModified"))
    with litellm_config(path) as started:
        assert started.returncode == 0, started.stderr
        subject, _ = approved_subject(world, evidence, extra=("--high-risk-tools", "echo"))
        sent = {"text": "rewritten"}
        original = {"text": "orig"}
        mark = support.marker()
        approval = world.call_approval(subject, {**sent, "marker": mark})
        outcome = world.call(subject, mark=mark, arguments={**original, "marker": mark})
        assert outcome.allowed, outcome.body
        assert "upstream-a:rewritten" in outcome.body
        evidence.assert_calls(mark, 1)
        payload = world.events(mark)[0]["payload"]
        assert payload["consumed_call_approval_id"] == approval
        # 원래 인자의 지문으로 받은 승인은 전송 인자와 맞지 않아 쓰이지 않는다.
        mark2 = support.marker()
        world.call_approval(subject, {**original, "marker": mark2})
        blocked = world.call(subject, mark=mark2, arguments={**original, "marker": mark2})
        assert blocked.code == code_of("CALL_APPROVAL_REQUIRED"), blocked.body
        evidence.assert_calls(mark2, 0)


def test_sequential_guardrail_replacing_only_mcp_arguments_is_blocked(world, evidence, variant):
    path = variant("replace", with_sequential("ReplaceArgumentsOnly"))
    with litellm_config(path) as started:
        assert started.returncode == 0, started.stderr
        subject, _ = approved_subject(world, evidence)
        mark = support.marker()
        outcome = world.call(subject, mark=mark, arguments={"text": "orig", "marker": mark})
        assert outcome.status == 403, outcome.body
        evidence.assert_calls(mark, 0)
        events = world.events(mark)
        assert len(events) == 1
        assert decision(events[0])[:2] == ("block", "block")
        assert outcome.code == code_of("SCHEMA_ERROR")
        assert events[0]["payload"]["stop"]["reason_code"] == "SCHEMA_ERROR"


def test_guardrail_added_after_start_does_not_change_judgement(world, evidence):
    subject, _ = approved_subject(world, evidence)
    created = httpx.post(
        f"{LITELLM}/guardrails",
        headers=support.master_headers(),
        json={
            "guardrail": {
                "guardrail_name": "it-late-guardrail",
                "litellm_params": {
                    "guardrail": "litellm_content_filter",
                    "mode": "pre_mcp_call",
                    "default_on": True,
                    "patterns": [
                        {"pattern_type": "prebuilt", "pattern_name": "us_ssn", "action": "BLOCK"}
                    ],
                },
            }
        },
        timeout=30,
    )
    assert created.status_code == 200, created.text
    guardrail_id = created.json()["guardrail_id"]
    try:
        time.sleep(3)
        assert_allowed(world, evidence, world.call(subject))
        unapproved = world.subject(("a",))
        world.prepare(unapproved)
        assert_blocked(world, evidence, world.call(unapproved), "APPROVAL_ABSENT")
    finally:
        httpx.delete(
            f"{LITELLM}/guardrails/{guardrail_id}", headers=support.master_headers(), timeout=30
        )


def test_client_cancel_during_decision_records_one_cancelled_decision(world, evidence, toxics):
    """MCP 클라이언트가 판정 중에 호출을 취소하면 취소 판정 사건이 한 건 남는다."""
    subject, _ = approved_subject(world, evidence)
    assert world.call(subject).allowed
    since = world.now()
    mark = support.marker()

    async def cancelled_call():
        async with mcp_session(subject.key) as session:
            toxics["postgres"].add("latency", stream="downstream", latency=400)
            with anyio.move_on_after(1.0) as scope:
                await session.call_tool("mcp_a-echo", {"text": "x", "marker": mark})
            assert scope.cancelled_caught
            await asyncio.sleep(1)

    run(cancelled_call())
    toxics["postgres"].clear()
    # 데이터베이스를 다시 쓰는 호출이 버퍼에 남은 사건을 적재한다.
    support.wait_until(lambda: world.call(subject).allowed, 30, 1, what="recovery")

    def cancelled():
        return [
            e
            for e in world.decisions_since(subject, since)
            if (e["payload"].get("stop") or {}).get("reason_code") == "CANCELLED"
        ]

    support.wait_until(cancelled, 60, 1, what="cancelled decision")
    assert len(cancelled()) == 1
    event = cancelled()[0]["payload"]
    assert (event["evaluated_decision"], event["enforced_action"]) == ("block", "block")
    evidence.assert_calls(mark, 0)


def test_status_reports_enforcement_and_matching_policy(world):
    done = world.mint.run("status", check=False)
    report = json.loads(done.stdout)
    assert done.returncode == 0, report
    workers = report["enforcement"]
    assert len(workers) >= 2 and all(w["passed"] for w in workers)
    assert report["policy_bundle"]["state"] == "match"
    assert report["mode"]["effective"] == "enforce"


def test_enforcement_verified_is_recorded_once_per_worker_start(world, variant):
    path = variant("verified", lambda text: text)
    since = world.now()
    with litellm_config(path) as started:
        assert started.returncode == 0, started.stderr
        rows = world.query(
            "select payload->>'worker_id' as worker, count(*) as n from mint.events "
            "where kind = 'enforcement_verified' and inserted_at >= %s group by 1",
            (since,),
        )
    assert len(rows) == 2
    assert all(row["n"] == 1 for row in rows), rows


def run_start(config: str, *args: str, env: dict | None = None):
    """파생 이미지 진입점을 설정 파일과 함께 한 번 실행해 종료 코드를 본다."""
    return support.compose(
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "litellm2",
        *args,
        env={"MINT_E_LITELLM_CONFIG": config, **(env or {})},
        check=False,
    )


@pytest.mark.parametrize(
    ("name", "edit"),
    [
        ("nomint", lambda t: re.sub(r"(?ms)^guardrails:.*?(?=^\S)", "", t)),
        ("nodefault", lambda t: t.replace("      default_on: true\n", "")),
        (
            "twologgers",
            lambda t: t.replace(
                "litellm_settings:\n",
                "litellm_settings:\n  callbacks: [mint_litellm.plugin.logger.MintLogger]\n",
                1,
            ),
        ),
    ],
    ids=["no-mint-guardrail", "default-on-missing", "logger-listed-twice"],
)
def test_derived_image_refuses_to_start_on_unsound_config(world, variant, name, edit):
    path = variant(name, edit)
    done = run_start(path, "--config", "/app/config/litellm.config.yaml", "--port", "4000")
    assert done.returncode != 0, done.stdout[-400:]
    assert "Uvicorn running" not in done.stdout + done.stderr


def test_plain_image_config_fails_the_external_check(world):
    done = world.mint.run("check", "--config", "/work/config/litellm.plain.yaml", check=False)
    report = json.loads(done.stdout)
    assert done.returncode == 1
    assert any(f["level"] == "FAIL" for f in report["findings"])


def test_an_old_two_mode_config_is_refused_then_fixed_by_upgrade_and_starts(world, variant):
    from mint_litellm.control import litellm_config as config_tools

    path = variant(
        "oldmodes",
        lambda text: text.replace(
            "mode: [pre_call, pre_mcp_call, post_mcp_call]", "mode: [pre_mcp_call, post_mcp_call]"
        ),
    )
    refused = run_start(path, "--config", "/app/config/litellm.config.yaml", "--port", "4000")
    assert refused.returncode != 0 and "Uvicorn running" not in refused.stdout + refused.stderr
    local = CONFIG_DIR / Path(path).name
    try:
        assert config_tools.ensure_guardrail_modes(local) == ["pre_call"]
        assert config_tools.ensure_guardrail_modes(local) == []
        with litellm_config(path) as started:
            assert started.returncode == 0, started.stderr
    finally:
        for backup in CONFIG_DIR.glob(f"{local.name}.bak-*"):
            backup.unlink()
