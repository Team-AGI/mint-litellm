"""LiteLLM 지출 기록에 MINT 가드레일 기록이 남는지 확인한다.

지출 기록은 일괄로 쓰이므로 행이 보일 때까지 기다린다. 지출 기록이 꺼진 구성에서는 행이 끝내
없으므로 시험을 건너뛴다. 프롬프트 저장이 꺼져 있어 응답 본문은 가려지고, 판정 참조·결과 구분은
``guardrail_id``·``guardrail_action``으로 남는다.
"""

import json

import httpx
import pytest
import support

SPEND_WAIT_SECONDS = 150


def mint_entries(mark: str) -> list[dict]:
    reply = httpx.get(
        support.url(support.LITELLM_PORTS[0], "/spend/logs"),
        params={"request_id": mark},
        headers=support.master_headers(),
        timeout=30,
    )
    if reply.status_code != 200 or not isinstance(reply.json(), list):
        return []
    found = []
    for row in reply.json():
        meta = row.get("metadata") or {}
        for entry in meta.get("guardrail_information") or []:
            if isinstance(entry, dict) and entry.get("guardrail_provider") == "mint":
                found.append(entry)
    return found


def spend_entries(mark: str) -> list[dict]:
    try:
        return support.wait_until(
            lambda: mint_entries(mark), timeout=SPEND_WAIT_SECONDS, interval=5, what="spend log"
        )
    except AssertionError:
        pytest.skip("지출 기록이 꺼져 있거나 행이 쓰이지 않았다")


def test_allowed_call_leaves_a_mint_guardrail_entry(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    relation = world.prepare(subject)
    world.approve(subject, relation)
    outcome = world.call(subject)
    assert outcome.allowed, outcome.body
    (decided,) = world.events(outcome.mark)
    reference = f"{decided['invocation_id']}:{decided['attempt_id']}"
    (entry,) = [e for e in spend_entries(outcome.mark) if e.get("guardrail_action") == "allowed"]
    assert entry["guardrail_status"] == "success"
    assert entry["guardrail_id"] == reference


def test_denied_call_leaves_an_intervened_entry_with_the_error_reference(world, evidence):
    evidence.positive_control()
    subject = world.subject()
    world.prepare(subject)
    outcome = world.call(subject)
    assert outcome.status == 403 and outcome.reference
    (entry,) = spend_entries(outcome.mark)
    assert entry["guardrail_status"] == "guardrail_intervened"
    assert entry["guardrail_action"] == "policy_denied"
    assert entry["guardrail_id"] == outcome.reference


@pytest.mark.parametrize(
    ("scan", "action", "status"),
    [("mask", "masked", "guardrail_flagged"), ("block", "output_blocked", "guardrail_intervened")],
)
def test_a_masked_or_blocked_result_leaves_an_output_entry(world, evidence, scan, action, status):
    """결과 단계 가드레일이 가렸거나 막은 호출은 지출 기록에 결과 구분과 판정 참조가 남는다."""
    evidence.positive_control()
    world.mint.run("settings", "mode", "enforce")
    subject = world.subject()
    world.approve(subject, world.prepare(subject), tools="leak", extra=("--response-scan", scan))
    mark = support.marker()
    outcome = world.call(
        subject,
        tool="leak",
        mark=mark,
        arguments={"kind": "secret", "where": "text", "marker": mark},
    )
    assert ("MINT-OUTPUT-BLOCKED" in outcome.body) is (scan == "block"), outcome.body
    (decided,) = world.events(mark)
    reference = f"{decided['invocation_id']}:{decided['attempt_id']}"
    (entry,) = [e for e in spend_entries(mark) if e.get("guardrail_action") == action]
    assert entry["guardrail_status"] == status
    assert entry["guardrail_id"] == reference
    assert "AKIA" not in json.dumps(entry)
