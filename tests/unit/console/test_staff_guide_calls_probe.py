"""직원 「내 MCP 서버」: 동의 한 번·이용 방법·내 호출, 신청 전 주소 확인."""

import json
import uuid

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.control import intake_checks
from mint_litellm.control.config import ControlConfig

from . import test_staff_pages as staff_tests
from .test_staff_pages import STAFFER, add_approval, csrf, logged_in

sworld = staff_tests.sworld


def intake_for(world, purpose="고객 문의 정리", decision="approved"):
    world.query(
        "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, purpose,"
        " data_grade, allowed_resources, provider, owner_user_id, readiness, data_return_terms,"
        " requested_by, status, decision, decided_by, decided_at)"
        " VALUES (gen_random_uuid(), %s, 'acme', 'srv-ok', 'staff', %s, 'internal', '[]', 'x', %s,"
        " '{\"credential_notice\":\"a\",\"revocation_record\":\"b\",\"audit_access_days\":90}',"
        " 't', %s, 'received', NULL, NULL, NULL)",
        INSTANCE, purpose, STAFFER, STAFFER)
    for step in ("checking", "passed"):
        world.query("UPDATE mint.intakes SET status = %s WHERE server_id = 'srv-ok'", step)
    world.query("UPDATE mint.intakes SET status = 'decided', decision = %s, decided_by = 'admin',"
                " decided_at = now() WHERE server_id = 'srv-ok'", decision)


def test_the_consent_form_is_prefilled_from_the_approved_application(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",), consent=True)
    intake_for(sworld)
    page = logged_in(sworld).get("/staff?open=acme%7Csrv-ok").text
    assert 'value="고객 문의 정리"' in page and "내부 자료" in page
    assert "동의하지 않음" in page and "이용 방법" in page
    assert "<details class=\"full\">" in page  # 값이 다 있으면 접혀 있다


def test_declining_consent_stops_only_my_use(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    client = logged_in(sworld)
    response = client.post("/staff/servers/stop", data={"csrf": csrf(client),
                                                        "target": "acme|srv-ok"})
    assert response.status_code == 303
    assert sworld.query("SELECT scope_id FROM mint.denials WHERE lifted_at IS NULL") == [
        (STAFFER,)]
    assert "사용 그만둠" in client.get("/staff").text


def test_my_calls_lists_only_my_decisions_with_the_block_reason(sworld):
    def decision(user, tool, outcome, code=None):
        payload = {"server_id": "srv-ok", "tool": tool, "outcome": outcome}
        if code:
            payload["stop"] = {"reason_code": code}
        sworld.query(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, subject,"
            " payload) VALUES (gen_random_uuid(), %s, 'decision_evaluated', %s, 'plugin',"
            " %s::jsonb, %s::jsonb)", INSTANCE, f"decision:{uuid.uuid4()}:1",
            json.dumps({"principal_type": "user", "principal_id": user}), json.dumps(payload))

    decision(STAFFER, "mine_ok", "allowed")
    decision(STAFFER, "mine_blocked", "blocked", "APPROVAL_ABSENT")
    decision(staff_tests.OTHER, "theirs", "allowed")
    page = logged_in(sworld).get("/staff?tab=calls").text
    assert "mine_ok" in page and "mine_blocked" in page and "승인 없음" in page
    assert "theirs" not in page and "APPROVAL_ABSENT" not in page


@pytest.fixture
def probe_stub(monkeypatch):
    seen = {}

    def definitions(client, spec):
        seen["spec"] = spec
        return intake_checks.Outcome("pass", None, "m", {"tools": 3})

    monkeypatch.setattr(intake_checks, "definitions", definitions)
    monkeypatch.setattr(ControlConfig, "litellm_control", lambda self: object())
    return seen


def probe(client, url):
    return client.post("/staff/intakes/probe", data={"csrf": csrf(client), "url": url})


def test_address_check_reports_the_tool_count_and_creates_nothing(sworld, probe_stub):
    client = logged_in(sworld)
    page = probe(client, "https://docs.example.com/mcp")
    assert page.status_code == 200 and "도구 3개" in page.text
    assert probe_stub["spec"]["url"] == "https://docs.example.com/mcp"
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(0,)]


def test_address_check_never_reaches_an_address_the_application_would_refuse(sworld, probe_stub):
    client = logged_in(sworld)
    assert "금지된 주소" in probe(client, "https://10." + "0.0.5/mcp").text
    assert "포트 8080" in probe(client, "https://docs.example.com:8080/mcp").text
    assert "spec" not in probe_stub


def test_a_failed_check_does_not_block_the_submission(sworld, probe_stub, monkeypatch):
    monkeypatch.setattr(intake_checks, "definitions", lambda c, s: intake_checks.Outcome(
        "indeterminate", "TEST_UNAVAILABLE", "m"))
    client = logged_in(sworld)
    page = probe(client, "https://docs.example.com/mcp")
    assert "제출은 할 수 있습니다" in page.text
