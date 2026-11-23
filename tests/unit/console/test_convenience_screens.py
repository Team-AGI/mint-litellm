"""주소 신청·접힌 결정·행 조치·서버 허용 화면의 제출 동작."""

import json
import re
import uuid
from types import SimpleNamespace

import pytest
from console_pages_support import INSTANCE, add_approval, form_post

from mint_litellm.console import setup_state

from .test_intake_contract_screens import add_intake


def test_admin_form_only_asks_for_address_and_purpose(admin):
    html = admin.get("/intakes/new").text
    form = html.split('action="/intakes"')[1].split("</form>")[0]
    assert re.findall(r'name="([^"]+)"', form) == ["csrf", "server_url", "purpose"]
    assert "서버 선택" not in html


def test_admin_address_creates_a_request_and_duplicate_opens_it(world, admin, monkeypatch):
    world.with_control_key()
    monkeypatch.setattr(world.config.litellm_admin, "list_servers", lambda: [])
    world.query("UPDATE mint.settings SET default_org_id='acme'")
    values = {"server_url": "https://new-docs.example.test/mcp", "purpose": "문서 검색"}
    first = form_post(world, admin, "/intakes", **values)
    assert first.status_code == 303, first.text
    identifier = world.query("SELECT id FROM mint.intakes")[0][0]
    row = world.query("SELECT requested_by, owner_user_id, source, staff_registry_required"
                      " FROM mint.intakes")[0]
    assert row == ("human-1", "human-1", "operator", True)
    assert world.query("SELECT target_ref FROM mint.jobs WHERE kind='intake_run'") == [
        (f"{identifier}/staff",)]
    assert f'href="/intakes/{identifier}"' in admin.get("/approvals?tab=servers").text
    world.query("UPDATE mint.intakes SET status='checking' WHERE id=%s", identifier)
    second = form_post(world, admin, "/intakes", **{**values, "purpose": "다른 목적"})
    assert second.status_code == 303
    assert second.headers["location"] == f"/intakes/{identifier}?ok=intake_existing"
    assert "이미 신청한 서버입니다" in admin.get(second.headers["location"]).text
    assert world.query("SELECT purpose FROM mint.intakes") == [("문서 검색",)]
    assert world.query("SELECT count(*) FROM mint.intakes") == [(1,)]


def test_different_addresses_on_a_host_are_separate_targets(world, admin, monkeypatch):
    world.with_control_key()
    monkeypatch.setattr(world.config.litellm_admin, "list_servers", lambda: [])
    world.query("UPDATE mint.settings SET default_org_id='acme'")
    for path in ("first", "second"):
        response = form_post(world, admin, "/intakes",
                             server_url=f"https://docs.example.test/{path}", purpose="검색")
        assert response.status_code == 303, response.text
    assert world.query("SELECT count(DISTINCT server_id) FROM mint.intakes") == [(2,)]


@pytest.mark.parametrize("address", ["file:///secret", "https://user:secret@example.test/mcp"])
def test_invalid_admin_address_is_returned_without_creating_a_request(world, admin, address):
    response = form_post(world, admin, "/intakes", server_url=address, purpose="검색")
    assert response.status_code == 400
    assert world.query("SELECT count(*) FROM mint.intakes") == [(0,)]


def test_decision_scope_and_optional_reason_are_collapsed(world, admin):
    identifier = add_intake(world)
    html = admin.get(f"/intakes/{identifier}").text
    form = html.split('id="decision"')[1].split("</form>")[0]
    settings = re.search(r"<details><summary>추가 설정</summary>(.*?)</details>", form, re.S)
    assert settings
    for field in ("scope_type", "scope_id", "valid_days", "reason"):
        assert f'name="{field}"' in settings.group(1)
    buttons = form.split("</details>")[1]
    assert 'value="approve"' in buttons and 'value="reject"' in buttons
    done = form_post(world, admin, f"/intakes/{identifier}/decision", decision="reject",
                     state_version=world.query("SELECT state_version FROM mint.intakes")[0][0])
    assert done.status_code == 303


def test_revocation_and_denial_accept_an_empty_reason(world, admin):
    approval = add_approval(world)
    version = world.query("SELECT state_version FROM mint.approvals WHERE id=%s", approval)[0][0]
    assert form_post(world, admin, f"/approvals/{approval}/revoke",
                     state_version=version).status_code == 303
    assert form_post(world, admin, "/denials", scope_type="server", scope_id="srv-ok"
                     ).status_code == 303
    assert world.query("SELECT reason FROM mint.denials") == [("관리자 거부",)]


def test_solo_root_approval_notifications_are_optional(monkeypatch):
    monkeypatch.setattr(setup_state, "_count", lambda *args: 0)
    monkeypatch.setattr(setup_state, "mark_time", lambda *args: None)
    actor = SimpleNamespace(config=SimpleNamespace(stage2=SimpleNamespace(webhook_urls=())),
                            role="admin")
    item = setup_state._approval_flow(actor)
    assert item["optional"] and setup_state.pending([item]) == 0
    assert "기본 관리자가 직접 결정" in item["line"]


def call_event(world, result, principal_type="user"):
    identifier = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.events(event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, subject, payload)"
        " VALUES(%s,%s,'decision_evaluated',%s,%s,1,%s::jsonb,%s::jsonb)",
        identifier, INSTANCE, f"call:{identifier}", identifier,
        json.dumps({"principal_type": principal_type, "principal_id": "caller"}),
        json.dumps({"resolved_server_id": "srv-ok", "tool": "echo", "enforced_action": result}),
    )
    return identifier


@pytest.mark.parametrize("result", ["allow", "deny"])
def test_ledger_rows_can_block_a_tool_or_user_with_one_confirmation(world, admin, result):
    identifier = call_event(world, result)
    html = admin.get("/ledger").text
    assert "이 도구 차단" in html and "이 사용자 차단" in html
    assert f'action="/ledger/{identifier}/block"' in html
    for target in ("tool", "user"):
        response = form_post(world, admin, f"/ledger/{identifier}/block", target=target)
        assert response.status_code == 303
    assert world.query("SELECT scope_type, scope_id, tools FROM mint.denials ORDER BY id") == [
        ("server", "srv-ok", ["echo"]), ("user", "caller", None)]


def test_ledger_does_not_mistake_a_key_for_a_user_or_offer_viewers_actions(world, admin):
    identifier = call_event(world, "allow", principal_type="key")
    html = admin.get("/ledger").text
    assert "이 도구 차단" in html and "이 사용자 차단" not in html
    refused = form_post(world, admin, f"/ledger/{identifier}/block", target="user")
    assert refused.status_code == 400
    viewer = world.session_client("viewer")
    assert "이 도구 차단" not in viewer.get("/ledger").text
    assert form_post(world, viewer, f"/ledger/{identifier}/block", target="tool"
                     ).status_code == 403


@pytest.mark.parametrize("page", ["/servers", "/approvals?tab=servers"])
def test_server_permission_switch_tracks_the_saved_state(world, admin, page):
    html = admin.get(page).text
    assert 'role="switch" aria-checked="true"' in html
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id='srv-ok'")[0][0]
    stopped = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version,
                        confirm_name="srv-ok", next=page)
    assert stopped.status_code == 303
    assert stopped.headers["location"].startswith(page)
    assert 'role="switch" aria-checked="false"' in admin.get(page).text
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id='srv-ok'")[0][0]
    assert form_post(world, admin, "/servers/srv-ok/resume", state_version=version,
                     next=page).status_code == 303
    assert 'role="switch" aria-checked="true"' in admin.get(page).text


def test_delivery_stages_mark_done_next_and_waiting():
    from mint_litellm.console.pages.servers import delivery_progress

    rows = [{"decision_version": v, "stage": s}
            for v, s in ((1, "approved"), (2, "approved"), (2, "registry_active"))]
    levels = [lv for lv, _ in delivery_progress(rows)]
    assert levels == ["ok", "ok", "wait", "off", "off", "off", "off"]
    assert delivery_progress([]) == []


def test_a_failed_start_shows_the_reason_on_the_start_step():
    from mint_litellm.console.pages.servers import delivery_progress

    rows = [{"decision_version": 1, "stage": s, "reason": None} for s in
            ("approved", "registry_active", "key_applied", "device_received")]
    rows.append({"decision_version": 1, "stage": "start_failed", "reason": "종료 코드 1"})
    steps = delivery_progress(rows)
    assert steps[4] == ("error", "시작 실패 · 종료 코드 1")
    assert [lv for lv, _ in steps[5:]] == ["off", "off"]


def test_service_accounts_do_not_count_as_human_operators(monkeypatch):
    seen = []
    monkeypatch.setattr(setup_state, "_count", lambda a, sql, *args: seen.append(args) or 0)
    monkeypatch.setattr(setup_state, "mark_time", lambda *args: None)
    actor = SimpleNamespace(config=SimpleNamespace(stage2=SimpleNamespace(webhook_urls=())),
                            role="admin")
    setup_state._approval_flow(actor)
    assert ["mint-control", "mint-kit-issuer"] in seen[0]
