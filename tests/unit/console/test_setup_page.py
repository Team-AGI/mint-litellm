"""시작하기 점검표: 항목별 상태 계산, 알림 시험 전송, 역할별 접근."""

import json
import re
import uuid

import pytest
from console_pages_support import INSTANCE, form_post

from mint_litellm.console.pages import setup as setup_page

HOOK = "https://hooks.example.test/mint"


def row_of(html: str, key: str) -> str:
    start = html.index(f'id="step-{key}"')
    return html[start : html.index("</tr>", start)]


def state(html: str, key: str) -> str:
    return re.search(r"</span>(완료|미완료|확인 필요)</span>", row_of(html, key)).group(1)


def verified(world, passed=True, litellm=None):
    kind = "enforcement_verified" if passed else "enforcement_unverified"
    litellm = litellm or {"version": "1.106.6", "grade": "A", "tested": True, "missing": []}
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
        " VALUES (%s, %s, %s, %s, %s::jsonb)",
        uuid.uuid4(),
        INSTANCE,
        kind,
        f"selfcheck:r1:{uuid.uuid4().hex[:6]}:{kind}",
        json.dumps({"worker_id": "r1:1", "litellm": litellm}),
    )


def activate_policy(world):
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s)",
        INSTANCE,
        "ab" * 32,
        "ab" * 32,
    )
    world.query("UPDATE mint.policy_versions SET status = 'staged' WHERE id = 'v1'")
    world.query(
        "UPDATE mint.policy_versions SET status = 'active', activated_at = now(),"
        " activated_by = 'admin' WHERE id = 'v1'"
    )


def add_install(world, ago="1 hour"):
    world.query(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
        " issued_by, install_mode, reported_at) VALUES (%s, 'k1', 'u1', 'k1', 'admin',"
        " 'managed', now() - %s::interval)",
        INSTANCE,
        ago,
    )


def test_a_fresh_install_shows_what_is_missing(world, admin):
    html = admin.get("/setup").text
    assert state(html, "gateway") == "미완료" and "복제본 보고가 아직 없습니다" in html
    assert state(html, "policy") == "미완료"
    assert state(html, "servers") == "완료"
    assert state(html, "approval") == "확인 필요" and "알림 주소 미설정" in html
    endpoint = row_of(html, "endpoint")
    assert "미완료" in endpoint and 'data-copy="tar -xzf mint-kit.tar.gz' in endpoint
    assert state(html, "rule") == state(html, "report") == "미완료"
    assert state(html, "endpoint") == "미완료"


def test_the_gateway_item_follows_the_reported_grade(world, admin):
    verified(world, litellm={"version": "1.99.0", "grade": "B", "tested": False, "missing": []})
    assert state(admin.get("/setup").text, "gateway") == "확인 필요"
    verified(world)
    assert state(admin.get("/setup").text, "gateway") == "완료"


def test_the_policy_item_needs_an_active_bundle_and_passing_verification(world, admin):
    activate_policy(world)
    verified(world, passed=False)
    assert state(admin.get("/setup").text, "policy") == "확인 필요"
    verified(world, passed=True)
    html = admin.get("/setup").text
    assert state(html, "policy") == "완료" and "집행 검증 통과" in html


def test_the_server_item_distinguishes_none_from_unapproved(world, admin):
    world.query("UPDATE mint.servers SET status = 'suspended' WHERE server_id = 'srv-ok'")
    assert state(admin.get("/setup").text, "servers") == "확인 필요"
    world.query("DELETE FROM mint.usage_relations")
    world.query("DELETE FROM mint.servers")
    html = admin.get("/setup").text
    assert state(html, "servers") == "미완료" and "/intakes/new" in row_of(html, "servers")


def test_the_endpoint_item_needs_a_report_in_the_last_day(world, admin):
    add_install(world, ago="3 days")
    assert state(admin.get("/setup").text, "endpoint") == "확인 필요"
    world.query("UPDATE mint.endpoint_installs SET reported_at = now()")
    html = admin.get("/setup").text
    assert state(html, "endpoint") == "완료" and "data-copy" not in row_of(html, "endpoint")


def test_optional_items_follow_rules_and_the_audit_report(world, admin):
    world.query(
        "INSERT INTO mint.call_approval_rules (id, instance_id, org_id, scope_type, action_class,"
        " window_minutes, created_by) VALUES (gen_random_uuid(), %s, 'acme', 'org', 'read', 10,"
        " 'admin')",
        INSTANCE,
    )
    html = admin.get("/setup").text
    assert state(html, "rule") == "완료" and state(html, "report") == "미완료"
    assert admin.get("/reports/audit").status_code == 200
    assert state(admin.get("/setup").text, "report") == "완료"


def test_the_test_send_marks_the_approval_item_only_when_every_address_answers(world, monkeypatch):
    client = world.client_with(webhook_urls=(HOOK,), webhook_hmac_key=b"k" * 32)
    login = client.post("/login", data={"key": "sk-admin"})
    assert login.status_code == 303
    html = client.get("/setup").text
    assert "시험 전송 전" in html and "/setup/webhook-test" in html
    calls = []

    def fake_post(http, url, key, delivery, body, deadline=5.0):
        calls.append((url, json.loads(body)))
        return False, 3

    monkeypatch.setattr(setup_page.webhook, "post", fake_post)
    csrf = world.csrf(client)
    failed = client.post("/setup/webhook-test", data={"csrf": csrf})
    assert failed.status_code == 502 and "보내지 못했습니다" in failed.text
    assert "시험 전송 전" in client.get("/setup").text

    monkeypatch.setattr(setup_page.webhook, "post", lambda *a, **k: (calls.append(a[1]) or True, 1))
    sent = client.post("/setup/webhook-test", data={"csrf": csrf})
    assert sent.status_code == 303 and sent.headers["location"] == "/setup?ok=webhook_tested"
    assert calls[0][0] == HOOK and calls[0][1]["kind"] == "webhook_test"
    assert state(client.get("/setup").text, "approval") == "완료"
    marks = world.query("SELECT mark FROM mint.setup_marks")
    assert marks == [("webhook_test",)]


def test_the_test_send_is_admin_only_and_needs_an_address(world, admin):
    assert admin.post("/setup/webhook-test", data={}).status_code == 403  # CSRF
    assert form_post(world, admin, "/setup/webhook-test").status_code == 409
    approver = world.session_client("approver")
    assert form_post(world, approver, "/setup/webhook-test").status_code == 403


@pytest.mark.parametrize("role", ["admin", "approver", "viewer"])
def test_every_role_can_open_the_checklist_and_the_menu_lists_it(world, role):
    client = world.session_client(role)
    html = client.get("/setup").text
    assert "<h1>시작하기</h1>" in html and 'href="/setup"' in html
    assert ("data-copy" in html) == (role == "admin")
    assert client.get("/").text.count('href="/setup"') == 1
