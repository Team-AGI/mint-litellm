"""시작하기 점검표: 항목별 상태 계산, 알림 시험 전송, 역할별 접근."""

import dataclasses
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
    assert state(html, "servers") == "완료" and state(html, "password") == "완료"
    assert state(html, "accounts") == "미완료"
    assert state(html, "approval") == "완료" and "알림 주소" not in html  # 알림은 화면에서 뺐다
    assert state(html, "rule") == state(html, "report") == "미완료"
    # 설치 명령에 필요한 서버 설정이 빠졌으면 관리자에게 정확한 원인을 보인다.
    endpoint = row_of(html, "endpoint")
    assert state(html, "endpoint") == "확인 필요"
    assert "MINT_KIT_ISSUER_KEY" in endpoint and "MINT_ENDPOINT_PUBLIC_URL" in endpoint
    world.app.state.config = dataclasses.replace(
        world.config, kit_issuer=object(), endpoint_url="https://mint.test", endpoint_routes=True)
    html = admin.get("/setup").text
    endpoint = row_of(html, "endpoint")
    assert state(html, "endpoint") == "미완료" and 'href="/staff/endpoint"' in endpoint


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
    assert "/setup/webhook-test" not in client.get("/setup").text  # 화면에는 없고 경로만 남는다
    calls = []

    def fake_post(http, url, key, delivery, body, deadline=5.0):
        calls.append((url, json.loads(body)))
        return False, 3

    monkeypatch.setattr(setup_page.webhook, "post", fake_post)
    csrf = world.csrf(client)
    failed = client.post("/setup/webhook-test", data={"csrf": csrf})
    assert failed.status_code == 502 and "보내지 못했습니다" in failed.text

    monkeypatch.setattr(setup_page.webhook, "post", lambda *a, **k: (calls.append(a[1]) or True, 1))
    sent = client.post("/setup/webhook-test", data={"csrf": csrf})
    assert sent.status_code == 303 and sent.headers["location"] == "/setup?ok=webhook_tested"
    assert calls[0][0] == HOOK and calls[0][1]["kind"] == "webhook_test"
    marks = world.query("SELECT mark FROM mint.setup_marks")
    assert marks == [("webhook_test",)]


def test_the_test_send_is_admin_only_and_needs_an_address(world, admin):
    assert admin.post("/setup/webhook-test", data={}).status_code == 403  # CSRF
    assert form_post(world, admin, "/setup/webhook-test").status_code == 409
    approver = world.session_client("approver")
    assert form_post(world, approver, "/setup/webhook-test").status_code == 403


def test_an_admin_saves_the_alert_address_on_screen_and_the_worker_reads_it(
    world, admin, monkeypatch
):
    from mint_litellm.control import webhook_store

    monkeypatch.setenv("MINT_EXPORT_HMAC_KEY", "k" * 32)
    assert 'action="/setup/webhook"' not in admin.get("/setup").text
    bad = form_post(world, admin, "/setup/webhook", url="http://hooks.example.com/x", fmt="slack")
    assert bad.status_code == 400
    ok = form_post(world, admin, "/setup/webhook", url=HOOK, fmt="slack")
    assert ok.status_code == 303 and "webhook_saved" in ok.headers["location"]
    stored = world.query("SELECT sealed FROM mint.webhook_settings")[0][0]
    assert HOOK.encode() not in bytes(stored)
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(world.admin_url, row_factory=dict_row) as conn:
        settings = webhook_store.effective(world.config.stage2, conn, INSTANCE)
    assert settings.webhook_urls == (HOOK,) and settings.webhook_format(HOOK) == "slack"
    html = admin.get("/setup").text
    assert "/setup/webhook-test" not in html
    assert form_post(world, admin, "/setup/webhook", url="").status_code == 303
    assert world.query("SELECT count(*) FROM mint.webhook_settings")[0][0] == 0
    approver = world.session_client("approver")
    assert form_post(world, approver, "/setup/webhook", url=HOOK).status_code == 403


@pytest.mark.parametrize("role", ["admin", "approver", "viewer"])
def test_every_role_can_open_the_checklist_and_the_menu_lists_it(world, role):
    client = world.session_client(role)
    html = client.get("/setup").text
    assert "<h1>시작하기</h1>" in html and 'href="/setup"' in html
    assert "mint-kit.tar.gz" not in html
    menu = re.findall(r'<nav\b[^>]*class="sidebar".*?</nav>', client.get("/").text, re.S)[0]
    assert menu.count('href="/setup"') == 1


def test_setup_links_the_password_change_and_the_alert_request(world, admin):
    from mint_litellm.console import setup_state

    item = setup_state._password(True)
    assert item["href"] == "/account/password" and item["status"] is setup_state.OPEN
    assert setup_state._password(False)["status"] is setup_state.DONE
    html = admin.get("/setup").text
    assert "알림 주소" not in html


def test_setup_steps_follow_the_onboarding_order(world, admin):
    html = admin.get("/setup").text
    keys = ["password", "accounts", "endpoint", "servers"]
    at = [html.index(f'id="step-{k}"') for k in keys]
    assert at == sorted(at)
    assert "허용 목록에 제공자 추가" not in html and "/access?tab=allowlists" not in html
