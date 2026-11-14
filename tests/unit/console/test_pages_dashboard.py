"""화면 시험: 모든 화면 렌더링, 보안 헤더, 개요·호출 기록·경보·정책, 로그인과 세션."""

import json
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from console_fixtures import Keys
from console_pages_support import (
    INSTANCE,
    PAGES,
    add_approval,
    form_post,
    server_status,
)

from mint_litellm.types.settings import Mode


@pytest.mark.parametrize("path", PAGES)
@pytest.mark.parametrize("role", ["admin", "approver", "viewer"])
def test_every_screen_renders_for_every_role(world, role, path):
    client = world.session_client(role)
    response = client.get(path)
    assert response.status_code == 200, response.text[:300]
    assert "text/html" in response.headers["content-type"]
    assert "MINT 관리자 콘솔" in response.text


def test_the_login_page_renders_without_a_session(world):
    response = world.client.get("/login")
    assert response.status_code == 200 and "LiteLLM 키" in response.text


def test_screens_redirect_to_the_login_page_without_a_session(world):
    for path in PAGES:
        response = world.client.get(path)
        assert response.status_code == 303 and response.headers["location"] == "/login", path


def test_the_menu_lists_only_screens_that_exist(admin):
    html = admin.get("/").text
    labels = re.findall(r'<nav class="sidebar".*?</nav>', html, re.S)[0]
    badge = r'(?: <span class="badge error">\d+</span>)?'
    names = [n.strip() for n in re.findall(r">([^<]+)" + badge + "</a>", labels)]
    assert names == ["대시보드", "승인 센터", "경보", "서버", "도입 신청", "접근 통제",
                     "엔드포인트", "호출 기록", "정책", "운영자·조직"]
    assert re.search(r"승인 센터 <span class=\"badge error\">[1-9]\d*</span>", labels)
    for text in ("준비 중", "예정", "곧 제공", "TBD"):
        assert text not in html


@pytest.mark.parametrize("path", PAGES + ["/login"])
def test_security_headers_and_no_external_or_inline_assets(world, path):
    client = world.session_client() if path != "/login" else world.client
    response = client.get(path)
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    html = response.text
    assert not re.search(r'(?:src|href|action)="https?://', html)
    assert " style=" not in html and "javascript:" not in html
    for script in re.findall(r"<script[^>]*>", html):
        assert 'src="/static/' in script


def test_bundled_assets_are_served_locally(world):
    for name in ("htmx.min.js", "echarts.min.js", "console.css", "console.js"):
        response = world.client.get(f"/static/{name}")
        assert response.status_code == 200 and len(response.content) > 500
    assert "default-src 'self'" in world.client.get("/static/console.css").headers[
        "content-security-policy"]


def test_the_overview_shows_counts_and_the_decision_chart(world, admin):
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES (%s, %s, 'decision_evaluated', %s, %s, 1,"
        " '{\"enforced_action\": \"deny\"}')",
        uuid.uuid4(), INSTANCE, "call:" + str(uuid.uuid4()) + ":1:decision_evaluated",
        uuid.uuid4())
    html = admin.get("/").text
    assert "승인 대기" in html and "열린 경보(치명·높음)" in html and "차단률" in html
    assert 'data-chart="' in html and "&#34;decision&#34;: &#34;block&#34;" in html
    assert "&#34;data&#34;: [0, 0, 0, 0, 0, 0, 1]" in html


def test_an_empty_list_shows_a_title_and_one_next_action(world, admin):
    html = admin.get("/approvals?tab=calls").text
    assert "승인을 기다리는 호출이 없습니다" in html
    assert html.count('class="empty"') == 1


def test_a_viewer_sees_no_action_buttons(world):
    add_approval(world)
    viewer = world.session_client("viewer")
    assert "서버 중지" not in viewer.get("/servers/srv-ok").text
    assert 'name="deny"' not in viewer.get("/access?tab=denials").text
    assert "조직 생성" not in viewer.get("/admin").text


def test_a_viewer_cannot_post_a_dangerous_action_from_the_screen(world):
    viewer = world.session_client("viewer")
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]
    response = form_post(world, viewer, "/servers/srv-ok/suspend", state_version=version,
                         confirm_name="srv-ok")
    assert response.status_code == 403
    assert server_status(world) == "approved"


def test_a_form_without_the_csrf_field_is_refused(world, admin):
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]
    response = admin.post("/servers/srv-ok/suspend",
                          data={"state_version": version, "confirm_name": "srv-ok"})
    assert response.status_code == 403
    assert server_status(world) == "approved"


def test_the_mode_can_be_changed_from_the_policy_screen_by_an_admin(world, admin):
    object.__setattr__(world.config.control, "mode_ceiling", Mode.OBSERVE)
    version = world.query("SELECT settings_version FROM mint.settings")[0][0]
    response = form_post(world, admin, "/policy/mode", mode="observe", state_version=version)
    assert response.status_code == 303
    assert world.query("SELECT mode FROM mint.settings")[0][0] == "observe"
    assert "관측" in admin.get("/policy").text


def test_the_overview_shows_jobs_nobody_can_handle_and_the_longest_wait(world, admin, monkeypatch):
    from mint_litellm.control import jobs

    # 처리기가 붙는 시점과 상관없이, 처리기가 없는 종류를 하나 만들어 시험한다.
    monkeypatch.delitem(jobs.HANDLERS, "sync_server", raising=False)
    world.query(
        "INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key, created_at)"
        " VALUES (gen_random_uuid(), %s, 'sync_server', 'x', NULL, now() - interval '2 hours')",
        INSTANCE)
    html = admin.get("/").text
    assert "지연 1" in html and 'title="최장 대기 2시간"' in html


def test_ledger_csv_neutralizes_spreadsheet_formulas(world):
    from mint_litellm.console.api import safe_cell

    assert [safe_cell(v) for v in ("=1+1", "+x", "-x", "@sum", "plain", "2026")] == [
        "'=1+1", "'+x", "'-x", "'@sum", "plain", "2026"]
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
        " VALUES (%s, %s, 'org_created', 'org:x:1:org_created', '=cmd', '{}')",
        uuid.uuid4(), INSTANCE)
    client = world.session_client()
    text = client.get("/api/v1/ledger/export?format=csv").text
    assert "'=cmd" in text and ",=cmd," not in text


@pytest.mark.parametrize("path,data", [
    ("/policy/mode", {"mode": "zz", "state_version": 1}),
    ("/denials", {"scope_type": "zz", "scope_id": "x", "reason": "r"}),
])
def test_bad_form_values_are_a_400_with_security_headers(world, admin, path, data):
    response = form_post(world, admin, path, **data)
    assert response.status_code == 400
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_a_bad_ledger_date_and_bad_paths_mode_are_400(world, admin):
    bad = admin.get("/ledger?since=zz")
    assert bad.status_code == 400 and "strict-transport-security" in bad.headers
    relation = world.query("SELECT id, state_version FROM mint.usage_relations LIMIT 1")[0]
    world.with_control_key()
    response = form_post(
        world, admin, "/approvals", relation_id=relation[0], state_version=relation[1],
        scope_type="key", scope_id="k", tools="echo", requested_by="u", paths_mode="zz")
    assert response.status_code == 400


def test_the_login_is_rate_limited_per_address(world):
    codes = [world.client.post("/login", data={"key": "sk-nope"}).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    assert world.client.post("/login", data={"key": Keys.admin}).status_code == 429


def test_the_alert_screen_lists_shows_and_acknowledges_an_alert(world, admin):
    alert_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.alerts (id, instance_id, kind, severity, dedup_key, subject)"
        " VALUES (%s, %s, 'sync_divergence', 'high', 'k1', %s::jsonb)",
        alert_id, INSTANCE, '{"server_id": "srv-ok", "reason": "registry_missing"}')
    listing = admin.get("/alerts")
    assert "LiteLLM 설정 불일치" in listing.text and "srv-ok" in listing.text
    assert "registry_missing" not in listing.text.replace('value="', "")
    assert "레지스트리에 없음" in admin.get(f"/alerts?open={alert_id}").text
    assert admin.get("/alerts?open=not-an-id").status_code == 404
    done = form_post(world, admin, f"/alerts/{alert_id}/acknowledge")
    assert done.status_code in (200, 303)
    assert world.query("SELECT status FROM mint.alerts WHERE id = %s", alert_id)[0][0] == (
        "acknowledged")


def add_shadow(world):
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v2', %s, %s)", INSTANCE, "ab" * 32, "ab" * 32)
    world.query(
        "INSERT INTO mint.policy_shadow (instance_id, version_id, bundle_sha256, set_by, set_at)"
        " VALUES (%s, 'v2', %s, 'admin', now())", INSTANCE, "ab" * 32)
    world.query(
        "INSERT INTO mint.policy_shadow_results (instance_id, version_id, server_id, tool,"
        " active_result, shadow_result, active_reason, shadow_reason, calls, samples)"
        " VALUES (%s, 'v2', 'srv-ok', 'echo', 'Allow', 'Block', '', 'R1', 3, ARRAY[%s])",
        INSTANCE, "0192f7a0-7c1e-7a10-8000-0123456789ab")


def test_the_policy_screen_shows_how_many_calls_would_flip_with_ledger_links(world, admin):
    add_shadow(world)
    html = admin.get("/policy").text
    assert "정책 시험 적용" in html and "허용에서 차단" in html and "srv-ok" in html
    assert "/ledger?invocation=0192f7a0-7c1e-7a10-8000-0123456789ab" in html
    assert ">적용<" in html and ">취소<" in html
    assert ">적용<" not in world.session_client("viewer").get("/policy").text


def test_the_shadow_version_is_cancelled_and_applied_from_the_screen(world, admin, monkeypatch):
    from mint_litellm.control import policy_versions

    add_shadow(world)
    response = form_post(world, admin, "/policy/shadow/apply", version="v2")
    assert response.status_code == 400 and "적용할 수 없습니다" in response.text
    seen = []
    monkeypatch.setattr(policy_versions, "activate", lambda *a: seen.append(a[4:5]))
    object.__setattr__(world.config, "policy_source", policy_versions.PolicySource(
        root=Path("."), opa="opa", bundle_path=Path("a.tar.gz"), opa_url="http://opa.test",
        timeout_seconds=1))
    assert form_post(world, admin, "/policy/shadow/apply", version="v2").status_code == 303
    assert len(seen) == 1
    assert "시험 중인 판본이 없습니다" in admin.get("/policy").text
    add_shadow_row_only(world)
    assert form_post(world, admin, "/policy/shadow/cancel").status_code == 303
    assert "시험 중인 판본이 없습니다" in admin.get("/policy").text


def add_shadow_row_only(world):
    world.query(
        "UPDATE mint.policy_shadow SET version_id = 'v2', bundle_sha256 = %s, set_by = 'admin',"
        " set_at = now()", "ab" * 32)


def test_the_ledger_can_be_filtered_by_invocation(world, admin):
    html = admin.get("/ledger?invocation=0192f7a0-7c1e-7a10-8000-0123456789ab").text
    assert "조건에 맞는 기록이 없습니다" in html
    assert "형식이 올바르지 않습니다" in admin.get("/ledger?invocation=zzz").text


def test_the_overview_shows_the_litellm_grade_each_replica_reported(world, admin):
    def verified(worker, litellm):
        world.query(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
            " VALUES (%s, %s, 'enforcement_verified', %s, %s::jsonb)",
            uuid.uuid4(), INSTANCE, f"selfcheck:{worker}:1:enforcement_verified",
            json.dumps({"worker_id": worker, "litellm": litellm}))

    verified("r1:1", {"version": "1.106.6", "grade": "A", "tested": True, "missing": []})
    verified("r2:1", {"version": "1.107.0", "grade": "A", "tested": False, "missing": []})
    verified("r3:1", {"version": "1.99.0", "grade": "B", "tested": False,
                      "missing": ["list_hook"]})
    verified("r4:1", None)
    html = admin.get("/").text
    assert "LiteLLM 1.106.6 · 보장 등급 A" in html
    assert "LiteLLM 1.107.0 · 보장 등급 A · 검증되지 않은 판본" in html
    assert "LiteLLM 1.99.0 · 보장 등급 B" in html and 'title="도구 목록 훅"' in html
    assert "list_hook" not in html


def test_the_ledger_defaults_to_seven_days_and_shows_the_organisation_time_zone(world, admin):
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, payload)"
        " VALUES (%s, %s, now(), 'org_created', 'org:x:1:org_created', '{}')",
        uuid.uuid4(), INSTANCE)
    html = admin.get("/ledger").text
    assert "조직 생성" in html and "조회 범위" not in html
    now = datetime.now(ZoneInfo("Asia/Seoul"))
    shown = {f"{moment:%Y-%m-%d %H:%M}" for moment in (now, now - timedelta(minutes=1))}
    assert any(f">{text}</a></td>" in html for text in shown)
    assert "UTC" not in html and 'type="date"' not in html
    assert "/api/v1/ledger/export?format=csv" in html


def test_the_environment_ceiling_blocks_the_observe_mode_and_the_screen_says_so(world, admin):
    version = world.query("SELECT settings_version FROM mint.settings")[0][0]
    response = form_post(world, admin, "/policy/mode", mode="observe", state_version=version)
    assert response.status_code == 400 and "MINT_MODE" in response.text
    assert '<option value="observe" disabled' in admin.get("/policy").text


def test_the_stranger_key_is_not_an_operator_so_no_screen_opens(world):
    assert world.client.post("/login", data={"key": Keys.stranger}).status_code == 403
    assert world.client.get("/").status_code == 303


def test_a_session_ends_when_its_operator_row_expires(world):
    client = world.session_client("approver")
    world.query("UPDATE mint.operators SET expires_at = now() - interval '1 minute'"
                " WHERE name = 'approver'")
    assert client.get("/").status_code == 303


LEGACY_PATHS = {
    "/call-approvals?focus=x": "/approvals?tab=calls&focus=x",
    "/contracts": "/servers?filter=changed",
    "/contracts/srv-ok?scope=a&name=b": "/servers/srv-ok?tab=contract&scope=a&name=b",
    "/revocations": "/access?tab=denials",
    "/approvals?filter=dormant&server=s": "/access?tab=dormant&server=s",
    "/approvals?focus=x": "/approvals?tab=renewals&focus=x",
    "/approvals/new?relation_id=r": "/approvals/review/r",
    "/endpoints/mcp": "/endpoints?tab=local-mcp",
    "/alerts/a1": "/alerts?open=a1",
}


@pytest.mark.parametrize("old,new", LEGACY_PATHS.items())
def test_old_screen_paths_redirect_to_the_new_ones(admin, old, new):
    response = admin.get(old)
    assert response.status_code == 303
    target = response.headers["location"]
    assert target.split("?")[0] == new.split("?")[0]
    assert sorted(target.split("?", 1)[-1].split("&")) == sorted(new.split("?", 1)[-1].split("&"))
