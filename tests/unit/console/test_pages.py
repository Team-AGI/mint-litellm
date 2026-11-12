"""화면: 렌더링(응답 200·한국어 표시명), 역할별 버튼, 보안 헤더, 위험 동작 흐름."""

import re
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from console_fixtures import Keys

from mint_litellm.types.settings import Mode

INSTANCE = "inst1"
PAGES = [
    "/", "/servers", "/servers/srv-ok", "/approvals", "/revocations", "/call-approvals",
    "/endpoints", "/ledger", "/policy", "/admin",
]
# 화면에 그대로 나오면 안 되는 영어 열거값(상세의 「코드」 칸과 원장의 사건 키는 예외)
ENUMS = ["awaiting_approval", "enforce", "approver", "terminated", "suspended", "pending"]


def server_status(world) -> str:
    return world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]


def add_approval(world, server_id: str = "srv-ok") -> str:
    approval_id = str(uuid.uuid4())
    relation = world.query(
        "SELECT id FROM mint.usage_relations WHERE server_id = %s", server_id)[0][0]
    world.query(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id, tools,"
        " scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by, status)"
        " VALUES (%s, %s, 'acme', %s, 'standard', %s, ARRAY['echo', 'ping'], 'user', 'human-5',"
        " now(), now() + interval '30 days', '{}', 'admin', 'human-5', 'active')",
        approval_id, INSTANCE, relation, server_id)
    return approval_id


@pytest.fixture
def admin(world):
    return world.session_client("admin")


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
    names = re.findall(r">([^<]+)</a>", labels)
    assert names == ["개요", "MCP 서버", "신청·수용검증", "승인 대기열", "계약 변경",
                     "거부·철회", "호출별 승인", "단말 설치", "원장", "정책·관측 설정",
                     "운영자·조직"]
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


def test_status_names_are_korean_on_the_list_and_the_detail(admin):
    servers = admin.get("/servers").text
    assert "승인됨" in servers and "승인 대기" in servers
    for enum in ENUMS:
        assert enum not in servers
    detail = admin.get("/servers/srv-ok").text
    assert "approved" not in detail and "승인됨" in detail


def test_the_overview_shows_counts_and_the_decision_chart(world, admin):
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES (%s, %s, 'decision_evaluated', %s, %s, 1,"
        " '{\"enforced_action\": \"deny\"}')",
        uuid.uuid4(), INSTANCE, "call:" + str(uuid.uuid4()) + ":1:decision_evaluated",
        uuid.uuid4())
    html = admin.get("/").text
    assert "승인 대기 서버" in html and "열린 경보" in html and "운영 상태" in html
    assert 'data-chart="' in html and "&#34;blocked&#34;: [1]" in html


def test_the_approval_queue_lists_waiting_servers_with_a_review_action(admin):
    html = admin.get("/approvals").text
    assert "srv-wait" in html and "/approvals/new?relation_id=" in html
    assert "srv-ok</a></td>" not in html.split("승인 내역")[0]


def test_an_empty_list_shows_a_title_and_one_next_action(world, admin):
    html = admin.get("/call-approvals").text
    assert "호출별 승인 요청이 없습니다" in html
    assert html.count('class="empty"') == 1


def test_a_viewer_sees_no_action_buttons(world):
    add_approval(world)
    viewer = world.session_client("viewer")
    assert "서버 중지" not in viewer.get("/servers/srv-ok").text
    assert 'name="deny"' not in viewer.get("/revocations").text
    assert "조직 생성" not in viewer.get("/admin").text


def test_the_review_form_is_prefilled_with_the_default_period(admin, world):
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    path = f"/approvals/new?relation_id={relation}"
    assert "이 콘솔에서는 승인할 수 없습니다" in admin.get(path).text  # 제어 평면 키가 없다
    world.with_control_key()
    html = admin.get(path).text
    assert 'name="valid_days" value="90"' in html and "신청자" in html


def test_the_ledger_defaults_to_seven_days_and_shows_the_organisation_time_zone(world, admin):
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, payload)"
        " VALUES (%s, %s, now(), 'org_created', 'org:x:1:org_created', '{}')",
        uuid.uuid4(), INSTANCE)
    html = admin.get("/ledger").text
    assert "조직 생성" in html and "조회 범위" not in html
    now = datetime.now(ZoneInfo("Asia/Seoul"))
    shown = {f"{moment:%Y-%m-%d %H:%M}" for moment in (now, now - timedelta(minutes=1))}
    assert any(f'<td class="nowrap">{text}</td>' in html for text in shown)
    assert "UTC" not in html and 'type="date"' not in html
    assert "/api/v1/ledger/export?format=csv" in html


# --- 위험 동작 -------------------------------------------------------------------------------


def form_post(world, client, path, **fields):
    return client.post(path, data={"csrf": world.csrf(client), **fields})


def test_suspending_from_the_screen_needs_the_name_and_shows_the_effect(world, admin):
    add_approval(world)
    html = admin.get("/servers/srv-ok").text
    assert "영향받는 서버 1개, 유효 승인 1건" in html
    assert 'data-confirm="srv-ok"' in html and "danger" in html
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]
    wrong = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version,
                      confirm_name="srv")
    assert wrong.status_code == 400 and "이름을 정확히 입력" in wrong.text
    ok = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version,
                   confirm_name="srv-ok")
    assert ok.status_code == 303 and ok.headers["location"] == "/servers/srv-ok?ok=suspended"
    assert "서버를 중지했습니다" in admin.get(ok.headers["location"]).text


def test_a_stale_screen_is_refused_with_a_conflict_message(world, admin):
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]
    response = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version + 5,
                         confirm_name="srv-ok")
    assert response.status_code == 409 and "상태 버전" in response.text


def test_revoke_and_revoke_with_denial_are_separate_buttons(world, admin):
    add_approval(world)
    html = admin.get("/revocations").text
    assert re.search(r'name="deny" value="0"[^>]*>철회<', html)
    assert re.search(r'name="deny" value="1"[^>]*>철회 \+ 거부<', html)
    assert "차단되는 대상: 사용자 human-5의 도구 2개, 서버 1개" in html


def test_revoking_requires_a_reason_and_revoke_plus_deny_records_both(world, admin):
    approval_id = add_approval(world)
    version = world.query("SELECT state_version FROM mint.approvals")[0][0]
    path = f"/approvals/{approval_id}/revoke"
    empty = form_post(world, admin, path, state_version=version, reason=" ", deny="0")
    assert empty.status_code == 400 and "reason" in empty.text
    ok = form_post(world, admin, path, state_version=version, reason="정책 위반", deny="1")
    assert ok.status_code == 303 and "revoked_denied" in ok.headers["location"]
    assert world.query("SELECT status FROM mint.approvals")[0][0] == "revoked"
    assert world.query("SELECT count(*) FROM mint.denials")[0][0] == 1
    kinds = {r[0] for r in world.query("SELECT kind FROM mint.events")}
    assert {"approval_revoked", "denial_created"} <= kinds


def test_revoking_without_a_denial_leaves_no_denial(world, admin):
    approval_id = add_approval(world)
    version = world.query("SELECT state_version FROM mint.approvals")[0][0]
    form_post(world, admin, f"/approvals/{approval_id}/revoke", state_version=version,
              reason="종료", deny="0")
    assert world.query("SELECT count(*) FROM mint.denials")[0][0] == 0


def test_closing_an_org_needs_its_identifier_typed(world, admin):
    version = world.query("SELECT state_version FROM mint.orgs WHERE org_id = 'acme'")[0][0]
    # 이용 관계가 열려 있어도 닫기 자체는 서비스 규칙을 따른다. 이름 확인이 먼저다.
    wrong = form_post(world, admin, "/orgs/acme/close", state_version=version, confirm_name="x")
    assert wrong.status_code == 400 and "이름을 정확히 입력" in wrong.text
    assert world.query("SELECT status FROM mint.orgs WHERE org_id = 'acme'")[0][0] == "active"


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


def test_the_environment_ceiling_blocks_the_observe_mode_and_the_screen_says_so(world, admin):
    version = world.query("SELECT settings_version FROM mint.settings")[0][0]
    response = form_post(world, admin, "/policy/mode", mode="observe", state_version=version)
    assert response.status_code == 400 and "MINT_MODE" in response.text
    assert '<option value="observe" disabled' in admin.get("/policy").text


def test_the_mode_can_be_changed_from_the_policy_screen_by_an_admin(world, admin):
    object.__setattr__(world.config.control, "mode_ceiling", Mode.OBSERVE)
    version = world.query("SELECT settings_version FROM mint.settings")[0][0]
    response = form_post(world, admin, "/policy/mode", mode="observe", state_version=version)
    assert response.status_code == 303
    assert world.query("SELECT mode FROM mint.settings")[0][0] == "observe"
    assert "관측" in admin.get("/policy").text


def test_the_call_approval_screen_decides_from_the_pending_row(world, admin):
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s)", INSTANCE, "ab" * 32, "ab" * 32)
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at) VALUES (%s, %s, 'acme', 'user', 'human-7', 'srv-ok', 'echo', %s, 1, 'v1',"
        " 'pending', 'human-7', now() + interval '1 hour')",
        call_id, INSTANCE, "ab" * 32)
    html = admin.get("/call-approvals").text
    assert "응답 대기" in html and "echo" in html
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    # 요청자 본인 승인은 두 번째 승인자가 필요하므로 거부로 결정한다
    response = form_post(world, admin, f"/call-approvals/{call_id}/reject", state_version=version)
    assert response.status_code == 303
    assert world.query("SELECT status FROM mint.call_approvals")[0][0] == "rejected"


def test_the_stranger_key_is_not_an_operator_so_no_screen_opens(world):
    assert world.client.post("/login", data={"key": Keys.stranger}).status_code == 403
    assert world.client.get("/").status_code == 303


def test_the_review_form_explains_what_an_unset_path_limit_does(world, admin):
    world.with_control_key()
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    html = admin.get(f"/approvals/new?relation_id={relation}").text
    assert "경로 이탈(<code>..</code>)만 차단하고" in html
    assert 'name="paths_mode" value="unset" checked' in html
    assert 'name="paths_mode" value="unrestricted"' in html and "제한 없음" in html


def test_the_overview_shows_jobs_nobody_can_handle_and_the_longest_wait(world, admin, monkeypatch):
    from mint_litellm.control import jobs

    # 처리기가 붙는 시점과 상관없이, 처리기가 없는 종류를 하나 만들어 시험한다.
    monkeypatch.delitem(jobs.HANDLERS, "sync_server", raising=False)
    world.query(
        "INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key, created_at)"
        " VALUES (gen_random_uuid(), %s, 'sync_server', 'x', NULL, now() - interval '2 hours')",
        INSTANCE)
    html = admin.get("/").text
    assert "처리기 없는 대기 작업" in html and "최장 대기 2시간" in html


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


def test_hsts_is_sent_and_server_links_are_url_encoded(world, admin):
    response = admin.get("/servers")
    assert "max-age=31536000" in response.headers["strict-transport-security"]
    world.query(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
        " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'a b\"c', 'awaiting_approval',"
        " %s, 'http', 'none', 'admin')", INSTANCE, "ab" * 32)
    html = admin.get("/servers").text
    assert 'href="/servers/a%20b%22c"' in html


def test_the_login_is_rate_limited_per_address(world):
    codes = [world.client.post("/login", data={"key": "sk-nope"}).status_code for _ in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]
    assert world.client.post("/login", data={"key": Keys.admin}).status_code == 429


def test_a_session_ends_when_its_operator_row_expires(world):
    client = world.session_client("approver")
    world.query("UPDATE mint.operators SET expires_at = now() - interval '1 minute'"
                " WHERE name = 'approver'")
    assert client.get("/").status_code == 303
