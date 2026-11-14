"""화면 시험: 운영자·조직과 조직 제안."""

import re
import uuid

import pytest
from console_pages_support import (
    INSTANCE,
    form_post,
)


def test_closing_an_org_needs_its_identifier_typed(world, admin):
    version = world.query("SELECT state_version FROM mint.orgs WHERE org_id = 'acme'")[0][0]
    # 이용 관계가 열려 있어도 닫기 자체는 서비스 규칙을 따른다. 이름 확인이 먼저다.
    wrong = form_post(world, admin, "/orgs/acme/close", state_version=version, confirm_name="x")
    assert wrong.status_code == 400 and "이름을 정확히 입력" in wrong.text
    assert world.query("SELECT status FROM mint.orgs WHERE org_id = 'acme'")[0][0] == "active"


def add_suggestion(world, subject_id, rule="email_domain", subject_type="user"):
    world.query(
        "INSERT INTO mint.org_suggestions (id, instance_id, subject_type, subject_id, org_id,"
        " rule, matched, calls) VALUES (%s, %s, %s, %s, 'acme', %s, 'acme.example', 3)",
        str(uuid.uuid4()), INSTANCE, subject_type, subject_id, rule)
    sql = "SELECT id FROM mint.org_suggestions WHERE subject_id = %s"
    return world.query(sql, subject_id)[0][0]


def test_org_suggestions_are_listed_and_applied_or_ignored_by_an_admin(world, admin):
    first, second, third = (add_suggestion(world, f"sug-{i}") for i in range(3))
    html = admin.get("/admin?tab=suggestions").text
    assert "이메일 도메인 (3건)" in html and "sug-0" in html
    viewer = world.session_client("viewer")
    assert "/apply" not in viewer.get("/admin?tab=suggestions").text
    assert form_post(world, viewer, f"/org-suggestions/{first}/apply").status_code == 403
    assert admin.post(f"/org-suggestions/{first}/apply", data={}).status_code == 403  # CSRF
    assert form_post(world, admin, f"/org-suggestions/{first}/apply").status_code == 303
    bound = world.query("SELECT org_id FROM mint.org_bindings WHERE subject_id = 'sug-0'")
    assert bound[0][0] == "acme"
    assert form_post(world, admin, f"/org-suggestions/{second}/ignore").status_code == 303
    assert form_post(world, admin, "/org-suggestions/rule", rule="email_domain").status_code == 303
    status = "SELECT status FROM mint.org_suggestions WHERE id = %s"
    assert world.query(status, third)[0][0] == "applied"
    assert world.query(status, second)[0][0] == "ignored"
    assert "조직 연결 제안이 없습니다" in admin.get("/admin?tab=suggestions").text


def test_the_screen_has_three_tabs_and_no_allowlist_section(world, admin):
    html = admin.get("/admin").text
    for tab in ("operators", "orgs", "suggestions"):
        assert f"/admin?tab={tab}" in html
    assert "허용 목록" not in html and "/allowlists" not in html
    assert "역할 변경" in html and "조직 생성" not in html
    assert "조직 생성" in admin.get("/admin?tab=orgs").text


def test_a_failed_org_action_stays_on_its_tab(world, admin):
    wrong = form_post(world, admin, "/orgs/acme/close", state_version=1, confirm_name="x")
    assert wrong.status_code == 400 and 'aria-current="page"' in wrong.text
    assert "조직 닫기" in wrong.text and "역할 변경" not in wrong.text


def add_install(world, user, mode, *, ago="0 minutes", processes="[]", outside="[]",
                revoked=False):
    alias = f"kit-{user}"
    world.query(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
        " issued_by, install_mode, reported_at, processes, outside_processes, revoked_at)"
        " VALUES (%s, %s, %s, %s, 'admin', %s::text,"
        " CASE WHEN %s::text IS NULL THEN NULL ELSE now() - %s::interval END,"
        " %s::jsonb, %s::jsonb, CASE WHEN %s THEN now() END)",
        INSTANCE, alias, user, alias, mode, mode, ago, processes, outside, revoked)


@pytest.fixture
def fleet(world):
    add_install(world, "ok-1", "managed")
    add_install(world, "ok-2", "managed", processes='[{"server": "s", "sandbox": "bwrap"}]')
    add_install(world, "bad-1", "managed",
                processes='[{"server": "s", "sandbox": "none", "egress_unfiltered": true}]',
                outside='[{"package": "left-pad", "ecosystem": "npm", "count": 2}]')
    add_install(world, "lost-1", "managed", ago="3 days")
    add_install(world, "free-1", "user")
    add_install(world, "gone-1", "managed", revoked=True)
    return world.session_client("admin")


def test_the_endpoint_screen_counts_the_fleet_and_links_each_slice(fleet):
    html = fleet.get("/endpoints").text
    for label in ("적용률", "격리 위반", "보고 끊김", "관리 밖 MCP"):
        assert label in html
    assert 'data-chart="' in html and "state=stale" in html and "state=violation" in html
    assert "단말 현황" in html and "tab=local-mcp" in html
    assert "ok-1" in html and "gone-1" in html  # 해제된 단말도 목록에는 남는다


@pytest.mark.parametrize("state, shown, hidden", [
    ("applied", "ok-1", "lost-1"), ("unapplied", "free-1", "ok-1"),
    ("stale", "lost-1", "ok-1"), ("violation", "bad-1", "ok-2"),
])
def test_the_state_filter_keeps_only_the_matching_endpoints(fleet, state, shown, hidden):
    html = fleet.get(f"/endpoints?tab=installs&state={state}").text
    assert shown in html and f">{hidden}<" not in html


def test_a_row_opens_a_drawer_with_isolation_and_outside_packages(fleet):
    html = fleet.get("/endpoints?tab=installs").text
    link = re.search(r'href="(/endpoints\?tab=installs&open=[^"]*bad-1[^"]*)"', html)
    assert link
    drawer = fleet.get(link[1]).text
    assert 'role="dialog"' in drawer and "호스트 제한 미집행" in drawer
    assert "left-pad (npm) 2개" in drawer


def test_the_endpoint_screen_has_no_explanatory_text_or_raw_enums(fleet):
    html = fleet.get("/endpoints").text
    assert "<p>" not in html
    for enum in ("managed", "pending", "removed", "revoked"):
        assert enum not in html


def test_transfer_tab_lists_commands_and_recent_backups_for_admins_only(world, admin):
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
        " VALUES (gen_random_uuid(), %s, 'backup_created', 'backup:t1:1:backup_created',"
        " 'admin', '{\"file\": \"b1.mbk\", \"mode\": \"json\", \"encrypted\": false}')", INSTANCE)
    html = admin.get("/admin?tab=transfer").text
    assert "mint-litellm backup create" in html and "b1.mbk" in html and "백업 생성" in html
    viewer = world.session_client("viewer")
    assert "mint-litellm backup" not in viewer.get("/admin?tab=transfer").text
