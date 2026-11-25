"""사람·운영자·시작하기·가입 요청 화면(WP-09): 상태 3종, 서랍, 전체 차단, Root 표지, 알림 줄."""

import psycopg
import pytest
from console_pages_support import INSTANCE, form_post

from mint_litellm.control import operators
from mint_litellm.control.services import root_controls as root


def add_person(world, user_id, email):
    world.query(
        "INSERT INTO mint.directory_users (instance_id, user_id, email, litellm_role, team_ids)"
        " VALUES (%s, %s, %s, 'internal_user', '[]'::jsonb)", INSTANCE, user_id, email)


def add_install(world, user_id, alias, host):
    world.query(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias, host,"
        " issued_by, install_mode, reported_at) VALUES (%s, %s, %s, %s, %s, 'admin',"
        " 'managed', now())", INSTANCE, alias, user_id, alias, host)


def add_operator(world, name, role, user_id):
    world.query(
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES (%s, %s, %s, %s, %s)", INSTANCE, name, role,
        operators.hash_token("tok-" + name), user_id)


def marks(world):
    with psycopg.connect(world.admin_url) as conn:
        return root.root_names(conn, INSTANCE)


@pytest.fixture
def boss(world):
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'admin']")
    return world.session_client("admin")


def test_the_people_table_shows_three_states_and_pc_counts(world, admin):
    for uid, mail in (("u-ok", "ok@acme.test"), ("u-part", "part@acme.test"),
                      ("u-all", "all@acme.test")):
        add_person(world, uid, mail)
    add_install(world, "u-ok", "k1", "pc-kim")
    blocked = form_post(world, admin, "/people/block", user_id="u-part", reason="점검")
    assert blocked.status_code == 303
    assert form_post(world, admin, "/people/u-all/lockout", reason="퇴사").status_code == 303
    html = admin.get("/people").text
    row = {m: html.split(m)[1].split("</tr>")[0]
           for m in ("ok@acme.test", "part@acme.test", "all@acme.test")}
    assert "정상" in row["ok@acme.test"] and '<td class="num">1</td>' in row["ok@acme.test"]
    assert "일부 차단" in row["part@acme.test"] and "전체 차단" in row["all@acme.test"]
    for head in ("LiteLLM 역할", "팀", "최근 로그인", "MINT 권한", "상태"):
        assert f"<th>{head}</th>" in html
    assert '<th class="num">PC</th>' in html


def test_the_drawer_lists_pcs_keys_sessions_and_actions(world, admin):
    add_person(world, "u-1", "kim@acme.test")
    add_install(world, "u-1", "k1", "pc-kim")
    html = admin.get("/people?open=u-1").text
    for text in ("pc-kim", "PC 키", "앱 키", "콘솔 세션", "직원 세션", "차단 목록",
                 "전체 차단…", "MCP 차단", "취소 불가", "되돌리기",
                 "PC 키 1개 · 앱 키 0개 · 세션 0개", 'data-confirm="차단"', "사유(필수)"):
        assert text in html, text
    assert 'action="/people/u-1/lockout"' in html and 'action="/people/u-1/unlock"' not in html
    assert admin.get("/people?open=nobody").status_code == 404
    assert world.session_client("viewer").get("/people?open=u-1").status_code == 403


def test_lockout_and_unlock_from_the_drawer(world, admin):
    add_person(world, "u-1", "kim@acme.test")
    assert form_post(world, admin, "/people/u-1/lockout", reason="").status_code == 400
    done = form_post(world, admin, "/people/u-1/lockout", reason="퇴사")
    assert done.status_code == 303
    assert "LiteLLM 키 최대 60초" in admin.get(done.headers["location"]).text  # 전파 상태 줄
    html = admin.get("/people?open=u-1").text
    assert 'action="/people/u-1/unlock"' in html and "전체 차단 해제" in html
    assert 'action="/people/u-1/lockout"' not in html
    assert world.query("SELECT action FROM mint.forced_actions") == [("person_lockout",)]
    assert form_post(world, admin, "/people/u-1/unlock", reason="").status_code == 400
    assert form_post(world, admin, "/people/u-1/unlock", reason="복직").status_code == 303
    assert "정상" in admin.get("/people").text
    viewer = world.session_client("viewer")
    assert form_post(world, viewer, "/people/u-1/lockout", reason="x").status_code == 403
    assert form_post(world, viewer, "/people/u-1/unlock", reason="x").status_code == 403


def test_lockout_is_disabled_for_oneself_and_for_root_targets(world, admin):
    add_person(world, "u-root", "root@acme.test")
    add_operator(world, "ops-root", "admin", "u-root")
    mine = admin.get("/people?open=human-1").text
    assert "본인은 차단할 수 없습니다." in mine and 'action="/people/human-1/lockout"' not in mine
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'ops-root']")
    shown = admin.get("/people?open=u-root").text
    assert "Root는 Root만 차단할 수 있습니다." in shown
    assert form_post(world, admin, "/people/u-root/lockout", reason="x").status_code == 403
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'ops-root', 'admin']")
    assert 'action="/people/u-root/lockout"' in admin.get("/people?open=u-root").text


def test_root_marks_are_given_and_taken_by_root_only(world, boss):
    add_operator(world, "ops2", "admin", "u-ops2")
    add_operator(world, "ops-view", "viewer", None)
    add_operator(world, "root", "admin", "u-root0")
    html = boss.get("/admin?tab=operators").text
    assert "Root 지정" in html and 'action="/admin/operators/ops2/root"' in html
    assert "본인의 Root 표지는 풀 수 없습니다" in html and "<th>Root</th>" in html
    path = "/admin/operators/ops2/root"
    assert form_post(world, boss, path, on="1", reason=" ").status_code == 400
    assert form_post(world, boss, "/admin/operators/ops-view/root", on="1",
                     reason="x").status_code == 400  # 관리자 역할만
    done = form_post(world, boss, path, on="1", reason="교대 근무")
    assert done.status_code == 303, done.text
    assert "root_set" in done.headers["location"]
    assert "ops2" in marks(world)
    assert form_post(world, boss, path, on="1", reason="또").status_code == 409
    assert form_post(world, boss, "/admin/operators/admin/root", on="0",
                     reason="x").status_code == 400  # 자기 자신
    assert form_post(world, boss, "/admin/operators/root/root", on="0",
                     reason="x").status_code == 400  # 기본 계정은 마지막 Root
    assert form_post(world, boss, path, on="0", reason="교대 끝").status_code == 303
    assert "ops2" not in marks(world)
    count = world.query("SELECT count(*) FROM mint.events WHERE kind = 'operator_role_changed'")
    assert count[0][0] == 2
    recorded = world.query("SELECT action FROM mint.forced_actions WHERE target = 'ops2'"
                           " ORDER BY created_at")
    assert [r[0] for r in recorded] == ["root_set", "root_unset"]  # 강제 조치 기록에도 남는다


def test_non_root_admin_cannot_set_root_marks(world, admin):
    add_operator(world, "ops2", "admin", "u-ops2")
    assert 'action="/admin/operators/ops2/root"' not in admin.get("/admin?tab=operators").text
    assert form_post(world, admin, "/admin/operators/ops2/root", on="1",
                     reason="x").status_code == 403
    viewer = world.session_client("viewer")
    assert form_post(world, viewer, "/admin/operators/ops2/root", on="1",
                     reason="x").status_code == 403


def test_the_menu_draws_the_root_group_only_for_root(world, admin):
    assert 'href="/root"' not in admin.get("/").text
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'admin']")
    assert 'href="/root"' in admin.get("/").text


def test_role_change_is_disabled_for_oneself(world, admin):
    assert "본인의 역할은 바꿀 수 없습니다" in admin.get("/admin?tab=operators").text
    add_operator(world, "ops2", "admin", "u-ops2")
    assert 'action="/operators/ops2/role"' in admin.get("/admin?tab=operators").text


def test_the_setup_screen_has_the_alert_form_and_counts_admins_as_approvers(
    world, admin, monkeypatch
):
    monkeypatch.setenv("MINT_EXPORT_HMAC_KEY", "k" * 32)
    html = admin.get("/setup").text
    assert 'action="/setup/webhook"' in html and "알림 주소를 먼저 저장하십시오" in html
    world.query("DELETE FROM mint.operators WHERE role = 'approver'")
    html = admin.get("/setup").text
    assert "승인할 수 있는 사람 1명" in html and "승인자 없음" not in html
    bad = form_post(world, admin, "/setup/webhook", url="http://hooks.example.com/x", fmt="slack")
    assert bad.status_code == 400 and 'id="alerts-error"' in bad.text
    ok = form_post(world, admin, "/setup/webhook", url="https://hooks.example.com/x",
                   fmt="slack")
    assert ok.status_code == 303
    saved = admin.get("/setup").text
    assert 'action="/setup/webhook-test"' in saved and "hooks.example.com" in saved
    assert "https://hooks.example.com/x" not in saved  # 주소 값은 보이지 않는다


def test_the_endpoints_screen_is_named_after_the_menu_and_confirms_danger(world, admin):
    add_person(world, "u-1", "kim@acme.test")
    add_install(world, "u-1", "k1", "pc-kim")
    html = admin.get("/endpoints").text
    assert "<h1>단말</h1>" in html and "pc-kim" in html
    ref = html.split("open=")[1].split('"')[0]
    drawer = admin.get(f"/endpoints?tab=installs&open={ref}").text
    assert "danger-outline" in drawer and "취소 불가" in drawer
    assert "pc-kim의 연결을 해제합니다" in drawer


def test_signup_decisions_use_dialogs_and_show_a_result_band(world, admin):
    world.query(
        "INSERT INTO mint.signup_requests (id, instance_id, email, display_name, password_sealed,"
        " status_token_hash) VALUES (gen_random_uuid(), %s, 'new@acme.test', '신입',"
        " decode(%s, 'hex'), NULL)", INSTANCE, "ab" * 40)
    html = admin.get("/signup-requests").text
    assert "data-dialog-open" in html and "거절 사유(선택)" in html
    rid = world.query("SELECT id FROM mint.signup_requests")[0][0]
    done = form_post(world, admin, f"/signup-requests/{rid}/reject", reason="중복")
    assert done.status_code == 303 and "signup_rejected" in done.headers["location"]
    assert "가입 요청을 거절했습니다" in admin.get(done.headers["location"]).text
    again = form_post(world, admin, f"/signup-requests/{rid}/reject", reason="")
    assert again.status_code == 404 and "처리할 가입 요청이 없습니다" in again.text
