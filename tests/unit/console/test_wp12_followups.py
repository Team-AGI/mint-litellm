"""WP-12: 중지 사유 표시, 사람 서랍 세션 종료, 승인 센터 배지의 권한 요청, 직원 차트 스크립트."""

import re

from console_pages_support import INSTANCE, form_post

from .test_wp02_screens import version_of
from .test_wp09_people_admin import add_person


def add_session(world, user_id, subject, n):
    world.query(
        "INSERT INTO mint.console_sessions (id_hash, instance_id, subject, user_id, key_token,"
        " operator_name, role, idle_expiry, absolute_expiry) VALUES (%s, %s, %s, %s, 'k', %s,"
        " %s, now() + interval '1 hour', now() + interval '2 hours')",
        f"{n:064x}", INSTANCE, subject, user_id, "x" if subject == "admin" else None,
        "viewer" if subject == "admin" else "staff")


def test_the_suspend_reason_actor_and_time_show_on_the_server_head(world, admin):
    done = form_post(world, admin, "/servers/srv-ok/suspend",
                     state_version=version_of(world, "srv-ok"), reason="점검 중 의심 동작")
    assert done.status_code == 303
    html = admin.get("/servers/srv-ok").text
    assert "사유: 점검 중 의심 동작" in html and "중지됨 ·" in html
    resumed = form_post(world, admin, "/servers/srv-ok/resume",
                        state_version=version_of(world, "srv-ok"))
    assert resumed.status_code == 303
    assert "사유: 점검" not in admin.get("/servers/srv-ok").text


def test_terminate_shows_the_terminating_notice(world, admin):
    done = form_post(world, admin, "/servers/srv-ok/terminate",
                     state_version=version_of(world, "srv-ok"), confirm_name="srv-ok")
    assert done.status_code == 303
    assert "서버 폐기를 시작했습니다" in admin.get(done.headers["location"]).text


def test_the_drawer_ends_sessions_with_a_reason_and_a_forced_action_record(world, admin):
    add_person(world, "u-1", "kim@acme.test")
    first = admin.get("/people?open=u-1").text
    assert "끝낼 활성 세션이 없습니다." in first
    assert 'action="/people/u-1/sessions/end"' not in first
    add_session(world, "u-1", "admin", 1)
    add_session(world, "u-1", "staff", 2)
    assert 'action="/people/u-1/sessions/end"' in admin.get("/people?open=u-1").text
    assert form_post(world, admin, "/people/u-1/sessions/end", reason="").status_code == 400
    done = form_post(world, admin, "/people/u-1/sessions/end", reason="분실 신고")
    assert done.status_code == 303
    assert world.query("SELECT count(*) FROM mint.console_sessions WHERE user_id = 'u-1'"
                       " AND revoked_at IS NULL") == [(0,)]
    assert world.query("SELECT action, target FROM mint.forced_actions") == [
        ("sessions_end", "u-1")]
    assert form_post(world, admin, "/people/u-1/sessions/end", reason="또").status_code == 400
    viewer = world.session_client("viewer")
    assert form_post(world, viewer, "/people/u-1/sessions/end", reason="x").status_code == 403


def test_open_access_requests_count_on_the_approvals_menu_badge(world, admin):
    def badge():
        found = re.search(r"승인 센터</span>\s*<span class=\"badge error\">(\d+)</span>",
                          admin.get("/").text)
        return int(found.group(1)) if found else 0

    before = badge()
    world.query(
        "INSERT INTO mint.access_requests (id, instance_id, requested_by, server_id, reason_code)"
        " VALUES (gen_random_uuid(), %s, 'u-9', 'srv-ok', 'APPROVAL_ABSENT')", INSTANCE)
    assert badge() == before + 1
