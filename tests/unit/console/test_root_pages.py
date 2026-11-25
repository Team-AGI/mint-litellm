"""Root 화면(WP-08): 긴급 통제, 강제 조치 기록, 신청·서버·사람 강제 조치 경로."""

import re
import uuid

import pytest
from console_pages_support import INSTANCE, form_post


@pytest.fixture
def boss(world):
    """운영자 admin이 Root 표지를 가진 세계의 클라이언트."""
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'admin']")
    return world.session_client("admin")


def halt_scope(world):
    return world.query("SELECT halt_scope FROM mint.settings")[0][0]


def test_only_root_sees_and_uses_the_emergency_screen(world, admin):
    assert admin.get("/root").status_code == 403  # Root 표지 없는 관리자
    assert form_post(world, admin, "/root/halt", scope="all", reason="x",
                     confirm_name="정지").status_code == 403
    assert halt_scope(world) is None
    html = admin.get("/").text
    assert "긴급 통제" not in html and 'href="/root/actions"' in html  # 기록은 관리자도 본다
    assert admin.get("/root/actions").status_code == 200
    assert world.session_client("approver").get("/root/actions").status_code == 403


def test_root_halts_with_a_reason_and_confirmation_then_lifts(world, boss):
    assert 'href="/root"' in boss.get("/").text
    page = boss.get("/root").text
    assert "정상 운영" in page and 'value="freeze"' in page and "취소 불가" in page
    assert form_post(world, boss, "/root/halt", scope="all", reason=" ",
                     confirm_name="정지").status_code == 400
    assert form_post(world, boss, "/root/halt", scope="all", reason="침해 의심",
                     confirm_name="").status_code == 400
    assert halt_scope(world) is None
    done = form_post(world, boss, "/root/halt", scope="all", reason="침해 의심",
                     confirm_name="정지")
    assert done.status_code == 303 and done.headers["location"].startswith("/root/actions?done=")
    assert halt_scope(world) == "all"
    shown = boss.get(done.headers["location"]).text
    assert "전역 정지를 걸었습니다" in shown and "LiteLLM 키 최대 60초" in shown
    held = boss.get("/root").text
    assert "전역 정지 중" in held and "침해 의심" in held and "정지 해제" in held
    assert form_post(world, boss, "/root/halt/lift", reason="").status_code == 400
    assert form_post(world, boss, "/root/halt/lift", reason="확인 끝").status_code == 303
    assert halt_scope(world) is None


def test_the_record_lists_actions_opens_the_drawer_and_verifies_again(world, boss):
    assert "강제 조치 기록이 없습니다" in boss.get("/root/actions").text
    form_post(world, boss, "/root/halt", scope="local", reason="점검", confirm_name="정지")
    action_id = world.query("SELECT id::text FROM mint.forced_actions")[0][0]
    table = boss.get("/root/actions").text
    assert "전역 정지" in table and "점검" in table
    assert "강제 조치 기록이 없습니다" in boss.get("/root/actions?action=server_suspend").text
    drawer = boss.get(f"/root/actions?open={action_id}").text
    assert "MINT 판정" in drawer and "관리 밖 경로" in drawer and "확인 못 함" in drawer
    assert world.query("SELECT verified_at FROM mint.forced_actions")[0][0] is None
    again = form_post(world, boss, f"/root/actions/{action_id}/verify")
    assert again.status_code == 303
    assert world.query("SELECT verified_at FROM mint.forced_actions")[0][0] is not None
    missing = form_post(world, boss, f"/root/actions/{uuid.uuid4()}/verify")
    assert missing.status_code == 404


def test_the_post_route_handles_server_and_intake_actions(world, boss):
    def force(action, target, reason="점검"):
        return form_post(world, boss, "/root/actions", action=action, target=target,
                         reason=reason)

    assert force("server_suspend", "srv-ok", " ").status_code == 400
    assert force("server_suspend", "srv-ok").status_code == 303
    assert world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'") == [
        ("suspended",)]
    assert force("server_resume", "srv-ok").status_code == 303
    assert force("server_terminate", "srv-ok").status_code == 303
    assert world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'")[0][0] in (
        "terminating", "terminated")
    assert force("bogus", "srv-ok").status_code == 400
    intake = str(uuid.uuid4())
    world.query("INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source,"
                " requested_by) VALUES (%s, %s, 'acme', 'srv-wait', 'submission', 'human-1')",
                intake, INSTANCE)
    done = force("intake_reject", intake, "출처 불명")
    assert done.status_code == 303, done.text
    assert world.query("SELECT status, decision FROM mint.intakes WHERE id = %s", intake) == [
        ("decided", "rejected")]
    kinds = [r[0] for r in world.query("SELECT action FROM mint.forced_actions ORDER BY id")]
    assert sorted(kinds) == sorted(
        ["server_suspend", "server_resume", "server_terminate", "intake_reject"])
    assert "반려했습니다" in boss.get(done.headers["location"]).text
    cancelled = force("server_run_cancel", "srv-ok", "사고 대응")
    assert cancelled.status_code == 303, cancelled.text
    assert "이미 보낸 호출은 끝까지 실행됩니다" in boss.get(cancelled.headers["location"]).text
    assert force("person_run_cancel", "human-1", "사고 대응").status_code == 303


def test_a_non_root_admin_cannot_force_actions(world, admin):
    done = form_post(world, admin, "/root/actions", action="server_suspend", target="srv-ok",
                     reason="점검")
    assert done.status_code == 403
    assert world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'") == [
        ("approved",)]


def test_the_lockout_and_unlock_routes_use_the_service(world, admin):
    world.query("INSERT INTO mint.directory_users (instance_id, user_id, email, litellm_role,"
                " team_ids) VALUES (%s, 'u-9', 'lee@acme.test', 'internal_user', '[]'::jsonb)",
                INSTANCE)
    assert form_post(world, admin, "/people/u-9/lockout", reason="").status_code == 400
    done = form_post(world, admin, "/people/u-9/lockout", reason="퇴사")
    assert done.status_code == 303, done.text
    assert world.query("SELECT scope_id, lifted_at IS NULL FROM mint.denials") == [("u-9", True)]
    assert "차단했습니다" in admin.get(done.headers["location"]).text
    assert form_post(world, admin, "/people/human-1/lockout", reason="실수").status_code == 400
    back = form_post(world, admin, "/people/u-9/unlock", reason="복직")
    assert back.status_code == 303 and "PC는 다시 설치해야 합니다" in admin.get(
        back.headers["location"]).text
    assert form_post(world, admin, "/people/u-9/unlock", reason="다시").status_code == 404
    assert world.session_client("approver").post(
        "/people/u-9/lockout", data={"reason": "x"}).status_code in (403,)


def test_the_root_panel_partial_renders_by_target(world, boss, admin):
    from mint_litellm.console.templating import templates

    def draw(client, target):
        actor = type("A", (), {"role": "admin", "csrf": "t", "session": type(
            "S", (), {"operator_name": "root"})(), "ctx": None})()
        actor.ctx = type("C", (), {"conn": None, "instance_id": INSTANCE, "operator": None})()
        env = templates.env
        return env.get_template("_root_panel.html").render(
            root_target=target, actor=actor, is_root=lambda a: a.session.operator_name == "root")

    html = draw(boss, {"kind": "server", "id": "srv-ok", "status": "approved"})
    assert 'value="server_suspend"' in html and 'value="server_terminate"' in html
    assert 'value="server_resume"' not in html
    html = draw(boss, {"kind": "server", "id": "srv-ok", "status": "suspended"})
    assert 'value="server_resume"' in html
    html = draw(boss, {"kind": "intake", "id": "abc", "status": "checking"})
    assert 'value="intake_reject"' in html and re.search(r"취소 불가", html)
    assert 'value="intake_except"' in html
    html = draw(boss, {"kind": "server", "id": "srv-ok", "status": "approved"})
    assert 'value="server_run_cancel"' in html
    assert draw(boss, {"kind": "intake", "id": "abc", "status": "decided"}).count("<dialog") == 0
    assert "<section" not in draw(boss, None)
