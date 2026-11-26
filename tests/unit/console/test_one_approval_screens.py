"""승인 한 번 화면: 결정 영역, 도구 사후 차단·호출별 검토, 시작하기, 신청 한 화면."""

import re

from console_pages_support import add_approval, form_post

from .test_intake_contract_screens import add_intake


def add_tool(world, tool="echo"):
    world.query(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (gen_random_uuid(), 'inst1', 'srv-ok', 'server', %s, '{}', repeat('a', 64),"
        " repeat('b', 64), 'high', 'read', 'intake', 'candidate')", tool)
    world.query("UPDATE mint.tool_contracts SET status = 'approved' WHERE tool = %s", tool)
    return tool


BLOCKERS = ("예외 승인 요청", "승인할 수 없습니다", "검사용 승인", "두 번째 승인")


def test_the_approve_button_shows_for_every_decidable_state(world):
    admin = world.session_client("admin")
    for status, result, server in (
        ("passed", "pass", "srv-wait"), ("indeterminate", "indeterminate", "srv-ok")
    ):
        intake = add_intake(
            world, status=status, result=result, requested_by="admin-1", server=server
        )
        html = admin.get(f"/intakes/{intake}").text
        assert 'value="reject"' in html and not [text for text in BLOCKERS if text in html]
        if status == "passed":
            assert 'name="decision" value="approve"' in html
            assert "disabled" not in html.split('id="decision"')[1].split("</form>")[0]
        else:  # 판별 불가는 예외 승인으로만 허용한다
            assert 'name="decision" value="approve"' not in html and 'id="exception"' in html


def test_the_decision_scope_defaults_to_the_requester_and_has_no_period(world):
    intake = add_intake(world, requested_by="human-9", source="staff")
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert re.search(r'name="scope_id"[^>]*value="human-9"', html)
    assert 'placeholder="기한 없음"' in html


def test_an_operator_registered_intake_leaves_the_decision_scope_blank(world):
    intake = add_intake(world, requested_by="human-9")
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert not re.search(r'name="scope_id"[^>]*value="human-9"', html)


def test_the_second_approval_tab_appears_only_with_a_pending_request(world):
    html = world.session_client("admin").get("/approvals").text
    assert "두 번째 승인" not in html


def test_tool_block_and_unblock_show_a_badge(world):
    admin = world.session_client("admin")
    page = "/servers/srv-ok?tab=contract"
    html = admin.get(page).text
    assert "/servers/srv-ok/tools/block" in html and "차단됨" not in html
    tool = add_tool(world)
    assert form_post(world, admin, "/servers/srv-ok/tools/block", tool=tool).status_code == 303
    html = admin.get(page).text
    assert "차단됨" in html and "/servers/srv-ok/tools/unblock" in html
    assert form_post(world, admin, "/servers/srv-ok/tools/unblock", tool=tool).status_code == 303
    assert "차단됨" not in admin.get(page).text


def test_per_call_review_is_off_until_the_admin_turns_it_on(world):
    add_approval(world)
    admin = world.session_client("admin")
    page = "/servers/srv-ok?tab=contract"
    tool = add_tool(world)
    html = admin.get(page).text
    assert "호출별 검토 켜기" in html and "호출별 검토</span>" not in html
    r = form_post(world, admin, "/servers/srv-ok/tools/review", tool=tool)
    assert r.status_code == 303, r.text[:800]
    html = admin.get(page).text
    assert "호출별 검토 끄기" in html and "호출별 검토</span>" in html
    form_post(world, admin, "/servers/srv-ok/tools/unreview", tool=tool)
    assert "호출별 검토 켜기" in admin.get(page).text


def test_the_setup_page_has_no_separate_registration_steps(world):
    html = world.session_client("admin").get("/setup").text
    assert "기본 비밀번호 바꾸기" in html
    for text in ("LiteLLM에서 서버 등록", "object_permission", "이용 승인"):
        assert text not in html


def test_the_intake_form_is_one_screen_with_address_and_purpose(world):
    html = world.session_client("admin").get("/intakes/new").text
    assert 'name="purpose"' in html and 'name="server_url"' in html
    for name in ("provider", "owner_user_id", "credential_notice", "data_return_terms"):
        assert f'name="{name}"' not in html


def test_action_block_shows_in_korean_and_lifts(world):
    admin = world.session_client("admin")
    page = "/servers/srv-ok?tab=contract"
    assert form_post(world, admin, "/servers/srv-ok/tools/block", action_type="delete"
                     ).status_code == 303
    html = admin.get(page).text
    assert "행위 차단: 삭제" in html
    assert form_post(world, admin, "/servers/srv-ok/tools/unblock", action_type="delete"
                     ).status_code == 303
    assert "행위 차단: 삭제" not in admin.get(page).text
    form_post(world, admin, "/servers/srv-ok/tools/block", action_type="delete")
    assert "행위: 삭제" in admin.get("/access?tab=denials").text


def test_a_failed_check_waits_for_the_admin_decision(world):
    intake = add_intake(world, status="failed", result="fail", server="srv-ok")
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert 'name="decision" value="approve"' not in html and 'value="reject"' in html
    assert 'id="exception"' in html
