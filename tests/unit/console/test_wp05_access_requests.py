"""승인 센터 「권한 요청」 탭·기본 탭·예외 탭·/approvals/new 안내(WP-05)."""

import uuid

from console_pages_support import INSTANCE, form_post


def seed_request(world, tool="echo", reason="DENIED", who="human-5"):
    rid = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.access_requests (id, instance_id, requested_by, server_id, tool,"
        " reason_code, note) VALUES (%s, %s, %s, 'srv-ok', %s, %s, '업무에 필요합니다')",
        rid, INSTANCE, who, tool, reason)
    return rid


def seed_denial(world, who="human-5"):
    did = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.denials (id, instance_id, scope_type, scope_id, server_id, reason,"
        " created_by) VALUES (%s, %s, 'user', %s, 'srv-ok', '검토 중', 'admin')",
        did, INSTANCE, who)
    return did


def version(world, rid):
    return world.query("SELECT state_version FROM mint.access_requests WHERE id = %s", rid)[0][0]


def status(world, rid):
    return world.query("SELECT status, resolution FROM mint.access_requests WHERE id = %s", rid)[0]


def test_the_tab_lists_requests_oldest_first_and_the_drawer_shows_the_suggestion(world, admin):
    first = seed_request(world, tool="echo")
    seed_request(world, tool="ping", who="human-6")
    seed_denial(world)
    html = admin.get("/approvals?tab=access").text
    assert html.index("echo") < html.index("ping") and "관리자 차단에 걸렸습니다" in html
    detail = admin.get(f"/approvals?tab=access&focus={first}").text
    assert "업무에 필요합니다" in detail and "검토 중" in detail
    assert 'name="how" value="lift"' in detail and "거절 사유" in detail
    assert "<dt>제안 처리</dt><dd>차단 해제" in detail


def test_lift_resolves_the_request_and_unblocks(world, admin):
    rid, did = seed_request(world), seed_denial(world)
    response = form_post(world, admin, f"/access-requests/{rid}/resolve", how="lift",
                         denial_ids=[did], state_version=version(world, rid))
    assert response.status_code == 303 and "access_lifted" in response.headers["location"]
    assert status(world, rid) == ("resolved", "lift")
    assert world.query("SELECT lifted_at IS NOT NULL FROM mint.denials")[0][0]


def test_temp_resolves_with_a_thirty_minute_rule(world, admin):
    rid = seed_request(world, reason="CALL_APPROVAL_REQUIRED")
    world.query("UPDATE mint.servers SET contract_status = 'managed' WHERE server_id = 'srv-ok'")
    response = form_post(world, admin, f"/access-requests/{rid}/resolve", how="temp",
                         state_version=version(world, rid))
    assert response.status_code == 303 and "access_temp" in response.headers["location"]
    assert status(world, rid) == ("resolved", "temp")
    assert world.query("SELECT count(*) FROM mint.call_approval_rules")[0][0] >= 1


def test_grant_needs_a_valid_period_and_reports_a_service_error(world, admin):
    world.with_control_key()
    rid = seed_request(world, reason="APPROVAL_ABSENT")
    response = form_post(world, admin, f"/access-requests/{rid}/resolve", how="grant",
                         valid_days=5, state_version=version(world, rid))
    assert response.status_code == 400 and "7일, 30일, 90일" in response.text
    assert status(world, rid)[0] == "open"
    assert "권한 요청" in response.text and 'name="how" value="grant"' in response.text


def test_reject_needs_a_reason_and_a_stale_version_is_a_conflict(world, admin):
    rid = seed_request(world)
    path = f"/access-requests/{rid}/reject"
    empty = form_post(world, admin, path, note=" ", state_version=version(world, rid))
    assert empty.status_code == 400 and "거절 사유를 적으십시오" in empty.text
    assert 'aria-invalid="true"' in empty.text
    stale = form_post(world, admin, path, note="범위 밖", state_version=version(world, rid) + 3)
    assert stale.status_code == 409 and "화면을 연 뒤 상태가 바뀌었습니다" in stale.text
    ok = form_post(world, admin, path, note="범위 밖", state_version=version(world, rid))
    assert ok.status_code == 303 and "access_rejected" in ok.headers["location"]
    assert status(world, rid)[0] == "rejected"
    assert "거절했습니다." in admin.get(ok.headers["location"]).text


def test_a_viewer_sees_disabled_buttons_with_a_reason_and_cannot_submit(world):
    rid = seed_request(world)
    seed_denial(world)
    viewer = world.session_client("viewer")
    html = viewer.get(f"/approvals?tab=access&focus={rid}").text
    assert "이 역할은 처리할 수 없습니다" in html and 'name="how" value="lift"' not in html
    assert "disabled" in html
    denied = form_post(world, viewer, f"/access-requests/{rid}/resolve", how="lift",
                       state_version=version(world, rid))
    assert denied.status_code in (400, 403) and status(world, rid)[0] == "open"


def test_the_default_tab_is_the_first_one_with_waiting_items(world, admin):
    world.query("DELETE FROM mint.intakes")
    html = admin.get("/approvals").text
    assert 'aria-current="page" class="active">호출' in html or "처리할 권한 요청" not in html
    seed_request(world)
    world.query("UPDATE mint.servers SET status = 'approved' WHERE status = 'awaiting_approval'")
    html = admin.get("/approvals").text
    assert "서버 도입" in html  # 대기 서버가 있으면 신청 심사 탭이 먼저다


def test_the_exception_tab_is_always_listed_with_an_empty_state(admin):
    html = admin.get("/approvals?tab=second").text
    assert "예외·2인 확인" in html and "2인 확인을 기다리는 요청이 없습니다" in html
    assert "예외·2인 확인" in admin.get("/approvals?tab=calls").text


def test_opening_the_approval_form_without_a_relation_explains_what_to_do(admin):
    moved = admin.get("/approvals/new")
    assert moved.status_code == 303 and moved.headers["location"] == "/approvals/review"
    response = admin.get("/approvals/review")
    assert response.status_code == 200
    assert "어느 이용 관계를 승인할지 먼저 고르십시오" in response.text
    assert "/servers" in response.text


def test_access_control_calls_the_tab_block_and_shows_the_source(world, admin):
    seed_denial(world)
    html = admin.get("/access?tab=denials").text
    assert ">차단 <" in html or ">차단<" in html
    assert "출처" in html and "사람" in html
    viewer = world.session_client("viewer").get("/access?tab=denials").text
    assert "거부 등록" in viewer and "disabled" in viewer
