"""화면 시험: 승인 대기열·재확인·거부·철회, 호출별 승인."""

import re
import uuid

from console_pages_support import (
    INSTANCE,
    add_approval,
    form_post,
)


def test_the_approval_queue_lists_waiting_servers_with_a_review_action(admin):
    html = admin.get("/approvals").text
    assert "srv-wait" in html and "/approvals/new?relation_id=" in html
    assert "srv-ok</a></td>" not in html.split("승인 내역")[0]


def test_the_review_form_is_prefilled_with_the_default_period(admin, world):
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    path = f"/approvals/review/{relation}"
    assert "이 콘솔에서는 승인할 수 없습니다" in admin.get(path).text  # 제어 평면 키가 없다
    world.with_control_key()
    html = admin.get(path).text
    assert 'name="valid_days" value="90"' in html and "신청자" in html


def test_a_stale_screen_is_refused_with_a_conflict_message(world, admin):
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]
    response = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version + 5,
                         confirm_name="srv-ok")
    assert response.status_code == 409 and "상태 버전" in response.text


def test_revoke_and_revoke_with_denial_are_separate_buttons(world, admin):
    add_approval(world)
    html = admin.get("/access?tab=denials").text
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


def overdue(world, held: bool) -> str:
    approval_id = add_approval(world)
    world.query(
        "UPDATE mint.approvals SET recert_confirmed_at = now() - interval '120 days',"
        " recert_confirmed_by = 'earlier', recert_requested_at = now() - interval '30 days',"
        " recert_held_at = CASE WHEN %s THEN now() END", held)
    return approval_id


def test_the_approval_list_shows_the_recertification_state_and_the_button(world, admin):
    overdue(world, held=True)
    html = admin.get("/approvals").text
    assert "재확인 기한" in html and "보류됨" in html
    assert re.search(r"<button[^>]*>재확인</button>", html)


def test_confirming_from_the_screen_lifts_the_hold_and_records_who(world, admin):
    approval_id = overdue(world, held=True)
    version = world.query("SELECT state_version FROM mint.approvals")[0][0]
    response = form_post(world, admin, f"/approvals/{approval_id}/recertify",
                         state_version=version)
    assert response.status_code == 303 and "recertified" in response.headers["location"]
    held, by = world.query("SELECT recert_held_at, recert_confirmed_by FROM mint.approvals")[0]
    assert held is None and by == "admin"
    kinds = {r[0] for r in world.query("SELECT kind FROM mint.events")}
    assert "approval_recert_confirmed" in kinds
    assert "기한 내" in admin.get("/approvals").text


def test_only_an_admin_can_confirm_from_the_screen(world):
    approval_id = overdue(world, held=True)
    version = world.query("SELECT state_version FROM mint.approvals")[0][0]
    for role in ("approver", "viewer"):
        client = world.session_client(role)
        assert not re.search(r"<button[^>]*>재확인</button>", client.get("/approvals").text)
        response = form_post(world, client, f"/approvals/{approval_id}/recertify",
                             state_version=version)
        assert response.status_code == 403
    assert world.query("SELECT recert_held_at IS NOT NULL FROM mint.approvals")[0][0]


def test_confirming_without_the_csrf_token_is_refused(world, admin):
    approval_id = overdue(world, held=True)
    version = world.query("SELECT state_version FROM mint.approvals")[0][0]
    response = admin.post(f"/approvals/{approval_id}/recertify", data={"state_version": version})
    assert response.status_code == 403
    assert world.query("SELECT recert_held_at IS NOT NULL FROM mint.approvals")[0][0]


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
    html = admin.get("/approvals?tab=calls").text
    assert "응답 대기" in html and "echo" in html
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    # 요청자 본인 승인은 두 번째 승인자가 필요하므로 거부로 결정한다
    response = form_post(world, admin, f"/call-approvals/{call_id}/reject", state_version=version)
    assert response.status_code == 303
    assert world.query("SELECT status FROM mint.call_approvals")[0][0] == "rejected"


def test_the_call_approval_screen_shows_what_is_asked_masked_and_the_denial_reason(world, admin):
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s)", INSTANCE, "ab" * 32, "ab" * 32)
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at, target, action, display) VALUES (%s, %s, 'acme', 'user', 'human-7',"
        " 'srv-ok', 'echo', %s, 1, 'v1', 'pending', 'mint-auto', now() + interval '1 hour',"
        " 'acme/repo', 'issue_write', %s::jsonb)",
        call_id, INSTANCE, "ab" * 32,
        '{"title": "<script>alert(1)</script>", "note": "key AKIAABCDEFGHIJKLMNOP",'
        ' "body": "' + "x" * 600 + '"}')
    html = admin.get("/approvals?tab=calls").text
    assert "acme/repo" in html and "issue_write" in html and "human-7" in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "AKIAABCDEFGHIJKLMNOP" not in html and "x" * 300 not in html
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    form_post(world, admin, f"/call-approvals/{call_id}/reject",
              state_version=version, reason="범위 밖 요청")
    assert world.query("SELECT decision_reason FROM mint.call_approvals")[0][0] == "범위 밖 요청"
    assert "거부 사유: 범위 밖 요청" in admin.get("/approvals?tab=calls").text


def test_the_review_form_offers_the_path_choices_and_the_result_limits(world, admin):
    world.with_control_key()
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    html = admin.get(f"/approvals/review/{relation}").text
    assert 'name="paths_mode" value="unset" checked' in html
    assert 'name="paths_mode" value="unrestricted"' in html and "제한 없음" in html
    assert 'name="max_result_bytes"' in html and "결과 크기 상한(바이트)" in html
    assert 'name="max_result_items"' in html and "결과 항목 수 상한" in html
    assert "경로 이탈" not in html


def _pending_calls(world, count=2):
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s) ON CONFLICT DO NOTHING", INSTANCE, "ab" * 32, "ab" * 32)
    ids = []
    for n in range(count):
        call_id = str(uuid.uuid4())
        ids.append(call_id)
        world.query(
            "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type,"
            " principal_id, server_id, tool, args_fp, fp_key_version, policy_version_id, status,"
            " requested_by, expires_at) VALUES (%s, %s, 'acme', 'user', 'human-7', 'srv-ok',"
            " 'echo', %s, 1, 'v1', 'pending', 'someone', now() + interval '1 hour')",
            call_id, INSTANCE, f"{n:02x}" * 32)
    return ids


def test_the_pending_queue_defaults_to_thirty_minutes_and_shows_the_age(world, admin):
    ids = _pending_calls(world)
    html = admin.get("/approvals?tab=calls").text
    assert html.count('<option value="30" selected>') == 3  # 행 2개와 일괄 처리
    assert "선택 승인" in html and "경과" in html
    assert "autofocus" in admin.get("/approvals?tab=calls&focus=" + ids[0]).text


def test_bulk_approval_uses_the_default_window_for_every_selected_row(world, admin):
    ids = _pending_calls(world)
    rows = world.query("SELECT id, state_version FROM mint.call_approvals")
    response = form_post(world, admin, "/call-approvals/bulk/approve",
                         ids=[f"{r[0]}:{r[1]}" for r in rows], window_minutes="30")
    assert response.status_code == 303
    result = world.query("SELECT status, window_minutes FROM mint.call_approvals")
    assert sorted(result) == [("approved", 30)] * len(ids)


def test_bulk_rejection_keeps_the_reason_and_reports_a_failed_row(world, admin):
    ids = _pending_calls(world)
    rows = world.query("SELECT id, state_version FROM mint.call_approvals ORDER BY id")
    items = [f"{r[0]}:{r[1]}" for r in rows] + [f"{uuid.uuid4()}:1"]
    response = form_post(world, admin, "/call-approvals/bulk/reject", ids=items, reason="범위 밖")
    assert response.status_code == 404 or "1건 실패" in response.text
    result = world.query("SELECT status, decision_reason FROM mint.call_approvals")
    assert sorted(result) == [("rejected", "범위 밖")] * len(ids)


def test_an_active_window_near_its_end_shows_an_extend_button_that_works_once(world, admin):
    (call_id,) = _pending_calls(world, 1)
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    form_post(world, admin, f"/call-approvals/{call_id}/approve",
              state_version=version, window_minutes="10")
    assert "10분 연장" in admin.get("/approvals?tab=calls").text
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    ok = form_post(world, admin, f"/call-approvals/{call_id}/extend", state_version=version)
    assert ok.status_code == 303
    assert world.query("SELECT extended_by FROM mint.call_approvals")[0][0] is not None
    assert "10분 연장" not in admin.get("/approvals?tab=calls").text
    version = world.query("SELECT state_version FROM mint.call_approvals")[0][0]
    again = form_post(world, admin, f"/call-approvals/{call_id}/extend", state_version=version)
    assert again.status_code >= 400
