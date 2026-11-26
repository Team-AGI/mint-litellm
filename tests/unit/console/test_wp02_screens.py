"""WP-02: 신청 상세·서버 상세 화면."""

from console_pages_support import INSTANCE, add_approval, form_post


def test_an_awaiting_server_detail_opens(world, admin):
    assert admin.get("/servers/srv-wait").status_code == 200


def test_an_awaiting_local_server_detail_opens(world, admin):
    world.query(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, identity_kind,"
        " exec_contract_sha256, exec_contract_version, transport, auth_type, registered_by)"
        " VALUES (gen_random_uuid(), %s, 'loc', 'awaiting_approval', 'stdio', %s, 1, 'stdio',"
        " 'none', 'admin')", INSTANCE, "ab" * 32)
    r = admin.get("/servers/loc")
    assert r.status_code == 200, r.text[:400]


def test_an_awaiting_server_without_a_recorded_hash_opens(world, admin):
    # 해시가 없는 승인 대기 서버가 「요청을 처리하지 못했습니다」(A12)로 열리지 않던 결함
    world.query(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, identity_kind, transport,"
        " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'nohash', 'awaiting_approval',"
        " 'stdio', 'stdio', 'none', 'admin')", INSTANCE)
    assert admin.get("/servers/nohash").status_code == 200


def version_of(world, sid):
    return world.query("SELECT state_version FROM mint.servers WHERE server_id = %s", sid)[0][0]


def test_the_control_panel_has_stop_with_reason_block_usage_and_terminate(world, admin):
    html = admin.get("/servers/srv-ok").text
    assert "<h2>통제</h2>" in html and 'name="reason"' in html
    assert "?tab=contract" in html and "?tab=usage" in html
    assert 'action="/servers/srv-ok/terminate"' in html and 'data-confirm="srv-ok"' in html
    assert "전파 상태" not in html


def test_a_waiting_server_shows_no_controls_but_where_to_decide(world, admin):
    """승인 전 서버에는 쓸 수 없는 통제 단추·재승인 대신 결정할 곳(신청 상세)을 한 줄로 보인다."""
    html = admin.get("/servers/srv-wait").text
    assert "승인 전 서버입니다" in html
    assert "/servers/srv-wait/terminate" not in html and "/servers/srv-wait/suspend" not in html
    assert "이용 탭에서 종료" not in html
    contract = admin.get("/servers/srv-wait?tab=contract").text
    assert "재승인 계획 등록" not in contract


def test_terminate_needs_the_exact_server_id_and_starts_termination(world, admin):
    path = "/servers/srv-ok/terminate"
    version = version_of(world, "srv-ok")
    bad = form_post(world, admin, path, state_version=version, confirm_name="other")
    assert bad.status_code == 400 and "서버 식별자" in bad.text
    assert world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'") == [
        ("approved",)]
    ok = form_post(world, admin, path, state_version=version, confirm_name="srv-ok")
    assert ok.status_code == 303 and ok.headers["location"].endswith("ok=server_terminating")
    assert world.query("SELECT status FROM mint.servers WHERE server_id = 'srv-ok'") == [
        ("terminating",)]
    html = admin.get(ok.headers["location"]).text
    assert "전파 상태" in html and "폐기를 시작했습니다" in html


def test_terminate_is_refused_for_a_waiting_server(world, admin):
    r = form_post(world, admin, "/servers/srv-wait/terminate",
                  state_version=version_of(world, "srv-wait"), confirm_name="srv-wait")
    assert r.status_code == 404


def test_suspend_shows_the_propagation_line(world, admin):
    version = version_of(world, "srv-ok")
    ok = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version, reason="점검")
    assert ok.status_code == 303
    html = admin.get("/servers/srv-ok").text
    assert "전파 상태" in html and "재개" in html


# --- 신청 상세 -----------------------------------------------------------------------------

import re  # noqa: E402

from .test_endpoint_intake_screens import make_inspectable, make_local  # noqa: E402
from .test_intake_contract_screens import add_intake, litellm_permission  # noqa: E402,F401

__all__ = ["litellm_permission"]


def test_the_tabs_are_summary_source_pack_content_and_evidence(world):
    intake = make_local(world)
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    order = [html.index(t) for t in ("심사 요약", "출처·공급망", "실행 묶음", "신청 내용")]
    assert order == sorted(order) and html.index("증빙", order[-1]) > order[-1]
    plain = world.session_client("admin").get(f"/intakes/{add_intake(world, server='srv-ok')}")
    assert "출처·공급망" in plain.text and "실행 묶음</a>" not in plain.text


def test_the_source_tab_has_six_rows_and_the_original_check_table(world):
    intake = make_local(world)
    html = world.session_client("admin").get(f"/intakes/{intake}?tab=source").text
    for label in ("출처·소유자", "고정", "의존성", "라이선스", "취약점·코드", "권한·네트워크·격리"):
        assert f"<td class=\"nowrap\">{label}</td>" in html
    assert "묶음 파일 1개" in html and "허용 호스트만" in html and "승인 때 좁히기" in html
    assert "원본 검사 표" in html and "<th>실행 시각</th>" in html


def test_the_source_view_says_checking_before_any_check_ran():
    from mint_litellm.console.pages.servers import source_view

    view = source_view({}, [], None, None, False)
    assert view["waiting"] and len(view["rows"]) == 6
    assert {r["status"].text for r in view["rows"]} == {"검사 중"}


def test_the_inspect_request_button_is_enabled_only_when_it_can_run(world):
    intake = make_inspectable(world)
    admin = world.session_client("admin")
    html = admin.get(f"/intakes/{intake}").text
    assert f'action="/intakes/{intake}/inspect"' in html
    assert "PC에서 도구 목록 확인 요청</button>" in html and "disabled>PC에서" not in html
    ok = form_post(world, admin, f"/intakes/{intake}/inspect")
    assert ok.status_code == 303 and "ok=inspection_issued" in ok.headers["location"]
    html = admin.get(ok.headers["location"]).text
    assert "확인 요청 취소" in html and "단말 검사 대기" in html
    open_id = world.query("SELECT id FROM mint.endpoint_inspections")[0][0]
    gone = form_post(world, admin, f"/intakes/{intake}/inspect-revoke", inspection_id=str(open_id))
    assert gone.status_code == 303
    assert "disabled>PC에서" not in admin.get(f"/intakes/{intake}").text


def test_the_inspect_request_button_is_disabled_with_a_reason_when_not_indeterminate(world):
    intake = make_local(world)
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert "disabled>PC에서 도구 목록 확인 요청" in html
    assert "판별 불가일 때만 요청합니다" in html


def test_the_exception_approval_needs_a_reason_and_is_disabled_unless_indeterminate(world):
    passed = add_intake(world)
    html = world.session_client("admin").get(f"/intakes/{passed}").text
    assert "<button type=\"button\" disabled>예외 승인</button>" in html
    world.query("UPDATE mint.intakes SET status = 'checking' WHERE id = %s", passed)
    world.query("UPDATE mint.intakes SET status = 'indeterminate' WHERE id = %s", passed)
    admin = world.session_client("admin")
    html = admin.get(f"/intakes/{passed}").text
    assert re.search(r'name="reason" required', html) and 'value="except"' in html
    version = world.query("SELECT state_version FROM mint.intakes WHERE id = %s", passed)[0][0]
    done = form_post(world, admin, f"/intakes/{passed}/decision", decision="except",
                     state_version=version, reason="검토함", scope_id="human-9",
                     scope_type="user")
    assert done.status_code == 303
    assert done.headers["location"].split("ok=")[1] in ("exception_requested", "intake_approved")


def test_a_stalled_key_step_shows_its_cause_and_the_change_target_link(world):
    intake = add_intake(world)
    world.query("UPDATE mint.intakes SET status = 'decided', decision = 'approved',"
                " decided_by = 'admin', decided_at = now() WHERE id = %s", intake)
    add_approval(world, "srv-wait")
    world.query("INSERT INTO mint.alerts (id, instance_id, kind, severity, dedup_key, subject)"
                " VALUES (gen_random_uuid(), %s, 'sync_target_missing', 'high',"
                " 'sync_target_missing:user:human-5', '{}')", INSTANCE)
    world.query("INSERT INTO mint.delivery_receipts (instance_id, intake_id, decision_version,"
                " stage) VALUES (%s, %s, 1, 'approved')", INSTANCE, intake)
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert "승인 대상 user human-5이(가) LiteLLM에 없습니다" in html
    assert "대상 바꾸기" in html and "/approvals/review/" in html


def test_the_contract_table_shows_calls_and_blocks_and_separates_uncalled_from_uncounted(world):
    intake = add_intake(world, server="srv-ok")
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert "<th>호출</th><th>차단</th>" in html and ">미집계<" in html


def test_tool_calls_marks_uncalled_uncounted_and_out_of_contract_tools():
    from mint_litellm.console.pages.servers import tool_calls

    tools = [{"tool": "a"}, {"tool": "b"}]
    seen = [{"tool": "a", "calls": 3, "blocked": 1}, {"tool": "z", "calls": 2, "blocked": 0}]
    rows = tool_calls(tools, seen, True)
    assert [(r["tool"], r["calls"], r["blocked"], r["note"]) for r in rows] == [
        ("a", 3, 1, None), ("b", None, None, "미호출"), ("z", 2, 0, "계약 밖")]
    assert tool_calls(tools, [], False)[0]["note"] == "미집계"
