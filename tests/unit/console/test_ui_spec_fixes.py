"""화면 점검 조치 시험: 오류 화면, 없는 식별자 404, 역할별 단추, 확인 창, 호출 승인 단추."""

import uuid

HTML = {"accept": "text/html"}


def test_errors_outside_a_screen_keep_the_menu_for_browsers_and_json_for_the_api(world, admin):
    page = admin.get("/servers/없음", headers=HTML)
    assert page.status_code == 404 and "text/html" in page.headers["content-type"]
    assert 'class="sidebar"' in page.text and 'href="/servers"' in page.text
    assert "찾을 수 없습니다" in page.text
    assert admin.get("/servers/없음").json()["code"]  # 브라우저가 아니면 JSON 그대로
    api = admin.get("/api/v1/servers/없음", headers=HTML)
    assert api.status_code == 404 and api.headers["content-type"].startswith("application/json")
    unknown = admin.get("/nowhere", headers=HTML)
    assert unknown.status_code == 404 and 'class="sidebar"' in unknown.text


def test_an_expired_signed_link_shows_a_way_back(world, admin):
    page = admin.get("/link/forged", headers=HTML)
    assert page.status_code == 404 and 'href="/approvals"' in page.text
    assert "링크가 만료되었거나" in page.text


def test_a_logged_out_error_page_has_no_menu_but_a_link_back(world):
    page = world.client.get("/nowhere", headers=HTML)
    assert page.status_code == 404 and 'class="sidebar"' not in page.text
    assert 'class="button primary"' in page.text


def test_unknown_ids_are_not_found_not_unavailable(world, admin):
    for path in (
        "/intakes/없는값",
        "/approvals/review/없는값",
        f"/intakes/{uuid.uuid4()}",
        f"/approvals/review/{uuid.uuid4()}",
    ):
        page = admin.get(path, headers=HTML)
        assert page.status_code == 404, path
        assert "데이터베이스" not in page.text


def test_intake_buttons_follow_the_role_the_service_requires(world):
    approver = world.session_client("approver")
    admin = world.session_client("admin")
    assert 'href="/intakes/new"' in admin.get("/intakes").text
    assert 'href="/intakes/new"' not in approver.get("/intakes").text
    assert 'action="/intakes"' in admin.get("/intakes/new").text
    page = approver.get("/intakes/new")
    assert 'action="/intakes"' not in page.text and "관리자만" in page.text


def test_template_role_checks_come_from_the_command_table():
    from mint_litellm.console.core import can

    assert can(_Role("admin"), "intake create")
    assert not can(_Role("approver"), "intake create") and not can(_Role("viewer"), "intake create")
    assert can(_Role("approver"), "approve") and not can(_Role("viewer"), "approve")


class _Role:
    def __init__(self, role):
        self.role = role


def test_the_instance_exception_evidence_is_offered_to_admins_only(world):
    admin = world.session_client("admin")
    approver = world.session_client("approver")
    viewer = world.session_client("viewer")
    path = "/servers/srv-ok?tab=usage"
    assert 'value="instance_exception"' in admin.get(path).text
    shown = approver.get(path).text
    assert 'name="kind"' in shown and 'value="instance_exception"' not in shown
    assert 'name="kind"' not in viewer.get(path).text


def test_server_detail_has_four_tabs_and_old_tab_names_still_open(world, admin):
    page = admin.get("/servers/srv-ok").text
    nav = page.split('class="tabs"')[1].split("</nav>")[0]
    assert nav.count("<a ") == 4
    for old, heading in (
        ("tools", "<h2>도구</h2>"),
        ("vulns", "<h2>취약점</h2>"),
        ("packages", "<h2>패키지</h2>"),
        ("evidence", "<h2>증빙</h2>"),
    ):
        assert heading in admin.get(f"/servers/srv-ok?tab={old}").text


def test_the_audit_report_is_in_the_sidebar(world, admin):
    page = admin.get("/ledger").text
    assert 'href="/reports/audit" hx-boost="false" class=' in page


def test_the_dormant_tab_can_filter_by_server(world, admin):
    page = admin.get("/access?tab=dormant&server=srv-ok").text
    assert 'name="server"' in page and 'value="srv-ok" selected' in page


def test_the_usage_tab_links_an_active_relation_to_the_approval_scope_screen(world, admin):
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-ok'")[0][0]
    page = admin.get("/servers/srv-ok?tab=usage").text
    assert f'href="/approvals/review/{relation}"' in page
    viewer = world.session_client("viewer").get("/servers/srv-ok?tab=usage").text
    assert "/approvals/review/" not in viewer


def _pending_call(world, requested_by="human-7"):
    from console_pages_support import INSTANCE

    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s) ON CONFLICT DO NOTHING",
        INSTANCE,
        "ab" * 32,
        "ab" * 32,
    )
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type,"
        " principal_id, server_id, tool, args_fp, fp_key_version, policy_version_id, status,"
        " requested_by, expires_at) VALUES (%s, %s, 'acme', 'user', 'human-7', 'srv-ok',"
        " 'echo', %s, 1, 'v1', 'pending', %s, now() + interval '1 hour')",
        call_id,
        INSTANCE,
        "cd" * 32,
        requested_by,
    )
    return call_id


def test_call_approval_buttons_show_their_window_and_dangerous_ones_ask_first(world, admin):
    call_id = _pending_call(world)
    _pending_call(world)
    page = admin.get(f"/approvals?tab=calls&focus={call_id}").text
    assert "30분 승인</button>" in page
    assert 'data-dialog-open="bulk-approve"' in page and 'data-dialog-open="bulk-reject"' in page
    assert 'form="bulk"' in page and 'formaction="/call-approvals/bulk/reject"' in page
    assert 'data-dialog-open="decide-reject"' in page and 'data-dialog-open="decide-cancel"' in page
    assert 'name="second_approver_token"' not in page  # 요청자와 같은 사람이 아니면 없다


def test_the_drawer_asks_for_a_second_approver_when_the_operator_is_the_requester(world, admin):
    call_id = _pending_call(world, requested_by="human-1")  # 관리자의 사용자와 같다
    page = admin.get(f"/approvals?tab=calls&focus={call_id}").text
    assert 'name="second_approver_token"' in page


def test_risky_actions_open_a_confirmation_first(world, admin):
    policy = admin.get("/policy").text
    assert 'data-dialog-open="mode-confirm"' in policy and 'form="mode-form"' in policy
    rules = admin.get("/approvals?tab=renewals").text
    assert "renew-all" not in rules  # 갱신할 항목이 없으면 단추도 없다


def test_a_viewer_sees_no_confirmation_triggers_on_the_policy_screen(world):
    viewer = world.session_client("viewer")
    page = viewer.get("/policy").text
    assert "data-dialog-open" not in page


def test_the_admin_screen_has_at_most_four_tabs_and_a_viewer_has_no_operator_tab(world, admin):
    nav = admin.get("/admin?tab=siem").text.split('class="tabs"')[1].split("</nav>")[0]
    assert nav.count("<a ") == 4 and "SIEM 전달" in admin.get("/admin?tab=siem").text
    viewer = world.session_client("viewer").get("/admin?tab=operators").text
    assert "운영자</a>" not in viewer.split('class="tabs"')[1].split("</nav>")[0]


def test_the_contract_tab_agrees_with_the_server_list_and_card(world, admin):
    """승인본에 출력 스키마 키가 없고 관측본에 있으면 변경이 아니다(목록·카드와 같은 판정)."""
    from mint_litellm.console.compare import changes

    approved = '{"description":"d","input_schema":{"type":"object"}}'
    observed = '{"description":"d","input_schema":{"type":"object"},"output_schema":{"a":1}}'
    info = {
        "tools": [
            {
                "credential_scope": "server",
                "tool": "echo",
                "status": "approved",
                "drift": "none",
                "canonical_text": approved,
            }
        ],
        "observations": [
            {
                "kind": "tool",
                "scope": "server",
                "name": "echo",
                "canonical_text": observed,
                "change_summary": None,
            }
        ],
        "deployments": [],
    }
    assert changes(info) == []
    info["observations"][0]["canonical_text"] = observed.replace('"d"', '"e"', 1)
    assert [r["change"] for r in changes(info)] == ["changed"]
