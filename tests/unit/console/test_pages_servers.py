"""화면 시험: MCP 서버 목록·상세와 위험 동작."""


from console_pages_support import (
    ENUMS,
    INSTANCE,
    add_approval,
    form_post,
)


def test_status_names_are_korean_on_the_list_and_the_detail(admin):
    servers = admin.get("/servers").text
    assert "승인됨" in servers and "승인 대기" in servers
    for enum in ENUMS:
        assert enum not in servers
    detail = admin.get("/servers/srv-ok").text
    assert "approved" not in detail and "승인됨" in detail


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


def test_hsts_is_sent_and_server_links_are_url_encoded(world, admin):
    response = admin.get("/servers")
    assert "max-age=31536000" in response.headers["strict-transport-security"]
    world.query(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
        " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'a b\"c', 'awaiting_approval',"
        " %s, 'http', 'none', 'admin')", INSTANCE, "ab" * 32)
    html = admin.get("/servers").text
    assert 'href="/servers/a%20b%22c"' in html


def test_a_server_without_an_approved_contract_shows_the_provisional_badge(world, admin):
    html = admin.get("/servers").text
    assert "임시 계약" in html and html.count("data-dialog-open") == 1
    world.query("UPDATE mint.servers SET contract_status = 'managed' WHERE server_id = 'srv-ok'")
    managed = admin.get("/servers").text
    assert "일치" in managed
    assert 'href="/servers/srv-ok?tab=contract"' in managed
    assert "임시 계약" in admin.get("/servers?filter=provisional").text
    assert "srv-ok" not in admin.get("/servers?filter=provisional").text


def test_the_list_has_a_status_donut_whose_slices_filter_the_rows(world, admin):
    html = admin.get("/servers").text
    assert 'data-chart="' in html and "status=waiting" in html
    only = admin.get("/servers?status=waiting").text
    assert "srv-wait" in only and "srv-ok" not in only


def test_stopping_from_the_list_needs_the_name_and_returns_to_the_list(world, admin):
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'srv-ok'")[0][0]
    html = admin.get("/servers").text
    assert 'name="confirm_name" data-confirm="srv-ok"' in html
    ok = form_post(world, admin, "/servers/srv-ok/suspend", state_version=version,
                   confirm_name="srv-ok", next="/servers")
    assert ok.status_code == 303 and ok.headers["location"] == "/servers?ok=suspended"


def test_the_detail_is_split_into_tabs_and_a_viewer_gets_no_stop_button(world):
    viewer = world.session_client("viewer")
    for tab in ("overview", "contract", "tools", "packages", "vulns", "usage", "evidence"):
        assert viewer.get(f"/servers/srv-ok?tab={tab}").status_code == 200
    html = viewer.get("/servers/srv-ok").text
    assert "변경된 도구" in html and "data-dialog-open" not in html
    assert "임시 계약" in html
    assert "필수 증빙" not in html and "증빙 첨부" not in viewer.get(
        "/servers/srv-ok?tab=evidence").text


def test_an_unknown_tab_falls_back_to_the_overview_and_old_paths_still_redirect(world, admin):
    assert admin.get("/servers/srv-ok?tab=zz").status_code == 200
    moved = admin.get("/contracts/srv-ok?scope=server&name=echo", follow_redirects=False)
    assert moved.status_code == 303
    assert moved.headers["location"].startswith("/servers/srv-ok?tab=contract")
    assert admin.get("/contracts", follow_redirects=False).headers["location"] == (
        "/servers?filter=changed")


def test_the_contract_tab_shows_provisional_contracts_and_converts_them(world, admin):
    world.query(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, identity_kind,"
        " exec_contract_sha256, exec_contract_version, transport, auth_type, registered_by)"
        " VALUES (gen_random_uuid(), %s, 'loc', 'awaiting_approval', 'stdio', %s, 1, 'stdio',"
        " 'none', 'admin')", INSTANCE, "ab" * 32)
    world.query("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'loc'")
    world.query(
        "INSERT INTO mint.provisional_contracts (instance_id, server_id, tool, action_type,"
        " risk_grade, description, input_schema, input_keys) VALUES"
        " (%s, 'loc', 'read_file', 'read', 'low', 'd', '{\"type\":\"object\"}', '{path}')",
        INSTANCE)
    html = admin.get("/servers/loc?tab=contract").text
    assert "임시 계약" in html and "read_file" in html and "읽기" in html
    assert "승인해 계약으로 전환" in html
    version = world.query("SELECT state_version FROM mint.servers WHERE server_id = 'loc'")[0][0]
    done = form_post(world, admin, "/contracts/loc/approve-provisional", state_version=version)
    assert done.status_code == 303 and "ok=provisional_approved" in done.headers["location"]
    assert world.query("SELECT status FROM mint.tool_contracts WHERE tool = 'read_file'") == [
        ("approved",)]
    assert world.query("SELECT count(*) FROM mint.provisional_contracts")[0][0] == 0
