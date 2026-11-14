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
