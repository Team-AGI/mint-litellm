import uuid

import psycopg
import pytest
from ctl_fixtures import INSTANCE, as_login

from . import test_staff_pages as staff_tests

sworld = staff_tests.sworld


def form(client, **changes):
    return {"csrf": staff_tests.csrf(client), "request_id": str(uuid.uuid4()),
            "url": "https://new-docs.example.com/mcp", "transport": "http",
            "purpose": "공개 문서 조회", "data_grade": "public", "resources": "docs\nmanuals",
            "credential_notice": "담당자 통지", "revocation_record": "관리 기록",
            "audit_access_days": "90", "data_return_terms": "종료 시 삭제", **changes}


def test_staff_form_and_submission_reach_the_admin_intake_queue(sworld):
    client = staff_tests.logged_in(sworld)
    assert "MCP 서버 도입 신청" in client.get("/staff").text
    page = client.get("/staff/intakes/new")
    assert page.status_code == 200 and 'name="csrf"' in page.text
    values = form(client, owner_user_id="forged", requested_by="forged", org_id="other")
    response = client.post("/staff/intakes", data=values)
    assert response.status_code == 303, response.text
    row = sworld.query("SELECT requested_by,owner_user_id,org_id,source,status,"
                       " staff_registry_required"
                       " FROM mint.intakes")[0]
    assert row == (staff_tests.STAFFER, staff_tests.STAFFER, "acme", "staff", "received", True)
    assert sworld.query("SELECT kind,target_ref,status FROM mint.jobs") == [
        ("intake_run", values["request_id"] + "/staff", "pending")]
    assert sworld.query(
        "SELECT status FROM mint.servers WHERE server_id='new-docs-example-com'") == [("pending",)]
    assert sworld.query("SELECT count(*) FROM mint.approvals") == [(0,)]
    assert client.get(response.headers["location"]).status_code == 200
    assert "new-docs" in client.get("/staff/intakes").text
    admin = sworld.session_client("admin")
    assert "new-docs" in admin.get("/intakes").text
    assert "직원 신청" in admin.get("/intakes").text


def test_replayed_form_is_idempotent_and_changed_payload_does_not_replace_it(sworld):
    client = staff_tests.logged_in(sworld)
    values = form(client)
    for _ in range(2):
        assert client.post("/staff/intakes", data=values).status_code == 303
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(1,)]
    assert sworld.query("SELECT count(*) FROM mint.events WHERE kind='intake_received'") == [(1,)]
    assert client.post("/staff/intakes", data={**values, "purpose": "changed"}).status_code == 409
    assert sworld.query("SELECT purpose FROM mint.intakes") == [("공개 문서 조회",)]


def test_other_staff_cannot_read_or_overwrite_an_introduction(sworld):
    client = staff_tests.logged_in(sworld)
    values = form(client)
    assert client.post("/staff/intakes", data=values).status_code == 303
    other = staff_tests.logged_in(sworld, staff_tests.OTHER_KEY)
    assert "new-docs" not in other.get("/staff/intakes").text
    assert other.get("/staff/intakes/" + values["request_id"]).status_code == 404
    assert other.post("/staff/intakes", data=form(other)).status_code == 409
    assert sworld.query("SELECT requested_by FROM mint.intakes") == [(staff_tests.STAFFER,)]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "https://u:p@example.com/mcp",
                                    "https://example.com/mcp?key=secret", "https://example.com/#x",
                                    "https://example.com:99999/mcp", "https://example.com/\npath"])
def test_invalid_or_credential_urls_never_create_an_intake(sworld, url):
    client = staff_tests.logged_in(sworld)
    response = client.post("/staff/intakes", data=form(client, url=url))
    assert response.status_code == 400
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(0,)]


def test_submission_requires_csrf_and_does_not_change_an_approved_server(sworld):
    client = staff_tests.logged_in(sworld)
    assert client.post("/staff/intakes", data=form(client, csrf="wrong")).status_code == 403
    joined = client.post("/staff/intakes", data=form(client, url="https://srv-ok/mcp"))
    assert joined.status_code == 409
    assert sworld.query("SELECT status FROM mint.servers WHERE server_id='srv-ok'") == [
        ("approved",)]
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(0,)]


def test_staff_database_role_cannot_write_an_intake_without_the_session_function(sworld):
    with as_login(sworld.admin_url, "mint_staff") as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
            conn.execute("INSERT INTO mint.intakes(id) VALUES(gen_random_uuid())")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
            conn.execute("SELECT mint.staff_submit_intake(%s,'{}'::jsonb,'{}')", (uuid.uuid4(),))
    assert sworld.query("SELECT count(*) FROM mint.intakes WHERE instance_id=%s", INSTANCE) == [
        (0,)]


def test_a_port_outside_the_allowed_list_is_refused_on_the_form_not_recorded(sworld):
    # 접수 뒤 자동 거절되는 대신 화면에서 허용 포트를 알려 고치게 한다.
    client = staff_tests.logged_in(sworld)
    page = client.get("/staff/intakes/new")
    # 허용 포트 표시(종료 준비 문구는 입력받지 않고 기본값으로 채운다)
    assert "443, 8443" in page.text
    response = client.post("/staff/intakes",
                           data=form(client, url="https://docs.example.com:8080/mcp"))
    assert response.status_code == 400
    assert "포트 8080" in response.text and "443, 8443" in response.text
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(0,)]
