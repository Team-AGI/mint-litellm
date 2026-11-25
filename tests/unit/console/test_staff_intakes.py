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
    assert "서버 신청" in client.get("/staff").text
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
        "SELECT status FROM mint.servers WHERE server_id='new_docs_example_com'") == [("pending",)]
    assert sworld.query("SELECT count(*) FROM mint.approvals") == [(0,)]
    assert client.get(response.headers["location"]).status_code == 200
    assert "new_docs" in client.get("/staff/intakes").text
    admin = sworld.session_client("admin")
    assert "new_docs" in admin.get("/intakes").text
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


def test_a_new_form_for_the_same_address_opens_the_existing_application(sworld):
    client = staff_tests.logged_in(sworld)
    original = form(client)
    assert client.post("/staff/intakes", data=original).status_code == 303
    response = client.post("/staff/intakes", data=form(client, purpose="다른 목적"))
    assert response.status_code == 303
    assert response.headers["location"] == (
        f"/staff/intakes/{original['request_id']}?ok=intake_existing")
    assert "이미 신청한 서버입니다" in client.get(response.headers["location"]).text
    assert sworld.query("SELECT purpose FROM mint.intakes") == [("공개 문서 조회",)]


def test_my_application_history_can_cancel_a_waiting_request(sworld):
    client = staff_tests.logged_in(sworld)
    values = form(client)
    assert client.post("/staff/intakes", data=values).status_code == 303
    history = client.get("/staff?tab=applications").text
    assert "내 신청 이력" in history and "대기 취소" in history
    version = sworld.query("SELECT state_version FROM mint.intakes")[0][0]
    response = client.post(f"/staff/intakes/{values['request_id']}/withdraw", data={
        "csrf": staff_tests.csrf(client), "state_version": version,
        "reason": "신청자 취소", "confirm": "yes",
    })
    assert response.status_code == 303
    assert "대기 취소" not in client.get("/staff?tab=applications").text


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
    # 허용 포트는 거절할 때만 알린다(신청 폼에 개발자식 포트 안내를 두지 않는다)
    assert "443, 8443" not in client.get("/staff/intakes/new").text
    response = client.post("/staff/intakes",
                           data=form(client, url="https://docs.example.com:8080/mcp"))
    assert response.status_code == 400
    assert "포트 8080" in response.text and "443, 8443" in response.text
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(0,)]


def test_staff_detail_shows_delivery_stages_for_an_approved_intake(sworld, monkeypatch):
    from mint_litellm.console import staff_pages

    real = staff_pages.staff_intakes.detail
    monkeypatch.setattr(staff_pages.staff_intakes, "detail",
                        lambda *a: {**real(*a), "status": "decided", "decision": "approved"})
    client = staff_tests.logged_in(sworld)
    values = form(client)
    location = client.post("/staff/intakes", data=values).headers["location"]
    sworld.query(
        "INSERT INTO mint.delivery_receipts (instance_id, intake_id, decision_version, stage)"
        " SELECT instance_id, id, 1, 'approved' FROM mint.intakes RETURNING 1")
    page = client.get(location.split("?")[0]).text
    assert 'aria-label="적용 단계"' in page and "LiteLLM 등록 대기" in page


SHA = "f" * 40
REPO = "https://github.com/o/ghidra-mcp"
COMMAND = f"uvx --from git+{REPO}@{SHA} ghidra-mcp"


def resolved(monkeypatch, **changes):
    from mint_litellm.control.services import local_intakes

    out = {"repo": REPO, "name": "ghidra_mcp", "commit": SHA, "command": COMMAND, "note": "",
           **changes}
    monkeypatch.setattr(local_intakes, "resolve", lambda url, fetch=None: out)


def test_a_repository_address_is_previewed_then_submitted_as_a_local_request(sworld, monkeypatch):
    resolved(monkeypatch)
    client = staff_tests.logged_in(sworld)
    values = {"csrf": staff_tests.csrf(client), "request_id": str(uuid.uuid4()), "url": REPO,
              "purpose": "분석 보조"}
    preview = client.post("/staff/intakes", data=values)
    assert preview.status_code == 200
    for text in ("ghidra_mcp", SHA, COMMAND, "로컬 MCP"):
        assert text in preview.text
    assert "소스 저장소 주소입니다" not in preview.text
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(0,)]
    done = client.post("/staff/intakes", data={
        **values, "step": "submit", "name": "ghidra_mcp", "commit": SHA, "command": COMMAND})
    assert done.status_code == 303, done.text
    row = sworld.query("SELECT source, server_id, requested_by, status FROM mint.intakes")[0]
    assert row == ("endpoint", "ghidra_mcp", staff_tests.STAFFER, "received")
    assert sworld.query(
        "SELECT identity_kind FROM mint.servers WHERE server_id='ghidra_mcp'") == [("stdio",)]
    assert client.get(done.headers["location"]).status_code == 200
    assert "ghidra_mcp" in client.get("/staff/intakes").text


def test_an_unresolved_repository_shows_the_reason_and_manual_fields(sworld, monkeypatch):
    resolved(monkeypatch, commit="", command="", note="GitHub에 연결하지 못했습니다. 직접 입력")
    client = staff_tests.logged_in(sworld)
    page = client.post("/staff/intakes", data={
        "csrf": staff_tests.csrf(client), "request_id": str(uuid.uuid4()), "url": REPO,
        "purpose": "분석"})
    assert page.status_code == 200 and "연결하지 못했습니다" in page.text
    assert 'name="commit"' in page.text and 'name="command"' in page.text


def test_a_wrong_command_returns_to_the_preview_with_the_reason(sworld, monkeypatch):
    client = staff_tests.logged_in(sworld)
    page = client.post("/staff/intakes", data={
        "csrf": staff_tests.csrf(client), "request_id": str(uuid.uuid4()), "url": REPO,
        "purpose": "분석", "step": "submit", "name": "ghidra_mcp", "commit": SHA,
        "command": "uvx other"})
    assert page.status_code == 400 and "이 커밋을 가리키는" in page.text
    assert 'name="command"' in page.text
