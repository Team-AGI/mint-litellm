"""가입 요청부터 승인, 계정 생성과 상태 확인까지."""

import hashlib
import uuid
from urllib.parse import urlsplit

import psycopg
import pytest
from console_fixtures import CONTROL_KEY as CONSOLE_KEY
from console_fixtures import user_info
from ctl_fixtures import as_login
from fake_litellm import CONTROL_KEY, FakeLiteLLM

from mint_litellm.console.core import ConsoleConfig
from mint_litellm.console.signup import COOKIE
from mint_litellm.control import jobs, signup
from mint_litellm.control.litellm_control import LiteLLMControl
from mint_litellm.control.worker import Worker


def submit(client, email, name="직원"):
    assert client.get("/staff/signup").status_code == 200
    return client.post("/staff/signup", data={"email": email, "name": name,
                                             "csrf": client.cookies[COOKIE]})


def test_proxy_public_address_is_used_when_ui_address_is_empty(tmp_path):
    config = ConsoleConfig.from_env({
        "MINT_DATABASE_URL": "postgresql://example/test",
        "MINT_LITELLM_URL": "http://gateway",
        "MINT_EXPORT_DIR": str(tmp_path), "MINT_EXPORT_HMAC_KEY": "a" * 43,
        "MINT_LITELLM_UI_URL": " ", "PROXY_BASE_URL": "https://gateway.example.test/",
    })
    assert config.litellm_ui_url == "https://gateway.example.test"


def test_signup_flow(world):
    client = world.client
    object.__setattr__(world.config, "litellm_ui_url", "https://gateway.example.test/ui")
    assert "가입 요청" in client.get("/staff/login").text
    assert "가입 요청" not in client.get("/login").text
    response = client.post("/staff/signup", data={"email": "x@example.test", "name": "직원"})
    assert response.status_code == 403
    response = submit(client, "person@example.test")
    assert response.status_code == 303
    path = urlsplit(response.headers["location"]).path
    token = path.rsplit("/", 1)[1]
    assert world.query("SELECT status_token_hash FROM mint.signup_requests") == [
        (hashlib.sha256(token.encode()).hexdigest(),)]
    assert "가입 요청을 받았습니다" in client.get(response.headers["location"]).text
    assert "승인 대기 중" in client.get(path).text
    with as_login(world.admin_url, "mint_staff") as staff_conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            staff_conn.execute("SELECT * FROM mint.signup_requests")
    assert client.get("/staff/signup/invalid").status_code == 404
    assert "이미 가입되었거나 요청 중입니다" in submit(client, "PERSON@example.test").text
    world.query("INSERT INTO mint.directory_users(instance_id,user_id,email,litellm_role)"
                " VALUES ('inst1','existing','exists@example.test','internal_user')")
    assert "이미 가입되었거나 요청 중입니다" in submit(client, "exists@example.test").text

    admin = world.session_client("admin")
    approver = world.session_client("approver")
    assert approver.get("/signup-requests").status_code == 403
    page = admin.get("/signup-requests")
    assert page.status_code == 200 and "person@example.test" in page.text
    request_id = world.query("SELECT id FROM mint.signup_requests")[0][0]
    response = admin.post(f"/signup-requests/{request_id}/approve",
                          data={"csrf": world.csrf(admin)})
    assert response.status_code == 303
    assert "계정 만들기 대기" in admin.get("/signup-requests").text
    assert admin.post(f"/signup-requests/{request_id}/reject", data={
        "csrf": world.csrf(admin)}).status_code == 404

    fake = FakeLiteLLM()
    try:
        lite = LiteLLMControl(fake.url, CONTROL_KEY)
        with psycopg.connect(world.admin_url, autocommit=True) as conn:
            ctx = jobs.JobContext(
                conn, "inst1", {"kind": "staff_signup", "target_ref": str(request_id)},
                litellm=lite,
            )
            fake.fail_writes["/invitation/new"] = 500
            with pytest.raises(Exception) as error:
                signup.run(ctx)
            assert getattr(error.value, "code", None) == "litellm_http_500"
            signup.record_failure(conn, "inst1", request_id, "litellm_http_500", "pending")
            del fake.fail_writes["/invitation/new"]
            signup.run(ctx)
        assert len(fake.writes("/user/new")) == 1
        assert fake.writes("/user/new")[0][2] == {
            "user_email": "person@example.test", "user_alias": "직원",
            "user_role": "internal_user_viewer", "auto_create_key": False,
            "send_invite_email": False,
        }
        assert fake.writes("/invitation/new")[-1][2] == {"user_id": "user-1"}
        page = client.get(path).text
        # 직원은 MINT 화면에서 바로 비밀번호를 정한다. LiteLLM 초대 주소는 관리자 화면에만 있다.
        assert "비밀번호 정하기" in page and 'name="password"' in page
        expected = "https://gateway.example.test/ui/onboarding?invitation_id=invite-user-1"
        assert expected not in page
        listing = admin.get("/signup-requests").text
        assert "복사" in listing and expected in listing
        assert "이미 가입되었거나 요청 중입니다" in submit(client, "person@example.test").text

        # 명부 동기화 전이어도 LiteLLM에 같은 이메일이 있으면 기존 사람을 재사용한다.
        second = submit(client, "second@example.test")
        second_id = world.query("SELECT id FROM mint.signup_requests WHERE email = %s",
                                "second@example.test")[0][0]
        assert admin.post(f"/signup-requests/{second_id}/approve", data={
            "csrf": world.csrf(admin)}).status_code == 303
        fake.users["existing-user"] = {
            "user_id": "existing-user", "user_email": "second@example.test",
        }
        with psycopg.connect(world.admin_url, autocommit=True) as conn:
            ctx = jobs.JobContext(
                conn, "inst1", {"kind": "staff_signup", "target_ref": str(second_id)},
                litellm=lite,
            )
            signup.run(ctx)
        assert len(fake.writes("/user/new")) == 1
        assert fake.writes("/invitation/new")[-1][2] == {"user_id": "existing-user"}
        assert "비밀번호 정하기" in client.get(urlsplit(second.headers["location"]).path).text

        # 비밀번호를 정한 첫 로그인에서 명부와 직원 세션이 즉시 만들어진다.
        world.with_control_key()
        user = user_info("user-1", "internal_user_viewer")
        user["user_info"]["user_email"] = "person@example.test"
        world.stub.routes[("/user/info", CONSOLE_KEY, "user-1")] = (200, user)
        world.stub.logins["person@example.test"] = ("example-password", {
            "user_id": "user-1", "user_email": "person@example.test",
        })
        login = client.post("/staff/login", data={"username": "person@example.test",
                                                  "password": "example-password"})
        assert login.status_code == 303 and login.headers["location"] == "/staff"
        assert world.query("SELECT email FROM mint.directory_users WHERE user_id = 'user-1'") == [
            ("person@example.test",)]

        third = submit(client, "failed@example.test")
        third_id = world.query("SELECT id FROM mint.signup_requests WHERE email = %s",
                               "failed@example.test")[0][0]
        assert admin.post(f"/signup-requests/{third_id}/approve", data={
            "csrf": world.csrf(admin)}).status_code == 303
        fake.fail_writes["/user/new"] = 500
        with psycopg.connect(world.admin_url, autocommit=True) as conn, \
                psycopg.connect(world.admin_url, autocommit=True) as beat:
            conn.execute("UPDATE mint.jobs SET max_attempts = 2 WHERE kind = 'staff_signup'"
                         " AND target_ref = %s", (str(third_id),))
            task = jobs.lease(conn, "inst1", "signup-test", 30, ["staff_signup"])
            # 앞의 두 작업은 직접 실행했으므로 대기 행을 완료로 바꾸고 실패 대상을 임대한다.
            while task and task["target_ref"] != str(third_id):
                jobs.complete(conn, task["id"], "signup-test")
                task = jobs.lease(conn, "inst1", "signup-test", 30, ["staff_signup"])
            assert task is not None
            worker = Worker(world.admin_url, "inst1", world.config.stage2, litellm=lite,
                            owner="signup-test")
            worker.conn, worker._beat_conn = conn, beat
            worker._run(task)
            assert conn.execute("SELECT status,last_error FROM mint.signup_requests WHERE id=%s",
                                (third_id,)).fetchone() == ("pending", "litellm_http_500")
            conn.execute("UPDATE mint.jobs SET run_after = now() WHERE id = %s", (task["id"],))
            task = jobs.lease(conn, "inst1", "signup-test", 30, ["staff_signup"])
            assert task is not None
            worker._run(task)
            expired = uuid.uuid4()
            conn.execute("INSERT INTO mint.signup_requests"
                         " (instance_id,id,email,display_name,status_token_hash,decided_at)"
                         " VALUES ('inst1',%s,'expired@example.test','직원',%s,now())",
                         (expired, "a" * 64))
            conn.execute("INSERT INTO mint.jobs (id,instance_id,kind,target_ref,max_attempts)"
                         " VALUES (%s,'inst1','staff_signup',%s,1)", (uuid.uuid4(), str(expired)))
            lost = jobs.lease(conn, "inst1", "lost", 30, ["staff_signup"])
            conn.execute("UPDATE mint.jobs SET lease_until = now() - interval '1 second'"
                         " WHERE id = %s", (lost["id"],))
            jobs.reclaim_expired(conn, "inst1", world.config.stage2)
            assert conn.execute("SELECT status,last_error FROM mint.signup_requests WHERE id=%s",
                                (expired,)).fetchone() == ("failed", "lease_expired")
        assert world.query("SELECT status FROM mint.signup_requests WHERE id = %s", third_id) == [
            ("failed",)]
        assert "계정 만들기 실패" in admin.get("/signup-requests").text
        assert "관리자에게 문의" in client.get(urlsplit(third.headers["location"]).path).text
        assert world.query("SELECT count(*) FROM mint.alerts WHERE kind = 'job_failed'")[0][0] == 2
    finally:
        fake._server.shutdown()
        fake._server.server_close()

    rejected = submit(client, "rejected@example.test")
    rejected_path = urlsplit(rejected.headers["location"]).path
    request_id = world.query("SELECT id FROM mint.signup_requests WHERE email = %s",
                             "rejected@example.test")[0][0]
    assert admin.post(f"/signup-requests/{request_id}/reject", data={
        "csrf": world.csrf(admin), "reason": "정보 확인 필요"}).status_code == 303
    assert "정보 확인 필요" in client.get(rejected_path).text
    for _ in range(11):
        response = submit(client, "throttled@example.test")
        if response.status_code == 429:
            break
    assert response.status_code == 429


def test_claim_invitation_sets_the_password_through_litellm_without_storing_it(monkeypatch):
    import base64
    import json

    from mint_litellm.console import signup

    inner = base64.urlsafe_b64encode(json.dumps({"user_id": "u1", "key": "onboard"}).encode())
    calls = []

    def fake(base, method, path, body=None, bearer=None):
        calls.append((method, path, body, bearer))
        if path.startswith("/onboarding/get_token"):
            return 200, {"token": "h." + inner.decode().rstrip("=") + ".s"}
        return 200, {}

    monkeypatch.setattr(signup, "_litellm", fake)
    assert signup.claim_invitation("http://litellm:4000", "inv-1", "longpassword12") is None
    assert calls[1] == ("POST", "/onboarding/claim_token",
                        {"invitation_link": "inv-1", "user_id": "u1", "password": "longpassword12"},
                        "onboard")
    monkeypatch.setattr(signup, "_litellm", lambda *a, **k: (
        401, {"detail": {"error": "Invitation link has already been used."}}))
    assert "이미 비밀번호를 정했습니다" in signup.claim_invitation("x", "inv-1", "longpassword12")
