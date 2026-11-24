"""가입 요청(비밀번호 포함)부터 승인, 계정 생성과 첫 로그인까지."""

import base64
import json
import uuid

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

PASSWORD = "example-password-12"


def submit(client, email, name="직원", password=PASSWORD, confirm=None, throttle=False):
    if not throttle:  # 분당 시도 제한은 마지막 단계에서만 시험한다
        client.app.state.attempts.clear()
    assert client.get("/staff/signup").status_code == 200
    return client.post("/staff/signup", data={
        "email": email, "name": name, "password": password,
        "confirm": password if confirm is None else confirm, "csrf": client.cookies[COOKIE]})


def run_job(world, lite, request_id):
    with psycopg.connect(world.admin_url, autocommit=True) as conn:
        signup.run(jobs.JobContext(
            conn, "inst1", {"kind": "staff_signup", "target_ref": str(request_id)}, litellm=lite))


def test_proxy_public_address_is_used_when_ui_address_is_empty(tmp_path):
    config = ConsoleConfig.from_env({
        "MINT_DATABASE_URL": "postgresql://example/test",
        "MINT_LITELLM_URL": "http://gateway",
        "MINT_EXPORT_DIR": str(tmp_path), "MINT_EXPORT_HMAC_KEY": "a" * 43,
        "MINT_LITELLM_UI_URL": " ", "PROXY_BASE_URL": "https://gateway.example.test/",
    })
    assert config.litellm_ui_url == "https://gateway.example.test"


def test_signup_flow(world, monkeypatch):
    monkeypatch.setenv("MINT_EXPORT_HMAC_KEY", "k" * 43)
    claimed = []
    monkeypatch.setattr(signup, "claim", lambda base, inv, pw: claimed.append((inv, pw)))
    client = world.client
    assert "가입 요청" in client.get("/staff/login").text
    assert "가입 요청" not in client.get("/login").text
    response = client.post("/staff/signup", data={"email": "x@example.test", "name": "직원"})
    assert response.status_code == 403
    assert "두 칸이 같아야" in submit(client, "person@example.test", confirm="other-pass-123").text
    assert "12자 이상" in submit(client, "person@example.test", password="short").text
    page = submit(client, "person@example.test").text
    assert "관리자가 승인하면 이 이메일과 비밀번호로 로그인할 수 있습니다" in page
    sealed, token = world.query(
        "SELECT password_sealed, status_token_hash FROM mint.signup_requests")[0]
    assert token is None and PASSWORD.encode() not in bytes(sealed)
    with as_login(world.admin_url, "mint_staff") as staff_conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            staff_conn.execute("SELECT * FROM mint.signup_requests")
    assert "이미 가입되었거나 요청 중입니다" in submit(client, "PERSON@example.test").text
    world.query("INSERT INTO mint.directory_users(instance_id,user_id,email,litellm_role)"
                " VALUES ('inst1','existing','exists@example.test','internal_user')")
    assert "이미 가입되었거나 요청 중입니다" in submit(client, "exists@example.test").text
    # 승인 전 로그인은 LiteLLM에 계정이 없어 거절되며, 가입 대기라고 알려 준다.
    client.app.state.attempts.clear()
    refused = client.post("/staff/login", data={"username": "person@example.test",
                                                "password": PASSWORD})
    assert refused.status_code == 401 and "가입 승인 대기 중" in refused.text

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
        fake.fail_writes["/invitation/new"] = 500
        with pytest.raises(Exception) as error:
            run_job(world, lite, request_id)
        assert getattr(error.value, "code", None) == "litellm_http_500"
        del fake.fail_writes["/invitation/new"]
        run_job(world, lite, request_id)
        assert len(fake.writes("/user/new")) == 1
        assert fake.writes("/user/new")[0][2] == {
            "user_email": "person@example.test", "user_alias": "직원",
            "user_role": "internal_user_viewer", "auto_create_key": False,
            "send_invite_email": False,
        }
        assert fake.writes("/invitation/new")[-1][2] == {"user_id": "user-1"}
        # 가입 때 받은 비밀번호로 초대를 확정하고 암호문은 지운다.
        assert claimed == [("invite-user-1", PASSWORD)]
        assert world.query("SELECT status, password_sealed FROM mint.signup_requests"
                           " WHERE id = %s", request_id) == [("approved", None)]
        assert "승인됨" in admin.get("/signup-requests").text
        assert "이미 가입되었거나 요청 중입니다" in submit(client, "person@example.test").text

        # 명부 동기화 전이어도 LiteLLM에 같은 이메일이 있으면 기존 사람을 재사용한다.
        submit(client, "second@example.test")
        second_id = world.query("SELECT id FROM mint.signup_requests WHERE email = %s",
                                "second@example.test")[0][0]
        assert admin.post(f"/signup-requests/{second_id}/approve", data={
            "csrf": world.csrf(admin)}).status_code == 303
        fake.users["existing-user"] = {
            "user_id": "existing-user", "user_email": "second@example.test",
        }
        run_job(world, lite, second_id)
        assert len(fake.writes("/user/new")) == 1
        assert fake.writes("/invitation/new")[-1][2] == {"user_id": "existing-user"}

        # 승인 뒤 첫 로그인에서 명부와 직원 세션이 즉시 만들어진다.
        world.with_control_key()
        user = user_info("user-1", "internal_user_viewer")
        user["user_info"]["user_email"] = "person@example.test"
        world.stub.routes[("/user/info", CONSOLE_KEY, "user-1")] = (200, user)
        world.stub.logins["person@example.test"] = (PASSWORD, {
            "user_id": "user-1", "user_email": "person@example.test",
        })
        client.app.state.attempts.clear()
        login = client.post("/staff/login", data={"username": "person@example.test",
                                                  "password": PASSWORD})
        assert login.status_code == 303 and login.headers["location"] == "/staff"
        assert world.query("SELECT email FROM mint.directory_users WHERE user_id = 'user-1'") == [
            ("person@example.test",)]

        submit(client, "failed@example.test")
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
                         " (instance_id,id,email,display_name,decided_at)"
                         " VALUES ('inst1',%s,'expired@example.test','직원',now())", (expired,))
            conn.execute("INSERT INTO mint.jobs (id,instance_id,kind,target_ref,max_attempts)"
                         " VALUES (%s,'inst1','staff_signup',%s,1)", (uuid.uuid4(), str(expired)))
            lost = jobs.lease(conn, "inst1", "lost", 30, ["staff_signup"])
            conn.execute("UPDATE mint.jobs SET lease_until = now() - interval '1 second'"
                         " WHERE id = %s", (lost["id"],))
            jobs.reclaim_expired(conn, "inst1", world.config.stage2)
            assert conn.execute("SELECT status,last_error FROM mint.signup_requests WHERE id=%s",
                                (expired,)).fetchone() == ("failed", "lease_expired")
        assert world.query("SELECT status, password_sealed FROM mint.signup_requests"
                           " WHERE id = %s", third_id) == [("failed", None)]
        assert "계정 만들기 실패" in admin.get("/signup-requests").text
        assert world.query("SELECT count(*) FROM mint.alerts WHERE kind = 'job_failed'")[0][0] == 2
    finally:
        fake._server.shutdown()
        fake._server.server_close()

    submit(client, "rejected@example.test")
    request_id = world.query("SELECT id FROM mint.signup_requests WHERE email = %s",
                             "rejected@example.test")[0][0]
    assert admin.post(f"/signup-requests/{request_id}/reject", data={
        "csrf": world.csrf(admin), "reason": "정보 확인 필요"}).status_code == 303
    assert world.query("SELECT password_sealed FROM mint.signup_requests WHERE id = %s",
                       request_id) == [(None,)]
    client.app.state.attempts.clear()
    refused = client.post("/staff/login", data={"username": "rejected@example.test",
                                                "password": PASSWORD})
    assert "거절되었습니다" in refused.text and "정보 확인 필요" in refused.text
    for _ in range(11):
        response = submit(client, "throttled@example.test", throttle=True)
        if response.status_code == 429:
            break
    assert response.status_code == 429


def test_the_password_is_sealed_per_request_and_claimed_through_litellm(monkeypatch):
    monkeypatch.setenv("MINT_EXPORT_HMAC_KEY", "k" * 43)
    sealed = signup.seal("inst1", "r1", PASSWORD)
    assert signup.unseal("inst1", "r1", sealed) == PASSWORD
    with pytest.raises(signup.SignupError):
        signup.unseal("inst1", "r2", sealed)  # 다른 요청의 암호문으로는 풀리지 않는다

    inner = base64.urlsafe_b64encode(json.dumps({"user_id": "u1", "key": "onboard"}).encode())
    calls = []

    def fake(base, method, path, body=None, bearer=None):
        calls.append((method, path, body, bearer))
        if path.startswith("/onboarding/get_token"):
            return 200, {"token": "h." + inner.decode().rstrip("=") + ".s"}
        return 200, {}

    monkeypatch.setattr(signup, "_call", fake)
    signup.claim("http://litellm:4000", "inv-1", PASSWORD)
    assert calls[1] == ("POST", "/onboarding/claim_token",
                        {"invitation_link": "inv-1", "user_id": "u1", "password": PASSWORD},
                        "onboard")
    monkeypatch.setattr(signup, "_call", lambda base, method, path, body=None, bearer=None: (
        fake(base, method, path) if "get_token" in path else (400, {"detail": "too weak"})))
    with pytest.raises(signup.SignupError) as error:
        signup.claim("x", "inv-1", PASSWORD)
    assert error.value.code == "password_policy"
