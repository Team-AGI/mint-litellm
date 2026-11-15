"""아이디·비밀번호 로그인(LiteLLM 화면 로그인에 위임)과 비밀번호 발급 도우미."""

import json
import re

import pytest
from console_fixtures import CONTROL_KEY, Keys, user_info

from mint_litellm.console.core import COOKIE, STAFF_COOKIE, ConsoleConfig
from mint_litellm.control import litellm_password
from mint_litellm.control.errors import ControlError

PASSWORD = "Correct-Horse-9"


def claims(user_id: str, email: str | None = "p@acme.test", **extra) -> dict:
    return {
        "user_id": user_id,
        "user_email": email,
        "user_role": "proxy_admin",
        "login_method": "username_password",
        **extra,
    }


@pytest.fixture
def pw(world):
    world.with_control_key()
    world.stub.logins["admin@acme.test"] = (PASSWORD, claims("human-1"))
    world.stub.logins["stranger@acme.test"] = (PASSWORD, claims("human-9"))
    return world


def attempt(world, username, password=PASSWORD, path="/login"):
    return world.client.post(path, data={"username": username, "password": password})


def sessions(world):
    return world.query("SELECT user_id, key_token, role FROM mint.console_sessions")


def refused(response, text, status=401):
    assert response.status_code == status, response.text
    assert text in response.text
    assert COOKIE not in response.cookies and STAFF_COOKIE not in response.cookies


def test_an_operator_signs_in_with_the_litellm_ui_credentials(pw):
    response = attempt(pw, "admin@acme.test")
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert COOKIE in pw.client.cookies
    [(user_id, key_token, role)] = sessions(pw)
    assert (user_id, role) == ("human-1", "admin") and key_token.startswith("pw:")
    assert pw.stub.posts == [("/v2/login", {"username": "admin@acme.test", "password": PASSWORD})]
    assert pw.client.get("/").status_code == 200


def test_the_audit_event_says_password_and_no_password_is_stored(pw):
    attempt(pw, "admin@acme.test")
    [(payload,)] = pw.query(
        "SELECT payload::text FROM mint.events WHERE kind = 'console_session_started'"
    )
    assert json.loads(payload)["method"] == "password"
    stored = pw.query(
        "SELECT (SELECT string_agg(t::text, ' ') FROM mint.console_sessions t)"
        " || ' ' || (SELECT string_agg(e::text, ' ') FROM mint.events e)"
    )[0][0]
    assert PASSWORD not in stored


def test_a_password_session_logs_out_locally_and_skips_key_checks(pw):
    from mint_litellm.control import session_verify

    attempt(pw, "admin@acme.test")
    token = pw.csrf(pw.client)
    response = pw.client.post("/logout", headers={"X-CSRF-Token": token}, data={"csrf": token})
    assert response.headers["location"] == "/login"
    session = {"key_token": "pw:" + "a" * 64, "user_id": "u", "subject": "admin", "role": "admin"}
    assert (
        session_verify.verdict(session, None, {"user_role": "internal_user"}, {"role": "admin"})
        is None
    )


def test_a_staff_member_signs_in_to_the_staff_screens(pw):
    response = attempt(pw, "stranger@acme.test", path="/staff/login")
    assert response.status_code == 303 and response.headers["location"] == "/staff"
    assert STAFF_COOKIE in pw.client.cookies


def test_a_wrong_password_is_refused_without_a_session(pw):
    refused(attempt(pw, "admin@acme.test", "wrong"), "아이디 또는 비밀번호가 올바르지 않습니다")
    refused(attempt(pw, "nobody@acme.test"), "아이디 또는 비밀번호")
    refused(attempt(pw, "", ""), "아이디와 비밀번호를 입력")
    assert sessions(pw) == []


def test_the_master_key_admin_is_not_a_person_and_is_refused(pw):
    pw.stub.logins["admin"] = (PASSWORD, claims("default_user_id", None))
    refused(attempt(pw, "admin"), "이름이 있는 관리자")
    pw.stub.logins["admin2"] = (PASSWORD, claims("default_user_id", "x@acme.test"))
    refused(attempt(pw, "admin2"), "이름이 있는 관리자")
    assert sessions(pw) == []


def test_a_user_who_is_not_an_operator_cannot_open_the_admin_console(pw):
    refused(attempt(pw, "stranger@acme.test"), "운영자로 등록된", 403)
    assert sessions(pw) == []


def test_a_service_account_is_not_a_person(pw):
    pw.stub.routes[("/user/info", CONTROL_KEY, "svc")] = (200, user_info("svc", "customer"))
    pw.stub.logins["svc@acme.test"] = (PASSWORD, claims("svc"))
    refused(attempt(pw, "svc@acme.test"), "사람 사용자가 아닙니다")


def test_a_password_that_must_be_changed_first_is_refused(pw):
    pw.stub.logins["admin@acme.test"] = (PASSWORD, claims("human-1", password_reset_required=True))
    refused(attempt(pw, "admin@acme.test"), "비밀번호를 먼저 바꾼")


def test_litellm_blocking_or_throttling_password_login_is_explained(pw):
    pw.stub.login_status = 403
    refused(attempt(pw, "nobody@acme.test"), "SSO로 로그인")
    pw.stub.login_status = 429
    refused(attempt(pw, "nobody@acme.test"), "시도가 너무 많습니다")


def test_failed_attempts_are_rate_limited(pw):
    for _ in range(10):
        attempt(pw, "admin@acme.test", "wrong")
    refused(attempt(pw, "admin@acme.test"), "시도가 너무 많습니다", 429)


def base_env(tmp_path) -> dict:
    return {
        "MINT_DATABASE_URL": "postgresql://x/y",
        "MINT_LITELLM_URL": "http://l",
        "MINT_EXPORT_DIR": str(tmp_path),
        "MINT_EXPORT_HMAC_KEY": "a" * 43,
    }


def test_key_login_is_off_by_default_and_hidden(pw, tmp_path):
    assert ConsoleConfig.from_env(base_env(tmp_path)).key_login is False
    assert ConsoleConfig.from_env({**base_env(tmp_path), "MINT_CONSOLE_KEY_LOGIN": "on"}).key_login
    object.__setattr__(pw.config, "key_login", False)
    for path in ("/login", "/staff/login"):
        page = pw.client.get(path).text
        assert 'name="username"' in page and 'name="password"' in page
        assert 'name="key"' not in page
    refused(
        pw.client.post("/login", data={"key": Keys.admin}), "키 로그인은 사용하지 않습니다", 403
    )
    refused(
        pw.client.post("/staff/login", data={"key": Keys.admin}),
        "키 로그인은 사용하지 않습니다",
        403,
    )
    assert sessions(pw) == []


def test_the_litellm_ui_link_is_shown_only_when_configured(pw):
    assert "LiteLLM 관리 화면" not in pw.client.get("/login").text
    object.__setattr__(pw.config, "litellm_ui_url", "https://gw.test/ui")
    assert 'href="https://gw.test/ui"' in pw.client.get("/login").text


def test_the_ui_url_must_be_an_http_address(tmp_path):
    env = {**base_env(tmp_path), "MINT_LITELLM_UI_URL": "https://gw.test/ui/"}
    assert ConsoleConfig.from_env(env).litellm_ui_url == "https://gw.test/ui"
    with pytest.raises(ControlError, match="MINT_LITELLM_UI_URL"):
        ConsoleConfig.from_env({**env, "MINT_LITELLM_UI_URL": "gw.test/ui"})


# --- 비밀번호 발급 도우미 -----------------------------------------------------------------


def with_user(world, email="p@acme.test"):
    world.stub.routes[("/user/info", "admin-key", "human-1")] = (
        200,
        {"user_info": {"user_id": "human-1", "user_email": email, "user_role": "internal_user"}},
    )


def test_a_generated_password_meets_the_litellm_default_rules():
    for _ in range(50):
        password = litellm_password.generate_password()
        assert len(password) >= 12 and re.search("[A-Z]", password)
        assert re.search("[a-z]", password) and re.search("[0-9]", password)


def test_set_password_updates_the_user_and_returns_the_login(world):
    with_user(world)
    login, password = litellm_password.set_password(world.stub.url, "admin-key", "human-1")
    assert login == "p@acme.test"
    assert world.stub.posts == [("/user/update", {"user_id": "human-1", "password": password})]
    assert world.stub.post_auth == ["Bearer admin-key"]


def test_set_password_can_set_the_email_and_refuses_what_it_cannot_do(world):
    with_user(world, email=None)
    with pytest.raises(ControlError, match="이메일이 없습니다"):
        litellm_password.set_password(world.stub.url, "admin-key", "human-1")
    login, _ = litellm_password.set_password(
        world.stub.url, "admin-key", "human-1", email="new@acme.test"
    )
    assert login == "new@acme.test"
    assert world.stub.posts[-1][1]["user_email"] == "new@acme.test"
    with pytest.raises(ControlError, match="MINT_LITELLM_ADMIN_KEY"):
        litellm_password.set_password(world.stub.url, "", "human-1")
    with pytest.raises(ControlError, match="없습니다"):
        litellm_password.set_password(world.stub.url, "admin-key", "ghost")
