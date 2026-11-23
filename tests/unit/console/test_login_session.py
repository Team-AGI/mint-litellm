"""로그인(본인 키 확인)과 세션: 거부 경우 전부, 쿠키 속성, 만료, 폐기, 평문 키 비저장."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from console_fixtures import CONTROL_KEY, Keys, auth_error, token_of

from mint_litellm.console import login
from mint_litellm.console.core import COOKIE, ConsoleConfig
from mint_litellm.control.errors import ControlError


def attempt(world, key: str):
    return world.client.post("/login", data={"key": key})


def sessions(world):
    return world.query("SELECT id_hash, user_id, key_token, operator_name, role, revoked_at"
                       " FROM mint.console_sessions")


def refused(response, text: str) -> None:
    assert response.status_code in (401, 403), response.text
    assert text in response.text
    assert COOKIE not in response.cookies


def test_a_registered_operator_logs_in_with_their_own_key(world):
    response = attempt(world, Keys.admin)
    assert response.status_code == 303 and response.headers["location"] == "/"
    rows = sessions(world)
    assert len(rows) == 1
    _, user_id, key_token, name, role, revoked = rows[0]
    assert (user_id, name, role, revoked) == ("human-1", "admin", "admin", None)
    assert key_token == token_of(Keys.admin)


def test_the_session_cookie_is_host_bound_http_only_secure_and_strict(world):
    response = attempt(world, Keys.admin)
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("__host-mint_session=")
    assert "httponly" in cookie and "secure" in cookie
    assert "samesite=strict" in cookie and "path=/" in cookie and "domain" not in cookie


def test_plain_http_keeps_the_login_with_an_unprefixed_non_secure_cookie(world):
    # 브라우저는 HTTP 응답의 Secure·__Host- 쿠키를 버리므로 평문 운영에서는 접두사 없는 쿠키를 쓴다.
    http = world.client.__class__(world.app, base_url="http://testserver", follow_redirects=False)
    response = http.post("/login", data={"key": Keys.admin})
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("mint_session=") and "secure" not in cookie
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert http.get("/").status_code == 200
    # HTTPS 요청은 __Host- 이름만 읽으므로 평문으로 받은 쿠키는 세션으로 쓰이지 않는다.
    https = world.client.__class__(world.app, base_url="https://testserver", follow_redirects=False)
    https.cookies.set("mint_session", http.cookies["mint_session"])
    assert https.get("/").status_code == 303


def test_the_plain_key_is_never_stored(world):
    attempt(world, Keys.admin)
    stored = world.query(
        "SELECT (SELECT string_agg(t::text, ' ') FROM mint.console_sessions t) || ' ' ||"
        " (SELECT string_agg(e::text, ' ') FROM mint.events e)")[0][0]
    assert Keys.admin not in stored
    assert token_of(Keys.admin) in stored


def test_login_writes_a_session_started_event(world):
    attempt(world, Keys.admin)
    rows = world.query("SELECT kind, actor, source_key FROM mint.events"
                       " WHERE kind LIKE 'console_session_%'")
    assert [(r[0], r[1]) for r in rows] == [("console_session_started", "admin")]
    key = rows[0][2]
    assert key.startswith("console_session:") and key.endswith(":1:console_session_started")


def test_a_blocked_key_is_refused(world):
    world.stub.routes[("/key/info", "sk-blocked", None)] = (
        401, auth_error("Authentication Error, Key is blocked. Update via `/key/unblock`."))
    refused(attempt(world, "sk-blocked"), "차단된 키")


def test_a_key_the_server_reports_as_blocked_is_refused(world):
    world.stub.own("sk-flag", "human-1", blocked=True)
    refused(attempt(world, "sk-flag"), "차단된 키")


def test_an_expired_key_is_refused(world):
    world.stub.routes[("/key/info", "sk-old", None)] = (
        401, auth_error("Authentication Error - Expired Key. Key Expiry passed", "expired_key"))
    refused(attempt(world, "sk-old"), "만료된 키")


def test_an_expiry_in_the_key_info_is_refused(world):
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    world.stub.own("sk-past", "human-1", expires=past)
    refused(attempt(world, "sk-past"), "만료된 키")


def test_the_master_key_is_refused(world):
    # 마스터 키는 /key/info가 404이다(실측)
    world.stub.routes[("/key/info", "sk-master", None)] = (404, {"error": {"code": "404"}})
    world.stub.routes[("/user/info", "sk-master", None)] = (
        200, {"user_id": "default_user_id", "user_info": None, "keys": []})
    refused(attempt(world, "sk-master"), "키를 확인할 수 없습니다")


def test_an_unknown_key_is_refused(world):
    world.stub.routes[("/key/info", "sk-nope", None)] = (
        401, auth_error("Authentication Error, Invalid proxy server token passed.",
                        "token_not_found_in_db"))
    refused(attempt(world, "sk-nope"), "키를 확인할 수 없습니다")


def test_a_key_without_a_user_is_refused(world):
    world.stub.own("sk-service", None)
    refused(attempt(world, "sk-service"), "사람 사용자에 연결된 키가 아닙니다")


def test_a_missing_user_record_is_refused(world):
    world.stub.own("sk-ghost", "human-1")
    del world.stub.routes[("/user/info", "sk-ghost", None)]
    refused(attempt(world, "sk-ghost"), "사용자를 확인할 수 없습니다")


def test_a_non_human_user_is_refused(world):
    world.stub.own("sk-customer", "human-1", role="customer")
    refused(attempt(world, "sk-customer"), "사람 사용자의 키가 아닙니다")


def test_a_user_record_for_a_different_user_is_refused(world):
    world.stub.own("sk-mismatch", "human-1")
    world.stub.routes[("/user/info", "sk-mismatch", None)] = (
        200, {"user_id": "other", "user_info": {"user_id": "other", "user_role": "internal_user"}})
    refused(attempt(world, "sk-mismatch"), "사람 사용자의 키가 아닙니다")


def test_a_key_hash_that_does_not_match_is_refused(world):
    world.stub.own("sk-swap", "human-1")
    body = world.stub.routes[("/key/info", "sk-swap", None)][1]
    body["key"] = "0" * 64
    refused(attempt(world, "sk-swap"), "키를 확인할 수 없습니다")


def test_a_human_user_who_is_not_an_operator_is_refused(world):
    refused(attempt(world, Keys.stranger), "운영자로 등록된 사용자가 아닙니다")
    assert sessions(world) == []


def test_an_expired_operator_row_is_refused(world):
    world.query("UPDATE mint.operators SET expires_at = now() - interval '1 day'"
                " WHERE name = 'viewer'")
    refused(attempt(world, Keys.viewer), "운영자로 등록된 사용자가 아닙니다")


def test_an_empty_key_is_refused(world):
    refused(attempt(world, "   "), "키를 입력하십시오")


def test_an_unreachable_litellm_is_refused_with_a_clear_message(world):
    with pytest.raises(login.LoginRefused, match="연결할 수 없습니다"):
        login.verify("http://localhost:9", Keys.admin, timeout=1)


def test_the_login_calls_use_only_the_users_own_key(world):
    attempt(world, Keys.admin)
    assert {(path, bearer) for path, bearer, _ in world.stub.requests} == {
        ("/key/info", Keys.admin), ("/user/info", Keys.admin)}
    assert all(not params for _, _, params in world.stub.requests)


def test_a_session_resolves_until_it_is_revoked(world):
    client = world.session_client("approver")
    assert client.get("/").status_code == 200
    world.query("UPDATE mint.console_sessions SET revoked_at = now()")
    response = client.get("/")
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_an_idle_session_expires_after_the_idle_window(world):
    client = world.session_client()
    world.query("UPDATE mint.console_sessions SET idle_expiry = now() - interval '1 second'")
    assert client.get("/").status_code == 303


def test_activity_extends_the_idle_expiry_but_not_past_the_absolute_expiry(world):
    client = world.client_with(session_idle_seconds=3600, session_absolute_seconds=120)
    assert client.post("/login", data={"key": Keys.admin}).status_code == 303
    client.get("/")
    idle, absolute = world.query(
        "SELECT idle_expiry, absolute_expiry FROM mint.console_sessions")[0]
    assert idle == absolute


def test_an_absolute_expiry_ends_the_session_even_when_active(world):
    client = world.client_with(session_idle_seconds=1, session_absolute_seconds=1)
    assert client.post("/login", data={"key": Keys.admin}).status_code == 303
    time.sleep(1.2)
    assert client.get("/servers").status_code == 303


def test_the_default_windows_are_thirty_minutes_idle_and_eight_hours_absolute(world):
    world.session_client()
    idle, absolute, created = world.query(
        "SELECT idle_expiry - created_at, absolute_expiry - created_at, created_at"
        " FROM mint.console_sessions")[0]
    assert 1790 <= idle.total_seconds() <= 1800
    assert 28790 <= absolute.total_seconds() <= 28800


def test_logout_revokes_the_session_and_records_the_end(world):
    client = world.session_client()
    response = client.post("/logout", data={"csrf": world.csrf(client)})
    assert response.status_code == 303
    live = world.query("SELECT count(*) FROM mint.console_sessions WHERE revoked_at IS NULL")
    assert live[0][0] == 0
    kinds = [r[0] for r in world.query(
        "SELECT kind FROM mint.events WHERE kind LIKE 'console_session_%' ORDER BY inserted_at")]
    assert kinds == ["console_session_started", "console_session_ended"]
    assert client.get("/").status_code == 303


def test_an_invalid_session_cookie_is_treated_as_logged_out(world):
    world.client.cookies.set(COOKIE, "forged", domain="testserver.local")
    assert world.client.get("/").status_code == 303


def test_the_console_refuses_to_start_without_required_settings():
    with pytest.raises(ControlError):
        ConsoleConfig.from_env({"MINT_DATABASE_URL": "postgresql://x/y",
                                "MINT_LITELLM_URL": "http://x"})
    with pytest.raises(ControlError, match="MINT_LITELLM_URL"):
        ConsoleConfig.from_env({"MINT_DATABASE_URL": "postgresql://x/y",
                                "MINT_EXPORT_DIR": "/tmp",
                                "MINT_EXPORT_HMAC_KEY": "A" * 43})


def test_the_control_key_constant_is_not_used_for_login(world):
    attempt(world, Keys.admin)
    assert all(bearer != CONTROL_KEY for _, bearer, _ in world.stub.requests)


def test_logging_in_again_works_while_a_stale_session_cookie_is_present(world):
    client = world.session_client()
    world.query("UPDATE mint.console_sessions SET revoked_at = now()")
    response = client.post("/login", data={"key": Keys.admin})
    assert response.status_code == 303
    assert client.get("/").status_code == 200


def test_the_login_form_refuses_a_request_from_another_site(world):
    response = world.client.post(
        "/login", data={"key": Keys.admin}, headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    assert world.query("SELECT count(*) FROM mint.console_sessions")[0][0] == 0


def test_a_browser_that_sends_origin_null_is_accepted_when_fetch_metadata_says_same_origin(world):
    response = world.client.post(
        "/login", data={"key": Keys.admin},
        headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"})
    assert response.status_code == 303


def test_logout_and_expiry_clear_the_litellm_screen_cookie(world):
    client = world.session_client()
    response = client.post("/logout", data={"csrf": world.csrf(client)})
    assert any(h.lower().startswith("token=") and "max-age=0" in h.lower()
               and "samesite=lax" in h.lower()
               and "path=/" in h.lower() for h in response.headers.get_list("set-cookie"))
    client.cookies.set(COOKIE, "forged", domain="testserver.local")
    expired = client.get("/")
    assert expired.status_code == 303
    assert any(h.lower().startswith("token=") for h in expired.headers.get_list("set-cookie"))


def test_opening_the_console_without_a_mint_session_leaves_the_litellm_cookie(world):
    response = world.client.get("/")
    assert response.status_code == 303
    assert not any(h.lower().startswith("token=") for h in response.headers.get_list("set-cookie"))
