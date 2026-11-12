"""직원 화면: 로그인(운영자 행 없이)·세션·소속 팀·화면 11~13·거부 경우.

직원 연결은 실제 ``mint_staff_app`` 로그인으로 접속하므로 표를 직접 읽거나 쓰지 못한다.
"""

import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from console_fixtures import CONTROL_KEY, key_info, token_of
from ctl_fixtures import INSTANCE, as_login

from mint_litellm.console.core import COOKIE, STAFF_COOKIE
from mint_litellm.control import jobs, session_verify
from mint_litellm.control.litellm_admin import LiteLLMAdmin

HEX = "ab" * 32
STAFFER = "human-4"
OTHER = "human-5"
HARNESS = "sk-staff-harness"
CONSOLE = "sk-staff-console"
OTHER_KEY = "sk-other-staff"


@pytest.fixture
def sworld(world):
    """운영자가 아닌 직원 두 명(같은 조직)과 본인 확인에 필요한 정책 판본이 있는 배치."""
    for key, user in ((HARNESS, STAFFER), (CONSOLE, STAFFER), (OTHER_KEY, OTHER)):
        world.stub.own(key, user)
        world.stub.control(key, user)
    with psycopg.connect(world.admin_url) as admin:
        for user in (STAFFER, OTHER):
            admin.execute(
                "INSERT INTO mint.org_bindings (id, instance_id, org_id, subject_type,"
                " subject_id, created_by) VALUES (gen_random_uuid(), %s, 'acme', 'user', %s,"
                " 'root')",
                (INSTANCE, user),
            )
        admin.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
            " VALUES (%s, 'v1', %s, %s)",
            (INSTANCE, HEX, HEX),
        )
    return world


def staff_login(world, key: str):
    client = world.client.__class__(
        world.app, base_url="https://testserver", follow_redirects=False
    )
    response = client.post("/staff/login", data={"key": key})
    return client, response


def logged_in(world, key: str = CONSOLE):
    client, response = staff_login(world, key)
    assert response.status_code == 303, response.text
    return client


def csrf(client) -> str:
    from mint_litellm.control.services.console_sessions import csrf_token

    return csrf_token(client.cookies[STAFF_COOKIE])


def add_confirmation(world, user=STAFFER, *, requested_key=HARNESS, tool="send_mail",
                     display=None, minutes=10, org="acme"):
    cid = uuid.uuid4()
    with psycopg.connect(world.admin_url) as admin:
        admin.execute(
            "INSERT INTO mint.self_confirmations (id, instance_id, org_id, principal_id,"
            " server_id, tool, args_fp, fp_key_version, policy_version_id, purpose,"
            " requested_by_key_token, expires_at, display)"
            " VALUES (%s, %s, %s, %s, 'srv-ok', %s, %s, 1, 'v1', '결제',"
            " %s, %s, %s::jsonb)",
            (cid, INSTANCE, org, user, tool, HEX, token_of(requested_key),
             datetime.now(UTC) + timedelta(minutes=minutes), display),
        )
    return str(cid)


def decide(client, cid: str, decision: str):
    return client.post(f"/staff/confirmations/{cid}/{decision}", data={"csrf": csrf(client)})


def status_of(world, cid: str) -> str:
    return world.query("SELECT status FROM mint.self_confirmations WHERE id = %s", cid)[0][0]


# --- 로그인·세션 ------------------------------------------------------------------------------


def test_a_human_who_is_not_an_operator_logs_in_to_the_staff_screens(sworld):
    client, response = staff_login(sworld, CONSOLE)
    assert response.status_code == 303 and response.headers["location"] == "/staff"
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("__host-mint_staff=")
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie
    rows = sworld.query("SELECT subject, user_id, role, operator_name, key_token"
                        " FROM mint.console_sessions")
    assert rows == [("staff", STAFFER, "staff", None, token_of(CONSOLE))]
    assert client.get("/staff").status_code == 200


def test_the_same_key_cannot_open_the_admin_console_without_an_operator_row(sworld):
    response = sworld.client.post("/login", data={"key": CONSOLE})
    assert response.status_code == 403


@pytest.mark.parametrize("key, text", [
    ("sk-unknown", "키를 확인할 수 없습니다"),
    ("", "키를 입력하십시오"),
])
def test_staff_login_refuses_unknown_and_empty_keys(sworld, key, text):
    client, response = staff_login(sworld, key)
    assert response.status_code == 401 and text in response.text
    assert STAFF_COOKIE not in response.cookies


def test_a_service_account_key_without_a_user_cannot_log_in(sworld):
    sworld.stub.own("sk-service", None)
    _, response = staff_login(sworld, "sk-service")
    assert response.status_code == 401


def test_staff_login_writes_a_session_event_and_stores_no_plain_key(sworld):
    logged_in(sworld)
    kinds = sworld.query("SELECT kind, actor, payload->>'subject' FROM mint.events"
                         " WHERE kind LIKE 'console_session_%'")
    assert kinds == [("console_session_started", STAFFER, "staff")]
    stored = sworld.query(
        "SELECT (SELECT string_agg(t::text, ' ') FROM mint.console_sessions t) || ' ' ||"
        " (SELECT string_agg(e::text, ' ') FROM mint.events e)")[0][0]
    assert CONSOLE not in stored and token_of(CONSOLE) in stored


def test_the_staff_cookie_does_not_open_admin_pages_or_the_api(sworld):
    client = logged_in(sworld)
    session_id = client.cookies[STAFF_COOKIE]
    for path in ("/", "/servers", "/approvals", "/ledger", "/admin"):
        response = client.get(path)
        assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.get("/api/v1/servers").status_code == 401
    forged = client.__class__(sworld.app, base_url="https://testserver", follow_redirects=False)
    forged.cookies.set(COOKIE, session_id)
    assert forged.get("/").status_code == 303
    assert forged.get("/api/v1/servers").status_code == 401


def test_the_admin_cookie_does_not_open_staff_screens(sworld):
    admin = sworld.session_client("admin")
    session_id = admin.cookies[COOKIE]
    assert admin.get("/staff").status_code == 303
    admin.cookies.set(STAFF_COOKIE, session_id)
    response = admin.get("/staff")
    assert response.status_code == 303 and response.headers["location"] == "/staff/login"


def test_logout_revokes_the_staff_session_and_records_it(sworld):
    client = logged_in(sworld)
    response = client.post("/staff/logout", data={"csrf": csrf(client)})
    assert response.status_code == 303 and response.headers["location"] == "/staff/login"
    assert client.get("/staff").status_code == 303
    ended = sworld.query("SELECT actor FROM mint.events WHERE kind = 'console_session_ended'")
    assert ended == [(STAFFER,)]


def test_a_staff_request_without_a_csrf_token_is_refused(sworld):
    client = logged_in(sworld)
    cid = add_confirmation(sworld, requested_key=HARNESS)
    assert client.post(f"/staff/confirmations/{cid}/reject").status_code == 403
    assert status_of(sworld, cid) == "pending"


# --- 소속 팀 ----------------------------------------------------------------------------------


def test_teams_come_from_the_key_info_only_never_from_the_user_info_or_the_request(sworld):
    sworld.stub.own("sk-team", STAFFER, team_id="team-key")
    sworld.stub.routes[("/user/info", "sk-team", None)] = (
        200, {"user_id": STAFFER, "keys": [], "user_info": {
            "user_id": STAFFER, "user_role": "internal_user", "teams": ["team-user", 7]}})
    logged_in(sworld, "sk-team")
    teams = sworld.query("SELECT team_ids FROM mint.console_sessions")[0][0]
    assert teams == ["team-key"]


def test_a_key_without_a_team_has_an_empty_team_list(sworld):
    logged_in(sworld)
    assert sworld.query("SELECT team_ids FROM mint.console_sessions") == [([],)]


def test_session_verification_refreshes_the_teams_of_a_staff_session(sworld):
    logged_in(sworld)
    sworld.stub.control(CONSOLE, STAFFER, team_id="team-new")
    run_verify(sworld)
    assert sworld.query("SELECT team_ids FROM mint.console_sessions") == [(["team-new"],)]


def test_every_verification_replaces_the_team_list_including_removal_and_a_new_owner_ends_it(
    sworld
):
    client = logged_in(sworld)
    for team, expected in (("team-a", ["team-a"]), ("team-b", ["team-b"]), (None, [])):
        sworld.stub.control(CONSOLE, STAFFER, **({"team_id": team} if team else {}))
        run_verify(sworld)
        assert sworld.query("SELECT team_ids FROM mint.console_sessions") == [(expected,)]
    body = key_info("someone-else")
    body["key"] = token_of(CONSOLE)
    sworld.stub.routes[("/key/info", CONTROL_KEY, token_of(CONSOLE))] = (200, body)
    run_verify(sworld)  # 키 소유자가 바뀌면 세션을 폐기한다
    assert sworld.query("SELECT revoked_at IS NOT NULL FROM mint.console_sessions") == [(True,)]
    assert client.get("/staff").status_code == 303


def test_session_verification_revokes_a_staff_session_of_a_blocked_key(sworld):
    client = logged_in(sworld)
    sworld.stub.control(CONSOLE, STAFFER, blocked=True)
    run_verify(sworld)
    assert sworld.query("SELECT revoked_at IS NOT NULL FROM mint.console_sessions") == [(True,)]
    assert client.get("/staff").status_code == 303


def run_verify(world):
    conn = as_login(world.admin_url, "mint_worker")
    conn.autocommit = True
    try:
        litellm = LiteLLMAdmin(world.stub.url, CONTROL_KEY)
        session_verify.run(jobs.JobContext(conn, INSTANCE, {}, None, litellm))
    finally:
        conn.close()



# --- 11 사용 가능한 서버·도구 -------------------------------------------------------------------


def add_approval(world, scope_type, scope_id, tools=("echo", "ping"), server_id="srv-ok",
                 org_id="acme"):
    relation = world.query(
        "SELECT id FROM mint.usage_relations WHERE server_id = %s AND org_id = %s",
        server_id, org_id)[0][0]
    world.query(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by,"
        " status) VALUES (gen_random_uuid(), %s, %s, %s, 'standard', %s, %s, %s, %s, now(),"
        " now() + interval '30 days', '{}', 'admin', 'x', 'active')",
        INSTANCE, org_id, relation, server_id, list(tools), scope_type, scope_id)


TEAM_USER = "human-6"
TEAM_KEY = "sk-team-user"


def team_world(world):
    """팀에만 묶인 직원(조직 beta): 사용자 바인딩이 없고 키 정보에 팀이 있다."""
    world.stub.own(TEAM_KEY, TEAM_USER, team_id="team-x")
    world.stub.control(TEAM_KEY, TEAM_USER, team_id="team-x")
    world.stub.own("sk-teamless", TEAM_USER)
    world.stub.control("sk-teamless", TEAM_USER)
    with psycopg.connect(world.admin_url) as admin:
        admin.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, 'beta',"
                      " 'beta사')", (INSTANCE,))
        admin.execute(
            "INSERT INTO mint.org_bindings (id, instance_id, org_id, subject_type, subject_id,"
            " created_by) VALUES (gen_random_uuid(), %s, 'beta', 'team', 'team-x', 'root')",
            (INSTANCE,))
        admin.execute(
            "INSERT INTO mint.usage_relations (id, instance_id, org_id, purpose, server_id)"
            " VALUES (gen_random_uuid(), %s, 'beta', '업무', 'srv-ok')", (INSTANCE,))


def test_the_server_screen_lists_servers_with_the_tools_approved_for_this_user(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    add_approval(sworld, "user", OTHER, tools=("secret_tool",))
    add_approval(sworld, "org", "acme", tools=("ping",))
    page = logged_in(sworld).get("/staff")
    assert page.status_code == 200
    assert "사용 가능한 서버·도구" in page.text and "srv-ok" in page.text
    assert "echo, ping" in page.text and "secret_tool" not in page.text
    assert "srv-wait" not in page.text
    assert "HTTP" in page.text and "없음" in page.text


def test_a_staff_member_without_an_organization_sees_an_empty_screen(sworld):
    sworld.stub.own("sk-loner", "human-7")
    sworld.stub.control("sk-loner", "human-7")
    page = logged_in(sworld, "sk-loner").get("/staff")
    assert page.status_code == 200 and "쓸 수 있는 서버가 없습니다" in page.text
    assert "srv-ok" not in page.text


def test_a_team_bound_staff_member_sees_the_servers_of_the_team_organization(sworld):
    team_world(sworld)
    add_approval(sworld, "team", "team-x", tools=("deploy",), org_id="beta")
    add_approval(sworld, "team", "team-y", tools=("other_team_tool",), org_id="beta")
    page = logged_in(sworld, TEAM_KEY).get("/staff")
    assert "beta사" in page.text and "deploy" in page.text and "other_team_tool" not in page.text
    assert "A사" not in page.text


def test_a_key_scoped_approval_is_shown_only_to_that_key(sworld):
    add_approval(sworld, "key", token_of(CONSOLE), tools=("key_only",))
    assert "key_only" in logged_in(sworld, CONSOLE).get("/staff").text
    assert "key_only" not in logged_in(sworld, HARNESS).get("/staff").text


# --- 12 본인 확인 요청 ------------------------------------------------------------------------


def test_the_confirmation_screen_lists_only_own_pending_requests_in_korean(sworld):
    mine = add_confirmation(sworld, display='{"받는 사람": "a@example.com"}')
    theirs = add_confirmation(sworld, OTHER, requested_key=OTHER_KEY, tool="their_tool")
    page = logged_in(sworld).get("/staff/confirmations")
    assert page.status_code == 200
    assert mine in page.text and theirs not in page.text and "their_tool" not in page.text
    assert "확인 대기" in page.text and "결제" in page.text
    assert "받는 사람" in page.text and "a@example.com" in page.text
    for english in ("pending", "confirmed", "rejected"):
        assert english not in page.text


def test_a_different_key_confirms_the_request(sworld):
    cid = add_confirmation(sworld, display='{"받는 사람": "a@example.com"}')
    client = logged_in(sworld, CONSOLE)
    response = decide(client, cid, "confirm")
    assert response.status_code == 303 and "ok=staff_confirmed" in response.headers["location"]
    assert status_of(sworld, cid) == "confirmed"
    row = sworld.query("SELECT confirmed_by_user_id, confirmed_by_key_token"
                       " FROM mint.self_confirmations WHERE id = %s", cid)[0]
    assert row == (STAFFER, token_of(CONSOLE))
    events = sworld.query("SELECT kind, actor, payload->>'kind' FROM mint.events"
                          " WHERE kind = 'call_approval_approved'")
    assert events == [("call_approval_approved", STAFFER, "confirmation")]
    after = client.get("/staff/confirmations")
    assert "확인됨" in after.text and "a@example.com" in after.text


def test_the_same_key_as_the_call_cannot_confirm_but_can_reject(sworld):
    cid = add_confirmation(sworld, requested_key=CONSOLE)
    client = logged_in(sworld, CONSOLE)
    page = client.get("/staff/confirmations")
    assert "다른 키로 로그인해야 확인할 수 있습니다" in page.text and "disabled" in page.text
    refused = decide(client, cid, "confirm")
    assert refused.status_code == 403 and "다른 키로 로그인하십시오" in refused.text
    assert status_of(sworld, cid) == "pending"
    assert decide(client, cid, "reject").status_code == 303
    assert status_of(sworld, cid) == "rejected"


def test_reject_and_cancel_clear_the_display_and_leave_no_value_in_events(sworld):
    first = add_confirmation(sworld, display='{"비밀 값": "SECRET-ONE"}')
    second = add_confirmation(sworld, tool="other_tool", display='{"비밀 값": "SECRET-TWO"}')
    client = logged_in(sworld, CONSOLE)
    assert decide(client, first, "reject").status_code == 303
    assert decide(client, second, "confirm").status_code == 303
    assert decide(client, second, "cancel").status_code == 303
    assert sworld.query("SELECT display FROM mint.self_confirmations"
                        " WHERE id IN (%s, %s)", first, second) == [(None,), (None,)]
    page = client.get("/staff/confirmations")
    assert "SECRET" not in page.text and "취소됨" in page.text and "거절됨" in page.text
    everything = sworld.query("SELECT string_agg(e::text, ' ') FROM mint.events e")[0][0]
    assert "SECRET" not in everything


def test_a_decided_confirmation_cannot_be_decided_again(sworld):
    cid = add_confirmation(sworld)
    client = logged_in(sworld, CONSOLE)
    assert decide(client, cid, "reject").status_code == 303
    again = decide(client, cid, "confirm")
    assert again.status_code == 409 and status_of(sworld, cid) == "rejected"


def test_an_expired_confirmation_shows_as_expired_and_cannot_be_confirmed(sworld):
    cid = add_confirmation(sworld, minutes=-1)
    client = logged_in(sworld, CONSOLE)
    page = client.get("/staff/confirmations")
    assert "만료" in page.text and "확인할 요청이 없습니다" in page.text
    response = decide(client, cid, "confirm")
    assert response.status_code == 409 and status_of(sworld, cid) == "pending"


def test_another_users_confirmation_cannot_be_decided(sworld):
    theirs = add_confirmation(sworld, OTHER, requested_key=OTHER_KEY)
    client = logged_in(sworld, CONSOLE)
    for decision in ("confirm", "reject", "cancel"):
        assert decide(client, theirs, decision).status_code == 404
    assert status_of(sworld, theirs) == "pending"
    assert decide(client, str(uuid.uuid4()), "confirm").status_code == 404
    assert decide(client, "not-a-uuid", "confirm").status_code == 400
    assert decide(client, theirs, "explode").status_code == 404


def test_a_team_bound_staff_member_confirms_and_a_teamless_login_is_refused(sworld):
    team_world(sworld)
    cid = add_confirmation(sworld, TEAM_USER, requested_key=HARNESS, org="beta")
    teamless = logged_in(sworld, "sk-teamless")
    assert decide(teamless, cid, "confirm").status_code == 403
    assert status_of(sworld, cid) == "pending"
    member = logged_in(sworld, TEAM_KEY)
    assert decide(member, cid, "confirm").status_code == 303
    assert status_of(sworld, cid) == "confirmed"
    assert decide(member, cid, "cancel").status_code == 303
    assert status_of(sworld, cid) == "cancelled"


def test_a_revoked_session_cannot_decide(sworld):
    cid = add_confirmation(sworld)
    client = logged_in(sworld, CONSOLE)
    sworld.query("UPDATE mint.console_sessions SET revoked_at = now()")
    assert decide(client, cid, "confirm").status_code == 303
    assert status_of(sworld, cid) == "pending"


def test_a_long_display_value_is_clipped_to_256_characters_on_screen(sworld):
    add_confirmation(sworld, display='{"본문": "' + "x" * 300 + '"}')
    page = logged_in(sworld).get("/staff/confirmations")
    assert "x" * 256 + "…" in page.text and "x" * 257 not in page.text


def test_display_values_are_escaped(sworld):
    add_confirmation(sworld, display='{"<b>키</b>": "<script>alert(1)</script>"}')
    page = logged_in(sworld).get("/staff/confirmations")
    assert "<script>alert" not in page.text and "&lt;script&gt;" in page.text


# --- 13 동의 관리와 내 기록 -------------------------------------------------------------------


def grant(client, **overrides):
    data = {"csrf": csrf(client), "target": "acme|srv-ok", "purpose": "고객 응대",
            "data_scope": "이메일 주소", "text_version": "v1", "valid_days": "30"}
    data.update(overrides)
    return client.post("/staff/consents", data=data)


def consents_of(world, user=STAFFER):
    return world.query("SELECT id, source, purpose, data_scope, text_version, revoked_at,"
                       " registered_by FROM mint.consents WHERE human_user_id = %s", user)


def test_a_staff_member_grants_a_purpose_consent_for_themselves(sworld):
    client = logged_in(sworld)
    response = grant(client)
    assert response.status_code == 303 and "ok=consent_given" in response.headers["location"]
    (row,) = consents_of(sworld)
    assert row[1:5] == ("self_service", "고객 응대", "이메일 주소", "v1")
    assert row[5] is None and row[6] == STAFFER
    kinds = sworld.query("SELECT kind, actor FROM mint.events WHERE kind = 'consent_granted'")
    assert kinds == [("consent_granted", STAFFER)]
    page = client.get("/staff/consents")
    assert "고객 응대" in page.text and "이메일 주소" in page.text and "유효" in page.text
    assert "동의 부여" in page.text


def test_the_consent_screen_shows_the_consent_text_and_the_maximum_period(sworld):
    page = logged_in(sworld).get("/staff/consents")
    assert "철회할 수 있습니다" in page.text
    assert 'max="90"' in page.text and 'name="text_version" value="v1"' in page.text


@pytest.mark.parametrize("override, text", [
    ({"valid_days": "91"}, "1일에서 90일"),
    ({"valid_days": "0"}, "1일에서 90일"),
    ({"text_version": "v0"}, "동의 문구"),
    ({"target": "beta|srv-ok"}, "활성 상태의 조직"),
    ({"target": "acme|srv-wait"}, "승인된 서버가 아니어서"),
    ({"target": "acme|nothing"}, "이용 관계"),
])
def test_consent_requests_outside_the_limits_are_refused(sworld, override, text):
    client = logged_in(sworld)
    response = grant(client, **override)
    assert response.status_code in (400, 403), response.text
    assert text in response.text
    assert consents_of(sworld) == []


def test_an_empty_purpose_is_refused(sworld):
    response = grant(logged_in(sworld), purpose="")
    assert response.status_code == 400 and consents_of(sworld) == []


def test_the_consent_limit_comes_from_the_settings_not_the_request(sworld):
    client = sworld.client_with(staff_consent_max_days=7)
    client.post("/staff/login", data={"key": CONSOLE})
    assert grant(client, valid_days="8").status_code == 400
    assert grant(client, valid_days="7").status_code == 303


def test_consent_can_be_withdrawn_and_cannot_be_withdrawn_twice(sworld):
    client = logged_in(sworld)
    grant(client)
    cid = str(consents_of(sworld)[0][0])
    response = client.post(f"/staff/consents/{cid}/revoke", data={"csrf": csrf(client)})
    assert response.status_code == 303 and "ok=consent_withdrawn" in response.headers["location"]
    assert consents_of(sworld)[0][5] is not None
    page = client.get("/staff/consents")
    assert "철회됨" in page.text and "동의 철회" in page.text
    again = client.post(f"/staff/consents/{cid}/revoke", data={"csrf": csrf(client)})
    assert again.status_code == 403


def test_another_users_consent_is_not_listed_or_withdrawable(sworld):
    other = logged_in(sworld, OTHER_KEY)
    grant(other, purpose="타인 동의")
    cid = str(consents_of(sworld, OTHER)[0][0])
    mine = logged_in(sworld, CONSOLE)
    assert "타인 동의" not in mine.get("/staff/consents").text
    response = mine.post(f"/staff/consents/{cid}/revoke", data={"csrf": csrf(mine)})
    assert response.status_code == 403
    assert consents_of(sworld, OTHER)[0][5] is None


def test_a_team_bound_staff_member_grants_consent_only_in_the_team_organization(sworld):
    team_world(sworld)
    member = logged_in(sworld, TEAM_KEY)
    assert grant(member, target="beta|srv-ok").status_code == 303
    assert grant(member, target="acme|srv-ok").status_code == 403
    teamless = logged_in(sworld, "sk-teamless")
    assert grant(teamless, target="beta|srv-ok").status_code == 403
    assert [r[2] for r in consents_of(sworld, TEAM_USER)] == ["고객 응대"]


def test_the_record_section_lists_only_own_events_with_korean_names(sworld):
    cid = add_confirmation(sworld)
    other = add_confirmation(sworld, OTHER, requested_key=OTHER_KEY)
    mine = logged_in(sworld, CONSOLE)
    decide(mine, cid, "confirm")
    grant(mine)
    other_client = logged_in(sworld, OTHER_KEY)
    decide(other_client, other, "reject")
    grant(other_client, purpose="타인 동의")
    page = mine.get("/staff/consents")
    assert "본인 확인 확정" in page.text and "동의 부여" in page.text
    assert "직원 화면 로그인" in page.text
    assert "본인 확인 거절" not in page.text
    for english in ("consent_granted", "call_approval", "console_session"):
        assert english not in page.text


def test_signing_in_works_while_an_expired_staff_cookie_is_still_in_the_browser(sworld):
    client = logged_in(sworld)
    sworld.query("UPDATE mint.console_sessions SET revoked_at = now()")
    assert client.get("/staff").status_code == 303
    response = client.post("/staff/login", data={"key": CONSOLE})
    assert response.status_code == 303 and response.headers["location"] == "/staff"
    assert client.get("/staff").status_code == 200


def test_a_denied_tool_or_server_is_not_listed_as_usable(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo", "ping"))
    deny = ("INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, server_id,"
            " tools, reason, created_by) VALUES (gen_random_uuid(), %s, NULL, 'user', %s,"
            " 'srv-ok', %s, '시험', 'admin')")
    sworld.query(deny, INSTANCE, STAFFER, ["ping"])
    page = logged_in(sworld).get("/staff")
    assert "echo" in page.text and "ping" not in page.text
    sworld.query("UPDATE mint.denials SET lifted_at = now(), lifted_by = 'admin'")
    assert "echo, ping" in logged_in(sworld).get("/staff").text
    sworld.query("INSERT INTO mint.denials (id, instance_id, scope_type, scope_id, server_id,"
                 " reason, created_by) VALUES (gen_random_uuid(), %s, 'server', 'srv-ok',"
                 " 'srv-ok', '시험', 'admin')",
                 INSTANCE)
    page = logged_in(sworld).get("/staff")
    assert "쓸 수 있는 서버가 없습니다" in page.text


def test_a_server_without_any_approval_for_the_user_is_not_listed(sworld):
    page = logged_in(sworld).get("/staff")
    assert "쓸 수 있는 서버가 없습니다" in page.text
    assert "srv-ok" in logged_in(sworld).get("/staff/consents").text


def test_revoking_a_users_operator_sessions_leaves_their_staff_session_alone(sworld):
    from mint_litellm.control.services import console_sessions

    sworld.stub.own("sk-both", "human-1")
    sworld.stub.control("sk-both", "human-1")
    staff_client_ = logged_in(sworld, "sk-both")
    admin = sworld.session_client("admin")
    with psycopg.connect(sworld.admin_url) as conn:
        count = console_sessions.revoke_user_sessions(
            conn, INSTANCE, "human-1", actor="root", reason="operator_changed")
    assert count == 1
    assert admin.get("/").status_code == 303
    assert staff_client_.get("/staff").status_code == 200
    ended = sworld.query("SELECT payload->>'subject' FROM mint.events"
                         " WHERE kind = 'console_session_ended'")
    assert ended == [("admin",)]


def test_a_staff_session_starts_with_its_team_list_in_one_statement(sworld):
    sworld.stub.own("sk-team2", STAFFER, team_id="team-z")
    logged_in(sworld, "sk-team2")
    assert sworld.query("SELECT team_ids FROM mint.console_sessions") == [(["team-z"],)]


def test_staff_pages_are_not_kept_in_the_browser_history_cache(sworld):
    add_confirmation(sworld, display='{"받는 사람": "a@example.com"}')
    client = logged_in(sworld)
    for path in ("/staff", "/staff/confirmations", "/staff/consents"):
        response = client.get(path)
        assert 'hx-history="false"' in response.text, path
        assert response.headers["cache-control"] == "no-store", path


def test_the_record_section_never_shows_operator_actions_with_the_same_name(sworld):
    def event(kind, source_key, payload="{}", actor=STAFFER):
        sworld.query(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
            " VALUES (gen_random_uuid(), %s, %s, %s, %s, %s::jsonb)",
            INSTANCE, kind, source_key, actor, payload)

    event("approval_granted", f"approval:{uuid.uuid4()}:1:approval_granted")
    event("server_suspended", f"server:{uuid.uuid4()}:2:server_suspended")
    event("call_approval_approved", f"call_approval:{uuid.uuid4()}:2:call_approval_approved")
    event("consent_granted", f"consent:{uuid.uuid4()}:1:consent_granted")
    event("console_session_started", f"console_session:{'44' * 32}:1:console_session_started",
          '{"subject": "admin"}')
    records = logged_in(sworld).get("/staff/consents").text.rsplit("<h2>내 기록", 1)[1]
    for label in ("승인", "서버 중지", "동의 부여", "콘솔 로그인"):
        assert label not in records, label
    assert "직원 화면 로그인" in records


# --- 14 단말 설치 -----------------------------------------------------------------------------


class KitIssuer:
    """키 발급 클라이언트 대역."""

    def __init__(self):
        self.made, self.deleted = [], []

    def generate_kit_key(self, *, user_id, team_id, alias):
        self.made.append((user_id, team_id, alias))
        return f"sk-kit-{alias}"

    def delete_kit_keys(self, aliases):
        self.deleted.append(list(aliases))


@pytest.fixture
def kits(sworld):
    """승인된 로컬 서버 하나가 있고 키 발급이 설정된 배치."""
    import dataclasses

    from ctl_fixtures import make_ctx

    from mint_litellm.control import servers
    from mint_litellm.types.exec_contract import ExecContract

    contract = ExecContract(
        executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
    )
    with psycopg.connect(sworld.admin_url) as admin:
        servers.register_local(make_ctx(admin), "local-1", contract)
        admin.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'local-1'")
    issuer = KitIssuer()
    sworld.stub.own(CONSOLE, STAFFER, team_id="team-a")  # 세션의 첫 팀이 키에 걸린다.
    sworld.app.state.config = dataclasses.replace(
        sworld.config, kit_issuer=issuer, endpoint_url="https://mint.test"
    )
    sworld.issuer = issuer
    return sworld


def download(client):
    return client.post("/staff/endpoint/kit", data={"csrf": csrf(client)})


def unpack(response):
    import io
    import json
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as bundle:
        return json.loads(bundle.extractfile("mint-kit/kit.json").read())


def test_the_download_hands_out_a_kit_with_the_users_own_key_and_the_approved_servers(kits):
    client = logged_in(kits)
    response = download(client)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert "mint-kit.tar.gz" in response.headers["content-disposition"]
    config = unpack(response)
    ((user, team, alias),) = kits.issuer.made
    assert (user, team) == (STAFFER, "team-a") and config["key"] == f"sk-kit-{alias}"
    assert config["decide_url"] == "https://mint.test" and list(config["servers"]) == ["local-1"]
    ((stored_token, owner, stored_alias),) = kits.query(
        "SELECT key_token, user_id, key_alias FROM mint.endpoint_installs")
    assert (stored_token, owner, stored_alias) == (token_of(config["key"]), STAFFER, alias)


def test_a_second_download_replaces_the_first_key_and_other_users_are_untouched(kits):
    first = download(logged_in(kits))
    other = download(logged_in(kits, OTHER_KEY))
    second = download(logged_in(kits))
    assert first.status_code == other.status_code == second.status_code == 200
    assert kits.issuer.deleted == [[kits.issuer.made[0][2]]]
    rows = kits.query(
        "SELECT user_id, revoked_at IS NOT NULL FROM mint.endpoint_installs ORDER BY issued_at")
    assert rows == [(STAFFER, True), (OTHER, False), (STAFFER, False)]


def test_the_page_shows_the_managed_and_the_unmanaged_state_in_korean(kits):
    client = logged_in(kits)
    download(client)
    page = client.get("/staff/endpoint").text
    assert "보고 전" in page and "다시 내려받기" in page
    assert "team-a" in client.get("/staff/endpoint").text
    kits.query("UPDATE mint.endpoint_installs SET install_mode = 'user', kit_version = 'k',"
               " claude_version = '2.1.0', mcp_servers = '[\"local-1\"]', reported_at = now()")
    page = client.get("/staff/endpoint").text
    assert "관리되지 않음" in page and "2.1.0" in page and "local-1" in page
    for enum in ("managed", "pending", "removed", "revoked"):
        assert enum not in page
    admin = kits.session_client("admin")
    table = admin.get("/endpoints").text
    assert "관리되지 않음" in table and STAFFER in table and "team-a" in table
    api = admin.get("/api/v1/endpoint/installs").json()["items"]
    assert [(r["user_id"], r["state"]) for r in api] == [(STAFFER, "user")]


def test_only_the_owner_sees_the_rows_and_revoking_disconnects_the_devices(kits):
    client = logged_in(kits)
    download(client)
    assert "보고 전" not in logged_in(kits, OTHER_KEY).get("/staff/endpoint").text
    response = client.post("/staff/endpoint/revoke", data={"csrf": csrf(client)})
    assert response.status_code == 303 and response.headers["location"].endswith("ok=kit_revoked")
    assert kits.issuer.deleted == [[kits.issuer.made[0][2]]]
    assert "연결 해제" in client.get("/staff/endpoint").text
    again = client.post("/staff/endpoint/revoke", data={"csrf": csrf(client)})
    assert again.status_code == 400 and "해제할 단말 연결이 없습니다" in again.text


def test_without_key_issuance_or_approved_servers_there_is_no_kit(sworld):
    client = logged_in(sworld)
    refused = download(client)
    assert refused.status_code == 503 and "발급할 수 없습니다" in refused.text
    assert sworld.query("SELECT count(*) FROM mint.endpoint_installs") == [(0,)]
    import dataclasses

    sworld.app.state.config = dataclasses.replace(sworld.config, kit_issuer=KitIssuer())
    empty = download(client)
    assert empty.status_code == 409 and "승인된 로컬 서버가 없습니다" in empty.text


def test_the_download_needs_a_staff_session_and_a_csrf_token(kits):
    client = logged_in(kits)
    assert client.post("/staff/endpoint/kit").status_code == 403
    anonymous = kits.client.__class__(
        kits.app, base_url="https://testserver", follow_redirects=False
    )
    assert anonymous.post("/staff/endpoint/kit").status_code in (303, 403)
    assert kits.issuer.made == []
