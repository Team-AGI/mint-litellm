"""작업 session_verify: 제어 평면 키로 세션의 키·사용자·운영자 행을 다시 확인하고 폐기한다."""

import psycopg
import pytest
from console_fixtures import CONTROL_KEY, Keys, key_info, token_of
from ctl_fixtures import INSTANCE, as_login

from mint_litellm.control import jobs, session_verify
from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin, LiteLLMError
from mint_litellm.control.services import console_sessions
from mint_litellm.control.stage2_config import Stage2Settings


@pytest.fixture
def verify(world):
    """작업 실행기 로그인으로 session_verify를 한 번 실행하는 함수."""
    conn = as_login(world.admin_url, "mint_worker")
    conn.autocommit = True
    litellm = LiteLLMAdmin(world.stub.url, CONTROL_KEY)

    def run(client=None):
        session_verify.run(jobs.JobContext(conn, INSTANCE, {}, None, litellm))

    yield run
    conn.close()


def live(world):
    return world.query("SELECT user_id FROM mint.console_sessions WHERE revoked_at IS NULL")


def end_reasons(world):
    return [r[0] for r in world.query(
        "SELECT payload->>'reason' FROM mint.events WHERE kind = 'console_session_ended'")]


def test_a_healthy_session_is_kept_and_marked_verified(world, verify):
    world.session_client()
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '1 hour'")
    verify()
    assert live(world) == [("human-1",)]
    age = world.query("SELECT now() - last_verified_at FROM mint.console_sessions")[0][0]
    assert age.total_seconds() < 30


def test_verification_reads_the_key_by_hash_with_the_control_key_only(world, verify):
    world.session_client()
    world.stub.requests.clear()
    verify()
    assert world.stub.requests == [
        ("/key/info", CONTROL_KEY, {"key": token_of(Keys.admin)}),
        ("/user/info", CONTROL_KEY, {"user_id": "human-1"}),
    ]


def test_a_blocked_key_revokes_the_session(world, verify):
    client = world.session_client()
    world.stub.control(Keys.admin, "human-1", blocked=True)
    verify()
    assert live(world) == [] and end_reasons(world) == ["key_blocked"]
    assert client.get("/").status_code == 303


def test_an_expired_key_revokes_the_session(world, verify):
    world.session_client()
    world.stub.control(Keys.admin, "human-1", expires="2000-01-01T00:00:00+00:00")
    verify()
    assert end_reasons(world) == ["key_expired"]


def test_a_deleted_key_archive_is_not_an_active_key(world, verify):
    world.session_client()
    world.stub.control(Keys.admin, "human-1", deleted_at="2026-01-01T00:00:00+00:00",
                       deleted_by="x")
    verify()
    assert end_reasons(world) == ["key_gone"]


def test_a_key_that_no_longer_exists_revokes_the_session(world, verify):
    world.session_client()
    del world.stub.routes[("/key/info", CONTROL_KEY, token_of(Keys.admin))]
    verify()
    assert end_reasons(world) == ["key_gone"]


def test_a_user_who_is_no_longer_human_revokes_the_session(world, verify):
    world.session_client()
    world.stub.control(Keys.admin, "human-1", role="customer")
    verify()
    assert end_reasons(world) == ["user_not_human"]


def test_a_key_that_moved_to_another_user_revokes_the_session(world, verify):
    world.session_client()
    body = key_info("someone-else")
    body["key"] = token_of(Keys.admin)
    world.stub.routes[("/key/info", CONTROL_KEY, token_of(Keys.admin))] = (200, body)
    verify()
    assert end_reasons(world) == ["key_owner_changed"]


def test_removing_the_operator_row_revokes_the_session(world, verify):
    world.session_client("approver")
    world.query("DELETE FROM mint.operators WHERE name = 'approver'")
    verify()
    assert end_reasons(world) == ["operator_changed"]


def test_changing_the_operator_role_revokes_the_session(world, verify):
    world.session_client("approver")
    world.query("UPDATE mint.operators SET role = 'viewer' WHERE name = 'approver'")
    verify()
    assert end_reasons(world) == ["operator_changed"]


def test_only_the_sessions_that_fail_are_revoked(world, verify):
    world.session_client("admin")
    world.session_client("viewer")
    world.stub.control(Keys.viewer, "human-3", blocked=True)
    verify()
    assert live(world) == [("human-1",)]


def test_an_unreachable_litellm_fails_the_job_without_revoking(world):
    world.session_client()
    conn = as_login(world.admin_url, "mint_worker")
    conn.autocommit = True
    broken = LiteLLMAdmin("http://localhost:9", CONTROL_KEY, timeout=1)
    with pytest.raises(LiteLLMError):
        session_verify.run(jobs.JobContext(conn, INSTANCE, {}, None, broken))
    conn.close()
    assert live(world) == [("human-1",)]


def test_the_job_has_a_handler_and_a_five_minute_schedule(world):
    assert "session_verify" in jobs.HANDLERS
    settings = Stage2Settings.from_env(
        {"MINT_EXPORT_DIR": "/tmp/x", "MINT_EXPORT_HMAC_KEY": "A" * 43})
    assert jobs.SCHEDULES["session_verify"](settings) == 300


def test_revoking_a_users_sessions_ends_all_of_them(world):
    world.session_client("approver")
    world.session_client("approver")
    with psycopg.connect(world.admin_url) as conn:
        count = console_sessions.revoke_user_sessions(
            conn, INSTANCE, "human-2", actor="admin", reason="operator_changed")
    assert count == 2 and live(world) == []



def test_an_unreachable_litellm_keeps_a_session_for_two_periods_then_revokes_it(world):
    world.session_client("admin")
    world.session_client("viewer")
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '9 minutes'"
                " WHERE user_id = 'human-1'")
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '11 minutes'"
                " WHERE user_id = 'human-3'")
    conn = as_login(world.admin_url, "mint_worker")
    conn.autocommit = True
    broken = LiteLLMAdmin("http://localhost:9", CONTROL_KEY, timeout=1)
    settings = Stage2Settings.from_env(
        {"MINT_EXPORT_DIR": "/tmp/x", "MINT_EXPORT_HMAC_KEY": "A" * 43})
    with pytest.raises(LiteLLMError):
        session_verify.run(jobs.JobContext(conn, INSTANCE, {}, settings, broken))
    conn.close()
    assert live(world) == [("human-1",)]
    assert end_reasons(world) == ["unverified"]


def test_the_console_holds_the_control_key_only_through_a_read_only_client():
    from mint_litellm.console.core import ReadOnlyLiteLLM

    client = ReadOnlyLiteLLM(LiteLLMAdmin("http://localhost:9", CONTROL_KEY))
    assert sorted(vars(client)) == [
        "get_key", "get_server", "get_team", "get_user", "list_servers", "spend_guardrail"]


def test_without_a_control_key_unverified_sessions_are_revoked_after_two_periods(world):
    world.session_client("admin")
    world.session_client("viewer")
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '9 minutes'"
                " WHERE user_id = 'human-1'")
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '11 minutes'"
                " WHERE user_id = 'human-3'")
    conn = as_login(world.admin_url, "mint_worker")
    conn.autocommit = True
    settings = Stage2Settings.from_env(
        {"MINT_EXPORT_DIR": "/tmp/x", "MINT_EXPORT_HMAC_KEY": "A" * 43})
    with pytest.raises(ControlError, match="제어 평면 키"):
        session_verify.run(jobs.JobContext(conn, INSTANCE, {}, settings, None))
    conn.close()
    assert live(world) == [("human-1",)]
    assert end_reasons(world) == ["unverified"]


def test_a_session_not_verified_within_two_periods_is_refused_on_every_request(world):
    """작업 실행기가 멈춰 session_verify가 돌지 않아도 요청마다 10분 기한이 집행된다."""
    client = world.session_client()
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '9 minutes'")
    assert client.get("/").status_code == 200
    world.query("UPDATE mint.console_sessions SET last_verified_at = now() - interval '11 minutes'")
    assert client.get("/").status_code == 303
    # 세션 행은 폐기되지 않았지만 요청은 더 받지 않는다(다시 로그인해야 한다)
    assert live(world) == [("human-1",)]
