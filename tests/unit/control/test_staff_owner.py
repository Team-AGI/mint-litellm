"""직원 함수의 제한된 소유자(마이그레이션 010): 슈퍼유저가 아닌 전용 역할이 소유하고, 함수가
필요한 표·열 권한만 갖는다. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import uuid

import pytest
from ctl_fixtures import DATABASE_URL, INSTANCE

from . import test_staff_services as base
from .test_staff_services import OTHER, SESSION, USER, add_confirmation, login

psycopg = pytest.importorskip("psycopg")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

world = base.world  # 직원·제어 연결이 있는 배치(픽스처)
OWNER = "mint_staff_owner"

READ_ONLY = {"orgs", "org_bindings", "servers", "usage_relations", "settings"}
LOCK_COLUMN = {"orgs": "state_version", "org_bindings": "state_version",
               "servers": "state_version", "usage_relations": "state_version",
               "settings": "settings_version"}
SELECTABLE = READ_ONLY | {"console_sessions", "self_confirmations", "consents", "events",
                          "intakes", "deployment_contracts", "tool_contracts", "jobs", "approvals"}
INSERTABLE = {
    "signup_requests": {"instance_id", "id", "email", "display_name", "status_token_hash",
                        "password_sealed"},
    "intakes": {"id", "instance_id", "org_id", "server_id", "source", "purpose", "data_grade",
                "allowed_resources", "provider", "owner_user_id", "readiness", "data_return_terms",
                "requested_by", "staff_request_sha256", "staff_registry_required"},
    "deployment_contracts": {"id", "instance_id", "server_id", "canonical_text", "sha256", "url",
                             "url_sha256", "transport", "auth_type", "proposed_by"},
    "servers": {"id", "instance_id", "server_id", "status", "url_sha256", "transport", "auth_type",
                "registered_by"},
    "jobs": {"id", "instance_id", "kind", "target_ref", "idempotency_key"},
    "console_sessions": {"id_hash", "instance_id", "subject", "user_id", "key_token", "role",
                         "idle_expiry", "absolute_expiry", "team_ids"},
    "consents": {"id", "instance_id", "org_id", "human_user_id", "server_id", "purpose",
                 "data_scope", "text_version", "source", "granted_at", "valid_until",
                 "registered_by"},
    "events": {"event_id", "instance_id", "kind", "source_key", "actor", "payload"},
}
UPDATABLE = {
    "console_sessions": {"last_seen_at", "idle_expiry", "revoked_at"},
    "self_confirmations": {"status", "confirmed_by_user_id", "confirmed_by_key_token",
                           "confirmed_at"},
    "consents": {"revoked_at"},
    **{table: {column} for table, column in LOCK_COLUMN.items()},
    "servers": {"state_version", "status"},
    "intakes": {"status", "decision", "decided_by", "decision_reason", "decided_at"},
    "tool_contracts": {"status"},
    "deployment_contracts": {"status"},
}


def scalar(conn, sql, *params):
    return conn.execute(sql, params or None).fetchone()[0]


def tables(conn) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'mint' ORDER BY 1")]


def columns(conn, table: str) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum > 0"
        " AND NOT attisdropped", (f"mint.{table}",))]


def test_the_owner_is_a_plain_group_role_that_cannot_log_in(world):
    url = world[0]
    with psycopg.connect(url) as conn:
        flags = conn.execute(
            "SELECT rolsuper, rolcanlogin, rolcreaterole, rolcreatedb, rolreplication,"
            " rolbypassrls FROM pg_roles WHERE rolname = %s", (OWNER,)).fetchone()
        assert flags == (False, False, False, False, False, False)
        groups = {r[0] for r in conn.execute(
            "SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid"
            " JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = %s", (OWNER,))}
        assert groups == {"mint_staff"}
        assert not scalar(conn, "SELECT has_schema_privilege(%s, 'mint', 'CREATE')", OWNER)
        assert scalar(conn, "SELECT has_schema_privilege(%s, 'mint', 'USAGE')", OWNER)


def test_every_staff_function_is_owned_by_the_restricted_owner(world):
    with psycopg.connect(world[0]) as conn:
        owners = conn.execute(
            "SELECT p.proname, pg_get_userbyid(p.proowner) FROM pg_proc p"
            " JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'mint' AND p.proname LIKE 'staff\\_%'").fetchall()
    assert len(owners) >= 15
    assert {owner for _, owner in owners} == {OWNER}
    names = {name for name, _ in owners}
    assert {"staff_confirm", "staff_reject", "staff_cancel", "staff_grant_consent",
            "staff_revoke_consent", "staff_start_session", "staff_event"} <= names


def test_the_owner_has_exactly_the_table_and_column_rights_the_functions_need(world):
    with psycopg.connect(world[0]) as conn:
        for table in tables(conn):
            for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
                assert not scalar(conn, "SELECT has_table_privilege(%s, %s, %s)",
                                  OWNER, f"mint.{table}", privilege), (table, privilege)
            has_select = scalar(conn, "SELECT has_table_privilege(%s, %s, 'SELECT')",
                                OWNER, f"mint.{table}")
            assert has_select == (table in SELECTABLE), table
            for column in columns(conn, table):
                for privilege, allowed in (("INSERT", INSERTABLE), ("UPDATE", UPDATABLE)):
                    got = scalar(conn, "SELECT has_column_privilege(%s, %s, %s, %s)",
                                 OWNER, f"mint.{table}", column, privilege)
                    assert got == (column in allowed.get(table, set())), (table, column, privilege)
        sequences = scalar(conn, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON"
                           " n.oid = c.relnamespace WHERE n.nspname = 'mint' AND c.relkind = 'S'")
        assert sequences == 0


def test_the_owner_is_not_a_member_of_any_other_mint_group(world):
    with psycopg.connect(world[0]) as conn:
        for group in ("mint_control", "mint_plugin", "mint_worker", "mint_sealer",
                      "mint_ledger_writer"):
            assert not scalar(conn, "SELECT pg_has_role(%s, %s, 'MEMBER')", OWNER, group), group


def test_the_staff_login_cannot_become_the_owner_or_touch_a_table(world):
    _, staff_conn, _ = world
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        staff_conn.execute(f"SET ROLE {OWNER}")
    staff_conn.rollback()
    for table in ("events", "consents", "console_sessions", "self_confirmations", "approvals",
                  "operators", "servers"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            staff_conn.execute(f"SELECT 1 FROM mint.{table}")
        staff_conn.rollback()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        staff_conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload)"
            " VALUES (gen_random_uuid(), 'x', 'consent_granted', 'k', '{}')")


def as_owner(conn, user: str, instance: str = INSTANCE):
    """슈퍼유저 연결에서 트랜잭션 하나를 소유 역할로 바꾸고 직원 설정을 건다."""
    conn.execute(f"SET LOCAL ROLE {OWNER}")
    conn.execute("SELECT set_config('mint.staff_user_id', %s, true),"
                 " set_config('mint.staff_instance_id', %s, true)", (user, instance))


def test_the_transition_trigger_judges_by_the_owner_membership_not_by_superuser(world):
    url = world[0]
    first = add_confirmation(url)
    with psycopg.connect(url) as conn:
        as_owner(conn, USER)
        conn.execute("UPDATE mint.self_confirmations SET status = 'cancelled' WHERE id = %s",
                     (first,))
        assert scalar(conn, "SELECT status FROM mint.self_confirmations WHERE id = %s",
                      first) == "cancelled"
    refused = [
        ("pending", "expired", {}),
        ("confirmed", "expired", {}),
        ("confirmed", "consumed", {}),
    ]
    for start, end, _ in refused:
        cid = add_confirmation(url, tool=f"t-{start}-{end}")
        with psycopg.connect(url) as admin:
            if start == "confirmed":
                admin.execute(
                    "UPDATE mint.self_confirmations SET status = 'confirmed',"
                    " confirmed_by_user_id = principal_id, confirmed_by_key_token = 'k',"
                    " confirmed_at = now() WHERE id = %s", (cid,))
        with psycopg.connect(url) as conn:
            as_owner(conn, USER)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("UPDATE mint.self_confirmations SET status = %s WHERE id = %s",
                             (end, cid))


def test_the_owner_policy_hides_other_users_confirmations_and_sessions(world):
    url = world[0]
    mine = add_confirmation(url)
    theirs = add_confirmation(url, OTHER)
    with psycopg.connect(url) as conn:
        as_owner(conn, USER)
        ids = {str(r[0]) for r in conn.execute("SELECT id FROM mint.self_confirmations")}
        assert ids == {mine} and theirs not in ids
        assert conn.execute("UPDATE mint.self_confirmations SET status = 'cancelled'"
                            " WHERE id = %s", (theirs,)).rowcount == 0
        conn.execute("SELECT set_config('mint.staff_instance_id', 'other', true)")
        assert scalar(conn, "SELECT count(*) FROM mint.self_confirmations") == 0


def test_the_owner_policy_only_shows_staff_sessions_of_the_signed_in_user(world):
    url = world[0]
    login(world)
    with psycopg.connect(url) as admin:
        admin.execute(
            "INSERT INTO mint.console_sessions (id_hash, instance_id, subject, user_id,"
            " key_token, operator_name, role, idle_expiry, absolute_expiry) VALUES (%s, %s,"
            " 'admin', %s, 'k', 'op', 'admin', now() + interval '1 hour',"
            " now() + interval '2 hours')", ("33" * 32, INSTANCE, USER))
    with psycopg.connect(url) as conn:
        as_owner(conn, USER)
        rows = conn.execute("SELECT subject, user_id FROM mint.console_sessions").fetchall()
        assert rows == [("staff", USER)]
        assert conn.execute("UPDATE mint.console_sessions SET revoked_at = now()"
                            " WHERE subject = 'admin'").rowcount == 0


def test_the_staff_functions_still_work_end_to_end_under_the_owner(world):
    from mint_litellm.control.services import staff

    from .test_staff_services import sctx

    url, _, _ = world
    cid = add_confirmation(url)
    login(world)
    staff.confirm(sctx(world), SESSION, cid)
    with psycopg.connect(url) as conn:
        assert scalar(conn, "SELECT status FROM mint.self_confirmations WHERE id = %s",
                      cid) == "confirmed"
        assert scalar(conn, "SELECT count(*) FROM mint.events WHERE kind ="
                      " 'call_approval_approved'") == 1
        assert scalar(conn, "SELECT pg_get_userbyid(proowner) FROM pg_proc"
                      " WHERE proname = 'staff_confirm'") == OWNER


def test_the_migrations_apply_for_a_role_that_is_not_a_superuser():
    """역할 만들기·권한 부여가 가능한 비슈퍼유저 실행자가 처음부터 끝까지 적용한다."""
    if not DATABASE_URL:
        pytest.skip("MINT_TEST_DATABASE_URL is not set")
    from mint_litellm.control.db import migrate

    suffix = uuid.uuid4().hex[:10]
    migrator, name = f"mint_migrator_{suffix}", f"mint_nosu_{suffix}"
    params = conninfo_to_dict(DATABASE_URL)
    with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
        admin.execute(f"CREATE ROLE {migrator} LOGIN PASSWORD 'pw' CREATEROLE")
        # 클러스터에 이미 있는 그룹 역할은 클러스터 관리자가 실행자에게 관리 권한을 준다.
        for role in ("mint_ledger_writer", "mint_sealer", "mint_plugin", "mint_control",
                     "mint_staff", "mint_worker", OWNER, "mint_endpoint_owner"):
            if scalar(admin, "SELECT count(*) FROM pg_roles WHERE rolname = %s", role):
                admin.execute(f"GRANT {role} TO {migrator} WITH ADMIN OPTION, SET TRUE,"
                              " INHERIT TRUE")
        admin.execute(f'CREATE DATABASE "{name}" OWNER {migrator}')
    try:
        with psycopg.connect(make_conninfo(**dict(params, dbname=name, user=migrator,
                                                  password="pw"))) as conn:
            assert not scalar(conn, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            applied = migrate.apply_migrations(conn)
            assert "010_staff_owner" in applied
            owners = {r[0] for r in conn.execute(
                "SELECT pg_get_userbyid(p.proowner) FROM pg_proc p JOIN pg_namespace n ON"
                " n.oid = p.pronamespace WHERE n.nspname = 'mint' AND p.proname LIKE 'staff\\_%'")}
            assert owners == {OWNER}
            assert not scalar(conn, "SELECT has_schema_privilege(%s, 'mint', 'CREATE')", OWNER)
            assert migrate.apply_migrations(conn) == []
    finally:
        with psycopg.connect(DATABASE_URL, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            admin.execute(f"DROP OWNED BY {migrator}")
            admin.execute(f"DROP ROLE IF EXISTS {migrator}")


def test_the_staff_login_can_execute_only_the_public_staff_functions(world):
    expected = {"staff_confirm", "staff_reject", "staff_cancel", "staff_grant_consent",
                "staff_revoke_consent", "staff_start_session", "staff_touch_session",
                "staff_end_session", "staff_list_confirmations", "staff_list_consents",
                "staff_list_events", "staff_submit_intake", "staff_withdraw_intake",
                "staff_signup_submit", "staff_signup_status", "staff_signup_request"}
    with psycopg.connect(world[0]) as conn:
        rows = conn.execute(
            "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'mint' AND p.prorettype <> 'trigger'::regtype"
            " AND has_function_privilege('mint_staff_app', p.oid, 'EXECUTE')").fetchall()
    assert {r[0] for r in rows} == expected
