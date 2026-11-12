"""마이그레이션 실행기. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import pytest

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control.db import migrate  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402


def test_applies_once_and_is_a_no_op_the_second_time(fresh_db):
    with psycopg.connect(fresh_db) as conn:
        assert migrate.apply_migrations(conn) == []
        names = [r[0] for r in conn.execute("SELECT name FROM mint.schema_migrations")]
        assert names == [
            "001_initial", "002_stage2", "003_negative_export", "004_staff_confirmation",
            "006_alert_delivery_count", "007_contract_observations", "008_restore_requests",
            "009_contract_reapproval_plans", "010_staff_owner",
            "011_reapproval_plan_cancelled", "012_staff_records", "013_stage2_hardening",
            "014_operator_negative", "015_deployment_proposer",
            "016_intake_address_reject", "017_approval_contract_binding",
            "018_exec_contract_fields", "019_exec_contract_approval_binding",
            "020_endpoint_installs", "023_plugin_condition_defaults",
        ]


def test_first_run_on_an_empty_database_applies_everything(fresh_db):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(fresh_db)
    admin = dict(params, dbname="postgres")
    name = params["dbname"] + "_b"
    with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    try:
        with psycopg.connect(make_conninfo(**dict(params, dbname=name))) as conn:
            assert migrate.apply_migrations(conn) == [
                "001_initial", "002_stage2", "003_negative_export", "004_staff_confirmation",
                "006_alert_delivery_count", "007_contract_observations", "008_restore_requests",
                "009_contract_reapproval_plans", "010_staff_owner",
                "011_reapproval_plan_cancelled", "012_staff_records", "013_stage2_hardening",
                "014_operator_negative", "015_deployment_proposer",
            "016_intake_address_reject", "017_approval_contract_binding",
                "018_exec_contract_fields", "019_exec_contract_approval_binding",
                "020_endpoint_installs", "023_plugin_condition_defaults",
            ]
            assert conn.execute("SELECT count(*) FROM mint.orgs").fetchone()[0] == 0
    finally:
        with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
            conn.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def test_a_changed_applied_migration_is_refused(fresh_db):
    with psycopg.connect(fresh_db) as conn:
        conn.execute("UPDATE mint.schema_migrations SET sha256 = repeat('0', 64)")
        with pytest.raises(ControlError, match="바뀌었습니다"):
            migrate.apply_migrations(conn)


def test_a_database_with_only_the_first_migration_is_upgraded(fresh_db):
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(fresh_db)
    admin = dict(params, dbname="postgres")
    name = params["dbname"] + "_c"
    with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    try:
        with psycopg.connect(make_conninfo(**dict(params, dbname=name))) as conn:
            files = dict(migrate._migration_files())
            conn.execute(files["001_initial"].encode("utf-8"))
            conn.execute("CREATE SCHEMA IF NOT EXISTS mint")
            conn.execute(
                "CREATE TABLE mint.schema_migrations (name text PRIMARY KEY, sha256 text NOT NULL,"
                " applied_at timestamptz NOT NULL DEFAULT now())"
            )
            import hashlib

            conn.execute(
                "INSERT INTO mint.schema_migrations (name, sha256) VALUES (%s, %s)",
                ("001_initial", hashlib.sha256(files["001_initial"].encode()).hexdigest()),
            )
            conn.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES ('i', 'o', 'o')")
            conn.execute(
                "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256,"
                " transport, auth_type, registered_by) VALUES"
                " (gen_random_uuid(), 'i', 's', 'awaiting_approval', repeat('a', 64), 'http',"
                " 'none', 'alice')"
            )
            before = conn.execute("SELECT epoch FROM mint.state_epoch").fetchone()[0]
            conn.commit()
            assert migrate.apply_migrations(conn) == [
                "002_stage2", "003_negative_export", "004_staff_confirmation",
                "006_alert_delivery_count", "007_contract_observations", "008_restore_requests",
                "009_contract_reapproval_plans", "010_staff_owner",
                "011_reapproval_plan_cancelled", "012_staff_records", "013_stage2_hardening",
                "014_operator_negative", "015_deployment_proposer",
            "016_intake_address_reject", "017_approval_contract_binding",
                "018_exec_contract_fields", "019_exec_contract_approval_binding",
                "020_endpoint_installs", "023_plugin_condition_defaults",
            ]
            assert conn.execute("SELECT count(*) FROM mint.intakes").fetchone()[0] == 0
            row = conn.execute(
                "SELECT contract_status, issuer, last_observed_at, deployment_drift,"
                " deployment_drift_fields FROM mint.servers"
            ).fetchone()
            assert row == ("none", None, None, False, None)
            # 이전 판본이 남긴 서버 행은 모두 원격이고 URL 해시를 그대로 가진다.
            assert conn.execute(
                "SELECT identity_kind, url_sha256, exec_contract_sha256, exec_contract_version"
                " FROM mint.servers").fetchone() == ("remote", "a" * 64, None, None)
            assert conn.execute("SELECT epoch FROM mint.state_epoch").fetchone()[0] == before
            roles = {r[0] for r in conn.execute("SELECT rolname FROM pg_roles")}
            assert {"mint_control", "mint_staff", "mint_worker", "mint_sealer"} <= roles
            assert migrate.apply_migrations(conn) == []
    finally:
        with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
            conn.execute(f'DROP DATABASE "{name}" WITH (FORCE)')


def test_open_approvals_without_a_contract_are_closed_on_managed_servers_only(fresh_db):
    import hashlib

    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(fresh_db)
    admin = dict(params, dbname="postgres")
    name = params["dbname"] + "_d"
    with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    try:
        with psycopg.connect(make_conninfo(**dict(params, dbname=name))) as conn:
            files = migrate._migration_files()
            conn.execute("CREATE SCHEMA IF NOT EXISTS mint")
            conn.execute(
                "CREATE TABLE mint.schema_migrations (name text PRIMARY KEY, sha256 text NOT NULL,"
                " applied_at timestamptz NOT NULL DEFAULT now())"
            )
            files = [f for f in files if f[0] < "017_approval_contract_binding"]
            for file_name, sql in files:
                conn.execute(sql.encode("utf-8"))
                conn.execute(
                    "INSERT INTO mint.schema_migrations (name, sha256) VALUES (%s, %s)",
                    (file_name, hashlib.sha256(sql.encode("utf-8")).hexdigest()),
                )
            conn.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES ('i', 'o', 'o')")
            conn.execute(
                "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
                " VALUES ('i', 'pv', repeat('a', 64), repeat('b', 64))"
            )
            for server, status in (("managed", "managed"), ("plain", "none")):
                conn.execute(
                    "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256,"
                    " transport, auth_type, registered_by, contract_status, last_observed_at)"
                    " VALUES (gen_random_uuid(), 'i', %s, 'awaiting_approval', repeat('a', 64),"
                    " 'http', 'none', 'alice', %s, now())", (server, status))
            for server in ("managed", "plain"):
                for approved in (False, True):
                    call_id = conn.execute(
                        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type,"
                        " principal_id, server_id, tool, args_fp, fp_key_version,"
                        " policy_version_id, status, requested_by, expires_at) VALUES"
                        " (gen_random_uuid(), 'i', 'o', 'user', 'u', %s, 't', repeat('c', 64), 1,"
                        " 'pv', 'pending', 'r', now() + interval '1 hour') RETURNING id",
                        (server,)).fetchone()[0]
                    if approved:
                        conn.execute(
                            "UPDATE mint.call_approvals SET status = 'approved',"
                            " approved_by = 'a' WHERE id = %s", (call_id,))
            assert migrate.apply_migrations(conn) == [
                "017_approval_contract_binding", "018_exec_contract_fields",
                "019_exec_contract_approval_binding", "020_endpoint_installs",
                "023_plugin_condition_defaults"]
            rows = conn.execute(
                "SELECT server_id, status, count(*) FROM mint.call_approvals"
                " GROUP BY server_id, status ORDER BY 1, 2"
            ).fetchall()
            assert rows == [("managed", "expired", 2), ("plain", "approved", 1),
                            ("plain", "pending", 1)]
    finally:
        with psycopg.connect(make_conninfo(**admin), autocommit=True) as conn:
            conn.execute(f'DROP DATABASE "{name}" WITH (FORCE)')
