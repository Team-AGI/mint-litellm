"""판정 스냅숏이 고정 차단 표지와 승인 계약 수를 실제 DB에서 읽는다(실 Postgres)."""

import uuid

import ctl_fixtures
import pytest
from ctl_fixtures import LOGIN_PASSWORDS

psycopg = pytest.importorskip("psycopg")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm.control.db.roles import LOGIN_ROLES  # noqa: E402
from mint_litellm.plugin.pipeline import contract_result  # noqa: E402
from mint_litellm.plugin.snapshot import CONFIRMATION_SNAPSHOT_SQL, parse_snapshot  # noqa: E402

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles


def read_server(fresh_db, iid):
    params = conninfo_to_dict(fresh_db)
    params.update(user=LOGIN_ROLES["mint_plugin"], password=LOGIN_PASSWORDS["mint_plugin"])
    with psycopg.connect(make_conninfo(**params)) as conn:
        row = conn.execute(CONFIRMATION_SNAPSHOT_SQL, {
            "iid": iid, "server_id": "srv-1", "tool": "search", "principal_id": "p",
            "key_id": "k", "user_id": "u", "team_id": "t"}).fetchone()
    return parse_snapshot(row[0])


def test_the_snapshot_carries_the_pin_marker_and_the_approved_contract_count(
    fresh_db, login_roles
):
    iid = f"t{uuid.uuid4().hex[:12]}"
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("INSERT INTO mint.settings (instance_id) VALUES (%s)", (iid,))
        conn.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by, contract_status, last_observed_at) VALUES"
            " (gen_random_uuid(), %s, 'srv-1', 'awaiting_approval', repeat('a', 64), 'http',"
            " 'none', 'x', 'managed', now())", (iid,))
        conn.execute("UPDATE mint.servers SET status = 'approved' WHERE instance_id = %s", (iid,))
    snap = read_server(fresh_db, iid)
    assert snap.server.approved_contracts == 0 and snap.server.pin_blocked is False
    assert contract_result(snap, "search", 60).reason_code == "CONTRACT_DRIFT_no_contract"
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("UPDATE mint.servers SET deployment_drift = true,"
                     " deployment_drift_fields = ARRAY['pin_reapproval'] WHERE instance_id = %s",
                     (iid,))
    snap = read_server(fresh_db, iid)
    assert snap.server.pin_blocked is True
    assert contract_result(snap, "search", 60).reason_code == "CONTRACT_DRIFT_pin"


def test_the_snapshot_carries_the_vulnerability_deadline_block(fresh_db, login_roles):
    iid = f"t{uuid.uuid4().hex[:12]}"
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("INSERT INTO mint.settings (instance_id) VALUES (%s)", (iid,))
        conn.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'srv-1',"
            " 'awaiting_approval', repeat('a', 64), 'http', 'none', 'x')", (iid,))
        conn.execute("UPDATE mint.servers SET status = 'approved' WHERE instance_id = %s", (iid,))
    assert read_server(fresh_db, iid).server.vuln_blocked is False
    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("UPDATE mint.servers SET vuln_blocked_at = now() WHERE instance_id = %s",
                     (iid,))
    assert read_server(fresh_db, iid).server.vuln_blocked is True
