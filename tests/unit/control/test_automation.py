"""운영 자동화: 호출별 승인 요청 알림, 승인 만료 알림과 갱신 후보. DB가 없으면 건너뛴다."""

from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE
from litellm_stub import GOOD_KEY

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import approvals, orgs, relations, servers  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.services import expiry, renewals  # noqa: E402
from mint_litellm.types.identity import SubjectType  # noqa: E402

NOW = datetime.now(UTC)
HEX = "ab" * 32


def prepare(ctx, litellm):
    orgs.add(ctx, "acme", "ACME")
    orgs.bind(ctx, "acme", SubjectType.USER, "human-1")
    servers.register(ctx, litellm, "ctl-everything", "http://upstream.test/mcp")
    return relations.add(ctx, "acme", "ctl-everything", "ops", None)


def approve(ctx, litellm, relation, **overrides):
    values = dict(
        relation_id=relation, scope_type="key", scope_id=GOOD_KEY, tools=["echo"],
        valid_from=NOW, valid_until=NOW + timedelta(days=30), approval_class="standard",
        basis_text="티켓", requested_by="requester", allowlist_ids=[], second=None,
    )
    values.update(overrides)
    return approvals.approve(ctx, litellm, **values)


def with_policy(conn):
    conn.execute(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s)", (INSTANCE, HEX, HEX))


def open_auto_request(conn, requested_by=expiry.AUTO_REQUESTER):
    conn.execute(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at) VALUES (gen_random_uuid(), %s, 'acme', 'user', 'alice', 'ctl-everything',"
        " 'echo', %s, 1, 'v1', 'pending', %s, now() + interval '1 day')",
        (INSTANCE, HEX, requested_by),
    )


def test_an_automatic_call_request_is_announced_once(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    open_auto_request(conn)
    assert expiry.announce_requests(conn, INSTANCE) == 1
    assert expiry.announce_requests(conn, INSTANCE) == 0
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.alerts"
                          " WHERE kind = 'call_approval_requested'")["n"] == 1
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.events"
                          " WHERE kind = 'call_approval_requested'")["n"] == 1


def test_an_operator_made_request_is_not_announced(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    open_auto_request(conn, requested_by="operator")
    assert expiry.announce_requests(conn, INSTANCE) == 0


def grant_ending_soon(ctx, litellm, **overrides):
    relation = prepare(ctx, litellm)
    values = dict(valid_from=NOW - timedelta(days=85), valid_until=NOW + timedelta(days=3))
    values.update(overrides)
    return relation, approve(ctx, litellm, relation, **values)[0]


def test_an_expiring_approval_alerts_and_unchanged_ones_are_renewable(ctx, litellm, conn):
    _, approval_id = grant_ending_soon(ctx, litellm)
    assert expiry.warn_expiring(conn, INSTANCE) == 1
    found = renewals.candidates(conn, INSTANCE)
    assert [str(r["id"]) for r in found["unchanged"]] == [approval_id]
    assert found["changed"] == []


def test_a_renewed_approval_leaves_the_list_and_closes_its_alert(ctx, litellm, conn):
    relation, _ = grant_ending_soon(ctx, litellm)
    expiry.warn_expiring(conn, INSTANCE)
    approve(ctx, litellm, relation, valid_from=NOW, valid_until=NOW + timedelta(days=90))
    assert renewals.candidates(conn, INSTANCE) == {"unchanged": [], "changed": []}
    expiry.warn_expiring(conn, INSTANCE)
    assert [r["status"] for r in fetchall(
        conn, "SELECT status FROM mint.alerts WHERE kind = 'approval_expiring'")] == ["resolved"]


def test_a_contract_change_after_the_grant_moves_it_to_the_changed_list(ctx, litellm, conn):
    _, approval_id = grant_ending_soon(ctx, litellm)
    conn.execute(
        "UPDATE mint.servers SET deployment_drift = true WHERE instance_id = %s", (INSTANCE,))
    found = renewals.candidates(conn, INSTANCE)
    assert found["unchanged"] == []
    assert [(str(r["id"]), r["reason"]) for r in found["changed"]] == [
        (approval_id, "배포 계약 변경")]
