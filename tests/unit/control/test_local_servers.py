"""로컬 실행(stdio) 서버를 LiteLLM 없이 MINT 표만으로 등록·승인한다.

MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE
from litellm_stub import GOOD_KEY

psycopg = pytest.importorskip("psycopg")
from psycopg.types.json import Jsonb  # noqa: E402

from mint_litellm.control import approvals as approvals_domain  # noqa: E402
from mint_litellm.control import (  # noqa: E402
    endpoint_results,  # noqa: E402
    orgs,
    relations,
    servers,
)
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.endpoint_results import GRACE_SECONDS  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.sync_state import desired_for_target  # noqa: E402
from mint_litellm.types.exec_contract import ExecContract  # noqa: E402
from mint_litellm.types.identity import SubjectType  # noqa: E402

NOW = datetime.now(UTC)
CONTRACT = ExecContract(
    executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
)


def register_local(ctx, server_id="local-1", contract=CONTRACT):
    servers.register_local(ctx, server_id, contract)


def approve(ctx, litellm, relation, scope_id=GOOD_KEY):
    return approvals_domain.approve(
        ctx, litellm, relation_id=relation, scope_type="key", scope_id=scope_id, tools=["echo"],
        valid_from=NOW, valid_until=NOW + timedelta(days=30), approval_class="standard",
        basis_text="티켓", requested_by="requester", allowlist_ids=[], second=None,
    )


def test_a_local_server_is_stored_with_its_contract_and_no_url_hash(ctx, conn):
    register_local(ctx)
    row = fetchone(conn, "SELECT * FROM mint.servers WHERE server_id = 'local-1'")
    assert row["status"] == "awaiting_approval" and row["identity_kind"] == "stdio"
    assert row["url_sha256"] is None
    assert (row["exec_contract_sha256"], row["exec_contract_version"]) == (CONTRACT.sha256(), 1)
    assert (row["transport"], row["auth_type"]) == ("stdio", "none")
    event = fetchone(conn, "SELECT payload FROM mint.events WHERE kind = 'server_registered'")
    assert event["payload"]["exec_contract"]["argv"] == ["/opt/srv/index.js"]
    assert event["payload"]["exec_contract_sha256"] == CONTRACT.sha256()


def test_registering_again_updates_the_contract_and_keeps_the_state(ctx, conn):
    register_local(ctx)
    other = CONTRACT.model_copy(update={"argv": ("/opt/srv/v2.js",)})
    register_local(ctx, contract=other)
    row = fetchone(conn, "SELECT * FROM mint.servers WHERE server_id = 'local-1'")
    assert row["status"] == "awaiting_approval"
    assert row["exec_contract_sha256"] == other.sha256()
    payloads = fetchall(conn, "SELECT payload FROM mint.events WHERE kind = 'server_registered'"
                       " ORDER BY inserted_at, event_id")
    assert [p["payload"].get("updated") for p in payloads] == [None, True]


def test_a_local_and_a_remote_registration_cannot_overwrite_each_other(ctx, litellm, conn):
    register_local(ctx, "ctl-everything")
    with pytest.raises(ControlError, match="로컬 실행 서버"):
        servers.register(ctx, litellm, "ctl-everything", "http://upstream.test/mcp")
    register_local(ctx, "local-2")
    with pytest.raises(psycopg.Error):
        conn.execute(
            "UPDATE mint.servers SET identity_kind = 'remote' WHERE server_id = 'local-2'"
        )


def test_approving_a_local_server_needs_no_litellm_server_permission(
    ctx, litellm, conn, stub
):
    orgs.add(ctx, "acme", "ACME")
    orgs.bind(ctx, "acme", SubjectType.USER, "human-1")
    register_local(ctx)
    relation = relations.add(ctx, "acme", "local-1", "ops", None)
    info = json.loads(json.dumps(stub.routes[("/key/info", frozenset({("key", GOOD_KEY)}))][1]))
    info["info"]["object_permission"]["mcp_servers"] = []
    stub.set("/key/info", info, key=GOOD_KEY)
    approve(ctx, litellm, relation)
    assert fetchone(conn, "SELECT status FROM mint.servers WHERE server_id = 'local-1'")[
        "status"] == "approved"
    # LiteLLM 권한 동기화는 로컬 서버를 키 권한으로 옮기지 않는다.
    assert desired_for_target(conn, INSTANCE, "key", GOOD_KEY).servers == frozenset()


def test_a_remote_approval_is_still_synced_to_litellm_permissions(ctx, litellm, conn):
    orgs.add(ctx, "acme", "ACME")
    orgs.bind(ctx, "acme", SubjectType.USER, "human-1")
    servers.register(ctx, litellm, "ctl-everything", "http://upstream.test/mcp")
    approve(ctx, litellm, relations.add(ctx, "acme", "ctl-everything", "ops", None))
    assert desired_for_target(conn, INSTANCE, "key", GOOD_KEY).servers == {"ctl-everything"}


def _granted_call_approval(ctx, conn, server_id):
    from ctl_fixtures import make_ctx

    orgs.add(ctx, "acme", "ACME")
    conn.execute(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'pv', repeat('a', 64), repeat('b', 64))", (INSTANCE,))
    call_id = approvals_domain.call_request(
        ctx, org_id="acme", principal_type="user", principal_id="u1", server_id=server_id,
        tool="echo", args_fp="c" * 64, fp_key_version=1, policy_version_id="pv",
        expires_in_minutes=30, requested_by="boss",
    )
    approvals_domain.call_approve(make_ctx(conn, "carol", "approver", "carol"), call_id, None)
    return call_id


def _consume(conn, call_id, exec_hash):
    from mint_litellm.plugin.snapshot import CONSUME_EXEC_SQL

    state = fetchone(conn, "SELECT state_version FROM mint.call_approvals WHERE id = %s",
                     (call_id,))["state_version"]
    return conn.execute(CONSUME_EXEC_SQL, {
        "iid": INSTANCE, "id": call_id, "invocation_id": "00000000-0000-7000-8000-000000000001",
        "principal_type": "user", "principal_id": "u1", "server_id": "local-1", "tool": "echo",
        "args_fp": "c" * 64, "policy_version_id": "pv", "state_version": state,
        "exec_contract_sha256": exec_hash,
    }).rowcount


def test_a_call_approval_is_bound_to_the_registered_execution_contract(ctx, conn):
    register_local(ctx)
    call_id = _granted_call_approval(ctx, conn, "local-1")
    bound = fetchone(conn, "SELECT exec_contract_sha256 FROM mint.call_approvals WHERE id = %s",
                     (call_id,))
    assert bound["exec_contract_sha256"] == CONTRACT.sha256()
    assert _consume(conn, call_id, "f" * 64) == 0  # 다른 계약으로는 소비되지 않는다
    assert _consume(conn, call_id, CONTRACT.sha256()) == 1


def test_changing_the_execution_contract_expires_the_open_approvals_bound_to_it(ctx, conn):
    register_local(ctx)
    call_id = _granted_call_approval(ctx, conn, "local-1")
    register_local(ctx, contract=CONTRACT.model_copy(update={"argv": ("/opt/srv/v2.js",)}))
    status = fetchone(conn, "SELECT status FROM mint.call_approvals WHERE id = %s", (call_id,))
    assert status["status"] == "expired"
    assert _consume(conn, call_id, CONTRACT.sha256()) == 0


def _decision_event(conn, call_id, *, age_seconds, identity="stdio", action="allow"):
    from uuid import uuid4

    invocation = uuid4()
    payload = {
        "decision_ref": f"{invocation}:1", "resolved_identity_kind": identity,
        "enforced_action": action, "consumed_call_approval_id": str(call_id),
    }
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key,"
        " invocation_id, attempt_id, payload) VALUES (gen_random_uuid(), %s,"
        " now() - make_interval(secs => %s), 'decision_evaluated', %s, %s, 1, %s)",
        (INSTANCE, age_seconds, f"call:{invocation}:1:decision_evaluated", invocation,
         Jsonb(payload)))
    return invocation


def _events(conn, kind):
    return fetchall(conn, "SELECT * FROM mint.events WHERE kind = %s", (kind,))


def test_a_consumed_approval_without_a_result_report_becomes_an_unconfirmed_outcome(ctx, conn):
    register_local(ctx)
    call_id = _granted_call_approval(ctx, conn, "local-1")
    assert _consume(conn, call_id, CONTRACT.sha256()) == 1
    # 응답이 단말에 닿지 않아 결과 보고가 없다. 승인은 되살아나지 않는다.
    assert _consume(conn, call_id, CONTRACT.sha256()) == 0
    invocation = _decision_event(conn, call_id, age_seconds=GRACE_SECONDS + 5)
    assert endpoint_results.scan(conn, INSTANCE) == 1
    (event,) = _events(conn, "call_outcome_unknown")
    assert event["invocation_id"] == invocation
    assert event["payload"]["cause"] == "no_report"
    assert event["payload"]["call_approval_id"] == str(call_id)
    # 다시 돌려도 같은 호출은 한 건에 수렴한다.
    endpoint_results.scan(conn, INSTANCE)
    assert len(_events(conn, "call_outcome_unknown")) == 1


def test_the_scan_leaves_calls_that_are_reported_recent_remote_or_blocked(ctx, conn):
    call_id = "00000000-0000-7000-8000-0000000000aa"
    recent = _decision_event(conn, call_id, age_seconds=10)
    remote = _decision_event(conn, call_id, age_seconds=GRACE_SECONDS + 5, identity="remote")
    blocked = _decision_event(conn, call_id, age_seconds=GRACE_SECONDS + 5, action="block")
    reported = _decision_event(conn, call_id, age_seconds=GRACE_SECONDS + 5)
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES (gen_random_uuid(), %s, 'call_response_received', %s, %s,"
        " 1, '{}')", (INSTANCE, f"call:{reported}:1:call_response_received", reported))
    assert endpoint_results.scan(conn, INSTANCE) == 0
    assert {recent, remote, blocked, reported}  # 모두 만들어졌다
    assert _events(conn, "call_outcome_unknown") == []


def test_a_widened_execution_contract_opens_a_drift_alert_listing_the_axes(ctx, conn):
    register_local(ctx)
    wider = CONTRACT.model_copy(update={"argv": ("/opt/srv/index.js", "/etc/shadow")})
    register_local(ctx, contract=wider)
    alert = fetchone(conn, "SELECT * FROM mint.alerts WHERE kind = 'contract_drift'")
    assert alert["severity"] == "high"
    assert alert["subject"]["widened"] == ["file"]
    assert "파일 접근 확대" in alert["subject"]["summary"]


def test_a_narrowed_execution_contract_raises_only_a_low_alert(ctx, conn):
    register_local(ctx)
    register_local(ctx, contract=CONTRACT.model_copy(update={"argv": ()}))
    alert = fetchone(conn, "SELECT * FROM mint.alerts WHERE kind = 'contract_drift'")
    assert alert["severity"] == "low" and alert["subject"]["widened"] == []
