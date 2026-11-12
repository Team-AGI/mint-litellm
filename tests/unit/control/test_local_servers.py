"""로컬 실행(stdio) 서버를 LiteLLM 없이 MINT 표만으로 등록·승인한다.

MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE
from litellm_stub import GOOD_KEY

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import approvals as approvals_domain  # noqa: E402
from mint_litellm.control import orgs, relations, servers  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
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
