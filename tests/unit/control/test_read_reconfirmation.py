"""Approval creation rejects reuse outside an explicitly reviewed read contract."""

import json
from uuid import uuid4

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.control.errors import ControlError
from mint_litellm.control.settings_store import ensure

from .test_flow import approve, prepare


@pytest.fixture
def conn(fresh_db):
    import psycopg

    with psycopg.connect(fresh_db) as connection:
        ensure(connection, INSTANCE)
        yield connection
        connection.rollback()


@pytest.mark.parametrize(
    "override",
    [
        {"reuse_read_confirmations": "true"},
        {"reuse_read_confirmations": True},
        {"reuse_read_confirmations": True, "allowed_hosts": ["docs.example"], "scan_result": False},
        {
            "reuse_read_confirmations": True,
            "allowed_hosts": ["docs.example"],
            "allow_input_secrets": ["token"],
        },
        {"reuse_read_confirmations": True, "allowed_hosts": ["docs.example"]},
    ],
)
def test_unreviewed_reuse_cannot_be_granted(ctx, litellm, override):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError):
        approve(ctx, litellm, relation, scope_type="user", scope_id="human-1", conditions=override)


def test_managed_read_low_url_contract_can_opt_in(ctx, conn, litellm, stub):
    relation = prepare(ctx, litellm)
    conn.execute("UPDATE mint.servers SET contract_status='managed'")
    contract = uuid4()
    conn.execute(
        "INSERT INTO mint.tool_contracts (id,instance_id,server_id,credential_scope,tool,"
        "canonical_text,sha256,pin_sha256,risk_grade,action_type,source,status) VALUES"
        " (%s,%s,'ctl-everything','server','echo',%s,repeat('a',64),repeat('b',64),"
        "'low','read','intake','candidate')",
        (
            contract,
            ctx.instance_id,
            json.dumps(
                {"input_schema": {"type": "object", "properties": {"url": {"type": "string"}}}}
            ),
        ),
    )
    conn.execute("UPDATE mint.tool_contracts SET status='approved' WHERE id=%s", (contract,))
    body = json.loads(
        json.dumps(stub.routes[("/user/info", frozenset({("user_id", "human-1")}))][1])
    )
    body["user_info"]["object_permission"] = {"mcp_servers": ["ctl-everything"]}
    stub.set("/user/info", body, user_id="human-1")
    identifier, _ = approve(
        ctx,
        litellm,
        relation,
        scope_type="user",
        scope_id="human-1",
        conditions={"reuse_read_confirmations": True, "allowed_hosts": ["docs.example"]},
    )
    row = conn.execute(
        "SELECT conditions FROM mint.approvals WHERE id=%s", (identifier,)
    ).fetchone()
    assert row[0]["reuse_read_confirmations"] is True
