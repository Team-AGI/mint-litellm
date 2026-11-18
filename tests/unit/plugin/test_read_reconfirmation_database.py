"""Real PostgreSQL: durable dual-check evidence, restart reuse and atomic revocation."""

from uuid import uuid4

import ctl_fixtures
import pytest
from plugin_helpers import FP_KEY, KEY, request, user_principal
from test_confirmation_database import decide_as_staff, replica
from test_confirmation_database import world as db_world
from test_plugin_database import run

from mint_litellm.control import approvals
from mint_litellm.control.context import Context, Operator
from mint_litellm.plugin.buffer import ConsumeRequest, ConsumptionLost, ReadReconfirmationConsume
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.read_reconfirmation import PROOFS_SQL
from mint_litellm.types.fingerprint import argument_fingerprint
from mint_litellm.types.reason_codes import Reason

fresh_db = ctl_fixtures.fresh_db
login_roles = ctl_fixtures.login_roles
world = db_world
ARGS = {"url": "https://docs.example/normal"}


def prepare(scene):
    from psycopg.types.json import Jsonb

    parent, contract = uuid4(), uuid4()
    scene.conn.execute(
        "INSERT INTO mint.approvals (id,instance_id,org_id,relation_id,class,server_id,tools,"
        "scope_type,scope_id,valid_from,valid_until,conditions,basis,granted_by,requested_by,status)"
        " VALUES (%s,%s,'org1',%s,'standard','srv-1',ARRAY['search'],'user','u1',"
        "now()-interval '1 hour',now()+interval '1 day',%s,'{}','boss','u1','active')",
        (
            parent,
            scene.iid,
            scene.relation,
            Jsonb(
                {
                    "reuse_read_confirmations": True,
                    "allowed_hosts": ["docs.example"],
                    "allowed_arg_keys": ["url"],
                }
            ),
        ),
    )
    scene.conn.execute(
        "UPDATE mint.servers SET contract_status='managed',last_observed_at=now()"
        " WHERE instance_id=%s",
        (scene.iid,),
    )
    scene.conn.execute(
        "INSERT INTO mint.tool_contracts (id,instance_id,server_id,credential_scope,tool,"
        "canonical_text,sha256,pin_sha256,risk_grade,action_type,source,status) VALUES"
        " (%s,%s,'srv-1','server','search',%s,repeat('a',64),repeat('b',64),'low','read',"
        "'intake','candidate')",
        (
            contract,
            scene.iid,
            '{"input_schema":{"type":"object","properties":{"url":{"type":"string"}}}}',
        ),
    )
    scene.conn.execute("UPDATE mint.tool_contracts SET status='approved' WHERE id=%s", (contract,))
    return str(parent), str(contract)


async def ask(scene, deps):
    return await evaluate_request(
        request(user_principal(instance_id=scene.iid), arguments=ARGS), deps
    )


@pytest.mark.parametrize("window", [None, 10])
def test_dual_checks_reused_across_replicas_and_revocation_is_atomic(world, tmp_path, window):
    scene, dsn = world
    parent, contract = prepare(scene)
    ctx = Context(scene.conn, scene.iid, Operator("boss", "admin", "boss"))

    async def go():
        a, da = replica(scene, dsn, tmp_path / "first")
        try:
            first = await ask(scene, da)
            assert (
                not first.allowed
                and first.snapshot.stop.reason_code == Reason.CALL_APPROVAL_REQUIRED
            )
            call_id = scene.conn.execute(
                "SELECT id FROM mint.call_approvals WHERE instance_id=%s AND status='pending'",
                (scene.iid,),
            ).fetchone()[0]
            approvals.call_approve(ctx, str(call_id), None, window_minutes=window)
            second = await ask(scene, da)
            assert (
                not second.allowed
                and second.snapshot.stop.reason_code == Reason.CONFIRMATION_REQUIRED
            )
            decide_as_staff(scene)
            initial = await ask(scene, da)
            assert initial.allowed
            assert initial.snapshot.read_reconfirmation_scope == parent
        finally:
            await a.close()
        # New pool/process state: authority is read from durable evidence, never memory.
        b, db = replica(scene, dsn, tmp_path / "second")
        try:
            repeated = await ask(scene, db)
            assert repeated.allowed
            assert repeated.snapshot.read_reconfirmation_proof_event_id
            cursor = scene.conn.execute(
                PROOFS_SQL,
                {
                    "iid": scene.iid,
                    "user_id": "u1",
                    "server_id": "srv-1",
                    "tool": "search",
                    "key_id": KEY,
                    "proof_event_id": None,
                },
            )
            proof = cursor.fetchone()
            assert proof and proof[1] == parent
            if window:
                until = scene.conn.execute(
                    "SELECT valid_until FROM mint.call_approvals WHERE id=%s", (call_id,)
                ).fetchone()[0]
                assert proof[13] <= until
            # Parent permission is revoked after the proof was read. Reusing that
            # stale proof must roll back the next allow audit event atomically.
            approvals.revoke(ctx, parent, "test revocation", False)
            event = scene.event()
            consume = ConsumeRequest(
                None,
                event.invocation_id,
                "user",
                "u1",
                "srv-1",
                "search",
                argument_fingerprint(ARGS, FP_KEY),
                "pv1",
                0,
                contract_id=contract,
                read_reconfirmation=ReadReconfirmationConsume(proof[0], parent, KEY, 1),
            )
            with pytest.raises(ConsumptionLost):
                await b.insert_event(event, consume)
            assert (
                scene.conn.execute(
                    "SELECT count(*) FROM mint.events WHERE event_id=%s", (event.event_id,)
                ).fetchone()[0]
                == 0
            )
            blocked = await ask(scene, db)
            assert not blocked.allowed
        finally:
            await b.close()

    run(go())
