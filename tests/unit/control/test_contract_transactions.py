"""실 DB에서 관측 재시도와 재승인 원자성을 검증한다."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb

from mint_litellm.control.context import Context, Operator
from mint_litellm.control.contract_observe import consume_deployment_events, record_tools
from mint_litellm.control.contract_pin import finalize_reapproval
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminError
from mint_litellm.control.services import contracts
from mint_litellm.plugin.pipeline import contract_result
from mint_litellm.plugin.snapshot import ToolContractRow
from mint_litellm.types.canonical import canonical_text, pin_sha256, sha256
from mint_litellm.types.decision import url_sha256
from mint_litellm.types.ids import new_uuid7

TOOL = {"description": "read", "input_schema": {"type": "object"}}
NEW = {**TOOL, "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}


def reapprove(ctx, pin, server_id, intake_id, candidate_ids, **kwargs):
    contracts.reapprove(ctx, server_id, intake_id, candidate_ids, **kwargs)
    return finalize_reapproval(ctx.conn, ctx.instance_id, server_id, pin)


@pytest.fixture
def contract_db(fresh_db):
    import psycopg

    with psycopg.connect(fresh_db, autocommit=True) as conn:
        conn.execute("INSERT INTO mint.orgs(instance_id,org_id,name) VALUES ('i','o','org')")
        conn.execute(  # 재승인 요청자는 확정 때도 유효한 승인자여야 한다
            "INSERT INTO mint.operators(instance_id,name,role,token_hash,user_id)"
            " VALUES ('i','reviewer','approver',repeat('d',64),'reviewer')")
        conn.execute(
            "INSERT INTO mint.servers(id,instance_id,server_id,status,url_sha256,transport,"
            "auth_type,registered_by,contract_status) VALUES (%s,'i','s','pending',%s,'http',"
            "'none','requester','managed')",
            (new_uuid7(), url_sha256("https://mcp.test/api")),
        )
        for status in ("validating", "awaiting_approval", "approved"):
            conn.execute("UPDATE mint.servers SET status=%s WHERE server_id='s'", (status,))
        old = add_tool(conn, TOOL)
        conn.execute("UPDATE mint.tool_contracts SET status='approved' WHERE id=%s", (old,))
        deployment = {"url": "https://mcp.test/api", "transport": "http", "auth_type": "none"}
        did = new_uuid7()
        conn.execute(
            "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,"
            "sha256,url,url_sha256,transport,auth_type)"
            " VALUES (%s,'i','s',%s,%s,%s,%s,'http','none')",
            (
                did,
                canonical_text(deployment),
                sha256(deployment),
                deployment["url"],
                url_sha256(deployment["url"]),
            ),
        )
        conn.execute("UPDATE mint.deployment_contracts SET status='approved' WHERE id=%s", (did,))
        yield conn, Context(conn, "i", Operator("reviewer", "approver", "reviewer")), old


def add_tool(conn, value):
    cid = new_uuid7()
    conn.execute(
        "INSERT INTO mint.tool_contracts(id,instance_id,server_id,credential_scope,tool,"
        "canonical_text,sha256,pin_sha256,risk_grade,action_type,source)"
        " VALUES (%s,'i','s','server','read',%s,%s,%s,'low','read','intake')",
        (cid, canonical_text(value), sha256(value), pin_sha256(value)),
    )
    return cid


def server(conn):
    return fetchone(conn, "SELECT *,now() AS current_time FROM mint.servers WHERE server_id='s'")


def events(conn, kind):
    return fetchall(
        conn, "SELECT * FROM mint.events WHERE kind=%s ORDER BY inserted_at,event_id", (kind,)
    )


def observe(conn, ctx, tools):
    record_tools(ctx, "s", "server", tools, server(conn)["state_version"])


def evidence(
    conn, candidate, *, requester="requester", age="0 hours", binding=None, deployment=None
):
    iid = new_uuid7()
    conn.execute(
        "INSERT INTO mint.intakes(id,instance_id,org_id,server_id,source)"
        " VALUES (%s,'i','o','s','operator')",
        (iid,),
    )
    conn.execute(
        "UPDATE mint.intakes SET status='checking',purpose='read',data_grade='public',"
        "allowed_resources='[]',provider='vendor',owner_user_id=%s,requested_by=%s,"
        "readiness=%s,data_return_terms='delete' WHERE id=%s",
        (
            requester,
            requester,
            Jsonb({"credential_notice": "ok", "revocation_record": "ok", "audit_access_days": 30}),
            iid,
        ),
    )
    conn.execute("UPDATE mint.intakes SET status='passed' WHERE id=%s", (iid,))
    bound = binding or sha256({"tools": {"read": sha256(NEW)}, "deployment": deployment})
    required = ["connection", "definitions", "description_scan", "risk_grade"]
    if deployment:
        required += ["url_guard", "oauth_issuer_allowlist"]
    for name in required:
        conn.execute(
            'INSERT INTO mint.intake_checks(id,instance_id,intake_id,"check",attempt,'
            "result,method,inputs,evidence_sha256,evidence_valid_until,ran_at)"
            " VALUES (%s,'i',%s,%s,1,'pass','test',%s,%s,"
            " now()+interval '1 day',now()-%s::interval)",
            (new_uuid7(), iid, name, Jsonb({"contract_sha256": bound}), "a" * 64, age),
        )
    return str(iid)


def test_observation_deduplicates_and_does_not_change_epoch_for_timestamps(contract_db):
    conn, ctx, _ = contract_db
    initial = fetchone(conn, "SELECT epoch FROM mint.state_epoch WHERE instance_id='i'")["epoch"]
    observe(conn, ctx, {"read": TOOL})
    observe(conn, ctx, {"read": TOOL})
    assert (
        fetchone(conn, "SELECT epoch FROM mint.state_epoch WHERE instance_id='i'")["epoch"]
        == initial
    )
    observe(conn, ctx, {"read": NEW})
    first = events(conn, "contract_drift_detected")
    observe(conn, ctx, {"read": NEW})
    assert len(events(conn, "contract_drift_detected")) == len(first) == 1
    assert first[0]["payload"]["version"] >= 1
    observe(conn, ctx, {"read": {**NEW, "description": "changed"}})
    keys = [e["source_key"].split(":")[2] for e in events(conn, "contract_drift_detected")]
    assert len(keys) == len(set(keys)) == 2
    assert fetchone(conn, "SELECT canonical_text FROM mint.tool_contracts WHERE status='approved'")[
        "canonical_text"
    ] == canonical_text(TOOL)


def test_removed_tool_is_superseded_once(contract_db):
    conn, ctx, old = contract_db
    observe(conn, ctx, {})
    observe(conn, ctx, {})
    assert fetchone(conn, "SELECT status FROM mint.tool_contracts WHERE id=%s", (old,))[
        "status"
    ] == ("superseded")
    assert len(events(conn, "contract_superseded")) == 1


def test_deployment_event_receipts_and_value_deduplication(contract_db):
    conn, ctx, _ = contract_db
    for seq, digest in enumerate(("a" * 64, "a" * 64, "b" * 64), 1):
        conn.execute(
            "INSERT INTO mint.events(event_id,instance_id,kind,source_key,payload)"
            " VALUES (%s,'i','server_identity_mismatch_observed',%s,%s)",
            (
                uuid4(),
                f"selfcheck:run:{seq}:server_identity_mismatch_observed",
                Jsonb(
                    {"server_id": "s", "fields": ["issuer"], "observed_hashes": {"issuer": digest}}
                ),
            ),
        )
        consume_deployment_events(ctx)
        consume_deployment_events(ctx)
    assert len(events(conn, "deployment_drift_detected")) == 2
    assert server(conn)["deployment_drift"]
    assert server(conn)["deployment_drift_fields"] == ["issuer"]


class Pin:
    def __init__(self, conn, old, candidate, response):
        self.conn, self.old, self.candidate, self.response = conn, old, candidate, response
        self.calls = self.unpins = 0

    def pin(self, _):
        self.calls += 1
        from psycopg.pq import TransactionStatus

        assert self.conn.info.transaction_status == TransactionStatus.IDLE
        assert server(self.conn)["deployment_drift"]
        rows = fetchall(self.conn, "SELECT id,status FROM mint.tool_contracts")
        assert {r["id"]: r["status"] for r in rows} == {
            self.old: "approved",
            self.candidate: "candidate",
        }
        return self.response

    def unpin(self, _):
        self.unpins += 1


def test_pin_mismatch_keeps_approval_and_retry_releases_block(contract_db):
    conn, ctx, old = contract_db
    observe(conn, ctx, {"read": NEW})
    candidate = add_tool(conn, NEW)
    iid = evidence(conn, candidate)
    pin = Pin(conn, old, candidate, {"read": TOOL})
    with pytest.raises(AdminError):
        reapprove(ctx, pin, "s", iid, [str(candidate)])
    assert pin.unpins == 1
    assert not events(conn, "contract_approved")
    pin.response = {"read": NEW}
    reapprove(ctx, pin, "s", iid, [str(candidate)])
    assert len(events(conn, "contract_approved")) == 1
    assert not server(conn)["deployment_drift"]
    assert server(conn)["last_observed_at"] is not None
    approved = fetchone(conn, "SELECT * FROM mint.tool_contracts WHERE status='approved'")
    assert approved["id"] == candidate and approved["drift"] == "none"
    # 플러그인의 계약 단계도 새 승인본과 회복된 관측 시각을 허용한다.
    from mint_litellm.plugin.snapshot import ServerRow, Snapshot

    state = server(conn)
    snap = Snapshot(
        state["current_time"],
        1,
        None,
        {},
        {},
        ServerRow(
            "s",
            "s",
            "approved",
            state["url_sha256"],
            "http",
            "none",
            (),
            "managed",
            last_observed_at=state["last_observed_at"],
        ),
        {},
        {},
        (),
        (),
        (),
        (),
        None,
        (ToolContractRow(str(candidate), "server", "read", "none", approved["version"]),),
    )
    assert contract_result(snap, "read", 60).reason_code is None
    assert contract_result(
        replace(snap, now=snap.now + timedelta(seconds=121)), "read", 60
    ).reason_code == ("CONTRACT_DRIFT_unobserved")


@pytest.mark.parametrize("mode", ["stale", "requester", "viewer", "unbound", "version"])
def test_reapproval_preconditions_do_not_pin(contract_db, mode):
    conn, ctx, old = contract_db
    candidate = add_tool(conn, NEW)
    iid = evidence(
        conn,
        candidate,
        age="25 hours" if mode == "stale" else "0 hours",
        requester="reviewer" if mode == "requester" else "requester",
        binding="b" * 64 if mode == "unbound" else None,
    )
    if mode == "viewer":
        ctx = Context(conn, "i", Operator("viewer", "viewer", "viewer"))
    pin = Pin(conn, old, candidate, {"read": NEW})
    with pytest.raises(AdminError):
        reapprove(
            ctx, pin, "s", iid, [str(candidate)], expected_version=-1 if mode == "version" else None
        )
    assert pin.calls == 0


def test_event_failure_rolls_back_both_contract_statuses(contract_db, monkeypatch):
    from mint_litellm.control import ledger

    conn, ctx, old = contract_db
    candidate = add_tool(conn, NEW)
    iid = evidence(conn, candidate)
    pin = Pin(conn, old, candidate, {"read": NEW})

    def fail(*args, **kwargs):
        raise RuntimeError("ledger unavailable")

    original = ledger.record

    def fail_approval(*args, **kwargs):
        if args[2].value == "contract_superseded":
            return fail(*args, **kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(ledger, "record", fail_approval)
    with pytest.raises(RuntimeError):
        reapprove(ctx, pin, "s", iid, [str(candidate)])
    rows = fetchall(conn, "SELECT id,status FROM mint.tool_contracts")
    assert {r["id"]: r["status"] for r in rows} == {old: "approved", candidate: "candidate"}
    assert server(conn)["deployment_drift"]
    assert [event.kind.value for event in ctx.emitted] == ["reapproval_requested"]


def test_concurrent_repin_is_rejected_before_external_call(contract_db):
    import psycopg

    conn, ctx, old = contract_db
    candidate = add_tool(conn, NEW)
    iid = evidence(conn, candidate)
    pin = Pin(conn, old, candidate, {"read": NEW})
    with psycopg.connect(conn.info.dsn, password=conn.info.password, autocommit=True) as other:
        other.execute("SELECT pg_advisory_lock(hashtextextended('contract-pin:i:s',0))")
        with pytest.raises(AdminError):
            reapprove(ctx, pin, "s", iid, [str(candidate)])
    assert pin.calls == 0


def test_deployment_proposal_blocks_until_atomic_reapproval(contract_db):
    from mint_litellm.control.services.contracts import request_deployment

    conn, ctx, old = contract_db
    candidate = add_tool(conn, NEW)
    definition = {
        "url": "https://changed.test/api",
        "transport": "http",
        "auth_type": "none",
        "issuer": None,
        "oauth_scopes": [],
        "allowed_tools": None,
        "image_digest": None,
        "source_commit": None,
    }
    did = new_uuid7()
    conn.execute(
        "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,"
        "sha256,url,url_sha256,transport,auth_type) VALUES (%s,'i','s',%s,%s,%s,%s,'http','none')",
        (
            did,
            canonical_text(definition),
            sha256(definition),
            definition["url"],
            url_sha256(definition["url"]),
        ),
    )
    request_deployment(ctx, "s", str(did))
    request_deployment(ctx, "s", str(did))
    assert server(conn)["deployment_drift"]
    assert len(events(conn, "deployment_drift_detected")) == 1
    iid = evidence(conn, candidate, deployment=sha256(definition))
    reapprove(
        ctx,
        Pin(conn, old, candidate, {"read": NEW}),
        "s",
        iid,
        [str(candidate)],
        deployment_id=str(did),
    )
    assert not server(conn)["deployment_drift"]
    assert server(conn)["deployment_drift_fields"] is None
    assert server(conn)["url_sha256"] == url_sha256(definition["url"])
    assert len(events(conn, "deployment_contract_approved")) == 1
    assert len(events(conn, "deployment_contract_superseded")) == 1


def test_login_roles_split_observation_planning_and_pin_writes(contract_db, fresh_db, login_roles):
    import psycopg
    from ctl_fixtures import as_login

    conn, _, old = contract_db
    state_version = server(conn)["state_version"]
    with as_login(fresh_db, "mint_worker") as worker, as_login(fresh_db, "mint_control") as control:
        worker.autocommit = control.autocommit = True
        operator = Operator("reviewer", "approver", "reviewer")
        wctx, cctx = Context(worker, "i", operator), Context(control, "i", operator)
        record_tools(wctx, "s", "server", {"read": NEW}, state_version)
        candidate = add_tool(conn, NEW)
        iid = evidence(conn, candidate)
        contracts.reapprove(cctx, "s", iid, [str(candidate)])
        guarded = (
            "INSERT INTO mint.litellm_grants(id,instance_id,target_type,target_id,item,"
            "server_id) VALUES (gen_random_uuid(),'i','server','s','pin','s')",
            "UPDATE mint.contract_observations SET change_seq = change_seq + 1",
            "INSERT INTO mint.contract_observation_receipts(instance_id,event_id)"
            " VALUES ('i',gen_random_uuid())",
            "UPDATE mint.contract_reapproval_plans SET status='completed',result='{}'::jsonb",
        )
        for statement in guarded:
            with pytest.raises(psycopg.errors.InsufficientPrivilege), control.transaction():
                control.execute(statement)
        result = finalize_reapproval(worker, "i", "s", Pin(conn, old, candidate, {"read": NEW}))
        assert result["pin_sha256"]
    plan = fetchone(conn, "SELECT status FROM mint.contract_reapproval_plans")
    assert plan["status"] == "completed"
    grant = fetchone(conn, "SELECT observed FROM mint.litellm_grants WHERE item='pin'")
    assert grant["observed"] is True


def test_failed_pin_confirmation_lowers_the_pin_row_after_unpin(contract_db):
    conn, ctx, old = contract_db
    observe(conn, ctx, {"read": NEW})
    candidate = add_tool(conn, NEW)
    iid = evidence(conn, candidate)
    conn.execute(
        "INSERT INTO mint.litellm_grants(id,instance_id,target_type,target_id,item,server_id,"
        "applied_sha256,observed) VALUES (%s,'i','server','s','pin','s',%s,true)",
        (new_uuid7(), "a" * 64),
    )
    pin = Pin(conn, old, candidate, {"read": TOOL})  # 응답이 후보와 다르면 확정 실패
    with pytest.raises(AdminError):
        reapprove(ctx, pin, "s", iid, [str(candidate)])
    assert pin.unpins == 1
    row = fetchone(conn, "SELECT observed FROM mint.litellm_grants WHERE item='pin'")
    assert row["observed"] is False


def test_contract_observe_reads_tools_through_the_g2_client(contract_db):
    from mint_litellm.control.contract_observe import handle
    from mint_litellm.control.errors import ControlError
    from mint_litellm.control.jobs import JobContext

    conn, ctx, _ = contract_db
    seen = []

    class Client:
        def test_tools_list(self, spec):
            seen.append(spec)
            return {"tools": [{"name": "read", **NEW, "inputSchema": NEW["input_schema"]}]}

    job = {"target_ref": "contract_observe"}
    handle(JobContext(conn, "i", job, litellm=Client()))
    assert seen == [{"server_id": "s", "url": "https://mcp.test/api", "transport": "http",
                     "auth_type": "none"}]
    assert fetchone(conn, "SELECT drift FROM mint.tool_contracts WHERE status='approved'")[
        "drift"
    ] == "input_schema"
    Client.test_tools_list = lambda self, spec: {"status": "error", "message": "down"}
    with pytest.raises(ControlError):
        handle(JobContext(conn, "i", job, litellm=Client()))
    with pytest.raises(ControlError):
        handle(JobContext(conn, "i", job))
