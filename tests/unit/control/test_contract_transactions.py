"""실 DB에서 관측 재시도와 재승인 원자성을 검증한다."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from ctl_fixtures import seed_version_evidence
from psycopg.types.json import Jsonb

from mint_litellm.control.context import Context, Operator
from mint_litellm.control.contract_observe import (
    compare_instances,
    consume_deployment_events,
    record_tools,
)
from mint_litellm.control.contract_pin import finalize_reapproval
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminError
from mint_litellm.control.services import contracts
from mint_litellm.control.services import evidence as evidence_service
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
    seed_version_evidence(conn, "s", "i")
    # 배포 후보가 있으면 도구만 고른 재승인은 증거와 맞지 않으므로 명확히 거절한다.
    with pytest.raises(AdminError, match="배포 값 후보"):
        reapprove(ctx, Pin(conn, old, candidate, {"read": NEW}), "s", iid, [str(candidate)])
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

    # 레지스트리 인증 방식이 승인 뒤 바뀌어도 관측은 승인된 배포 계약의 값을 보낸다.
    conn.execute("UPDATE mint.servers SET auth_type='oauth2' WHERE server_id='s'")
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



class FlowClient:
    """승인된 배포 계약이 oauth2인 서버에 대한 LiteLLM 읽기 응답(바꿔 가며 쓴다).

    ``flow``는 현재 서버 설정(``get_server``)의 값, ``submissions``는 제출 목록이다.
    """

    def __init__(self, flow, listing=True, submissions=()):
        self.flow, self.listing, self.submissions = flow, listing, list(submissions)
        self.tool_calls = 0

    def test_tools_list(self, spec):
        self.tool_calls += 1
        return {"tools": [{"name": "read", **TOOL, "inputSchema": TOOL["input_schema"]}]}

    def list_submissions(self):
        from mint_litellm.control.litellm_admin import LiteLLMError

        if not self.listing:
            raise LiteLLMError("down")
        return self.submissions

    def get_server(self, server_id):
        from mint_litellm.control.litellm_admin import LiteLLMError

        if not self.listing:
            raise LiteLLMError("down")
        return None if self.flow is None else {"server_id": server_id, "oauth2_flow": self.flow}


def submitted(flow, status="approved"):
    return {"server_id": "s", "oauth2_flow": flow, "approval_status": status}


@pytest.fixture
def oauth_db(contract_db):
    conn, ctx, old = contract_db
    # 배포 계약의 고정 열을 시험용으로 바꾼다
    conn.execute("SET session_replication_role = replica")
    conn.execute("UPDATE mint.deployment_contracts SET auth_type='oauth2', issuer='https://i.test'"
                 " WHERE status='approved'")
    conn.execute("SET session_replication_role = DEFAULT")
    return conn, ctx


def run_observe(conn, client):
    from mint_litellm.control.contract_observe import handle
    from mint_litellm.control.jobs import JobContext

    handle(JobContext(conn, "i", {"target_ref": "contract_observe"}, litellm=client))


def test_a_server_credential_flow_leaves_an_oauth2_server_untouched(oauth_db):
    conn, _ = oauth_db
    client = FlowClient("client_credentials")
    run_observe(conn, client)
    assert not server(conn)["deployment_drift"] and client.tool_calls == 1
    assert events(conn, "deployment_drift_detected") == []


def test_a_changed_oauth2_flow_blocks_at_the_next_observation_and_asks_for_reapproval(oauth_db):
    conn, _ = oauth_db
    run_observe(conn, FlowClient("client_credentials"))
    for _ in range(2):  # 같은 값이 이어져도 사건·경보는 한 번이다
        run_observe(conn, FlowClient("authorization_code"))
    row = server(conn)
    assert row["deployment_drift"] and row["deployment_drift_fields"] == ["oauth2_flow"]
    assert len(events(conn, "deployment_drift_detected")) == 1
    assert len(events(conn, "reapproval_requested")) == 1
    alert = fetchone(conn, "SELECT severity, kind FROM mint.alerts")
    assert (alert["severity"], alert["kind"]) == ("critical", "contract_drift")
    # 정상으로 돌아와도 재승인 전에는 풀리지 않는다
    run_observe(conn, FlowClient("client_credentials"))
    assert server(conn)["deployment_drift"]


def test_a_missing_oauth2_flow_blocks_at_once(oauth_db):
    conn, _ = oauth_db
    run_observe(conn, FlowClient(None))
    assert server(conn)["deployment_drift"]


def test_the_current_server_config_wins_over_the_submission_list(oauth_db):
    conn, _ = oauth_db
    run_observe(conn, FlowClient("authorization_code",
                                 submissions=[submitted("client_credentials")]))
    assert server(conn)["deployment_drift"]


def test_only_approved_submissions_count_when_the_server_is_not_configured(oauth_db):
    conn, _ = oauth_db
    mixed = [submitted("authorization_code", "pending_review"),
             submitted("authorization_code", "rejected")]
    run_observe(conn, FlowClient(None, submissions=mixed))  # 승인 제출이 없다: 값 없음
    assert server(conn)["deployment_drift"]
    conn.execute("UPDATE mint.servers SET deployment_drift=false, deployment_drift_fields=NULL")
    conn.execute("DELETE FROM mint.contract_observations WHERE kind='deployment'")
    run_observe(conn, FlowClient(None, submissions=[*mixed, submitted("client_credentials")]))
    assert not server(conn)["deployment_drift"]


def test_an_unreadable_flow_only_alerts_twice_and_blocks_from_the_third_failure(oauth_db):
    conn, _ = oauth_db
    for failures in (1, 2):
        run_observe(conn, FlowClient("client_credentials", listing=False))
        assert not server(conn)["deployment_drift"]
        alert = fetchone(conn, "SELECT kind, count FROM mint.alerts"
                         " WHERE kind='oauth_flow_unreadable'")
        assert alert["count"] == failures
    run_observe(conn, FlowClient("client_credentials", listing=False))
    assert server(conn)["deployment_drift"]
    assert fetchone(conn, "SELECT 1 AS x FROM mint.events WHERE kind='reapproval_requested'")


def test_a_successful_read_resets_the_failure_count(oauth_db):
    conn, _ = oauth_db
    for _ in range(2):
        run_observe(conn, FlowClient("client_credentials", listing=False))
    run_observe(conn, FlowClient("client_credentials"))
    for _ in range(2):  # 연속이 아니므로 다시 두 번까지는 막지 않는다
        run_observe(conn, FlowClient("client_credentials", listing=False))
    assert not server(conn)["deployment_drift"]


def test_other_auth_types_are_not_asked_for_a_flow(contract_db):
    conn, _, _ = contract_db

    class Strict(FlowClient):
        def get_server(self, server_id):
            raise AssertionError("oauth2가 아닌 서버의 흐름은 읽지 않는다")

    run_observe(conn, Strict("authorization_code"))
    assert not server(conn)["deployment_drift"]


def test_the_oauth2_events_do_not_collide_with_identity_events(oauth_db):
    """같은 계약의 oauth2 관측 사건과 identity 사건은 서로 다른 개체 키를 쓴다."""
    conn, ctx = oauth_db
    run_observe(conn, FlowClient("authorization_code"))
    conn.execute(
        "INSERT INTO mint.events(event_id,instance_id,kind,source_key,payload)"
        " VALUES (%s,'i','server_identity_mismatch_observed',%s,%s)",
        (uuid4(), "selfcheck:run:1:server_identity_mismatch_observed",
         Jsonb({"server_id": "s", "fields": ["issuer"], "observed_hashes": {"issuer": "a" * 64}})),
    )
    consume_deployment_events(ctx)
    run_observe(conn, FlowClient("client_credentials"))  # 다음 관측도 멈추지 않는다
    keys = [e["source_key"] for e in events(conn, "deployment_drift_detected")]
    assert len(keys) == 2 and len(set(keys)) == 2
    assert sorted(server(conn)["deployment_drift_fields"]) == ["issuer", "oauth2_flow"]


def test_failures_counted_for_an_earlier_contract_start_over(oauth_db):
    conn, _ = oauth_db
    for _ in range(2):
        run_observe(conn, FlowClient("client_credentials", listing=False))
    # 재승인으로 승인 계약이 바뀐 것과 같다: 옛 계약의 실패는 이어 세지 않는다
    conn.execute("UPDATE mint.contract_observations SET entity_id = gen_random_uuid()"
                 " WHERE name = 'oauth2_flow_read'")
    run_observe(conn, FlowClient("client_credentials", listing=False))
    assert not server(conn)["deployment_drift"]


def test_intake_evidence_binding_matches_what_reapproval_demands(contract_db):
    from mint_litellm.control.services import intakes

    conn, _, _ = contract_db
    new = add_tool(conn, NEW)
    deployment = {"url": "https://mcp.test/api", "transport": "http", "auth_type": "none"}
    conn.execute(
        "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,"
        "sha256,url,url_sha256,transport,auth_type) VALUES (%s,'i','s',%s,%s,%s,%s,'http','none')",
        (new_uuid7(), canonical_text(deployment), sha256(deployment), deployment["url"],
         url_sha256(deployment["url"])),
    )
    bound = intakes.contract_binding(conn, "i", "s")
    assert bound == sha256({"tools": {"read": sha256(NEW)}, "deployment": sha256(deployment)})
    assert new


@pytest.mark.parametrize(
    ("tools", "severity"),
    [
        ({"read": NEW}, "high"),  # 입력 스키마
        ({"read": {**TOOL, "description": "changed"}}, "medium"),  # 설명
        ({"read": TOOL, "extra": TOOL}, "low"),  # 도구 추가
        ({}, "low"),  # 도구 삭제
    ],
)
def test_every_contract_alert_opens_with_an_alert_opened_event(contract_db, tools, severity):
    conn, ctx, _ = contract_db
    observe(conn, ctx, tools)
    alert = fetchone(conn, "SELECT id, severity, kind FROM mint.alerts")
    assert (alert["severity"], alert["kind"]) == (severity, "contract_drift")
    opened = events(conn, "alert_opened")
    assert [e["source_key"] for e in opened] == [f"alert:{alert['id']}:0:alert_opened"]
    observe(conn, ctx, tools)  # 같은 관측은 경보도 사건도 늘리지 않는다
    assert len(events(conn, "alert_opened")) == 1


def test_a_contract_alert_resolved_then_a_new_drift_opens_a_new_alert_event(contract_db):
    from mint_litellm.control import alerts

    conn, ctx, _ = contract_db
    observe(conn, ctx, {"read": NEW})
    key = fetchone(conn, "SELECT dedup_key FROM mint.alerts")["dedup_key"]
    assert alerts.resolve(conn, "i", key) == 1
    observe(conn, ctx, {"read": {**TOOL, "description": "again"}})
    assert len(events(conn, "alert_opened")) == 2
    assert len(events(conn, "alert_resolved")) == 1


def test_a_deployment_drift_alert_also_has_its_opening_event(contract_db):
    conn, ctx, _ = contract_db
    conn.execute(
        "INSERT INTO mint.events(event_id,instance_id,kind,source_key,payload)"
        " VALUES (%s,'i','server_identity_mismatch_observed','selfcheck:run:1:x',%s)",
        (uuid4(),
         Jsonb({"server_id": "s", "fields": ["issuer"], "observed_hashes": {"issuer": "a" * 64}})),
    )
    consume_deployment_events(ctx)
    alert = fetchone(conn, "SELECT id, severity FROM mint.alerts")
    assert alert["severity"] == "critical"
    assert [e["source_key"] for e in events(conn, "alert_opened")] == [
        f"alert:{alert['id']}:0:alert_opened"
    ]


def seed_peer(conn, url, tool_value):
    """같은 서버 식별자를 계약 관리하는 두 번째 인스턴스와 그 승인 계약."""
    conn.execute("INSERT INTO mint.orgs(instance_id,org_id,name) VALUES ('j','o','org')")
    conn.execute(
        "INSERT INTO mint.servers(id,instance_id,server_id,status,url_sha256,transport,"
        "auth_type,registered_by,contract_status) VALUES (%s,'j','s','pending',%s,'http',"
        "'none','requester','managed')",
        (new_uuid7(), url_sha256(url)),
    )
    for status in ("validating", "awaiting_approval", "approved"):
        conn.execute("UPDATE mint.servers SET status=%s WHERE instance_id='j'", (status,))
    deployment = {"url": url, "transport": "http", "auth_type": "none"}
    did = new_uuid7()
    conn.execute(
        "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,"
        "sha256,url,url_sha256,transport,auth_type)"
        " VALUES (%s,'j','s',%s,%s,%s,%s,'http','none')",
        (did, canonical_text(deployment), sha256(deployment), url, url_sha256(url)),
    )
    conn.execute("UPDATE mint.deployment_contracts SET status='approved' WHERE id=%s", (did,))
    tid = new_uuid7()
    conn.execute(
        "INSERT INTO mint.tool_contracts(id,instance_id,server_id,credential_scope,tool,"
        "canonical_text,sha256,pin_sha256,risk_grade,action_type,source)"
        " VALUES (%s,'j','s','server','read',%s,%s,%s,'low','read','intake')",
        (tid, canonical_text(tool_value), sha256(tool_value), pin_sha256(tool_value)),
    )
    conn.execute("UPDATE mint.tool_contracts SET status='approved' WHERE id=%s", (tid,))


def instance_alerts(conn):
    return fetchall(
        conn, "SELECT * FROM mint.alerts WHERE kind='instance_mismatch' AND status<>'resolved'"
    )


def test_instances_with_the_same_approved_contracts_raise_nothing(contract_db):
    conn, ctx, _ = contract_db
    seed_peer(conn, "https://mcp.test/api", TOOL)
    assert compare_instances(ctx) == 0
    assert instance_alerts(conn) == []
    assert events(conn, "deployment_drift_detected") == []


def test_a_differing_peer_raises_one_alert_and_one_event_until_it_changes(contract_db):
    conn, ctx, _ = contract_db
    seed_peer(conn, "https://other.test/api", NEW)
    assert compare_instances(ctx) == 1
    (alert,) = instance_alerts(conn)
    assert alert["subject"]["instances"] == ["i", "j"]
    assert sorted(alert["subject"]["items"]) == ["deployment", "tool:server/read"]
    assert len(events(conn, "deployment_drift_detected")) == 1
    # 같은 차이를 다시 보아도 경보 횟수만 오르고 사건은 늘지 않는다
    assert compare_instances(ctx) == 1
    assert len(events(conn, "deployment_drift_detected")) == 1
    assert instance_alerts(conn)[0]["count"] == 2


def test_the_alert_closes_when_the_peer_leaves(contract_db):
    conn, ctx, _ = contract_db
    seed_peer(conn, "https://other.test/api", TOOL)
    assert compare_instances(ctx) == 1
    conn.execute("UPDATE mint.servers SET status='suspended' WHERE instance_id='j'")
    assert compare_instances(ctx) == 0
    assert instance_alerts(conn) == []


def blocked(conn) -> bool:
    row = fetchone(
        conn, "SELECT instance_mismatch_at FROM mint.servers"
        " WHERE instance_id='i' AND server_id='s'"
    )
    return row["instance_mismatch_at"] is not None


def test_a_differing_peer_blocks_the_server_until_the_difference_goes(contract_db):
    conn, ctx, _ = contract_db
    seed_peer(conn, "https://other.test/api", NEW)
    assert compare_instances(ctx) == 1
    assert blocked(conn)
    conn.execute("UPDATE mint.servers SET status='suspended' WHERE instance_id='j'")
    assert compare_instances(ctx) == 0
    assert not blocked(conn)


def test_a_single_instance_is_never_blocked(contract_db):
    conn, ctx, _ = contract_db
    assert compare_instances(ctx) == 0
    assert not blocked(conn)


def test_differing_security_settings_count_as_a_mismatch(contract_db):
    conn, ctx, _ = contract_db
    seed_peer(conn, "https://mcp.test/api", TOOL)
    conn.execute("INSERT INTO mint.settings(instance_id,mode) VALUES ('i','enforce')")
    conn.execute("INSERT INTO mint.settings(instance_id,mode) VALUES ('j','observe')")
    assert compare_instances(ctx) == 1
    (alert,) = instance_alerts(conn)
    assert alert["subject"]["items"] == ["setting:guardrail_mode"]
    assert blocked(conn)
    conn.execute("UPDATE mint.settings SET mode='enforce' WHERE instance_id='j'")
    assert compare_instances(ctx) == 0
    assert not blocked(conn)


def test_an_admin_exception_releases_the_block_but_keeps_the_alert(contract_db):
    conn, ctx, _ = contract_db
    seed_peer(conn, "https://other.test/api", NEW)
    with pytest.raises(AdminError):
        evidence_service.attach(replace(ctx, operator=Operator("a", "approver", None)),
                        "instance_exception", "s", summary="의도한 차이")
    evidence_service.attach(replace(ctx, operator=Operator("a", "admin", None)),
                    "instance_exception", "s", summary="의도한 차이")
    assert compare_instances(ctx) == 1
    assert not blocked(conn)
    assert len(instance_alerts(conn)) == 1
