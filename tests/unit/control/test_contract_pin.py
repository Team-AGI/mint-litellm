"""외부 pin과 DB 확정 사이의 경쟁·실패를 DB 없이 재현한다."""

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest
from psycopg.pq import TransactionStatus

from mint_litellm.control import contract_pin, jobs
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.errors import AdminError
from mint_litellm.control.services import base, contracts
from mint_litellm.types.canonical import pin_sha256, sha256

TOOL = {"description": "read", "input_schema": {"type": "object"}}
NEW = {**TOOL, "input_schema": {"type": "object", "required": ["q"]}}


class MemoryConnection:
    """DB 경계 대역: 트랜잭션·커밋 실패와 사용되는 쓰기만 모델링한다."""

    def __init__(self):
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.old, self.candidate, self.intake = (str(uuid4()) for _ in range(3))
        self.state = {
            "server": {
                "state_version": 1,
                "deployment_drift": False,
                "deployment_drift_fields": [],
            },
            "tools": {self.old: "approved", self.candidate: "candidate"},
            "events": [],
            "jobs": [],
            "saved": None,
            "grant": None,
        }
        self.version = 2
        self.fail_commit = False
        self.fail_event = False
        self.locked = False

    @contextmanager
    def transaction(self):
        before = deepcopy(self.state)
        self.info.transaction_status = TransactionStatus.INTRANS
        try:
            yield
            if self.fail_commit:
                self.fail_commit = False
                raise RuntimeError("commit failed")
        except BaseException:
            self.state = before
            raise
        finally:
            self.info.transaction_status = TransactionStatus.IDLE

    def execute(self, sql, params=()):
        if sql.startswith("SELECT pg_advisory_unlock"):
            self.locked = False
        elif sql.startswith("INSERT INTO mint.contract_reapproval_plans"):
            pid, instance, server, intake, actor, user, plan = params
            self.state["saved"] = {
                "id": pid,
                "instance_id": instance,
                "server_id": server,
                "intake_id": intake,
                "requested_by": actor,
                "requested_user_id": user,
                "plan": deepcopy(plan.obj),
                "status": "pending",
                "result": None,
            }
        elif sql.startswith("INSERT INTO mint.events"):
            if self.fail_event and params[2] == "contract_approved":
                raise RuntimeError("ledger failed")
            self.state["events"].append((params[2], params[3], params[-1].obj))
        elif sql.startswith("UPDATE mint.servers SET last_observed_at"):
            self.state["server"]["deployment_drift"] = params[0]
            if params[1]:
                self.state["server"]["deployment_drift_fields"] = None
        elif sql.startswith("INSERT INTO mint.litellm_grants"):
            self.state["grant"] = params[-1]
        elif sql.startswith("UPDATE mint.contract_reapproval_plans"):
            self.state["saved"].update(status="completed", result=params[0].obj)
        else:
            raise AssertionError(sql)

    def fetchone(self, sql, params=()):
        if "pg_try_advisory_lock" in sql:
            ok = not self.locked
            self.locked = True
            return {"ok": ok}
        if "FROM mint.operators" in sql:
            return None if self.state.get("requester_gone") else {"ok": 1, "role": "approver"}
        if sql.startswith("SELECT * FROM mint.contract_reapproval_plans"):
            return deepcopy(self.state["saved"])
        if sql.startswith("UPDATE mint.servers SET deployment_drift=true"):
            self.state["server"].update(deployment_drift=True, deployment_drift_fields=params[0])
            self.state["server"]["state_version"] += 1
            return {"state_version": self.state["server"]["state_version"]}
        if sql.startswith("SELECT 1 FROM mint.events"):
            return next(({"ok": 1} for _, key, _ in self.state["events"] if key == params[1]), None)
        if sql.startswith("INSERT INTO mint.jobs"):
            self.state["jobs"].append(params)
            return {"id": params[0]}
        if sql.startswith("UPDATE mint.tool_contracts SET status="):
            status = "approved" if "status='approved'" in sql else "superseded"
            self.state["tools"][params[1]] = status
            return {"version": 3}
        raise AssertionError(sql)

    def plan(self, *args, **kwargs):
        candidate = {
            "id": self.candidate,
            "version": self.version,
            "tool": "read",
            "sha256": sha256(NEW),
            "pin_sha256": pin_sha256(NEW),
        }
        return deepcopy(
            {
                "server": self.state["server"],
                "candidates": [candidate],
                "deployment": None,
                "approved": [
                    {"id": self.old, "version": 1, "tool": "read", "sha256": sha256(TOOL)}
                ],
                "desired": {"read": NEW},
                "scope": "server",
                "evidence_hash": sha256(NEW),
            }
        )


class Pin:
    def __init__(self, conn, during=lambda: None, response=None):
        self.conn, self.during = conn, during
        self.response = response if response is not None else {"read": NEW}
        self.calls = self.unpins = 0
        self.fail_unpin = False

    def pin(self, server_id):
        assert self.conn.info.transaction_status == TransactionStatus.IDLE
        assert self.conn.state["server"]["deployment_drift"]
        assert self.conn.state["tools"][self.conn.old] == "approved"
        self.calls += 1
        self.during()
        return self.response

    def unpin(self, server_id):
        self.unpins += 1
        if self.fail_unpin:
            raise RuntimeError("unpin failed")


@pytest.fixture
def setup(monkeypatch):
    conn = MemoryConnection()
    for module in (contract_pin, contracts, base):
        monkeypatch.setattr(
            module, "fetchone", lambda conn, sql, params=(): conn.fetchone(sql, params)
        )
    monkeypatch.setattr(contracts, "_plan", conn.plan)
    monkeypatch.setattr(contract_pin, "_plan", conn.plan)
    ctx = Context(conn, "i", Operator("reviewer", "approver", "reviewer"))
    return conn, ctx


def request(conn, ctx):
    return contracts.reapprove(ctx, "s", conn.intake, [conn.candidate])


def assert_pending(conn):
    assert conn.state["tools"][conn.old] == "approved"
    assert conn.state["tools"][conn.candidate] == "candidate"
    assert conn.state["server"]["deployment_drift"]
    assert conn.state["saved"]["status"] == "pending"
    assert conn.state["grant"] is None
    assert [kind for kind, _, _ in conn.state["events"]] == ["reapproval_requested"]
    assert not conn.locked


def test_request_commits_frozen_plan_block_event_and_the_sync_job(setup):
    conn, ctx = setup
    assert "sync_server" in jobs.KINDS
    result = request(conn, ctx)
    saved = conn.state["saved"]
    assert str(saved["id"]) == result["plan_id"]
    assert saved["plan"]["candidates"] == [
        {"id": conn.candidate, "version": 2, "sha256": sha256(NEW)}
    ]
    assert saved["plan"]["drift_fields"] == ["pin_reapproval"]
    assert conn.state["jobs"][0][1:] == ("i", "sync_server", "s", None)
    assert_pending(conn)


def test_job_failure_rolls_back_request_plan_block_and_events(setup, monkeypatch):
    conn, ctx = setup

    def fail(*args):
        raise RuntimeError("queue failed")

    monkeypatch.setattr(contracts, "enqueue_job", fail)
    with pytest.raises(RuntimeError, match="queue failed"):
        request(conn, ctx)
    assert not conn.state["server"]["deployment_drift"]
    assert conn.state["saved"] is None and conn.state["events"] == []
    assert ctx.emitted == []


def test_cli_reapproval_needs_no_litellm_client_or_key(setup):
    from mint_litellm.cli import _contract

    conn, ctx = setup
    messages = []
    run = SimpleNamespace(
        args=SimpleNamespace(
            command_name="contract reapprove",
            server_id="s",
            intake=conn.intake,
            tool_contract=[conn.candidate],
            deployment_contract=None,
            state_version=None,
        ),
        context=lambda: ctx,
        data={},
        say=messages.append,
    )
    _contract(run)
    assert run.data["plan_id"] == str(conn.state["saved"]["id"])
    assert len(messages) == 1
    assert_pending(conn)


def test_finalize_atomically_replaces_approval_and_is_idempotent(setup):
    conn, ctx = setup
    request(conn, ctx)
    pin = Pin(conn)
    result = contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert conn.state["tools"] == {conn.old: "superseded", conn.candidate: "approved"}
    assert not conn.state["server"]["deployment_drift"]
    assert conn.state["grant"] == result["pin_sha256"]
    assert conn.state["saved"]["status"] == "completed"
    assert [kind for kind, _, _ in conn.state["events"]] == [
        "reapproval_requested",
        "contract_superseded",
        "contract_approved",
    ]
    assert contract_pin.finalize_reapproval(conn, "i", "s", pin) == result
    assert pin.calls == 1 and pin.unpins == 0 and not conn.locked


@pytest.mark.parametrize("change", ["candidate_id", "candidate_version", "plan_id"])
def test_candidate_or_plan_changed_while_pin_response_is_pending(setup, change):
    conn, ctx = setup
    request(conn, ctx)

    def changed():
        if change == "candidate_id":
            conn.candidate = str(uuid4())
            conn.state["tools"][conn.candidate] = "candidate"
        elif change == "candidate_version":
            conn.version += 1
        else:
            conn.state["saved"]["id"] = uuid4()

    pin = Pin(conn, changed)
    with pytest.raises(AdminError):
        contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert pin.calls == pin.unpins == 1
    assert_pending(conn)


def test_same_definition_hash_but_different_tool_set_is_not_accepted(setup):
    conn, ctx = setup
    request(conn, ctx)
    assert pin_sha256(NEW) == pin_sha256(deepcopy(NEW))
    pin = Pin(conn, response={"renamed": deepcopy(NEW)})
    with pytest.raises(AdminError, match="도구 집합"):
        contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert pin.unpins == 1
    assert_pending(conn)


@pytest.mark.parametrize("failure", ["event", "commit", "commit_and_unpin"])
def test_pin_success_followed_by_db_failure_preserves_approval_and_block(setup, failure):
    conn, ctx = setup
    request(conn, ctx)

    def fail_after_pin():
        if failure == "event":
            conn.fail_event = True
        else:
            conn.fail_commit = True

    pin = Pin(conn, fail_after_pin)
    pin.fail_unpin = failure == "commit_and_unpin"
    with pytest.raises(RuntimeError, match="ledger failed|commit failed"):
        contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert pin.calls == pin.unpins == 1
    assert_pending(conn)


def test_changed_candidate_is_rejected_before_pin(setup):
    conn, ctx = setup
    request(conn, ctx)
    conn.version += 1
    pin = Pin(conn)
    with pytest.raises(AdminError):
        contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert pin.calls == pin.unpins == 0
    assert_pending(conn)


def test_a_lost_lease_after_the_pin_write_keeps_the_block_and_unpins(setup):
    conn, ctx = setup
    request(conn, ctx)

    def lost():
        raise jobs.Cancelled

    pin = Pin(conn)
    with pytest.raises(jobs.Cancelled):
        contract_pin.finalize_reapproval(conn, "i", "s", pin, guard=lost)
    assert pin.calls == pin.unpins == 1
    assert_pending(conn)
    # 다음 실행이 다시 수렴한다(임대를 얻은 새 실행)
    result = contract_pin.finalize_reapproval(conn, "i", "s", Pin(conn), guard=lambda: None)
    assert conn.state["saved"]["status"] == "completed" and result["pin_sha256"]


def test_the_requesting_approver_removed_while_waiting_blocks_the_replacement(setup):
    conn, ctx = setup
    request(conn, ctx)
    pin = Pin(conn, lambda: conn.state.update(requester_gone=True))
    with pytest.raises(AdminError, match="승인자"):
        contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert pin.calls == pin.unpins == 1
    assert_pending(conn)


def test_a_response_that_arrives_after_a_newer_plan_replaced_the_old_one_is_discarded(setup):
    conn, ctx = setup
    request(conn, ctx)

    def newer_plan():
        conn.state["saved"]["id"] = uuid4()
        conn.state["saved"]["status"] = "pending"

    pin = Pin(conn, newer_plan)
    with pytest.raises(AdminError):
        contract_pin.finalize_reapproval(conn, "i", "s", pin)
    assert conn.state["tools"][conn.old] == "approved"
    assert conn.state["grant"] is None
