"""고정(pin) 단계: 해시·도구 집합 대조, 활성화 완결의 고정 조건, 재승인 확정(실제 로그인 역할),
쓰기 직전 경계, 쓰기 뒤 DB 실패 수렴, 배포 후보 기록(작업 실행기 경로).
"""

import pytest
from ctl_fixtures import INSTANCE, as_login

psycopg = pytest.importorskip("psycopg")

from psycopg.types.json import Jsonb  # noqa: E402

from mint_litellm.control import sync_jobs, sync_state  # noqa: E402
from mint_litellm.control.context import Context, Operator  # noqa: E402
from mint_litellm.control.db.connection import fetchone  # noqa: E402
from mint_litellm.control.services import contracts  # noqa: E402
from mint_litellm.restore.judge import BLOCKED, Verdict  # noqa: E402
from mint_litellm.types.canonical import canonical_text, pin_sha256, sha256  # noqa: E402
from mint_litellm.types.decision import url_sha256  # noqa: E402
from mint_litellm.types.ids import new_uuid7  # noqa: E402

from . import test_sync  # noqa: E402
from .test_sync import (  # noqa: E402
    add_approval,
    add_server,
    alerts,
    drain,
    enqueue,
    events,
    grant,
    job_rows,
    past,
)

url = test_sync.url
admin = test_sync.admin
fake = test_sync.fake
make_worker = test_sync.make_worker
worker = test_sync.worker

TOOL = {"description": "read", "input_schema": {"type": "object"}}
NEW = {**TOOL, "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}}
DIGEST = sha256({"read": pin_sha256(TOOL)})


def add_contract(
    admin, tool_name="read", value=TOOL, status="approved", server="srv-1", scope="server"
) -> str:
    cid = new_uuid7()
    admin.execute(
        "INSERT INTO mint.tool_contracts(id,instance_id,server_id,credential_scope,tool,"
        "canonical_text,sha256,pin_sha256,risk_grade,action_type,source)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'low','read','intake')",
        (cid, INSTANCE, server, scope, tool_name, canonical_text(value), sha256(value),
         pin_sha256(value)))
    if status == "approved":
        admin.execute("UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s", (cid,))
    return str(cid)


def make_managed(admin) -> None:
    """계약을 관리하는 서버. 도구 고정은 제어 평면 키 토큰이 저장돼 있어야 한다."""
    admin.execute("UPDATE mint.servers SET contract_status = 'managed'")
    admin.execute("UPDATE mint.settings SET control_key_token = repeat('c', 64)")


def managed_world(admin, fake, *, tools=None, approval_scope="user", status="pending"):
    """계약을 관리하는 서버(승인 계약 도구 하나)와 대기 승인 하나."""
    add_server(admin)
    make_managed(admin)
    fake.add_server("srv-1", tools={"read": TOOL} if tools is None else tools)
    add_contract(admin)
    if approval_scope == "key":
        fake.add_key("k1")
    return add_approval(admin, approval_scope, "k1" if approval_scope == "key" else "u1",
                        status=status)


def pin_calls(fake, method="POST"):
    return [r for r in fake.requests if r[0] == method and r[1].endswith("/pin")]


def approval_status(admin, approval) -> str:
    return fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (approval,))["status"]


# --- 고정 단계 ---------------------------------------------------------------------


def test_a_matching_pin_is_recorded_and_the_approval_activates(admin, fake, worker):
    approval = managed_world(admin, fake)
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert len(pin_calls(fake)) == 1 and pin_calls(fake, "DELETE") == []
    row = grant(admin, "pin", "server", "srv-1", "srv-1")
    assert (row["observed"], row["applied_sha256"]) == (True, DIGEST)
    assert row["last_applied_at"] is not None
    pins = [e for e in events(admin, "sync_applied") if e["payload"]["item"] == "pin"]
    assert len(pins) == 1 and pins[0]["payload"]["applied_sha256"] == DIGEST
    assert approval_status(admin, approval) == "active"
    assert sync_state.pin_satisfied(admin, INSTANCE, "srv-1") is True


def test_a_pin_recorded_for_the_approved_contracts_is_not_repeated(admin, fake, worker):
    managed_world(admin, fake)
    for _ in range(3):
        enqueue(admin, "sync_server", "srv-1")
        drain(worker)
    assert len(pin_calls(fake)) == 1


def test_a_different_definition_is_unpinned_alerted_and_not_recorded(admin, fake, worker):
    approval = managed_world(admin, fake, tools={"read": NEW})
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert len(pin_calls(fake)) == 1 and len(pin_calls(fake, "DELETE")) == 1
    row = grant(admin, "pin", "server", "srv-1", "srv-1")
    assert (row["observed"], row["applied_sha256"]) == (False, None)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "pin_mismatch" and alert["subject"]["tools"] == ["read"]
    assert approval_status(admin, approval) == "pending"
    assert sync_state.pin_satisfied(admin, INSTANCE, "srv-1") is False
    assert [e for e in events(admin, "sync_applied") if e["payload"]["item"] == "pin"] == []


def test_a_different_tool_set_is_a_mismatch_in_both_directions(admin, fake, worker):
    managed_world(admin, fake, tools={"read": TOOL, "extra": TOOL})
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert alerts(admin, "sync_divergence")[0]["subject"]["tools"] == ["extra"]
    admin.execute("UPDATE mint.servers SET deployment_drift = false,"
                  " deployment_drift_fields = NULL")
    fake.servers["srv-1"]["tools"] = {}  # 승인된 도구가 없어졌다
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert alerts(admin, "sync_divergence")[0]["count"] == 2
    assert grant(admin, "pin", "server", "srv-1", "srv-1")["applied_sha256"] is None


def test_a_mismatch_creates_pin_candidates_blocks_the_server_and_requests_reapproval(
    admin, fake, worker
):
    managed_world(admin, fake, tools={"read": NEW, "added": TOOL})
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    rows = admin.execute(
        "SELECT tool, status, source, drift FROM mint.tool_contracts ORDER BY tool, status"
    ).fetchall()
    assert rows == [("added", "candidate", "pin", "none"),
                    ("read", "approved", "intake", "input_schema"),  # 승인본은 드리프트로 막힌다
                    ("read", "candidate", "pin", "none")]
    server = fetchone(admin, "SELECT deployment_drift, deployment_drift_fields FROM mint.servers")
    assert server == {"deployment_drift": True, "deployment_drift_fields": ["pin_reapproval"]}
    requested = events(admin, "reapproval_requested")
    assert sorted(e["payload"]["tool"] for e in requested) == ["added", "read"]
    assert all(e["payload"]["source"] == "pin" for e in requested)
    assert len(events(admin, "contract_drift_detected")) == 1
    assert len(alerts(admin, "sync_divergence")) == 1  # 경보도 그대로 낸다
    enqueue(admin, "sync_server", "srv-1")  # 드리프트 중에는 다시 고정하지 않고 후보도 늘지 않는다
    drain(worker)
    assert len(pin_calls(fake)) == 1
    assert len(events(admin, "reapproval_requested")) == 2


def test_only_the_contracts_of_the_servers_one_scope_are_used(admin, fake, worker):
    managed_world(admin, fake)
    add_contract(admin, "read", NEW, scope="per_user")
    assert sync_state.expected_pin(admin, INSTANCE, "srv-1") == {"read": pin_sha256(TOOL)}
    admin.execute("UPDATE mint.servers SET auth_type = 'oauth_delegate'")  # 범위가 바뀐다
    assert sync_state.expected_pin(admin, INSTANCE, "srv-1") == {"read": pin_sha256(NEW)}


def test_a_managed_server_without_approved_contracts_is_never_satisfied(admin, fake, worker):
    approval = managed_world(admin, fake)
    admin.execute("UPDATE mint.tool_contracts SET status = 'superseded'")
    assert sync_state.expected_pin(admin, INSTANCE, "srv-1") == {}
    assert sync_state.pin_satisfied(admin, INSTANCE, "srv-1") is False
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert pin_calls(fake) == []
    assert approval_status(admin, approval) == "pending"


def test_a_failed_unpin_is_alerted_retried_and_keeps_the_drift_marker(admin, fake, worker):
    managed_world(admin, fake, tools={"read": NEW})
    fake.fail_writes["DELETE /v1/mcp/server/srv-1/pin"] = 500
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.servers["srv-1"]["pinned"] is True  # 풀지 못했다
    reasons = sorted(a["subject"]["reason"] for a in alerts(admin, "sync_divergence"))
    assert reasons == ["pin_mismatch", "unpin_failed"]
    marker = "SELECT deployment_drift, deployment_drift_fields FROM mint.servers"
    assert fetchone(admin, marker)["deployment_drift"] is True
    [job] = job_rows(admin, "sync_server")
    assert (job["status"], job["last_error_code"]) == ("pending", "litellm_http_500")
    past(admin)
    drain(worker)  # 여전히 실패: 표지는 유지되고 다시 시도한다
    assert fetchone(admin, marker)["deployment_drift"] is True
    assert len(pin_calls(fake, "DELETE")) == 2
    fake.fail_writes.clear()
    past(admin)
    drain(worker)
    assert fake.servers["srv-1"]["pinned"] is False  # 다음 실행이 다시 풀었다
    assert fetchone(admin, marker)["deployment_drift"] is True  # 재승인 전까지 막힌다
    failed = [a for a in alerts(admin, "sync_divergence")
              if a["subject"]["reason"] == "unpin_failed"]
    assert failed[0]["status"] == "resolved"
    assert len(pin_calls(fake)) == 1  # 풀기 재시도는 다시 고정하지 않는다


def test_a_response_value_that_is_not_a_definition_is_a_mismatch_not_a_crash(
    admin, fake, worker
):
    managed_world(admin, fake, tools={"read": "not a definition"})
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    [job] = job_rows(admin, "sync_server")
    assert job["status"] == "done"
    assert alerts(admin, "sync_divergence")[0]["subject"]["tools"] == ["read"]
    rows = admin.execute("SELECT status, source, drift FROM mint.tool_contracts").fetchall()
    assert rows == [("approved", "intake", "input_schema")]  # 후보는 만들지 않는다
    assert fetchone(admin, "SELECT deployment_drift FROM mint.servers")["deployment_drift"] is True


def test_a_pin_that_could_not_be_removed_is_removed_after_every_approval_is_gone(
    admin, fake, worker
):
    approval = managed_world(admin, fake, tools={"read": NEW}, status="active")
    fake.fail_writes["DELETE /v1/mcp/server/srv-1/pin"] = 500
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.servers["srv-1"]["pinned"] is True
    admin.execute("UPDATE mint.approvals SET status = 'revoked', revoked_at = now(),"
                  " revoke_reason = 'r' WHERE id = %s", (approval,))
    fake.fail_writes.clear()
    past(admin)
    drain(worker)  # 승인이 하나도 없어도 남은 고정을 푼다
    assert fake.servers["srv-1"]["pinned"] is False
    failed = [a for a in alerts(admin, "sync_divergence")
              if a["subject"]["reason"] == "unpin_failed"]
    assert failed[0]["status"] == "resolved"


def test_a_mismatch_also_holds_back_key_permissions(admin, fake, worker):
    approval = managed_world(admin, fake, tools={"read": NEW}, approval_scope="key")
    enqueue(admin, "sync_server", "srv-1")
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1") == ([], {})
    assert fake.writes("/key/update") == []
    assert approval_status(admin, approval) == "pending"


def test_a_matching_pin_releases_the_key_permissions_and_finishes_the_activation(
    admin, fake, worker
):
    approval = managed_world(admin, fake, approval_scope="key")
    enqueue(admin, "sync_target", "key:k1")  # 고정 전: 권한이 나가지 않는다
    drain(worker)
    assert fake.writes("/key/update") == []
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a"]})
    assert approval_status(admin, approval) == "active"


def test_an_unmanaged_server_is_never_pinned_and_activates_as_before(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    approval = add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert pin_calls(fake) == []
    assert approval_status(admin, approval) == "active"


def test_a_drifting_server_is_not_pinned_again(admin, fake, worker):
    managed_world(admin, fake, tools={"read": NEW})
    admin.execute("UPDATE mint.servers SET deployment_drift = true,"
                  " deployment_drift_fields = ARRAY['issuer']")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert pin_calls(fake) == []
    admin.execute("UPDATE mint.servers SET deployment_drift = false,"
                  " deployment_drift_fields = NULL")
    admin.execute("UPDATE mint.tool_contracts SET drift = 'input_schema'")  # 도구 드리프트
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert pin_calls(fake) == []


def test_a_failed_database_write_after_the_pin_converges_on_the_next_run(
    admin, fake, worker, monkeypatch
):
    approval = managed_world(admin, fake)
    real = sync_jobs.upsert_grant

    def fail_for_pin(conn, inst, kind, target, item, *args, **kwargs):
        if item == "pin":
            raise RuntimeError("database down after the pin")
        return real(conn, inst, kind, target, item, *args, **kwargs)

    monkeypatch.setattr(sync_jobs, "upsert_grant", fail_for_pin)
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert len(pin_calls(fake)) == 1 and fake.servers["srv-1"]["pinned"] is True
    assert grant(admin, "pin", "server", "srv-1", "srv-1") is None  # 맞다고 적지 않았다
    assert approval_status(admin, approval) == "pending"
    monkeypatch.undo()
    past(admin)
    drain(worker)
    assert len(pin_calls(fake)) == 2  # 고정은 멱등이라 다시 걸어 확인한다
    assert grant(admin, "pin", "server", "srv-1", "srv-1")["applied_sha256"] == DIGEST
    assert approval_status(admin, approval) == "active"


def test_a_blocked_or_restored_database_never_pins(admin, fake, make_worker, monkeypatch):
    managed_world(admin, fake)
    blocked = make_worker(restore_check=lambda c, i: Verdict(BLOCKED, "restore_pending"))
    enqueue(admin, "sync_server", "srv-1")
    drain(blocked)  # 작업을 잡기 전부터 차단
    assert pin_calls(fake) == []

    worker = make_worker(restore_check=lambda c, i: False)
    past(admin)
    real = sync_jobs.expected_pin

    def then_blocked(*args):  # 작업 도중(쓰기 직전)에 되돌림이 감지된다
        result = real(*args)
        worker.verdict = Verdict(BLOCKED, "restore_pending")
        return result

    monkeypatch.setattr(sync_jobs, "expected_pin", then_blocked)
    drain(worker)
    assert pin_calls(fake) == []
    [job] = job_rows(admin, "sync_server")
    assert (job["status"], job["last_error_code"]) == ("pending", "restore_blocked")


def test_the_activation_rechecks_the_pin_inside_its_transaction(
    admin, fake, worker, monkeypatch
):
    approval = managed_world(admin, fake, tools={"read": NEW})
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)  # 서버 승인은 확인됐고 고정은 맞지 않다
    assert grant(admin, "pin", "server", "srv-1", "srv-1")["observed"] is False
    real = sync_jobs.pin_satisfied
    calls = []

    def stale_then_real(conn, inst, server_id, **kwargs):  # 바깥 확인은 오래된 값(참)을 본 경우
        calls.append(kwargs.get("lock", False))
        return True if len(calls) == 1 else real(conn, inst, server_id, **kwargs)

    monkeypatch.setattr(sync_jobs, "pin_satisfied", stale_then_real)
    enqueue(admin, "activation_finalize", approval)
    drain(worker)
    assert calls == [False, True]  # 두 번째는 행을 잠그고 확인했다
    assert approval_status(admin, approval) == "pending"


# --- 재승인 확정과 배포 후보(실제 로그인 역할) -------------------------------------------


def reapproval_world(admin, fake, tools):
    admin.execute(  # 재승인을 요청한 승인자는 확정 때도 유효해야 한다
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES (%s, 'reviewer', 'approver', repeat('c', 64), 'reviewer')"
        " ON CONFLICT DO NOTHING", (INSTANCE,))
    add_server(admin, status="approved")
    make_managed(admin)
    fake.add_server("srv-1", tools=tools)
    old = add_contract(admin)
    deployment = {"url": "https://mcp.test/api", "transport": "http", "auth_type": "none"}
    did = new_uuid7()
    admin.execute(
        "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,sha256,"
        "url,url_sha256,transport,auth_type) VALUES (%s,%s,'srv-1',%s,%s,%s,%s,'http','none')",
        (did, INSTANCE, canonical_text(deployment), sha256(deployment), deployment["url"],
         url_sha256(deployment["url"])))
    admin.execute("UPDATE mint.deployment_contracts SET status = 'approved' WHERE id = %s", (did,))
    candidate = add_contract(admin, value=NEW, status="candidate")
    iid = new_uuid7()
    admin.execute(
        "INSERT INTO mint.intakes(id,instance_id,org_id,server_id,source)"
        " VALUES (%s,%s,'acme','srv-1','operator')", (iid, INSTANCE))
    admin.execute(
        "UPDATE mint.intakes SET status='checking',purpose='read',data_grade='public',"
        "allowed_resources='[]',provider='vendor',owner_user_id='requester',"
        "requested_by='requester',readiness=%s,data_return_terms='delete' WHERE id=%s",
        (Jsonb({"credential_notice": "ok", "revocation_record": "ok", "audit_access_days": 30}),
         iid))
    admin.execute("UPDATE mint.intakes SET status='passed' WHERE id=%s", (iid,))
    bound = sha256({"tools": {"read": sha256(NEW)}, "deployment": None})
    for name in ("connection", "definitions", "description_scan", "risk_grade"):
        admin.execute(
            'INSERT INTO mint.intake_checks(id,instance_id,intake_id,"check",attempt,result,'
            "method,inputs,evidence_sha256,evidence_valid_until,ran_at)"
            " VALUES (%s,%s,%s,%s,1,'pass','test',%s,%s,now()+interval '1 day',now())",
            (new_uuid7(), INSTANCE, iid, name, Jsonb({"contract_sha256": bound}), "a" * 64))
    return old, candidate, str(iid)


def request_reapproval(url, candidate, iid) -> None:
    with as_login(url, "mint_control") as conn:
        ctx = Context(conn, INSTANCE, Operator("reviewer", "approver", "reviewer"))
        contracts.reapprove(ctx, "srv-1", iid, [candidate])
        conn.commit()


def test_a_reapproval_is_finalized_by_the_worker_login_from_start_to_finish(
    url, admin, fake, worker
):
    old, candidate, iid = reapproval_world(admin, fake, {"read": NEW})
    request_reapproval(url, candidate, iid)  # 제어 로그인은 계획·차단·작업 등록만 한다
    assert fetchone(admin, "SELECT deployment_drift_fields FROM mint.servers")[
        "deployment_drift_fields"] == ["pin_reapproval"]
    assert pin_calls(fake) == []
    drain(worker)  # 작업 실행기 로그인 하나로 재pin·승인본 교체·고정 기록·계획 완료
    rows = admin.execute("SELECT id, status FROM mint.tool_contracts").fetchall()
    status = {str(i): st for i, st in rows}
    assert status == {old: "superseded", candidate: "approved"}
    new_digest = sha256({"read": pin_sha256(NEW)})
    assert grant(admin, "pin", "server", "srv-1", "srv-1")["applied_sha256"] == new_digest
    assert fetchone(admin, "SELECT status FROM mint.contract_reapproval_plans")[
        "status"] == "completed"
    assert fetchone(admin, "SELECT deployment_drift FROM mint.servers")["deployment_drift"] is False
    assert len(events(admin, "contract_approved")) == 1
    assert len(pin_calls(fake)) == 1


def test_a_reapproval_whose_pin_differs_fails_for_good_keeps_the_block_and_alerts(
    url, admin, fake, worker
):
    old, candidate, iid = reapproval_world(admin, fake, {"read": TOOL})  # 후보와 다른 응답
    request_reapproval(url, candidate, iid)
    drain(worker)
    [job] = job_rows(admin, "sync_server")
    assert (job["status"], job["last_error_code"]) == ("failed", "reapproval_conflict")
    assert job["attempts"] == 0  # 재시도하지 않는다
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "reapproval_conflict"
    plan = "SELECT status FROM mint.contract_reapproval_plans"
    assert fetchone(admin, plan)["status"] == "cancelled"  # 같은 실패를 되풀이하지 않는다
    assert alerts(admin, "sync_divergence")[0]["subject"]["plan"] == "cancelled"
    assert fetchone(admin, "SELECT status FROM mint.tool_contracts WHERE id = %s",
                    (old,))["status"] == "approved"
    assert fetchone(admin, "SELECT deployment_drift FROM mint.servers")["deployment_drift"] is True
    assert len(pin_calls(fake, "DELETE")) == 1
    pins = len(pin_calls(fake))
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert len(pin_calls(fake)) == pins  # 취소된 계획으로는 다시 고정하지 않는다
    fake.servers["srv-1"]["tools"] = {"read": NEW}  # 운영자가 재승인을 다시 요청한다
    request_reapproval(url, candidate, iid)
    assert fetchone(admin, plan)["status"] == "pending"
    drain(worker)
    assert fetchone(admin, plan)["status"] == "completed"
    assert fetchone(admin, "SELECT deployment_drift FROM mint.servers")["deployment_drift"] is False


def test_the_deployment_candidate_is_recorded_through_the_worker_login(url, admin, fake):
    add_server(admin, status="approved")
    make_managed(admin)
    old = {"url": "https://mcp.test/api", "transport": "http", "auth_type": "none"}
    new = {**old, "url": "https://changed.test/api"}
    ids = []
    for definition in (old, new):
        did = new_uuid7()
        ids.append(did)
        admin.execute(
            "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,sha256,"
            "url,url_sha256,transport,auth_type) VALUES (%s,%s,'srv-1',%s,%s,%s,%s,'http','none')",
            (did, INSTANCE, canonical_text(definition), sha256(definition), definition["url"],
             url_sha256(definition["url"])))
    admin.execute("UPDATE mint.deployment_contracts SET status = 'approved' WHERE id = %s",
                  (ids[0],))
    with as_login(url, "mint_worker") as conn:
        ctx = Context(conn, INSTANCE, Operator("mint-worker", "system", None))
        with conn.transaction():
            contracts.request_deployment(ctx, "srv-1", str(ids[1]))
            contracts.request_deployment(ctx, "srv-1", str(ids[1]))
    assert fetchone(admin, "SELECT deployment_drift FROM mint.servers")["deployment_drift"] is True
    assert len(events(admin, "deployment_drift_detected")) == 1


def test_a_reapproval_whose_requester_was_removed_is_cancelled_and_keeps_the_block(
    url, admin, fake, worker
):
    old, candidate, iid = reapproval_world(admin, fake, {"read": NEW})
    request_reapproval(url, candidate, iid)
    admin.execute("DELETE FROM mint.operators WHERE name = 'reviewer'")
    drain(worker)
    status = {str(i): st for i, st in admin.execute(
        "SELECT id, status FROM mint.tool_contracts").fetchall()}
    assert status == {old: "approved", candidate: "candidate"}
    assert fetchone(admin, "SELECT status FROM mint.contract_reapproval_plans"
                    )["status"] == "cancelled"
    assert fetchone(admin, "SELECT deployment_drift FROM mint.servers")["deployment_drift"] is True


def test_the_requester_recheck_holds_a_share_lock_until_the_transaction_ends(url, admin, fake):
    from mint_litellm.control import contract_pin

    reapproval_world(admin, fake, {"read": NEW})
    saved = {"requested_by": "reviewer", "requested_user_id": "reviewer"}
    holder = psycopg.connect(url)
    other = psycopg.connect(url, autocommit=True)
    try:
        assert contract_pin._requester_valid(holder, INSTANCE, saved) is True
        other.execute("SET lock_timeout = '300ms'")
        with pytest.raises(psycopg.errors.LockNotAvailable):  # 확인한 승인자의 철회가 기다린다
            other.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'reviewer'")
        holder.rollback()
        other.execute("UPDATE mint.operators SET role = 'viewer' WHERE name = 'reviewer'")
        assert contract_pin._requester_valid(holder, INSTANCE, saved) is False
    finally:
        holder.close()
        other.close()


def test_a_missing_control_key_token_alerts_with_the_cause_and_the_next_run_pins(
    admin, fake, worker
):
    approval = managed_world(admin, fake)
    admin.execute("UPDATE mint.settings SET control_key_token = NULL")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert not pin_calls(fake)
    [row] = [a for a in alerts(admin) if a["kind"] == "sync_divergence"]
    assert row["subject"]["reason"] == "control_key_not_set"
    assert row["subject"]["action"] == "settings control-key"
    assert approval_status(admin, approval) == "pending"
    admin.execute("UPDATE mint.settings SET control_key_token = repeat('c', 64)")
    admin.execute("UPDATE mint.jobs SET run_after = now() WHERE status = 'pending'")
    drain(worker)
    assert pin_calls(fake)
    assert not [a for a in alerts(admin)
                if a["kind"] == "sync_divergence" and a["status"] != "resolved"]
