"""2단계 스키마 시험. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

# ruff: noqa: F811  (공용 fixture를 가져와 같은 이름의 인자로 쓴다)

import json

import pytest

psycopg = pytest.importorskip("psycopg")
import test_ddl  # noqa: E402
from psycopg import errors  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402
from test_ddl import (  # noqa: E402
    ENFORCEMENT_TABLES,
    HEX,
    NOW,
    I,
    add_call_approval,
    add_event,
    add_org,
    add_server,
    epoch,
    fails,
    scalar,
    server_in,
    set_server_status,
)

base = test_ddl.base  # 공용 fixture를 이 모듈에도 등록한다

from mint_litellm.types.ids import new_uuid7  # noqa: E402

STAGE2_TABLES = {
    "intakes", "intake_checks", "tool_contracts", "deployment_contracts", "jobs", "schedules",
    "litellm_grants", "seal_batches", "exports", "alerts", "alert_deliveries",
    "console_sessions", "self_confirmations",
}  # fmt: skip
STAGE2_EPOCH_TABLES = {"tool_contracts", "deployment_contracts", "self_confirmations"}
H2 = "b" * 64

READINESS = json.dumps(
    {"credential_notice": "x", "revocation_record": "y", "audit_access_days": 30}
)
INPUTS = {
    "purpose": "research",
    "data_grade": "internal",
    "allowed_resources": "[]",
    "provider": "vendor",
    "owner_user_id": "owner1",
    "readiness": READINESS,
    "data_return_terms": "delete on exit",
    "requested_by": "req1",
}


def insert(conn, table, **cols):
    names = ", ".join(f'"{c}"' for c in cols)
    marks = ", ".join(["%s"] * len(cols))
    conn.execute(f"INSERT INTO mint.{table} ({names}) VALUES ({marks})", list(cols.values()))


def update(conn, table, where, **cols):
    sets = ", ".join(f'"{c}" = %s' for c in cols)
    conn.execute(f"UPDATE mint.{table} SET {sets} WHERE {where}", list(cols.values()))


def add_intake(conn, server="srv-1", org="orgA", **cols):
    iid = new_uuid7()
    insert(conn, "intakes", id=iid, instance_id=I, org_id=org, server_id=server,
           source="operator", **cols)  # fmt: skip
    return iid


def intake_to(conn, iid, *steps):
    for i, step in enumerate(steps):
        if i == 0:
            update(conn, "intakes", f"id = '{iid}'", status=step, **INPUTS)
        elif step == "decided":
            update(conn, "intakes", f"id = '{iid}'", status="decided", decision="approved",
                   decided_by="alice", decided_at=NOW)  # fmt: skip
        else:
            update(conn, "intakes", f"id = '{iid}'", status=step)


def add_tool(conn, tool="read", server="srv-1", scope="server", **cols):
    cid = new_uuid7()
    row = {"id": cid, "instance_id": I, "server_id": server, "credential_scope": scope,
           "tool": tool, "canonical_text": "{}", "sha256": HEX, "pin_sha256": HEX,
           "source": "intake", **cols}  # fmt: skip
    insert(conn, "tool_contracts", **row)
    return cid


def approve_tool(conn, cid):
    update(conn, "tool_contracts", f"id = '{cid}'", status="approved",
           risk_grade="low", action_type="read")  # fmt: skip


def add_deployment(conn, server="srv-1", **cols):
    cid = new_uuid7()
    row = {"id": cid, "instance_id": I, "server_id": server, "canonical_text": "{}",
           "sha256": HEX, "url": "https://mcp.example/x", "url_sha256": HEX,
           "transport": "http", "auth_type": "none", **cols}  # fmt: skip
    insert(conn, "deployment_contracts", **row)
    return cid


def add_job(conn, kind="sync_server", target="srv-1", key=None, **cols):
    jid = new_uuid7()
    insert(conn, "jobs", id=jid, instance_id=I, kind=kind, target_ref=target,
           idempotency_key=key, **cols)  # fmt: skip
    return jid


def add_confirmation(conn, principal="u1", fp=HEX, **cols):
    cid = new_uuid7()
    row = {"id": cid, "instance_id": I, "org_id": "orgA", "principal_id": principal,
           "server_id": "srv-1", "tool": "write", "args_fp": fp, "fp_key_version": 1,
           "policy_version_id": "pv-1", "purpose": "transfer",
           "requested_by_key_token": "tok-req",
           "display": '{"amount": "10"}', "expires_at": NOW.replace(year=2100), **cols}  # fmt: skip
    insert(conn, "self_confirmations", **row)
    return cid


def confirm(conn, cid, principal="u1", token="tok-other"):
    update(conn, "self_confirmations", f"id = '{cid}'", status="confirmed",
           confirmed_by_user_id=principal, confirmed_by_key_token=token,
           confirmed_at=NOW)  # fmt: skip


def consume(conn, cid, invocation=None):
    update(conn, "self_confirmations", f"id = '{cid}'", status="consumed",
           consumed_invocation_id=invocation or new_uuid7(), consumed_at=NOW)  # fmt: skip


def status_of(conn, table, cid):
    return scalar(conn, f"SELECT status FROM mint.{table} WHERE id = %s", cid)


# ---------------------------------------------------------------------------
# 목록
# ---------------------------------------------------------------------------


def test_stage_two_adds_exactly_the_declared_tables(db):
    rows = db.execute(
        "SELECT table_name FROM information_schema.tables"
        " WHERE table_schema = 'mint' AND table_type = 'BASE TABLE'"
    ).fetchall()
    names = {r[0] for r in rows}
    assert STAGE2_TABLES <= names
    assert len(names & STAGE2_TABLES) == 13


def test_epoch_triggers_cover_exactly_the_enforcement_tables(db):
    rows = db.execute(
        "SELECT DISTINCT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
        " JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = 'mint' AND right(t.tgname, 6) = '_epoch' AND NOT t.tgisinternal"
    ).fetchall()
    assert {r[0] for r in rows} == ENFORCEMENT_TABLES | STAGE2_EPOCH_TABLES


def test_the_first_migration_state_columns_are_defaulted(db):
    assert (
        scalar(db, "SELECT column_default FROM information_schema.columns"
                   " WHERE table_schema = 'mint' AND table_name = 'servers'"
                   " AND column_name = 'contract_status'") == "'none'::text"
    )  # fmt: skip
    add_org(db)
    insert(db, "settings", instance_id=I)
    row = db.execute(
        "SELECT control_key_token, require_separate_confirm_key FROM mint.settings"
    ).fetchone()
    assert row == (None, True)


# ---------------------------------------------------------------------------
# 서버 전이와 수용검증 우회 차단
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["validating", "rejected"])
def test_an_awaiting_server_can_be_rechecked_or_rejected(db, target):
    sid = server_in(db, "awaiting_approval")
    set_server_status(db, sid, target)
    assert status_of(db, "servers", sid) == target


@pytest.mark.parametrize(
    ("source", "target"),
    [("pending", "approved"), ("validating", "approved"), ("rejected", "approved"),
     ("awaiting_approval", "terminated"), ("awaiting_approval", "pending")],
)  # fmt: skip
def test_other_server_transitions_stay_forbidden(db, source, target):
    sid = server_in(db, source)
    with fails(db, errors.CheckViolation):
        set_server_status(db, sid, target)


OPEN_INTAKE_STEPS = {
    "received": [],
    "checking": ["checking"],
    "passed": ["checking", "passed"],
    "failed": ["checking", "failed"],
    "indeterminate": ["checking", "indeterminate"],
}


@pytest.mark.parametrize("open_status", sorted(OPEN_INTAKE_STEPS))
def test_a_server_with_an_undecided_intake_cannot_be_approved(db, open_status):
    sid = server_in(db, "awaiting_approval")
    iid = add_intake(db)
    steps = OPEN_INTAKE_STEPS[open_status]
    if steps:
        intake_to(db, iid, *steps)
    with fails(db, errors.CheckViolation):
        set_server_status(db, sid, "approved")
    assert status_of(db, "servers", sid) == "awaiting_approval"


@pytest.mark.parametrize("last", ["passed", "failed", "indeterminate"])
def test_a_decided_intake_lets_the_server_be_approved(db, last):
    sid = server_in(db, "awaiting_approval")
    iid = add_intake(db)
    intake_to(db, iid, "checking", last, "decided")
    set_server_status(db, sid, "approved")
    assert status_of(db, "servers", sid) == "approved"


def test_a_server_without_an_intake_is_approved_as_before(db):
    sid = server_in(db, "awaiting_approval")
    set_server_status(db, sid, "approved")
    assert status_of(db, "servers", sid) == "approved"


def test_the_approval_guard_ignores_other_servers_intakes(db):
    sid = server_in(db, "awaiting_approval")
    add_server(db, "srv-2")
    add_intake(db, server="srv-2")
    set_server_status(db, sid, "approved")


# ---------------------------------------------------------------------------
# 신청
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [["checking", "passed", "decided"], ["checking", "failed", "decided"],
     ["checking", "indeterminate", "decided"],
     ["checking", "passed", "checking", "indeterminate", "checking", "passed", "decided"]],
)  # fmt: skip
def test_intake_walks_the_legal_paths(db, base, path):
    iid = add_intake(db)
    intake_to(db, iid, *path)
    assert status_of(db, "intakes", iid) == "decided"


@pytest.mark.parametrize(
    ("path", "target"),
    [([], "passed"), (["checking"], "decided"), (["checking"], "received"),
     (["checking", "failed"], "checking"), (["checking", "passed", "decided"], "checking"),
     (["checking", "passed"], "failed")],
)  # fmt: skip
def test_intake_rejects_illegal_transitions(db, base, path, target):
    iid = add_intake(db)
    if path:
        intake_to(db, iid, *path)
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", status=target, decision="approved",
               decided_by="a", decided_at=NOW, **INPUTS)  # fmt: skip


def test_a_received_intake_can_be_rejected_without_inputs_but_not_approved(db, base):
    iid = add_intake(db)
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", status="decided", decision="approved",
               decided_by="a", decided_at=NOW)
    update(db, "intakes", f"id = '{iid}'", status="decided", decision="rejected",
           decided_by="a", decided_at=NOW)
    assert status_of(db, "intakes", iid) == "decided"


def test_only_one_undecided_intake_per_server(db, base):
    first = add_intake(db)
    with fails(db, errors.UniqueViolation):
        add_intake(db)
    intake_to(db, first, "checking", "passed", "decided")
    add_intake(db)


def test_inputs_are_required_before_checking(db, base):
    iid = add_intake(db)
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", status="checking")
    partial = {k: v for k, v in INPUTS.items() if k != "provider"}
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", status="checking", **partial)
    update(db, "intakes", f"id = '{iid}'", status="checking", **INPUTS)


def test_readiness_needs_its_three_items_and_grades_are_closed(db, base):
    iid = add_intake(db)
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", readiness='{"credential_notice": "x"}')
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", data_grade="secret")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", purpose="")


def test_the_decision_columns_move_together_and_once(db, base):
    iid = add_intake(db)
    intake_to(db, iid, "checking", "failed")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", status="decided")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", decision="rejected")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", status="decided", decision="exception",
               decided_by="a", decided_at=NOW)  # fmt: skip
    update(db, "intakes", f"id = '{iid}'", status="decided", decision="exception",
           decided_by="a", decided_at=NOW, decision_reason="accepted risk")  # fmt: skip
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", decided_by="b")


def test_the_requester_is_assigned_once_and_the_origin_is_frozen(db, base):
    iid = add_intake(db)
    update(db, "intakes", f"id = '{iid}'", requested_by="req1")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", requested_by="req2")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", source="submission")
    with fails(db, errors.CheckViolation):
        update(db, "intakes", f"id = '{iid}'", server_id="srv-9")


def test_intake_does_not_move_the_epoch_but_its_version_follows_updates(db, base):
    iid = add_intake(db)
    before = epoch(db)
    update(db, "intakes", f"id = '{iid}'", requested_by="req1")
    assert epoch(db) == before
    assert scalar(db, "SELECT state_version FROM mint.intakes WHERE id = %s", iid) == 2


def test_intake_checks_are_append_only_and_unique_per_attempt(db, base):
    iid = add_intake(db)
    row = {"id": new_uuid7(), "instance_id": I, "intake_id": iid, "check": "url_guard",
           "attempt": 1, "result": "pass", "method": "static"}  # fmt: skip
    insert(db, "intake_checks", **row)
    with fails(db, errors.UniqueViolation):
        insert(db, "intake_checks", **{**row, "id": new_uuid7()})
    insert(db, "intake_checks", **{**row, "id": new_uuid7(), "attempt": 2})
    with fails(db, errors.CheckViolation):
        update(db, "intake_checks", f"id = '{row['id']}'", result="fail")
    with fails(db, errors.CheckViolation):
        db.execute("DELETE FROM mint.intake_checks")
    with fails(db, errors.CheckViolation):
        db.execute("TRUNCATE mint.intake_checks")
    with fails(db, errors.CheckViolation):
        insert(db, "intake_checks", **{**row, "id": new_uuid7(), "attempt": 3, "check": "other"})
    with fails(db, errors.CheckViolation):
        insert(db, "intake_checks", **{**row, "id": new_uuid7(), "attempt": 4,
                                       "evidence_sha256": "xyz"})  # fmt: skip


# ---------------------------------------------------------------------------
# 계약
# ---------------------------------------------------------------------------


def test_tool_contract_lifecycle_and_single_approved_row(db, base):
    first = add_tool(db)
    approve_tool(db, first)
    second = add_tool(db)
    with fails(db, errors.UniqueViolation):
        approve_tool(db, second)
    update(db, "tool_contracts", f"id = '{first}'", status="superseded")
    approve_tool(db, second)
    # 다른 자격 범위와 다른 도구는 따로 하나씩 승인된다.
    approve_tool(db, add_tool(db, scope="per_user"))
    approve_tool(db, add_tool(db, tool="other"))
    with fails(db, errors.CheckViolation):
        update(db, "tool_contracts", f"id = '{first}'", status="approved")


@pytest.mark.parametrize(
    ("source", "target"),
    [("approved", "candidate"), ("superseded", "approved"), ("superseded", "candidate")],
)  # fmt: skip
def test_tool_contract_illegal_transitions(db, base, source, target):
    cid = add_tool(db)
    if source != "candidate":
        approve_tool(db, cid)
    if source == "superseded":
        update(db, "tool_contracts", f"id = '{cid}'", status="superseded")
    with fails(db, errors.CheckViolation):
        update(db, "tool_contracts", f"id = '{cid}'", status=target)


def test_a_candidate_can_be_superseded_without_approval(db, base):
    cid = add_tool(db)
    update(db, "tool_contracts", f"id = '{cid}'", status="superseded")


def test_a_tool_contract_is_born_a_candidate_and_needs_a_grade_to_be_approved(db, base):
    with fails(db, errors.CheckViolation):
        add_tool(db, status="approved", risk_grade="low", action_type="read")
    cid = add_tool(db)
    with fails(db, errors.CheckViolation):
        update(db, "tool_contracts", f"id = '{cid}'", status="approved")
    update(db, "tool_contracts", f"id = '{cid}'", risk_grade="high", action_type="write")
    update(db, "tool_contracts", f"id = '{cid}'", status="approved")
    with fails(db, errors.CheckViolation):
        update(db, "tool_contracts", f"id = '{cid}'", risk_grade="low")
    for column, value in [("tool", "x"), ("sha256", H2), ("pin_sha256", H2),
                          ("canonical_text", "{ }"), ("source", "pin")]:  # fmt: skip
        with fails(db, errors.CheckViolation):
            update(db, "tool_contracts", f"id = '{cid}'", **{column: value})


def test_tool_contract_columns_are_validated(db, base):
    for bad in ({"sha256": "abc"}, {"risk_grade": "extreme"}, {"drift": "other"},
                {"credential_scope": "x"}, {"action_type": "run"},
                {"observed_sha256": HEX}):  # fmt: skip
        with fails(db, errors.CheckViolation):
            add_tool(db, **bad)


def test_epoch_moves_for_contract_status_and_drift_but_not_for_observations(db, base):
    cid = add_tool(db)
    before = epoch(db)
    update(db, "tool_contracts", f"id = '{cid}'", risk_grade="low", action_type="read")
    assert epoch(db) == before
    update(db, "tool_contracts", f"id = '{cid}'", status="approved")
    assert epoch(db) == before + 1
    update(db, "tool_contracts", f"id = '{cid}'", observed_sha256=H2, observed_at=NOW)
    update(db, "tool_contracts", f"id = '{cid}'", observed_sha256=HEX, observed_at=NOW)
    assert epoch(db) == before + 1
    update(db, "tool_contracts", f"id = '{cid}'", drift="input_schema")
    assert epoch(db) == before + 2
    update(db, "tool_contracts", f"id = '{cid}'", drift="none")
    assert epoch(db) == before + 3
    update(db, "tool_contracts", f"id = '{cid}'", status="superseded")
    assert epoch(db) == before + 4
    assert scalar(db, "SELECT version FROM mint.tool_contracts WHERE id = %s", cid) == 8


def test_deployment_contract_lifecycle_epoch_and_uniqueness(db, base):
    first = add_deployment(db)
    before = epoch(db)
    update(db, "deployment_contracts", f"id = '{first}'", status="approved")
    assert epoch(db) == before + 1
    second = add_deployment(db)
    assert epoch(db) == before + 1
    with fails(db, errors.UniqueViolation):
        update(db, "deployment_contracts", f"id = '{second}'", status="approved")
    update(db, "deployment_contracts", f"id = '{first}'", status="superseded")
    update(db, "deployment_contracts", f"id = '{second}'", status="approved")
    for column, value in [("url", "https://other.example"), ("url_sha256", H2),
                          ("issuer", "https://idp.example"), ("oauth_scopes", ["a"])]:  # fmt: skip
        with fails(db, errors.CheckViolation):
            update(db, "deployment_contracts", f"id = '{second}'", **{column: value})
    with fails(db, errors.CheckViolation):
        update(db, "deployment_contracts", f"id = '{second}'", status="candidate")


def test_inserting_contract_rows_never_moves_the_epoch(db, base):
    before = epoch(db)
    add_tool(db)
    add_deployment(db)
    assert epoch(db) == before


# ---------------------------------------------------------------------------
# 서버 열과 세대
# ---------------------------------------------------------------------------


def test_last_observation_alone_does_not_move_the_epoch(db, base):
    before = epoch(db)
    update(db, "servers", f"id = '{base['server']}'", last_observed_at=NOW)
    update(db, "servers", f"id = '{base['server']}'", last_observed_at=None)
    assert epoch(db) == before
    assert scalar(db, "SELECT state_version FROM mint.servers WHERE id = %s", base["server"]) == 3


@pytest.mark.parametrize(
    ("column", "value"),
    [("contract_status", "managed"), ("issuer", "https://idp.example"),
     ("deployment_drift", True), ("deployment_drift_fields", ["url"]),
     ("transport", "sse"), ("status", "validating")],
)  # fmt: skip
def test_other_server_changes_move_the_epoch(db, base, column, value):
    before = epoch(db)
    update(db, "servers", f"id = '{base['server']}'", **{column: value})
    assert epoch(db) == before + 1


def test_a_server_update_that_also_changes_the_observation_moves_the_epoch(db, base):
    before = epoch(db)
    update(db, "servers", f"id = '{base['server']}'", last_observed_at=NOW, deployment_drift=True)
    assert epoch(db) == before + 1


def test_a_no_op_server_update_still_moves_the_epoch_as_before(db, base):
    before = epoch(db)
    update(db, "servers", f"id = '{base['server']}'", transport="http")
    assert epoch(db) == before + 1


def test_server_insert_and_delete_move_the_epoch(db):
    add_org(db)
    before = epoch(db)
    add_server(db, "srv-x")
    assert epoch(db) == before + 1
    db.execute("DELETE FROM mint.servers WHERE server_id = 'srv-x'")
    assert epoch(db) == before + 2


def test_contract_status_and_drift_columns_are_closed(db, base):
    for column, value in [("contract_status", "other"), ("issuer", "")]:
        with fails(db, errors.CheckViolation):
            update(db, "servers", f"id = '{base['server']}'", **{column: value})


# ---------------------------------------------------------------------------
# 작업·동기화·봉인·내보내기·경보·세션
# ---------------------------------------------------------------------------


def test_job_transitions_and_the_lease_requirement(db):
    jid = add_job(db, key="a")
    with fails(db, errors.CheckViolation):
        update(db, "jobs", f"id = '{jid}'", status="running")
    update(db, "jobs", f"id = '{jid}'", status="running", lease_owner="w1", lease_until=NOW)
    update(db, "jobs", f"id = '{jid}'", status="pending", lease_owner=None, lease_until=None)
    update(db, "jobs", f"id = '{jid}'", status="running", lease_owner="w1", lease_until=NOW)
    update(db, "jobs", f"id = '{jid}'", status="done")
    for target in ("pending", "running", "failed"):
        with fails(db, errors.CheckViolation):
            update(db, "jobs", f"id = '{jid}'", status=target, lease_owner="w", lease_until=NOW)
    other = add_job(db, key="b")
    with fails(db, errors.CheckViolation):
        update(db, "jobs", f"id = '{other}'", status="done")
    with fails(db, errors.CheckViolation):
        update(db, "jobs", f"id = '{other}'", target_ref="other")


def test_job_failure_path(db):
    jid = add_job(db, key="f")
    update(db, "jobs", f"id = '{jid}'", status="running", lease_owner="w1", lease_until=NOW)
    update(db, "jobs", f"id = '{jid}'", status="failed", last_error_code="boom")


def test_job_idempotency_key_is_unique_and_null_is_not(db):
    add_job(db, kind="seal", target="i", key="seal:t1")
    with fails(db, errors.UniqueViolation):
        add_job(db, kind="seal", target="i", key="seal:t1")
    add_job(db, kind="seal", target="i", key="seal:t2")
    add_job(db, kind="sync_server", target="a")
    add_job(db, kind="sync_server", target="b")


def test_convergent_jobs_have_one_pending_row_per_target(db):
    first = add_job(db)
    with fails(db, errors.UniqueViolation):
        add_job(db)
    update(db, "jobs", f"id = '{first}'", status="running", lease_owner="w", lease_until=NOW)
    add_job(db)  # 실행 중인 행만 있으면 새 대기 행을 만들 수 있다.
    with fails(db, errors.UniqueViolation):
        add_job(db)
    add_job(db, kind="sync_target")


def test_job_columns_are_validated(db):
    for bad in ({"max_attempts": 0}, {"attempts": -1}, {"kind": "Sync"}, {"target": ""}):
        with fails(db, errors.CheckViolation):
            add_job(db, **bad)


def test_schedules_are_one_row_per_kind(db):
    insert(db, "schedules", instance_id=I, kind="seal", interval_seconds=60, next_run_at=NOW)
    with fails(db, errors.UniqueViolation):
        insert(db, "schedules", instance_id=I, kind="seal", interval_seconds=30, next_run_at=NOW)
    with fails(db, errors.CheckViolation):
        insert(db, "schedules", instance_id=I, kind="x", interval_seconds=0, next_run_at=NOW)


def add_grant(conn, **cols):
    gid = new_uuid7()
    row = {"id": gid, "instance_id": I, "target_type": "key", "target_id": "k1",
           "item": "mcp_server", "server_id": "srv-1", **cols}  # fmt: skip
    insert(conn, "litellm_grants", **row)
    return gid


def test_grants_are_unique_per_target_item_and_server_and_versioned(db, base):
    gid = add_grant(db)
    with fails(db, errors.UniqueViolation):
        add_grant(db)
    add_grant(db, item="tool_permission")
    add_grant(db, target_type="server", target_id="srv-1", item="pin", applied_sha256=HEX)
    update(db, "litellm_grants", f"id = '{gid}'", held=True, held_at=NOW, missing_count=2)
    assert scalar(db, "SELECT state_version FROM mint.litellm_grants WHERE id = %s", gid) == 2
    with fails(db, errors.CheckViolation):
        update(db, "litellm_grants", f"id = '{gid}'", target_id="k2")
    before = epoch(db)
    update(db, "litellm_grants", f"id = '{gid}'", held=False)
    assert epoch(db) == before


@pytest.mark.parametrize(
    "bad",
    [{"item": "pin"}, {"target_type": "server", "item": "mcp_server"},
     {"applied_sha256": HEX}, {"missing_count": -1}, {"server_id": "missing"}],
)  # fmt: skip
def test_grant_constraints(db, base, bad):
    with pytest.raises((errors.CheckViolation, errors.ForeignKeyViolation)), db.transaction():
        add_grant(db, **bad)


def test_seal_batches_are_append_only_with_32_byte_hashes(db):
    row = {"instance_id": I, "from_seal_seq": 1, "to_seal_seq": 5,
           "prev_tail_hash": b"\x00" * 32, "tail_hash": b"\x01" * 32}  # fmt: skip
    insert(db, "seal_batches", **row)
    with fails(db, errors.UniqueViolation):
        insert(db, "seal_batches", **row)
    insert(db, "seal_batches", **{**row, "from_seal_seq": 6, "to_seal_seq": 9})
    for bad in ({"to_seal_seq": 10, "tail_hash": b"\x01" * 31},
                {"from_seal_seq": 12, "to_seal_seq": 11}):  # fmt: skip
        with fails(db, errors.CheckViolation):
            insert(db, "seal_batches", **{**row, **bad})
    with fails(db, errors.CheckViolation):
        update(db, "seal_batches", "to_seal_seq = 5", tail_hash=b"\x02" * 32)
    with fails(db, errors.CheckViolation):
        db.execute("DELETE FROM mint.seal_batches")
    with fails(db, errors.CheckViolation):
        db.execute("TRUNCATE mint.seal_batches")


def add_export(conn, kind="negative_state", state_epoch=3, **cols):
    eid = new_uuid7()
    insert(conn, "exports", id=eid, instance_id=I, kind=kind, state_epoch=state_epoch,
           payload_sha256=HEX, path="/exports/x.json", **cols)  # fmt: skip
    return eid


def test_one_negative_state_export_per_epoch_but_many_checkpoints(db):
    first = add_export(db)
    with fails(db, errors.UniqueViolation):
        add_export(db)
    add_export(db, state_epoch=4)
    add_export(db, kind="checkpoint", state_epoch=3)
    add_export(db, kind="checkpoint", state_epoch=3)
    update(db, "exports", f"id = '{first}'", status="failed", attempts=1)
    update(db, "exports", f"id = '{first}'", status="pending")
    update(db, "exports", f"id = '{first}'", status="written", written_at=NOW)
    for target in ("pending", "failed"):
        with fails(db, errors.CheckViolation):
            update(db, "exports", f"id = '{first}'", status=target)
    with fails(db, errors.CheckViolation):
        update(db, "exports", f"id = '{first}'", payload_sha256=H2)


def test_a_written_export_needs_its_time(db):
    eid = add_export(db)
    with fails(db, errors.CheckViolation):
        update(db, "exports", f"id = '{eid}'", status="written")


def add_alert(conn, key="k1", **cols):
    aid = new_uuid7()
    insert(conn, "alerts", id=aid, instance_id=I, kind="contract_drift", severity="high",
           dedup_key=key, **cols)  # fmt: skip
    return aid


def test_alerts_are_unique_while_unresolved_and_move_forward_only(db):
    first = add_alert(db)
    with fails(db, errors.UniqueViolation):
        add_alert(db)
    update(db, "alerts", f"id = '{first}'", status="acknowledged", acknowledged_by="alice")
    with fails(db, errors.UniqueViolation):
        add_alert(db)
    with fails(db, errors.CheckViolation):
        update(db, "alerts", f"id = '{first}'", status="open")
    update(db, "alerts", f"id = '{first}'", status="resolved", resolved_at=NOW)
    add_alert(db)
    direct = add_alert(db, key="k2")
    update(db, "alerts", f"id = '{direct}'", status="resolved", resolved_at=NOW)
    with fails(db, errors.CheckViolation):
        update(db, "alerts", f"id = '{direct}'", status="open")
    with fails(db, errors.CheckViolation):
        update(db, "alerts", f"id = '{first}'", dedup_key="other")


def test_an_acknowledged_alert_names_who_did_it_and_a_severity_is_closed(db):
    aid = add_alert(db)
    with fails(db, errors.CheckViolation):
        update(db, "alerts", f"id = '{aid}'", status="acknowledged")
    with fails(db, errors.CheckViolation):
        insert(db, "alerts", id=new_uuid7(), instance_id=I, kind="x", severity="urgent",
               dedup_key="z")  # fmt: skip


def test_alert_deliveries_follow_their_alert_and_finish_once(db):
    aid = add_alert(db)
    did = new_uuid7()
    insert(db, "alert_deliveries", id=did, instance_id=I, alert_id=aid, channel="webhook",
           delivery_id=new_uuid7())  # fmt: skip
    with fails(db, errors.ForeignKeyViolation):
        insert(db, "alert_deliveries", id=new_uuid7(), instance_id=I, alert_id=new_uuid7(),
               channel="webhook", delivery_id=new_uuid7())  # fmt: skip
    with fails(db, errors.CheckViolation):
        update(db, "alert_deliveries", f"id = '{did}'", status="sent")
    update(db, "alert_deliveries", f"id = '{did}'", status="sent", sent_at=NOW, attempts=1)
    with fails(db, errors.CheckViolation):
        update(db, "alert_deliveries", f"id = '{did}'", status="failed")


def add_session(conn, subject="staff", user="u1", name=None, **cols):
    sid = new_uuid7().hex + new_uuid7().hex[:32]
    row = {"id_hash": sid[:64], "instance_id": I, "subject": subject, "user_id": user,
           "key_token": "tok", "operator_name": name, "role": subject,
           "idle_expiry": NOW.replace(year=2090), "absolute_expiry": NOW.replace(year=2091),
           **cols}  # fmt: skip
    insert(conn, "console_sessions", **row)
    return row["id_hash"]


def test_console_session_rules(db):
    sid = add_session(db)
    with fails(db, errors.CheckViolation):
        add_session(db, subject="admin")
    add_session(db, subject="admin", name="root")
    with fails(db, errors.CheckViolation):
        add_session(db, idle_expiry=NOW.replace(year=2092))
    update(db, "console_sessions", f"id_hash = '{sid}'", last_seen_at=NOW, revoked_at=NOW)
    with fails(db, errors.CheckViolation):
        update(db, "console_sessions", f"id_hash = '{sid}'", revoked_at=None)
    with fails(db, errors.CheckViolation):
        update(db, "console_sessions", f"id_hash = '{sid}'", user_id="u2")
    with fails(db, errors.CheckViolation):
        update(db, "console_sessions", f"id_hash = '{sid}'", absolute_expiry=NOW)


# ---------------------------------------------------------------------------
# 본인 확인
# ---------------------------------------------------------------------------


def test_a_confirmation_starts_pending_and_empty(db, base):
    for bad in ({"status": "confirmed"}, {"confirmed_by_user_id": "u1"},
                {"consumed_invocation_id": new_uuid7()}, {"consumed_at": NOW},
                {"confirmed_at": NOW}):  # fmt: skip
        with fails(db, (errors.CheckViolation, errors.RaiseException)):
            add_confirmation(db, **bad)
    cid = add_confirmation(db)
    assert status_of(db, "self_confirmations", cid) == "pending"


def test_confirmation_walks_to_confirmed_then_consumed(db, base):
    cid = add_confirmation(db)
    confirm(db, cid)
    consume(db, cid)
    assert status_of(db, "self_confirmations", cid) == "consumed"
    assert scalar(db, "SELECT display IS NULL FROM mint.self_confirmations WHERE id = %s", cid)
    assert scalar(db, "SELECT state_version FROM mint.self_confirmations WHERE id = %s", cid) == 3


@pytest.mark.parametrize(
    ("path", "target"),
    [([], "consumed"), (["confirmed"], "rejected"), (["confirmed"], "pending"),
     (["rejected"], "confirmed"), (["cancelled"], "pending"), (["expired"], "confirmed"),
     (["confirmed", "consumed"], "cancelled"), (["confirmed", "cancelled"], "consumed")],
)  # fmt: skip
def test_confirmation_illegal_transitions(db, base, path, target):
    cid = add_confirmation(db)
    for step in path:
        if step == "confirmed":
            confirm(db, cid)
        elif step == "consumed":
            consume(db, cid)
        else:
            update(db, "self_confirmations", f"id = '{cid}'", status=step,
                   **({"confirmed_by_user_id": "u1", "confirmed_by_key_token": "t",
                       "confirmed_at": NOW} if step == "rejected" else {}))  # fmt: skip
    with fails(db, errors.CheckViolation):
        extra = {}
        if target == "consumed":
            extra = {"consumed_invocation_id": new_uuid7(), "consumed_at": NOW}
        if target == "confirmed":
            extra = {"confirmed_by_user_id": "u1", "confirmed_by_key_token": "t",
                     "confirmed_at": NOW}  # fmt: skip
        update(db, "self_confirmations", f"id = '{cid}'", status=target, **extra)


@pytest.mark.parametrize("terminal", ["rejected", "cancelled", "expired"])
def test_display_is_cleared_on_every_terminal_transition(db, base, terminal):
    cid = add_confirmation(db)
    extra = (
        {"confirmed_by_user_id": "u1", "confirmed_by_key_token": "t", "confirmed_at": NOW}
        if terminal == "rejected"
        else {}
    )
    update(db, "self_confirmations", f"id = '{cid}'", status=terminal, **extra)
    assert scalar(db, "SELECT display IS NULL FROM mint.self_confirmations WHERE id = %s", cid)


def test_display_stays_until_a_terminal_state_and_cannot_be_edited(db, base):
    cid = add_confirmation(db)
    confirm(db, cid)
    assert not scalar(db, "SELECT display IS NULL FROM mint.self_confirmations WHERE id = %s", cid)
    with fails(db, errors.CheckViolation):
        update(db, "self_confirmations", f"id = '{cid}'", display='{"amount": "99"}')


def test_request_columns_are_frozen_and_decision_columns_fill_once(db, base):
    cid = add_confirmation(db)
    for column, value in [("principal_id", "u2"), ("server_id", "srv-2"), ("tool", "x"),
                          ("args_fp", H2), ("fp_key_version", 2), ("policy_version_id", "pv-2"),
                          ("purpose", "x"), ("requested_by_key_token", "t2"),
                          ("expires_at", NOW)]:  # fmt: skip
        with fails(db, (errors.CheckViolation, errors.ForeignKeyViolation)):
            update(db, "self_confirmations", f"id = '{cid}'", **{column: value})
    confirm(db, cid)
    with fails(db, errors.CheckViolation):
        update(db, "self_confirmations", f"id = '{cid}'", confirmed_by_user_id="u2")
    with fails(db, errors.CheckViolation):
        update(db, "self_confirmations", f"id = '{cid}'", confirmed_by_key_token="t3")
    consume(db, cid)
    with fails(db, errors.CheckViolation):
        update(db, "self_confirmations", f"id = '{cid}'", consumed_invocation_id=new_uuid7())


def test_only_the_requesting_principal_can_confirm_or_reject(db, base):
    cid = add_confirmation(db)
    with fails(db, errors.InsufficientPrivilege):
        confirm(db, cid, principal="someone-else")
    other = add_confirmation(db, fp=H2)
    with fails(db, errors.InsufficientPrivilege):
        update(db, "self_confirmations", f"id = '{other}'", status="rejected",
               confirmed_by_user_id="mallory", confirmed_by_key_token="t",
               confirmed_at=NOW)  # fmt: skip


def test_a_decision_needs_all_three_columns_and_pending_has_none(db, base):
    cid = add_confirmation(db)
    with fails(db, errors.CheckViolation):
        update(db, "self_confirmations", f"id = '{cid}'", status="confirmed",
               confirmed_by_user_id="u1")  # fmt: skip
    with fails(db, errors.InsufficientPrivilege):
        update(db, "self_confirmations", f"id = '{cid}'", confirmed_by_user_id="u1",
               confirmed_by_key_token="t", confirmed_at=NOW)  # fmt: skip


def test_one_pending_confirmation_per_subject_and_arguments(db, base):
    first = add_confirmation(db)
    with fails(db, errors.UniqueViolation):
        add_confirmation(db)
    add_confirmation(db, fp=H2)
    add_confirmation(db, principal="u2")
    update(db, "self_confirmations", f"id = '{first}'", status="cancelled")
    add_confirmation(db)


def test_one_invocation_consumes_one_confirmation(db, base):
    invocation = new_uuid7()
    first, second = add_confirmation(db), add_confirmation(db, fp=H2)
    confirm(db, first)
    confirm(db, second)
    consume(db, first, invocation)
    with fails(db, errors.UniqueViolation):
        consume(db, second, invocation)


def test_the_same_invocation_can_consume_a_call_approval_and_a_confirmation(db, base):
    invocation = new_uuid7()
    cid = add_confirmation(db)
    confirm(db, cid)
    consume(db, cid, invocation)
    approval = add_call_approval(db)
    db.execute("UPDATE mint.call_approvals SET status = 'approved', approved_by = 'a'"
               " WHERE id = %s", (approval,))  # fmt: skip
    db.execute("UPDATE mint.call_approvals SET status = 'consumed', consumed_invocation_id = %s"
               " WHERE id = %s", (invocation, approval))  # fmt: skip


def test_epoch_follows_confirmation_transitions_but_not_the_request_row(db, base):
    before = epoch(db)
    cid = add_confirmation(db)
    assert epoch(db) == before
    confirm(db, cid)
    assert epoch(db) == before + 1
    consume(db, cid)
    assert epoch(db) == before + 2


def test_call_approvals_are_untouched_by_confirmations(db, base):
    cols = {r[0] for r in db.execute(
        "SELECT column_name FROM information_schema.columns"
        " WHERE table_schema = 'mint' AND table_name = 'call_approvals'").fetchall()}  # fmt: skip
    assert "kind" not in cols and "confirmed_by_user_id" not in cols
    cid = add_confirmation(db)
    confirm(db, cid)
    assert scalar(db, "SELECT count(*) FROM mint.call_approvals") == 0


# ---------------------------------------------------------------------------
# 역할
# ---------------------------------------------------------------------------


def as_role(conn, role):
    conn.execute(f"SET LOCAL ROLE {role}")


def denied(conn, *statements):
    for statement in statements:
        with fails(conn, errors.InsufficientPrivilege):
            conn.execute(statement)


def staff_context(conn, user="u1", instance=I):
    conn.execute("SELECT set_config('mint.staff_user_id', %s, true)", (user,))
    conn.execute("SELECT set_config('mint.staff_instance_id', %s, true)", (instance,))


def staff_call(conn, sql, *params):
    return conn.execute(sql, params).fetchall()


def event_keys(conn, kind):
    rows = conn.execute(
        "SELECT source_key, actor, payload FROM mint.events WHERE kind = %s ORDER BY source_key",
        (kind,),
    ).fetchall()
    return rows


def test_staff_confirms_rejects_and_cancels_only_their_own_rows_with_events(db, base):
    mine, rej, can, theirs = (
        add_confirmation(db),
        add_confirmation(db, fp=H2),
        add_confirmation(db, fp="c" * 64),
        add_confirmation(db, principal="u2"),
    )
    as_role(db, "mint_staff")
    staff_context(db)
    staff_call(db, "SELECT mint.staff_confirm(%s, 'tok-other')", mine)
    staff_call(db, "SELECT mint.staff_reject(%s, 'tok-other')", rej)
    staff_call(db, "SELECT mint.staff_cancel(%s)", can)
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_confirm(%s, 'tok-other')", theirs)
    assert len(staff_call(db, "SELECT * FROM mint.staff_list_confirmations()")) == 3
    db.execute("RESET ROLE")
    assert status_of(db, "self_confirmations", mine) == "confirmed"
    assert status_of(db, "self_confirmations", rej) == "rejected"
    assert status_of(db, "self_confirmations", can) == "cancelled"
    assert status_of(db, "self_confirmations", theirs) == "pending"
    assert scalar(db, "SELECT confirmed_by_user_id FROM mint.self_confirmations WHERE id = %s", mine) == "u1"  # noqa: E501
    # 상태 변경과 사건이 같은 트랜잭션에 있고 키의 번호는 새 버전이다.
    assert event_keys(db, "call_approval_approved") == [
        (f"call_approval:{mine}:2:call_approval_approved", "u1", {"kind": "confirmation"})
    ]
    assert len(event_keys(db, "call_approval_rejected")) == 1
    assert len(event_keys(db, "call_approval_cancelled")) == 1


def test_staff_functions_refuse_without_a_declared_user_or_instance(db, base):
    cid = add_confirmation(db)
    as_role(db, "mint_staff")
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_confirm(%s, 't')", cid)
    db.execute("SELECT set_config('mint.staff_user_id', '', true)")
    staff_context(db, user="")
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_confirm(%s, 't')", cid)
    staff_context(db)
    db.execute("SELECT set_config('mint.staff_instance_id', '', true)")
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_cancel(%s)", cid)
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT * FROM mint.staff_list_events()")
    staff_context(db, user="u2")
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_cancel(%s)", cid)
    db.execute("RESET ROLE")
    assert status_of(db, "self_confirmations", cid) == "pending"


def test_staff_cannot_repeat_or_reverse_a_decision(db, base):
    cid = add_confirmation(db)
    as_role(db, "mint_staff")
    staff_context(db)
    staff_call(db, "SELECT mint.staff_confirm(%s, 't')", cid)
    with fails(db, errors.CheckViolation):
        staff_call(db, "SELECT mint.staff_reject(%s, 't')", cid)
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_confirm(%s, 't')", cid)
    staff_call(db, "SELECT mint.staff_cancel(%s)", cid)
    db.execute("RESET ROLE")
    assert len(event_keys(db, "call_approval_approved")) == 1


def test_staff_cannot_confirm_or_reject_an_expired_row_but_can_cancel_it(db, base):
    past = NOW.replace(year=2000)
    a, b, c = (add_confirmation(db, fp=fp, expires_at=past) for fp in (HEX, H2, "c" * 64))
    as_role(db, "mint_staff")
    staff_context(db)
    with fails(db, errors.CheckViolation):
        staff_call(db, "SELECT mint.staff_confirm(%s, 't')", a)
    with fails(db, errors.CheckViolation):
        staff_call(db, "SELECT mint.staff_reject(%s, 't')", b)
    staff_call(db, "SELECT mint.staff_cancel(%s)", c)
    db.execute("RESET ROLE")
    assert status_of(db, "self_confirmations", a) == "pending"
    assert status_of(db, "self_confirmations", c) == "cancelled"


def test_staff_cannot_revive_an_expired_or_revoked_session_and_idle_is_capped(db, base):
    past, far = NOW.replace(year=2000), NOW.replace(year=2090)
    expired = add_session(db, user="u1", idle_expiry=past, absolute_expiry=far)
    gone = add_session(db, user="u1", revoked_at=NOW)
    capped = add_session(db, user="u1", idle_expiry=far, absolute_expiry=far)
    as_role(db, "mint_staff")
    staff_context(db)
    for sid in (expired, gone):
        with fails(db, errors.InsufficientPrivilege):
            staff_call(db, "SELECT mint.staff_touch_session(%s, %s)", sid, far)
    staff_call(db, "SELECT mint.staff_touch_session(%s, %s)", capped, NOW.replace(year=2200))
    db.execute("RESET ROLE")
    assert scalar(db, "SELECT idle_expiry FROM mint.console_sessions WHERE id_hash = %s", capped) == far  # noqa: E501
    assert scalar(db, "SELECT idle_expiry FROM mint.console_sessions WHERE id_hash = %s", expired) == past  # noqa: E501


def test_staff_has_no_direct_table_rights(db, base):
    cid = add_confirmation(db)
    sid = add_session(db, user="u1")
    as_role(db, "mint_staff")
    staff_context(db)
    denied(
        db,
        "SELECT * FROM mint.self_confirmations",
        f"UPDATE mint.self_confirmations SET status = 'cancelled' WHERE id = '{cid}'",
        "INSERT INTO mint.self_confirmations (id) VALUES (gen_random_uuid())",
        "SELECT * FROM mint.console_sessions",
        f"UPDATE mint.console_sessions SET revoked_at = now() WHERE id_hash = '{sid}'",
        "INSERT INTO mint.console_sessions (id_hash) VALUES ('x')",
        "SELECT * FROM mint.consents",
        "INSERT INTO mint.consents (id) VALUES (gen_random_uuid())",
        "UPDATE mint.consents SET revoked_at = now()",
        "SELECT * FROM mint.approvals",
        "SELECT * FROM mint.call_approvals",
        "SELECT * FROM mint.operators",
        "SELECT * FROM mint.events",
        "INSERT INTO mint.events (event_id) VALUES (gen_random_uuid())",
        "SELECT * FROM mint.intakes",
        "SELECT * FROM mint.jobs",
        "UPDATE mint.servers SET status = 'approved'",
        "UPDATE mint.settings SET mode = 'observe'",
        "SELECT mint.raise_epoch('inst1', 5)",
        "SELECT mint.restore_attest_epoch('inst1', 5)",
        "UPDATE mint.state_epoch SET epoch = epoch + 1",
        "SELECT mint.staff_event('x', 'y', 'z', 1, 'a', '{}')",
        "SELECT mint.staff_decide_confirmation(gen_random_uuid(), 'confirmed', 't')",
    )


def test_staff_functions_are_closed_to_other_roles(db, base):
    for role in ("mint_plugin", "mint_control", "mint_worker", "mint_sealer"):
        db.execute(f"SET LOCAL ROLE {role}")
        staff_context(db)
        with fails(db, errors.InsufficientPrivilege):
            staff_call(db, "SELECT mint.staff_cancel(gen_random_uuid())")
        db.execute("RESET ROLE")


def test_staff_consents_are_granted_and_revoked_with_events(db, base):
    cid = new_uuid7()
    as_role(db, "mint_staff")
    staff_context(db)
    staff_call(db, "SELECT mint.staff_grant_consent(%s, 'orgA', 'srv-1', 'research', 'all', 'v1', %s)",  # noqa: E501
               cid, NOW.replace(year=2100))
    assert len(staff_call(db, "SELECT * FROM mint.staff_list_consents()")) == 1
    staff_context(db, user="u2")
    assert len(staff_call(db, "SELECT * FROM mint.staff_list_consents()")) == 0
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_revoke_consent(%s)", cid)
    staff_context(db)
    staff_call(db, "SELECT mint.staff_revoke_consent(%s)", cid)
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_revoke_consent(%s)", cid)
    db.execute("RESET ROLE")
    row = db.execute(
        "SELECT human_user_id, source, registered_by, revoked_at IS NOT NULL FROM mint.consents"
    ).fetchone()
    assert row == ("u1", "self_service", "u1", True)
    assert event_keys(db, "consent_granted")[0][0] == f"consent:{cid}:1:consent_granted"
    assert event_keys(db, "consent_revoked")[0][0] == f"consent:{cid}:2:consent_revoked"


def test_staff_grant_cannot_name_another_user_or_instance_object(db, base):
    as_role(db, "mint_staff")
    staff_context(db)
    with fails(db, errors.ForeignKeyViolation):
        staff_call(db, "SELECT mint.staff_grant_consent(gen_random_uuid(), 'orgA', 'nope', 'p',"
                       " 's', 'v', now() + interval '1 day')")


def test_staff_sessions_start_and_end_with_events_and_stay_personal(db, base):
    far = NOW.replace(year=2090)
    as_role(db, "mint_staff")
    staff_context(db)
    sid = "a" * 64
    staff_call(db, "SELECT mint.staff_start_session(%s, 'tok', %s, %s, '[]'::jsonb)", sid, far, far)
    staff_call(db, "SELECT mint.staff_touch_session(%s, %s)", sid, far)
    staff_context(db, user="u2")
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_end_session(%s)", sid)
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_touch_session(%s, %s)", sid, far)
    staff_context(db)
    staff_call(db, "SELECT mint.staff_end_session(%s)", sid)
    with fails(db, errors.InsufficientPrivilege):
        staff_call(db, "SELECT mint.staff_end_session(%s)", sid)
    mine = staff_call(db, "SELECT kind FROM mint.staff_list_events() ORDER BY kind")
    assert [r[0] for r in mine] == ["console_session_ended", "console_session_started"]
    db.execute("RESET ROLE")
    row = db.execute("SELECT subject, role, user_id, revoked_at IS NOT NULL FROM mint.console_sessions").fetchone()  # noqa: E501
    assert row == ("staff", "staff", "u1", True)
    assert [r[0] for r in event_keys(db, "console_session_started")] == [
        f"console_session:{sid}:1:console_session_started"
    ]


def test_staff_event_listing_is_personal(db, base):
    # 행위자 이름이 같아도 운영자 행위는 보이지 않고, 본인이 주체인 사건만 보인다.
    add_event(db, key="approval:a1:1:approval_granted", actor="u1")
    add_event(db, key="decision:d1:1:decision_evaluated", kind="decision_evaluated",
              actor="u1", subject='{"principal_id": "u1"}')
    add_event(db, key="decision:d2:1:decision_evaluated", kind="decision_evaluated",
              actor="x", subject='{"principal_id": "u2"}')
    as_role(db, "mint_staff")
    staff_context(db)
    rows = staff_call(db, "SELECT source_key FROM mint.staff_list_events(10)")
    assert [r[0] for r in rows] == ["decision:d1:1:decision_evaluated"]


def test_the_search_path_of_staff_functions_is_pinned(db):
    rows = db.execute(
        "SELECT proname, proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE n.nspname = 'mint' AND proname LIKE 'staff\\_%' AND prosecdef"
    ).fetchall()
    assert len(rows) >= 12
    for name, config in rows:
        assert config and any(c.startswith("search_path=") for c in config), name


def test_two_staff_decisions_at_once_leave_one_decision_and_one_event(migrated_database):

    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(migrated_database)
    admin = make_conninfo(**dict(params, dbname="postgres"))
    name = params["dbname"] + "_conc"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    try:
        _concurrent_decisions(make_conninfo(**dict(params, dbname=name)))
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


SA, SB = "aa" * 32, "bb" * 32


def _concurrent_decisions(migrated_database):
    import threading
    import time

    with psycopg.connect(migrated_database, autocommit=True) as setup:
        from mint_litellm.control.db.migrate import _migration_files

        for _, text in _migration_files():
            setup.execute(text)
    instance = f"conc{new_uuid7().hex[:12]}"
    with psycopg.connect(migrated_database, autocommit=True) as setup:
        setup.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, 'o', 'o')", (instance,))  # noqa: E501
        setup.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 's',"
            " 'awaiting_approval', %s, 'http', 'none', 'a')", (instance, HEX))
        setup.execute("INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256,"
                      " bundle_sha256) VALUES (%s, 'pv', %s, %s)", (instance, HEX, HEX))
        setup.execute("UPDATE mint.servers SET status = 'approved' WHERE instance_id = %s",
                      (instance,))
        setup.execute("INSERT INTO mint.usage_relations (id, instance_id, org_id, purpose,"
                      " server_id) VALUES (gen_random_uuid(), %s, 'o', 'p', 's')", (instance,))
        setup.execute("INSERT INTO mint.settings (instance_id, default_org_id) VALUES (%s, 'o')"
                      " ON CONFLICT (instance_id) DO UPDATE SET default_org_id = 'o'", (instance,))
        setup.execute(
            "INSERT INTO mint.console_sessions (id_hash, instance_id, subject, user_id, key_token,"
            " role, idle_expiry, absolute_expiry) VALUES ('" + SA + "', %s, 'staff', 'u1', 'tok-a',"
            " 'staff', now() + interval '1 hour', now() + interval '1 day'),"
            " ('" + SB + "', %s, 'staff', 'u1', 'tok-b', 'staff', now() + interval '1 hour',"
            " now() + interval '1 day')", (instance, instance))
        cid = new_uuid7()
        setup.execute(
            "INSERT INTO mint.self_confirmations (id, instance_id, org_id, principal_id,"
            " server_id, tool, args_fp, fp_key_version, policy_version_id, purpose,"
            " requested_by_key_token, expires_at) VALUES (%s, %s, 'o', 'u1', 's', 't', %s, 1,"
            " 'pv', 'p', 'tok', now() + interval '1 day')", (cid, instance, HEX))
    first = psycopg.connect(migrated_database)
    second = psycopg.connect(migrated_database)
    outcome = {}

    def late():
        try:
            second.execute("SELECT set_config('mint.staff_user_id', 'u1', true)")
            second.execute("SELECT set_config('mint.staff_instance_id', %s, true)", (instance,))
            second.execute("SELECT set_config('mint.staff_session_id_hash', %s, true)", (SB,))
            second.execute("SELECT set_config('mint.staff_team_ids', '[]', true)")
            second.execute("SELECT mint.staff_confirm(%s, 'tok-b')", (cid,))
            second.commit()
            outcome["second"] = "ok"
        except psycopg.Error as error:
            second.rollback()
            outcome["second"] = type(error).__name__

    try:
        first.execute("SELECT set_config('mint.staff_user_id', 'u1', true)")
        first.execute("SELECT set_config('mint.staff_instance_id', %s, true)", (instance,))
        first.execute("SELECT set_config('mint.staff_session_id_hash', %s, true)", (SA,))
        first.execute("SELECT set_config('mint.staff_team_ids', '[]', true)")
        first.execute("SELECT mint.staff_confirm(%s, 'tok-a')", (cid,))
        thread = threading.Thread(target=late)
        thread.start()
        time.sleep(0.5)
        assert thread.is_alive()
        first.commit()
        thread.join(10)
    finally:
        first.close()
        second.close()
    assert outcome["second"] == "CheckViolation"
    with psycopg.connect(migrated_database) as check:
        assert check.execute("SELECT confirmed_by_key_token FROM mint.self_confirmations"
                             " WHERE id = %s", (cid,)).fetchone()[0] == "tok-a"
        assert check.execute("SELECT count(*) FROM mint.events WHERE instance_id = %s"
                             " AND kind = 'call_approval_approved'", (instance,)).fetchone()[0] == 1


def test_control_can_cancel_and_expire_but_never_confirm_or_consume(db, base):
    a, b, c = add_confirmation(db), add_confirmation(db, fp=H2), add_confirmation(db, fp="c" * 64)
    confirm(db, c)
    as_role(db, "mint_control")
    assert scalar(db, "SELECT count(*) FROM mint.self_confirmations") == 3
    update(db, "self_confirmations", f"id = '{a}'", status="cancelled")
    update(db, "self_confirmations", f"id = '{c}'", status="expired")
    with fails(db, errors.InsufficientPrivilege):
        confirm(db, b)
    denied(db, f"UPDATE mint.self_confirmations SET status = 'rejected' WHERE id = '{b}'",
           f"UPDATE mint.self_confirmations SET display = '{{}}' WHERE id = '{b}'",
           "INSERT INTO mint.self_confirmations (id) VALUES (gen_random_uuid())",
           "DELETE FROM mint.self_confirmations")  # fmt: skip


def test_control_cannot_consume_a_confirmation(db, base):
    cid = add_confirmation(db)
    confirm(db, cid)
    as_role(db, "mint_control")
    with fails(db, errors.InsufficientPrivilege):
        consume(db, cid)


def test_control_registers_jobs_but_does_not_run_them(db, base):
    as_role(db, "mint_control")
    jid = add_job(db)
    assert scalar(db, "SELECT count(*) FROM mint.jobs") == 1
    denied(db, f"UPDATE mint.jobs SET status = 'running' WHERE id = '{jid}'",
           "DELETE FROM mint.jobs",
           "INSERT INTO mint.exports (id) VALUES (gen_random_uuid())",
           "INSERT INTO mint.seal_batches (instance_id) VALUES ('inst1')",
           "UPDATE mint.state_epoch SET epoch = epoch + 1",
           "SELECT mint.raise_epoch('inst1', 5)")  # fmt: skip


def test_control_runs_the_service_tables(db, base):
    as_role(db, "mint_control")
    iid = add_intake(db)
    intake_to(db, iid, "checking", "passed")
    insert(db, "intake_checks", id=new_uuid7(), instance_id=I, intake_id=iid, check="url_guard",
           attempt=1, result="pass", method="static")  # fmt: skip
    tool = add_tool(db)
    approve_tool(db, tool)
    add_deployment(db)
    add_session(db, subject="admin", user="u1", name="root")
    db.execute("RESET ROLE")
    alert = add_alert(db)
    grant = add_grant(db)
    as_role(db, "mint_control")
    update(db, "alerts", f"id = '{alert}'", status="acknowledged", acknowledged_by="alice")
    update(db, "litellm_grants", f"id = '{grant}'", held=False, missing_count=0)
    assert scalar(db, "SELECT count(*) FROM mint.exports") == 0
    denied(db, f"UPDATE mint.litellm_grants SET applied_sha256 = '{HEX}' WHERE id = '{grant}'",
           f"UPDATE mint.alerts SET count = 9 WHERE id = '{alert}'",
           f"UPDATE mint.tool_contracts SET observed_at = now() WHERE id = '{tool}'")  # fmt: skip


def test_worker_runs_jobs_exports_and_alerts(db, base):
    job = add_job(db)
    alert = add_alert(db)
    tool = add_tool(db)
    as_role(db, "mint_worker")
    update(db, "jobs", f"id = '{job}'", status="running", lease_owner="w", lease_until=NOW)
    update(db, "jobs", f"id = '{job}'", status="done", updated_at=NOW)
    add_job(db, key="x")
    export = add_export(db)
    update(db, "exports", f"id = '{export}'", status="written", written_at=NOW, attempts=1)
    add_grant(db)
    update(db, "alerts", f"id = '{alert}'", last_at=NOW, count=2)
    add_alert(db, key="other")
    insert(db, "alert_deliveries", id=new_uuid7(), instance_id=I, alert_id=alert,
           channel="webhook", delivery_id=new_uuid7())  # fmt: skip
    insert(db, "schedules", instance_id=I, kind="seal", interval_seconds=60, next_run_at=NOW)
    update(db, "schedules", "kind = 'seal'", next_run_at=NOW)
    update(db, "tool_contracts", f"id = '{tool}'", observed_sha256=H2, observed_at=NOW)
    denied(db, f"UPDATE mint.tool_contracts SET status = 'approved' WHERE id = '{tool}'",
           f"UPDATE mint.alerts SET status = 'resolved' WHERE id = '{alert}'",
           "UPDATE mint.approvals SET status = 'revoked'",
           "UPDATE mint.servers SET status = 'suspended'",
           "INSERT INTO mint.events (event_id) VALUES (gen_random_uuid())",
           "UPDATE mint.state_epoch SET epoch = epoch + 1",
           "INSERT INTO mint.seal_batches (instance_id) VALUES ('inst1')",
           "SELECT mint.raise_epoch('inst1', 5)")  # fmt: skip


def test_sealer_appends_batches_and_still_only_fills_seal_columns(db, base):
    as_role(db, "mint_sealer")
    insert(db, "seal_batches", instance_id=I, from_seal_seq=1, to_seal_seq=2,
           prev_tail_hash=b"\x00" * 32, tail_hash=b"\x01" * 32)  # fmt: skip
    assert scalar(db, "SELECT count(*) FROM mint.seal_batches") == 1
    denied(db, "UPDATE mint.seal_batches SET tail_hash = tail_hash",
           "DELETE FROM mint.seal_batches", "SELECT * FROM mint.jobs",
           "UPDATE mint.events SET payload = '{}'")  # fmt: skip


def test_plugin_creates_a_request_row_and_consumes_a_confirmed_one(db, base):
    as_role(db, "mint_plugin")
    cid = new_uuid7()
    db.execute(
        "INSERT INTO mint.self_confirmations (id, instance_id, org_id, principal_id, server_id,"
        " tool, args_fp, fp_key_version, policy_version_id, purpose, requested_by_key_token,"
        " display, expires_at) VALUES (%s, %s, 'orgA', 'u1', 'srv-1', 'write', %s, 1, 'pv-1',"
        " 'transfer', 'tok', '{\"amount\": \"1\"}', %s)",
        (cid, I, HEX, NOW.replace(year=2100)),
    )
    again = db.execute(
        "INSERT INTO mint.self_confirmations (id, instance_id, org_id, principal_id, server_id,"
        " tool, args_fp, fp_key_version, policy_version_id, purpose, requested_by_key_token,"
        " expires_at) VALUES (%s, %s, 'orgA', 'u1', 'srv-1', 'write', %s, 1, 'pv-1',"
        " 'transfer', 'tok', %s) ON CONFLICT DO NOTHING",
        (new_uuid7(), I, HEX, NOW.replace(year=2100)),
    )
    assert again.rowcount == 0
    # 결정 열과 상태는 요청 행에 쓸 수 없다.
    for column in ("status", "confirmed_by_user_id", "consumed_at", "state_version"):
        with fails(db, errors.InsufficientPrivilege):
            db.execute(
                f"INSERT INTO mint.self_confirmations (id, instance_id, org_id, principal_id,"
                f" server_id, tool, args_fp, fp_key_version, policy_version_id, purpose,"
                f" requested_by_key_token, expires_at, {column}) SELECT gen_random_uuid(), %s,"
                f" 'orgA', 'u9', 'srv-1', 'write', %s, 1, 'pv-1', 'p', 'tok', now(), NULL",
                (I, H2),
            )
    with fails(db, errors.InsufficientPrivilege):
        confirm(db, cid)
    db.execute("RESET ROLE")
    confirm(db, cid)
    as_role(db, "mint_plugin")
    consume(db, cid)
    assert status_of(db, "self_confirmations", cid) == "consumed"
    denied(db, "DELETE FROM mint.self_confirmations",
           f"UPDATE mint.self_confirmations SET display = '{{}}' WHERE id = '{cid}'")  # fmt: skip


def test_plugin_cannot_cancel_expire_or_consume_a_pending_row(db, base):
    cid = add_confirmation(db)
    as_role(db, "mint_plugin")
    for target in ("cancelled", "expired"):
        with fails(db, errors.InsufficientPrivilege):
            update(db, "self_confirmations", f"id = '{cid}'", status=target)
    with fails(db, errors.CheckViolation):
        consume(db, cid)


def test_plugin_reads_contracts_and_exports_but_not_the_intake_side(db, base):
    add_tool(db)
    add_export(db)
    as_role(db, "mint_plugin")
    assert scalar(db, "SELECT count(*) FROM mint.tool_contracts") == 1
    assert scalar(db, "SELECT count(*) FROM mint.exports") == 1
    assert scalar(db, "SELECT count(*) FROM mint.seal_batches") == 0
    assert scalar(db, "SELECT contract_status FROM mint.servers") == "none"
    assert scalar(db, "SELECT input_keys FROM mint.tool_contracts") == []
    denied(db, "SELECT canonical_text FROM mint.tool_contracts",
           "SELECT * FROM mint.deployment_contracts", "SELECT * FROM mint.intakes",
           "SELECT * FROM mint.intake_checks", "SELECT * FROM mint.jobs",
           "SELECT * FROM mint.alerts", "SELECT * FROM mint.console_sessions",
           "UPDATE mint.tool_contracts SET drift = 'input_schema'",
           "UPDATE mint.servers SET last_observed_at = now()",
           "INSERT INTO mint.exports (id) VALUES (gen_random_uuid())")  # fmt: skip


def test_the_input_keys_come_from_the_contract_text_and_are_unknown_when_unreadable(db, base):
    add_tool(db, tool="a", canonical_text='{"input_schema":{"properties":{"q":{},"limit":{}}}}')
    add_tool(db, tool="b", canonical_text='{"input_schema":{"type":"object"}}')
    add_tool(db, tool="c", canonical_text="not json")
    keys = dict(db.execute("SELECT tool, input_keys FROM mint.tool_contracts").fetchall())
    assert keys == {"a": ["limit", "q"], "b": [], "c": None}


CALL_EVENT = "decision_evaluated"
SYSTEM_EVENTS = [
    "enforcement_unverified", "enforcement_verified", "server_identity_mismatch_observed",
    "buffer_overflow", "buffer_replayed",
]  # fmt: skip
CONTROL_EVENTS = [
    "server_approved", "approval_granted", "intake_decided", "contract_approved",
    "contract_drift_detected", "reapproval_requested", "sync_applied", "restore_attested",
    "alert_opened", "console_session_started", "operator_added", "policy_activated",
]  # fmt: skip


def test_plugin_appends_call_and_system_events_only(db):
    as_role(db, "mint_plugin")
    invocation = new_uuid7()
    for kind in ("decision_evaluated", "discovery_evaluated", "call_response_received",
                 "call_outcome_unknown"):  # fmt: skip
        key, count = add_event(db, key=f"call:{new_uuid7()}:1:{kind}", kind=kind,
                               invocation_id=invocation, attempt_id=1)  # fmt: skip
        assert count == 1
    for kind in SYSTEM_EVENTS:
        assert add_event(db, key=f"selfcheck:r1:1:{kind}", kind=kind)[1] == 1
    for kind in CONTROL_EVENTS:
        with fails(db, errors.InsufficientPrivilege):
            add_event(db, key=f"approval:{new_uuid7()}:1:{kind}", kind=kind)


@pytest.mark.parametrize("role", ["mint_control", None])
def test_control_and_owner_still_append_every_event_kind(db, role):
    if role:
        as_role(db, role)
    for kind in CONTROL_EVENTS:
        assert add_event(db, key=f"approval:{new_uuid7()}:1:{kind}", kind=kind)[1] == 1


def test_a_plugin_member_of_the_control_role_is_not_restricted(db):
    db.execute("DROP ROLE IF EXISTS g0_both")
    db.execute("CREATE ROLE g0_both NOLOGIN IN ROLE mint_plugin, mint_control")
    db.execute("SET LOCAL ROLE g0_both")
    key = f"approval:{new_uuid7()}:1:server_approved"
    assert add_event(db, key=key, kind="server_approved")[1] == 1
    db.execute("RESET ROLE")


# ---------------------------------------------------------------------------
# 세대 올리기
# ---------------------------------------------------------------------------


def raise_to(conn, target, function="mint.raise_epoch", instance=I):
    return conn.execute(f"SELECT {function}(%s, %s)", (instance, target)).fetchone()[0]


def test_raise_epoch_increases_within_the_limit(db, base):
    current = epoch(db)
    assert raise_to(db, current + 1) == current + 1
    assert epoch(db) == current + 1
    assert raise_to(db, current + 1001) == current + 1001
    assert epoch(db) == current + 1001


@pytest.mark.parametrize("delta", [0, -1])
def test_raise_epoch_never_lowers_or_repeats(db, base, delta):
    current = epoch(db)
    with fails(db, errors.CheckViolation):
        raise_to(db, current + delta)
    assert epoch(db) == current


def test_raise_epoch_is_bounded_to_a_thousand_at_a_time(db, base):
    current = epoch(db)
    with fails(db, errors.CheckViolation):
        raise_to(db, current + 1002)
    with fails(db, errors.CheckViolation):
        db.execute("SELECT mint.raise_epoch(%s, NULL)", (I,))
    assert epoch(db) == current


def test_raise_epoch_creates_a_missing_instance_row(db):
    assert raise_to(db, 10, instance="fresh") == 10
    assert epoch(db, "fresh") == 10
    with fails(db, errors.CheckViolation):
        raise_to(db, 2000, instance="fresh2")


def test_only_the_wrapper_is_open_to_the_control_role(db, base):
    current = epoch(db)
    as_role(db, "mint_control")
    assert raise_to(db, current + 5, "mint.restore_attest_epoch") == current + 5
    with fails(db, errors.InsufficientPrivilege):
        raise_to(db, current + 6)
    with fails(db, errors.CheckViolation):
        raise_to(db, current + 5, "mint.restore_attest_epoch")
    with fails(db, errors.CheckViolation):
        raise_to(db, current + 2000, "mint.restore_attest_epoch")
    db.execute("RESET ROLE")
    assert epoch(db) == current + 5


@pytest.mark.parametrize("role", ["mint_plugin", "mint_worker", "mint_sealer", "mint_staff"])
def test_other_roles_cannot_raise_the_epoch(db, base, role):
    as_role(db, role)
    for function in ("mint.raise_epoch", "mint.restore_attest_epoch"):
        with fails(db, errors.InsufficientPrivilege):
            raise_to(db, 5, function)


def test_the_epoch_trigger_still_forbids_lowering_by_update(db, base):
    with fails(db, errors.CheckViolation):
        db.execute("UPDATE mint.state_epoch SET epoch = epoch - 1")


def add_stdio_server(conn, server_id="stdio-1", **cols):
    row = {"id": new_uuid7(), "instance_id": I, "server_id": server_id, "status": "pending",
           "identity_kind": "stdio", "url_sha256": None, "exec_contract_sha256": HEX,
           "exec_contract_version": 1, "transport": "stdio", "auth_type": "none",
           "registered_by": "alice", **cols}  # fmt: skip
    insert(conn, "servers", **row)
    return row["id"]


def test_server_identity_fields_are_separate_and_default_to_remote(db, base):
    kind = scalar(db, "SELECT identity_kind FROM mint.servers WHERE server_id = 'srv-1'")
    assert kind == "remote"
    add_stdio_server(db)
    assert db.execute(
        "SELECT url_sha256, exec_contract_sha256, exec_contract_version FROM mint.servers"
        " WHERE server_id = 'stdio-1'"
    ).fetchone() == (None, HEX, 1)


@pytest.mark.parametrize(
    "cols",
    [
        {"url_sha256": HEX},  # 로컬 서버에 URL 해시 자리 값
        {"exec_contract_sha256": None},
        {"exec_contract_version": None},
        {"exec_contract_version": 0},
        {"exec_contract_sha256": "XYZ"},
        {"identity_kind": "ftp"},
        {"identity_kind": "remote"},  # URL 해시 없는 원격 서버
    ],
)
def test_server_identity_shape_is_enforced(db, base, cols):
    with fails(db, errors.CheckViolation):
        add_stdio_server(db, **cols)


def test_remote_server_cannot_carry_an_execution_contract_and_kind_is_frozen(db, base):
    sid = base["server"]
    with fails(db, errors.CheckViolation):
        db.execute(
            "UPDATE mint.servers SET exec_contract_sha256 = %s, exec_contract_version = 1"
            " WHERE id = %s", (HEX, sid))
    stdio = add_stdio_server(db)
    with fails(db, errors.CheckViolation):
        db.execute("UPDATE mint.servers SET identity_kind = 'remote', url_sha256 = %s,"
                   " exec_contract_sha256 = NULL, exec_contract_version = NULL WHERE id = %s",
                   (HEX, stdio))


def test_deployment_contract_identity_shape_and_extension_fields(db, base):
    remote = add_deployment(db)
    assert db.execute(
        "SELECT identity_kind, exec_contract_sha256, exec_location, artifact_source, permissions"
        " FROM mint.deployment_contracts WHERE id = %s", (remote,)).fetchone() == (
        "remote", None, None, None, None)
    local = {"url": None, "url_sha256": None, "identity_kind": "stdio", "transport": "stdio",
             "exec_contract_sha256": HEX, "exec_contract_version": 1}  # fmt: skip
    add_stdio_server(db)
    permissions = Jsonb({"network": "none"})
    stdio = add_deployment(db, server="stdio-1", exec_location="local",
                           artifact_source="oci", permissions=permissions, **local)  # fmt: skip
    bad = [{"url": "https://mcp.example/x"}, {"url_sha256": HEX},
           {"exec_contract_sha256": None}, {"exec_contract_version": None},
           {"exec_location": ""}, {"artifact_source": ""}, {"permissions": Jsonb([])}]  # fmt: skip
    for cols in bad:
        with fails(db, errors.CheckViolation):
            add_deployment(db, server="stdio-1", **{"exec_location": "local", **local, **cols})
    with fails(db, errors.CheckViolation):
        add_deployment(db, url=None)  # 원격 계약에 URL이 없음
    with fails(db, errors.CheckViolation):
        add_deployment(db, exec_contract_sha256=HEX, exec_contract_version=1)
    for column, value in [("exec_contract_sha256", H2), ("exec_location", "remote"),
                          ("artifact_source", "npm"), ("identity_kind", "remote")]:  # fmt: skip
        with fails(db, errors.CheckViolation):
            update(db, "deployment_contracts", f"id = '{stdio}'", **{column: value})
