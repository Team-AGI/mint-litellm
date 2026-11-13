"""서비스 틀: 한 트랜잭션의 원자성, 역할·직무 분리, 낙관적 잠금, 관리 오류, 작업 등록,
외부 읽기의 위치. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from ctl_fixtures import INSTANCE, make_ctx
from litellm_stub import GOOD_KEY

psycopg = pytest.importorskip("psycopg")

import mint_litellm  # noqa: E402
from mint_litellm.control import jobs, ledger  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import AdminCode, AdminError, ControlError  # noqa: E402
from mint_litellm.control.services import (  # noqa: E402
    approvals,
    base,
    call_approvals,
    consents,
    expiry,
    operators,
    orgs,
    relations,
    servers,
    settings,
)
from mint_litellm.types.cli_commands import OperatorRole  # noqa: E402
from mint_litellm.types.identity import SubjectType  # noqa: E402

URL = "http://upstream.test/mcp"
NOW = datetime.now(UTC)
LATER = NOW + timedelta(days=30)


@pytest.fixture(autouse=True)
def handlers_for_the_job_kinds_used_here(monkeypatch):
    """작업 등록의 원자성·수렴만 보는 파일이라 처리기 없는 종류에는 빈 처리기를 둔다."""
    for kind in ("sync_server", "export_negative_state"):
        monkeypatch.setitem(jobs.HANDLERS, kind, lambda job: None)


def count(conn, table):
    return fetchone(conn, f"SELECT count(*) AS n FROM mint.{table} WHERE instance_id = %s",
                    (INSTANCE,))["n"]


def prepare(ctx, litellm):
    orgs.add(ctx, "acme", "ACME")
    servers.register(ctx, litellm, "ctl-everything", URL)
    return relations.add(ctx, "acme", "ctl-everything", "ops", None)


# --- 오류 객체 ------------------------------------------------------------


def test_admin_error_body_is_what_the_api_returns():
    error = AdminError(AdminCode.CONFLICT, "바뀌었습니다.")
    body = error.body()
    assert set(body) == {"code", "message", "reference"}
    assert body["code"] == "MINT-ADMIN-CONFLICT" and body["message"] == "바뀌었습니다."
    assert UUID(body["reference"]).version == 7  # 사건이 없으면 요청 식별자(uuid7)
    assert AdminError(AdminCode.NOT_FOUND, "x", reference="org:a:1:org_created").reference == (
        "org:a:1:org_created"
    )
    with pytest.raises(ValueError):
        AdminError("MINT-ADMIN-NOPE", "x")
    assert isinstance(error, ControlError)  # 명령줄은 기존처럼 메시지와 종료 코드로 다룬다


def test_the_five_admin_codes_are_the_documented_ones():
    assert AdminCode.ALL == {
        "MINT-ADMIN-SEPARATION-OF-DUTIES",
        "MINT-ADMIN-CONFLICT",
        "MINT-ADMIN-STALE-EVIDENCE",
        "MINT-ADMIN-NOT-FOUND",
        "MINT-ADMIN-FORBIDDEN",
    }


# --- 원자성 ---------------------------------------------------------------


def test_a_failed_event_write_rolls_back_the_state_change(ctx, conn, monkeypatch):
    def failing(*args, **kwargs):
        raise psycopg.errors.CheckViolation("event write failed")

    monkeypatch.setattr(ledger, "record", failing)
    with pytest.raises(psycopg.errors.CheckViolation):
        orgs.add(ctx, "acme", "ACME")
    assert count(conn, "orgs") == 0
    assert ctx.emitted == []
    monkeypatch.undo()
    orgs.add(ctx, "acme", "ACME")  # 연결은 그대로 쓸 수 있다
    assert count(conn, "orgs") == 1 and len(ctx.emitted) == 1


def test_a_successful_service_commits_state_and_event_together(ctx, conn):
    orgs.add(ctx, "acme", "ACME")
    assert count(conn, "orgs") == 1
    rows = fetchall(conn, "SELECT kind FROM mint.events WHERE instance_id = %s", (INSTANCE,))
    assert [r["kind"] for r in rows] == ["org_created"]
    assert len(ctx.emitted) == 1


def test_a_job_is_registered_in_the_same_transaction(ctx, conn):
    @base.service("org add")
    def add_with_job(ctx, org_id):
        orgs.domain.add(ctx, org_id, "ACME")
        base.enqueue_job(ctx, "sync_server", org_id)
        raise ControlError("이 서비스는 마지막에 실패한다")

    with pytest.raises(ControlError):
        add_with_job(ctx, "acme")
    assert count(conn, "orgs") == 0 and count(conn, "jobs") == 0 and ctx.emitted == []

    @base.service("org add")
    def add_and_enqueue(ctx, org_id):
        orgs.domain.add(ctx, org_id, "ACME")
        return base.enqueue_job(ctx, "sync_server", org_id)

    add_and_enqueue(ctx, "acme")
    assert count(conn, "orgs") == 1 and count(conn, "jobs") == 1


def test_enqueued_jobs_converge(ctx, conn):
    first = base.enqueue_job(ctx, "sync_server", "srv-a")
    assert base.enqueue_job(ctx, "sync_server", "srv-a") == first
    assert base.enqueue_job(ctx, "sync_server", "srv-b") != first
    keyed = base.enqueue_job(ctx, "export_negative_state", "epoch-3", "export_negative:3")
    assert base.enqueue_job(ctx, "export_negative_state", "epoch-3", "export_negative:3") == keyed
    assert count(conn, "jobs") == 3
    # 실행 중인 같은 대상의 작업만 있으면 새 대기 작업을 만든다
    conn.execute(
        "UPDATE mint.jobs SET status = 'running', lease_owner = 'w', lease_until = now()"
        " + interval '1 minute' WHERE id = %s",
        (first,),
    )
    assert base.enqueue_job(ctx, "sync_server", "srv-a") != first
    assert count(conn, "jobs") == 4


# --- 역할과 직무 분리 -----------------------------------------------------


def test_a_role_outside_the_command_table_is_forbidden_and_changes_nothing(conn):
    viewer = make_ctx(conn, "v", "viewer", "viewer-user")
    with pytest.raises(AdminError) as raised:
        orgs.add(viewer, "acme", "ACME")
    assert raised.value.code == AdminCode.FORBIDDEN and raised.value.exit_code == 4
    assert count(conn, "orgs") == 0
    approver = make_ctx(conn, "a", "approver", "approver-user")
    with pytest.raises(AdminError):  # org add는 admin만
        orgs.add(approver, "acme", "ACME")


def test_init_needs_no_token(db):
    conn = db
    conn.execute("SELECT 1")  # 바깥 트랜잭션 안이어야 세이브포인트가 되어 시험 뒤 되돌아간다
    ctx = make_ctx(conn, "init", "admin", None)
    settings.initialize(ctx, "default", "기본 조직")
    settings.initialize(ctx, "default", "바뀐 이름")  # 다시 실행해도 그대로
    assert count(conn, "orgs") == 1 and len(ctx.emitted) == 3  # 설정, 조직, 기본 조직


HEX = "ab" * 32


def with_policy(conn):
    conn.execute(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s)",
        (INSTANCE, HEX, HEX),
    )


def request_call(ctx, **overrides):
    values = dict(
        org_id="acme", principal_type="user", principal_id="human-1", server_id="ctl-everything",
        tool="echo", args_fp=HEX, fp_key_version=1, policy_version_id="v1",
        expires_in_minutes=30, requested_by="requester",
    )
    values.update(overrides)
    return call_approvals.request(ctx, **values)


def test_separation_of_duties_is_a_distinct_admin_error(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    call_id = request_call(ctx)
    same_person = make_ctx(conn, "p", "approver", "human-1")  # 호출 주체와 같은 사용자
    with pytest.raises(AdminError) as raised:
        call_approvals.approve(same_person, call_id, None)
    assert raised.value.code == AdminCode.SEPARATION_OF_DUTIES
    status = fetchone(conn, "SELECT status FROM mint.call_approvals WHERE id = %s", (call_id,))
    assert status["status"] == "pending"


def test_requester_cannot_approve_without_a_second_person(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    with pytest.raises(AdminError) as raised:
        approvals.approve(
            ctx, litellm, relation_id=relation, scope_type="key", scope_id=GOOD_KEY,
            tools=["echo"], valid_from=NOW, valid_until=LATER, approval_class="standard",
            basis_text="티켓", requested_by="root-user", allowlist_ids=[], second=None,
        )
    assert raised.value.code == AdminCode.SEPARATION_OF_DUTIES
    assert count(conn, "approvals") == 0


# --- 낙관적 잠금 ----------------------------------------------------------


def test_a_stale_state_version_is_a_conflict_and_leaves_the_state(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    version = fetchone(
        conn, "SELECT state_version FROM mint.usage_relations WHERE id = %s", (relation,)
    )["state_version"]
    with pytest.raises(AdminError) as raised:
        relations.terminate(ctx, relation, expected_version=version + 5)
    assert raised.value.code == AdminCode.CONFLICT
    row = fetchone(conn, "SELECT status FROM mint.usage_relations WHERE id = %s", (relation,))
    assert row["status"] == "active"
    relations.terminate(ctx, relation, expected_version=version)
    row = fetchone(conn, "SELECT status FROM mint.usage_relations WHERE id = %s", (relation,))
    assert row["status"] == "terminating"


def test_a_missing_target_is_not_found(ctx, conn):
    with pytest.raises(AdminError) as raised:
        orgs.close(ctx, "no-such-org", expected_version=1)
    assert raised.value.code == AdminCode.NOT_FOUND
    with pytest.raises(AdminError) as raised:
        orgs.close(ctx, "no-such-org")  # 버전을 안 보내도 같은 코드
    assert raised.value.code == AdminCode.NOT_FOUND


def test_settings_use_their_own_version_column(ctx, conn):
    settings.initialize(ctx, "default", "기본 조직")
    version = fetchone(
        conn, "SELECT settings_version FROM mint.settings WHERE instance_id = %s", (INSTANCE,)
    )["settings_version"]
    with pytest.raises(AdminError) as raised:
        settings.set_default_org(ctx, None, expected_version=version + 1)
    assert raised.value.code == AdminCode.CONFLICT
    settings.set_default_org(ctx, None, expected_version=version)


def test_the_stale_evidence_helper_carries_its_code():
    from mint_litellm.control.errors import stale_evidence

    assert stale_evidence("옛 증거").code == AdminCode.STALE_EVIDENCE


# --- 외부 읽기는 트랜잭션 앞에서 ----------------------------------------------


class Spy:
    """LiteLLM 읽기를 부를 때의 연결 상태를 기록한다."""

    def __init__(self, inner, conn):
        self.inner, self.conn, self.states = inner, conn, []

    def __getattr__(self, name):
        target = getattr(self.inner, name)

        def call(*args):
            self.states.append((name, self.conn.info.transaction_status))
            return target(*args)

        return call


def test_litellm_is_read_before_the_transaction_starts(fresh_db, litellm):
    from mint_litellm.control.settings_store import ensure

    with psycopg.connect(fresh_db) as conn:
        ensure(conn, INSTANCE)
        conn.commit()
        ctx = make_ctx(conn)
        spy = Spy(litellm, conn)
        orgs.add(ctx, "acme", "ACME")
        orgs.bind(ctx, "acme", SubjectType.USER, "human-1")  # 시험 키의 소유 사용자
        conn.commit()
        servers.register(ctx, spy, "ctl-everything", URL)
        conn.commit()
        relation = relations.add(ctx, "acme", "ctl-everything", "ops", None)
        conn.commit()
        operators.add(ctx, spy, "ops1", OperatorRole.ADMIN, "human-2", None)
        conn.commit()
        consents.add(
            ctx, spy, "acme", "human-2", "ctl-everything", "ops", "all", "v1", NOW, LATER,
            "ticket-1", "ab" * 32,
        )
        conn.commit()
        approvals.approve(
            ctx, spy, relation_id=relation, scope_type="key", scope_id=GOOD_KEY,
            tools=["echo"], valid_from=NOW, valid_until=LATER, approval_class="standard",
            basis_text="티켓", requested_by="someone", allowlist_ids=[], second=None,
        )
    from psycopg.pq import TransactionStatus

    assert spy.states and all(s == TransactionStatus.IDLE for _, s in spy.states), spy.states
    assert {name for name, _ in spy.states} >= {"get_server", "get_user", "get_key"}


def test_a_read_that_was_not_prefetched_is_refused(litellm):
    facts = base.Prefetched(litellm).prefetch("get_user", "human-1")
    assert facts.get_user("human-1")["user_id"] == "human-1"
    with pytest.raises(RuntimeError):
        facts.get_user("someone-else")


# --- 만료 검사는 expired로만 --------------------------------------------------


def test_expiry_only_marks_due_rows_expired(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    for tag, delta in (("past", "-1 minute"), ("future", "+1 hour")):
        conn.execute(
            "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type,"
            " principal_id, server_id, tool, args_fp, fp_key_version, policy_version_id, status,"
            " requested_by, expires_at) VALUES (gen_random_uuid(), %s, 'acme', 'user', %s,"
            " 'ctl-everything', 't', %s, 1, 'v1', 'pending', 'r', now() + %s::interval)",
            (INSTANCE, tag, HEX, delta),
        )
    assert expiry.expire_due(conn, INSTANCE) == {"call_approvals": 1, "self_confirmations": 0}
    states = {
        r["principal_id"]: r["status"]
        for r in fetchall(conn, "SELECT principal_id, status FROM mint.call_approvals")
    }
    assert states == {"past": "expired", "future": "pending"}


# --- 명령줄은 서비스만 부른다 ---------------------------------------------------


DOMAIN_MUTATORS = {
    "allowlists": {"add", "lift"},
    "approvals": {"approve", "revoke", "create_denial", "lift_denial", "call_request",
                  "call_approve", "call_reject", "call_cancel"},
    "consents": {"add", "revoke"},
    "operators": {"add", "bootstrap"},
    "orgs": {"add", "close", "bind", "unbind"},
    "relations": {"add", "terminate"},
    "servers": {"register", "suspend", "resume", "terminate"},
    "settings_store": {"ensure", "set_default_org", "set_mode", "set_observable"},
    "policy_versions": {"activate"},
}


def test_the_cli_changes_state_only_through_services():
    source = Path(mint_litellm.__file__).with_name("cli.py").read_text(encoding="utf-8")
    hits = [
        f"{node.value.id}.{node.attr}"
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.attr in DOMAIN_MUTATORS.get(node.value.id, ())
    ]
    assert not hits, hits


def test_every_state_changing_command_has_a_service():
    from mint_litellm import cli

    stateful = {
        "init", "operator add", "operator bootstrap", "server register",
        "server register-local", "server suspend", "server resume", "server terminate",
        "relation add",
        "relation terminate", "approve", "deny", "denial lift",
        "revoke", "call-approval request", "call-approval approve", "call-approval reject",
        "call-approval cancel", "consent add", "consent revoke", "allowlist add",
        "allowlist lift", "org add", "org close", "org bind", "org unbind",
        "settings default-org", "settings mode", "settings control-key", "settings observable",
        "policy activate", "policy shadow", "policy shadow-cancel",
        "contract reapprove", "sync resume", "alert ack", "alert resolve", "intake create",
        "intake recheck", "intake assign", "intake approve", "intake reject", "intake except",
        "operator remove", "operator set-role",
    }
    assert stateful <= set(cli.HANDLERS)
    assert stateful <= set(base._COMMANDS)
    assert set(cli.HANDLERS) - stateful == {
        "check", "status", "ledger list", "alert list", "sync status", "intake list",
        "intake show", "contract show", "contract diff", "doctor", "policy status",
    }
