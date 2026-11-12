"""플러그인의 DB 접근을 실제 PostgreSQL에서 확인한다. ``MINT_TEST_DATABASE_URL``이 필요하다."""

import asyncio
import io
import os
import socket
import time
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from plugin_helpers import config, evaluator, request, snapshot, user_principal  # noqa: E402
from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm.control.db.migrate import apply_migrations  # noqa: E402
from mint_litellm.plugin import snapshot as snapshot_module  # noqa: E402
from mint_litellm.plugin.buffer import (  # noqa: E402
    ConsumeRequest,
    ConsumptionLost,
    EvidenceRecorder,
    LocalBuffer,
)
from mint_litellm.plugin.pipeline import PipelineDeps, evaluate_request  # noqa: E402
from mint_litellm.plugin.snapshot import (  # noqa: E402
    NegativeStateQuery,
    PluginDatabase,
    SnapshotQuery,
)
from mint_litellm.types.decision import url_sha256  # noqa: E402
from mint_litellm.types.events import (  # noqa: E402
    Event,
    EventKind,
    Evidence,
    call_source_key,
)
from mint_litellm.types.fingerprint import argument_fingerprint  # noqa: E402
from mint_litellm.types.identity import OrgStatus, SubjectType  # noqa: E402
from mint_litellm.types.ids import new_uuid7  # noqa: E402
from mint_litellm.types.settings import Mode  # noqa: E402

URL_HASH = url_sha256("https://mcp.example/api")
FP_KEY = bytes(range(32))
ARGS_FP = argument_fingerprint({"q": "x"}, FP_KEY)


ADMIN_URL = os.environ.get("MINT_TEST_DATABASE_URL")


@pytest.fixture(scope="module")
def plugin_database():
    """이 모듈만 쓰는 일회용 데이터베이스. 다른 시험의 전역 조회와 섞이지 않는다."""
    if not ADMIN_URL:
        pytest.skip("MINT_TEST_DATABASE_URL is not set")
    name = f"mint_plugin_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    params = conninfo_to_dict(ADMIN_URL)
    params["dbname"] = name
    url = make_conninfo(**params)
    with psycopg.connect(url, autocommit=True) as conn:
        apply_migrations(conn)
    yield url
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture(scope="module")
def plugin_dsn(plugin_database):
    """``mint_plugin`` 그룹에 속한 로그인 역할의 접속 주소."""
    role = f"mint_plugin_login_{uuid.uuid4().hex[:8]}"
    password = uuid.uuid4().hex
    with psycopg.connect(plugin_database, autocommit=True) as conn:
        conn.execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}' IN ROLE mint_plugin")
    params = conninfo_to_dict(plugin_database)
    params["user"], params["password"] = role, password
    yield make_conninfo(**params)
    with psycopg.connect(plugin_database, autocommit=True) as conn:
        conn.execute(f"DROP OWNED BY {role}")
        conn.execute(f"DROP ROLE {role}")


class Scenario:
    """한 배치 안의 조직·서버·승인 한 벌."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.iid = f"t{uuid.uuid4().hex[:12]}"
        self.relation = uuid.uuid4()
        self.approval = uuid.uuid4()
        self.policy = "pv1"
        self.conn = psycopg.connect(url, autocommit=True)
        self.seed()

    def close(self) -> None:
        self.conn.close()

    def seed(self) -> None:
        c, iid = self.conn, self.iid
        c.execute(
            "INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, 'org1', 'Org')", (iid,)
        )
        c.execute(
            "INSERT INTO mint.org_bindings (id, instance_id, org_id, subject_type, subject_id,"
            " created_by) VALUES (%s, %s, 'org1', 'team', 't1', 'admin')",
            (uuid.uuid4(), iid),
        )
        c.execute("INSERT INTO mint.settings (instance_id) VALUES (%s)", (iid,))
        c.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by) VALUES (%s, %s, 'srv-1', 'awaiting_approval', %s,"
            " 'http', 'none', 'admin')",
            (uuid.uuid4(), iid, URL_HASH),
        )
        c.execute(
            "UPDATE mint.servers SET status = 'approved'"
            " WHERE instance_id = %s AND server_id = 'srv-1'",
            (iid,),
        )
        c.execute(
            "INSERT INTO mint.usage_relations"
            " (id, instance_id, org_id, team_id, purpose, server_id)"
            " VALUES (%s, %s, 'org1', 't1', 'support', 'srv-1')",
            (self.relation, iid),
        )
        self.add_approval(self.approval)
        c.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
            " VALUES (%s, 'pv1', %s, %s)",
            (iid, "1" * 64, "2" * 64),
        )
        for status in ("staged",):
            c.execute(
                "UPDATE mint.policy_versions SET status = %s WHERE instance_id = %s", (status, iid)
            )
        c.execute(
            "UPDATE mint.policy_versions SET status = 'active', activated_at = now(),"
            " activated_by = 'admin' WHERE instance_id = %s",
            (iid,),
        )

    def add_approval(
        self, approval_id, *, status="active", scope=("team", "t1"), tools=("search",)
    ):
        self.conn.execute(
            "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
            " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by,"
            " requested_by, status) VALUES (%s, %s, 'org1', %s, 'standard', 'srv-1', %s, %s, %s,"
            " now() - interval '1 day', now() + interval '30 days', '{}', 'admin', 'req', %s)",
            (approval_id, self.iid, self.relation, list(tools), scope[0], scope[1], status),
        )

    def add_call_approval(self, call_id, *, args_fp=ARGS_FP, hours=1, principal_id="u1"):
        self.conn.execute(
            "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type,"
            " principal_id, server_id, tool, args_fp, fp_key_version, policy_version_id, status,"
            " requested_by, expires_at) VALUES (%s, %s, 'org1', 'user', %s, 'srv-1', 'search',"
            " %s, 1, 'pv1', 'pending', 'req', now() + make_interval(hours => %s))",
            (call_id, self.iid, principal_id, args_fp, hours),
        )
        self.conn.execute(
            "UPDATE mint.call_approvals SET status = 'approved', approved_by = 'approver'"
            " WHERE id = %s",
            (call_id,),
        )

    def query(self, **override):
        args = {
            "instance_id": self.iid,
            "server_id": "srv-1",
            "tool": "search",
            "principal_id": "u1",
            "key_id": "k" * 64,
            "user_id": "u1",
            "team_id": "t1",
        }
        args.update(override)
        return SnapshotQuery(**args)

    def event(self, kind=EventKind.DECISION_EVALUATED, **override):
        invocation = new_uuid7()
        args = {
            "instance_id": self.iid,
            "inserted_at": snapshot().now,
            "kind": kind,
            "source_key": call_source_key(invocation, 1, kind),
            "invocation_id": invocation,
            "attempt_id": 1,
            "payload": {"ok": True},
        }
        args.update(override)
        return Event(**args)


@pytest.fixture
def scenario(plugin_database):
    current = Scenario(plugin_database)
    yield current
    current.close()


def database(dsn, **kw):
    kw.setdefault("acquire_timeout", 2.0)
    return PluginDatabase(dsn, **kw)


def run(coro):
    # psycopg's async mode cannot use the Windows proactor event loop.
    return asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)


def test_the_snapshot_collects_the_state_in_one_read(scenario, plugin_dsn):
    scenario.add_call_approval(uuid.uuid4())
    scenario.conn.execute(
        "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, reason,"
        " created_by) VALUES (%s, %s, NULL, 'team', 't1', 'why', 'admin')",
        (uuid.uuid4(), scenario.iid),
    )
    scenario.conn.execute(
        "INSERT INTO mint.consents (id, instance_id, org_id, human_user_id, server_id, purpose,"
        " data_scope, text_version, source, evidence_ref, evidence_sha256, granted_at, valid_until,"
        " registered_by) VALUES (%s, %s, 'org1', 'u1', 'srv-1', 'support', 'all', 'v1',"
        " 'operator_attested', 'doc-1', %s, now() - interval '1 day', now() + interval '1 day',"
        " 'admin')",
        (uuid.uuid4(), scenario.iid, "3" * 64),
    )

    async def read():
        db = database(plugin_dsn)
        try:
            return await db.read_snapshot(scenario.query())
        finally:
            await db.close()

    snap = run(read())
    assert snap.epoch >= 1
    assert snap.settings.mode is Mode.ENFORCE and snap.settings.settings_version == 1
    assert snap.bindings == {(SubjectType.TEAM, "t1"): "org1"}
    assert snap.org_status == {"org1": OrgStatus.ACTIVE}
    assert snap.server.status == "approved" and snap.server.url_sha256 == URL_HASH
    assert [a.id for a in snap.approvals] == [str(scenario.approval)]
    assert snap.approvals[0].tools == ("search",) and snap.approvals[0].approval_class == "standard"
    assert snap.relations == {
        str(scenario.relation): snapshot()
        .relations["r1"]
        .__class__(id=str(scenario.relation), status="active")
    }
    assert len(snap.denials) == 1 and snap.denials[0].scope_id == "t1"
    assert len(snap.call_approvals) == 1 and snap.call_approvals[0].state_version >= 1
    assert len(snap.consents) == 1 and snap.consents[0].source == "operator_attested"
    assert snap.policy_version.id == "pv1" and snap.policy_version.bundle_sha256 == "2" * 64
    assert snap.now.tzinfo is not None


def test_the_snapshot_filters_by_scope_and_leaves_out_pending_approvals(scenario, plugin_dsn):
    scenario.add_approval(uuid.uuid4(), scope=("team", "t2"))
    scenario.add_approval(uuid.uuid4(), scope=("user", "someone-else"))
    scenario.add_approval(uuid.uuid4(), status="pending")
    scenario.add_approval(uuid.uuid4(), status="active", scope=("key", "k" * 64))

    async def read(query):
        db = database(plugin_dsn)
        try:
            return await db.read_snapshot(query)
        finally:
            await db.close()

    snap = run(read(scenario.query()))
    scopes = sorted((a.scope_type, a.scope_id) for a in snap.approvals)
    assert scopes == [("key", "k" * 64), ("team", "t1")]
    other = run(
        read(scenario.query(team_id="t9", user_id="u9", key_id="z" * 64, principal_id="u9"))
    )
    assert other.approvals == () and other.bindings == {}


def test_the_snapshot_is_read_by_one_statement_outside_a_transaction_block(
    scenario, plugin_dsn, monkeypatch
):
    # 한 문장은 하나의 스냅숏을 본다. 트랜잭션 블록이 여러 문장을 감싸면 now()가
    # 문장 시작과 달라진다.
    monkeypatch.setattr(
        snapshot_module,
        "SNAPSHOT_SQL",
        "SELECT jsonb_build_object('one_statement', now() = statement_timestamp())",
    )
    monkeypatch.setattr(
        snapshot_module,
        "CONFIRMATION_SNAPSHOT_SQL",
        "SELECT jsonb_build_object('one_statement', now() = statement_timestamp())",
    )
    monkeypatch.setattr(snapshot_module, "parse_snapshot", lambda doc: doc)

    async def read():
        db = database(plugin_dsn)
        try:
            return await db.read_snapshot(scenario.query())
        finally:
            await db.close()

    assert run(read()) == {"one_statement": True}


def test_an_unregistered_server_yields_an_empty_server_row(scenario, plugin_dsn):
    async def read():
        db = database(plugin_dsn)
        try:
            return await db.read_snapshot(scenario.query(server_id="nope"))
        finally:
            await db.close()

    snap = run(read())
    assert snap.server is None and snap.approvals == () and snap.allowlists == {}


def test_the_plugin_role_can_only_read_state_append_events_and_consume(scenario, plugin_dsn):
    with psycopg.connect(plugin_dsn, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE mint.approvals SET status = 'revoked'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM mint.operators")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM mint.events")
    db = database(plugin_dsn)
    event = scenario.event()

    async def append():
        try:
            return await db.insert_event(event)
        finally:
            await db.close()

    assert run(append()) is True


def test_inserting_the_same_event_twice_keeps_one_row(scenario, plugin_dsn):
    db = database(plugin_dsn)
    event = scenario.event()

    async def twice():
        first = await db.insert_event(event)
        second = await db.insert_event(event.with_evidence(Evidence.BUFFER))
        await db.close()
        return first, second

    assert run(twice()) == (True, False)
    (count,) = scenario.conn.execute(
        "SELECT count(*) FROM mint.events WHERE instance_id = %s", (scenario.iid,)
    ).fetchone()
    assert count == 1


def consume(scenario, call_id, event, **override):
    args = {
        "call_approval_id": call_id,
        "invocation_id": event.invocation_id,
        "principal_type": "user",
        "principal_id": "u1",
        "server_id": "srv-1",
        "tool": "search",
        "args_fp": ARGS_FP,
        "policy_version_id": "pv1",
        "state_version": 2,
    }
    args.update(override)
    return ConsumeRequest(**args)


def test_consumption_marks_the_call_approval_in_the_same_transaction(scenario, plugin_dsn):
    call_id = uuid.uuid4()
    scenario.add_call_approval(call_id)
    event = scenario.event()
    db = database(plugin_dsn)

    async def go():
        try:
            return await db.insert_event(event, consume(scenario, call_id, event))
        finally:
            await db.close()

    assert run(go()) is True
    row = scenario.conn.execute(
        "SELECT status, consumed_invocation_id FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone()
    assert row == ("consumed", event.invocation_id)


@pytest.mark.parametrize(
    "override",
    [
        {"args_fp": "0" * 64},
        {"tool": "other"},
        {"principal_id": "u2"},
        {"policy_version_id": "pv0"},
        {"state_version": 99},
        {"server_id": "srv-2"},
    ],
)
def test_a_mismatching_consumption_rolls_back_the_event_too(scenario, plugin_dsn, override):
    call_id = uuid.uuid4()
    scenario.add_call_approval(call_id)
    event = scenario.event()
    db = database(plugin_dsn)

    async def go():
        try:
            await db.insert_event(event, consume(scenario, call_id, event, **override))
        finally:
            await db.close()

    with pytest.raises(ConsumptionLost):
        run(go())
    assert scenario.conn.execute(
        "SELECT status FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone() == ("approved",)
    assert scenario.conn.execute(
        "SELECT count(*) FROM mint.events WHERE instance_id = %s", (scenario.iid,)
    ).fetchone() == (0,)


def test_an_expired_call_approval_cannot_be_consumed(scenario, plugin_dsn):
    call_id = uuid.uuid4()
    scenario.add_call_approval(call_id, hours=1)
    scenario.conn.execute("ALTER TABLE mint.call_approvals DISABLE TRIGGER call_approvals_2_frozen")
    try:
        scenario.conn.execute(
            "UPDATE mint.call_approvals SET expires_at = now() - interval '1 second' WHERE id = %s",
            (call_id,),
        )
    finally:
        scenario.conn.execute(
            "ALTER TABLE mint.call_approvals ENABLE TRIGGER call_approvals_2_frozen"
        )
    event = scenario.event()
    db = database(plugin_dsn)

    async def go():
        try:
            await db.insert_event(event, consume(scenario, call_id, event, state_version=3))
        finally:
            await db.close()

    with pytest.raises(ConsumptionLost):
        run(go())


def test_concurrent_resubmission_consumes_exactly_once(scenario, plugin_dsn):
    call_id = uuid.uuid4()
    scenario.add_call_approval(call_id)
    events = [scenario.event() for _ in range(8)]
    db = database(plugin_dsn, max_size=8)

    async def one(event):
        try:
            await db.insert_event(event, consume(scenario, call_id, event))
            return "consumed"
        except ConsumptionLost:
            return "lost"

    async def go():
        try:
            return await asyncio.gather(*(one(e) for e in events))
        finally:
            await db.close()

    results = run(go())
    assert results.count("consumed") == 1 and results.count("lost") == 7
    assert scenario.conn.execute(
        "SELECT count(*) FROM mint.events WHERE instance_id = %s", (scenario.iid,)
    ).fetchone() == (1,)


def test_the_epoch_follows_changes_and_negative_state_is_detected(scenario, plugin_dsn):
    query = NegativeStateQuery(
        instance_id=scenario.iid,
        server_id="srv-1",
        tool="search",
        key_id="k" * 64,
        user_id="u1",
        team_id="t1",
        org_id="org1",
        approval_id=str(scenario.approval),
        relation_id=str(scenario.relation),
    )
    db = database(plugin_dsn)

    async def probe(revoke=False):
        try:
            first = await db.read_epoch(scenario.iid)
            before = await db.has_negative_state(query)
            if revoke:
                scenario.conn.execute(
                    "UPDATE mint.approvals SET status = 'revoked', revoked_at = now(),"
                    " revoke_reason = 'r' WHERE id = %s",
                    (scenario.approval,),
                )
            return (
                first,
                before,
                await db.read_epoch(scenario.iid),
                await db.has_negative_state(query),
            )
        finally:
            await db.close()

    first, before, after, negative = run(probe(revoke=True))
    assert before is False and after > first and negative is True


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE mint.servers SET status = 'suspended' WHERE instance_id = %(iid)s",
        "UPDATE mint.usage_relations SET status = 'terminating' WHERE instance_id = %(iid)s",
        "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, reason,"
        " created_by) VALUES (gen_random_uuid(), %(iid)s, NULL, 'user', 'u1', 'x', 'admin')",
        "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, tools, reason,"
        " created_by) VALUES (gen_random_uuid(), %(iid)s, 'org1', 'team', 't1', ARRAY['search'],"
        " 'x', 'admin')",
        "INSERT INTO mint.denials (id, instance_id, scope_type, scope_id, server_id, reason,"
        " created_by) VALUES (gen_random_uuid(), %(iid)s, 'server', 'srv-1', 'srv-1', 'x',"
        " 'admin')",
    ],
)
def test_each_kind_of_negative_state_is_detected(scenario, plugin_dsn, statement):
    query = NegativeStateQuery(
        instance_id=scenario.iid,
        server_id="srv-1",
        tool="search",
        key_id="k" * 64,
        user_id="u1",
        team_id="t1",
        org_id="org1",
        approval_id=str(scenario.approval),
        relation_id=str(scenario.relation),
    )
    scenario.conn.execute(statement, {"iid": scenario.iid})

    async def probe():
        db = database(plugin_dsn)
        try:
            return await db.has_negative_state(query)
        finally:
            await db.close()

    assert run(probe()) is True


def test_denials_that_do_not_apply_are_not_negative_state(scenario, plugin_dsn):
    scenario.conn.execute(
        "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, tools, reason,"
        " created_by) VALUES (gen_random_uuid(), %s, 'org1', 'team', 't1', ARRAY['other'], 'x',"
        " 'admin')",
        (scenario.iid,),
    )
    query = NegativeStateQuery(
        instance_id=scenario.iid,
        server_id="srv-1",
        tool="search",
        key_id=None,
        user_id="u1",
        team_id="t1",
        org_id="org1",
        approval_id=None,
        relation_id=None,
    )

    async def probe():
        db = database(plugin_dsn)
        try:
            return await db.has_negative_state(query)
        finally:
            await db.close()

    assert run(probe()) is False


def test_registered_servers_are_listed_for_the_instance(scenario, plugin_dsn):
    async def go():
        db = database(plugin_dsn)
        try:
            return await db.registered_servers(scenario.iid)
        finally:
            await db.close()

    (server,) = run(go())
    assert (server.server_id, server.status, server.url_sha256) == ("srv-1", "approved", URL_HASH)
    assert (server.transport, server.auth_type) == ("http", "none")


def test_buffered_events_converge_into_the_database_with_duplicates_counted(scenario, plugin_dsn):
    """DB 불능 동안 버퍼에 쌓은 사건과 커밋 뒤 응답이 유실된 사건이 재적재로 한 건씩 수렴한다."""
    live = database(plugin_dsn)
    dead = database("postgresql://nobody:x@localhost:1/none", acquire_timeout=0.2)
    buffer_dir = scenario.conn.info.dbname  # unique per scenario database
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        buffer = LocalBuffer(Path(tmp) / buffer_dir, 1024 * 1024)
        stderr = io.StringIO()
        offline = EvidenceRecorder(
            dead,
            buffer,
            budget_seconds=0.5,
            instance_id=scenario.iid,
            stderr=stderr,
            replay_interval_seconds=3600,
        )
        online = EvidenceRecorder(
            live,
            buffer,
            budget_seconds=2.0,
            instance_id=scenario.iid,
            stderr=stderr,
            replay_interval_seconds=3600,
        )
        events = [scenario.event() for _ in range(3)]

        async def scenario_run():
            try:
                for event in events:
                    assert await offline.record(event) is Evidence.BUFFER
                # 커밋은 됐지만 응답을 잃은 것처럼 첫 사건은 DB에도 이미 있다.
                assert await live.insert_event(events[0]) is True
                buffer.close()
                await online.replay()
            finally:
                await live.close()
                await dead.close()

        run(scenario_run())
        counts = dict(
            scenario.conn.execute(
                "SELECT kind, count(*) FROM mint.events WHERE instance_id = %s GROUP BY kind",
                (scenario.iid,),
            ).fetchall()
        )
        assert counts == {"decision_evaluated": 3, "buffer_replayed": 1}
        (report,) = scenario.conn.execute(
            "SELECT payload FROM mint.events WHERE instance_id = %s AND kind = 'buffer_replayed'",
            (scenario.iid,),
        ).fetchone()
        assert report == {"replayed": 2, "duplicates": 1, "unreadable": 0}
        assert not buffer.has_pending() and stderr.getvalue() == ""


def test_the_pool_is_opened_lazily_and_closed_idempotently(plugin_dsn):
    db = database(plugin_dsn)
    assert db._pool is None
    run(db.close())
    assert config() is not None


def _fake_pool(monkeypatch, wait):
    import psycopg_pool

    seen = {"events": []}

    class FakePool:
        def __init__(self, dsn, **kw):
            seen.update(kw)

        async def open(self):
            seen["events"].append("open")

        async def wait(self, timeout):
            seen["events"].append(("wait", timeout))
            await wait()

        def connection(self):
            seen["events"].append("connection")
            return "connection"

    monkeypatch.setattr(psycopg_pool, "AsyncConnectionPool", FakePool)
    return seen


def test_the_pool_opens_with_every_connection_up_front_and_waits_for_them(monkeypatch):
    """최소 크기가 최대 크기와 같고, 첫 호출은 연결이 다 찰 때까지 기다린 뒤에 연결을 내준다."""

    async def ready():
        pass

    seen = _fake_pool(monkeypatch, ready)
    db = PluginDatabase("postgresql://unused", max_size=8, acquire_timeout=0.3)
    run(db._connection())
    assert seen["min_size"] == seen["max_size"] == 8
    assert seen["events"] == ["open", ("wait", 2), "connection"]


def test_a_pool_that_is_not_full_in_time_stays_open_and_serves_calls(monkeypatch):
    import psycopg_pool

    async def late():
        raise psycopg_pool.PoolTimeout("not full")

    seen = _fake_pool(monkeypatch, late)
    db = PluginDatabase("postgresql://unused", max_size=8)
    assert run(db._connection()) == "connection"
    assert seen["events"][-1] == "connection"


def test_a_burst_as_wide_as_the_pool_is_served_within_the_budget(scenario, plugin_dsn):
    db = database(plugin_dsn, max_size=8, acquire_timeout=0.3)

    async def go():
        try:
            await db.read_epoch(scenario.iid)  # 첫 사용이 풀을 열고 연결이 다 찰 때까지 기다린다
            assert db._pool.get_stats()["pool_size"] == 8
            return await asyncio.gather(*(db.read_epoch(scenario.iid) for _ in range(8)))
        finally:
            await db.close()

    assert len(run(go())) == 8


def test_a_full_judgment_reads_the_real_state_and_consumes_a_call_approval_once(
    scenario, plugin_dsn, tmp_path
):
    call_id = uuid.uuid4()
    scenario.add_call_approval(call_id)
    live = database(plugin_dsn)
    cfg = config(tmp_path, instance_id=scenario.iid, decision_budget_seconds=2.0)
    recorder = EvidenceRecorder(
        live,
        LocalBuffer(tmp_path / "buffer", 1024 * 1024),
        budget_seconds=2.0,
        instance_id=scenario.iid,
        stderr=io.StringIO(),
    )
    deps = PipelineDeps(
        config=cfg,
        snapshots=live,
        recorder=recorder,
        evaluate=evaluator("RequireApproval", policy_ids=("R2",), version="pv1", bundle="2" * 64),
        verified=lambda: True,
    )
    principal = user_principal(instance_id=scenario.iid)

    async def judge():
        try:
            return [
                await evaluate_request(request(principal), deps),
                await evaluate_request(request(principal), deps),
            ]
        finally:
            await live.close()

    first, second = run(judge())
    assert first.allowed and first.evidence is Evidence.DB
    assert first.snapshot.consumed_call_approval_id == str(call_id)
    assert not second.allowed and second.error.code == "MINT-CALL-APPROVAL-REQUIRED"
    assert scenario.conn.execute(
        "SELECT status FROM mint.call_approvals WHERE id = %s", (call_id,)
    ).fetchone() == ("consumed",)
    kinds = scenario.conn.execute(
        "SELECT kind, count(*) FROM mint.events WHERE instance_id = %s GROUP BY kind",
        (scenario.iid,),
    ).fetchall()
    assert dict(kinds) == {"decision_evaluated": 2}


def test_a_revoked_approval_blocks_a_call_through_the_real_snapshot(scenario, plugin_dsn, tmp_path):
    scenario.conn.execute(
        "UPDATE mint.approvals SET status = 'revoked', revoked_at = now(), revoke_reason = 'r'"
        " WHERE id = %s",
        (scenario.approval,),
    )
    live = database(plugin_dsn)
    recorder = EvidenceRecorder(
        live,
        LocalBuffer(tmp_path / "buffer", 1024 * 1024),
        budget_seconds=2.0,
        instance_id=scenario.iid,
        stderr=io.StringIO(),
    )
    deps = PipelineDeps(
        config=config(tmp_path, instance_id=scenario.iid, decision_budget_seconds=2.0),
        snapshots=live,
        recorder=recorder,
        evaluate=evaluator(version="pv1", bundle="2" * 64),
        verified=lambda: True,
    )

    async def judge():
        try:
            return await evaluate_request(request(user_principal(instance_id=scenario.iid)), deps)
        finally:
            await live.close()

    outcome = run(judge())
    assert not outcome.allowed and outcome.error.code == "MINT-APPROVAL-REVOKED"
    assert outcome.evidence is Evidence.DB


LOOPBACK = socket.gethostbyname("localhost")


class SilentProxy:
    """데이터베이스 앞의 TCP 중계. ``silent``이면 연결은 열어 둔 채 양방향 전달을 멈춘다."""

    def __init__(self, host: str, port: int) -> None:
        self.target = (host, port)
        self.silent = False
        self.port = 0
        self._server = None
        self._writers: list = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, LOOPBACK, 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer) -> None:
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(*self.target)
        except OSError:
            writer.close()
            return
        self._writers += [writer, upstream_writer]

        async def pump(source, sink) -> None:
            try:
                while data := await source.read(65536):
                    while self.silent:
                        await asyncio.sleep(0.02)
                    sink.write(data)
                    await sink.drain()
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                sink.close()

        await asyncio.gather(pump(reader, upstream_writer), pump(upstream_reader, writer))

    async def close(self) -> None:
        self._server.close()
        for writer in self._writers:
            writer.close()


def through(proxy: SilentProxy, url: str) -> str:
    params = conninfo_to_dict(url)
    params["host"], params["port"] = LOOPBACK, str(proxy.port)
    return make_conninfo(**params)


def test_a_silent_database_ends_every_access_at_the_budget_and_recovers(scenario, plugin_database):
    target = conninfo_to_dict(plugin_database)
    proxy = SilentProxy(target.get("host", "localhost"), int(target.get("port", 5432)))

    async def go():
        await proxy.start()
        db = database(through(proxy, plugin_database), max_size=2, acquire_timeout=1.0)
        event = scenario.event()
        try:
            await db.read_snapshot(scenario.query())
            proxy.silent = True
            elapsed = {}
            for name, call in (
                ("snapshot", lambda: db.read_snapshot(scenario.query())),
                ("insert", lambda: db.insert_event(event)),
                ("epoch", lambda: db.read_epoch(scenario.iid)),
                ("snapshot again", lambda: db.read_snapshot(scenario.query())),
            ):
                started = time.monotonic()
                with pytest.raises((TimeoutError, Exception)) as raised:
                    async with asyncio.timeout(0.4):
                        await call()
                elapsed[name] = time.monotonic() - started
                assert not isinstance(raised.value, asyncio.CancelledError), name
            proxy.silent = False
            deadline = time.monotonic() + 15
            while True:
                try:
                    async with asyncio.timeout(1.0):
                        return elapsed, await db.read_snapshot(scenario.query())
                except Exception:
                    assert time.monotonic() < deadline, "the pool did not recover"
                    await asyncio.sleep(0.2)
        finally:
            await db.close()
            await proxy.close()

    elapsed, snap = run(go())
    assert all(seconds < 1.5 for seconds in elapsed.values()), elapsed
    assert snap.server.status == "approved"
    assert scenario.conn.execute(
        "SELECT count(*) FROM mint.events WHERE instance_id = %s", (scenario.iid,)
    ).fetchone() in {(0,), (1,)}


def test_a_call_to_a_silent_database_is_blocked_as_a_dependency_failure_at_the_budget(
    scenario, plugin_database, tmp_path
):
    target = conninfo_to_dict(plugin_database)
    proxy = SilentProxy(target.get("host", "localhost"), int(target.get("port", 5432)))

    async def go():
        await proxy.start()
        live = database(through(proxy, plugin_database), max_size=2, acquire_timeout=0.4)
        recorder = EvidenceRecorder(
            live,
            LocalBuffer(tmp_path / "buffer", 1024 * 1024),
            budget_seconds=0.4,
            instance_id=scenario.iid,
            stderr=io.StringIO(),
        )
        deps = PipelineDeps(
            config=config(tmp_path, instance_id=scenario.iid, decision_budget_seconds=0.4),
            snapshots=live,
            recorder=recorder,
            evaluate=evaluator(version="pv1", bundle="2" * 64),
            verified=lambda: True,
        )
        principal = user_principal(instance_id=scenario.iid)
        try:
            warm = await evaluate_request(request(principal), deps)
            proxy.silent = True
            started = time.monotonic()
            outcome = await evaluate_request(request(principal), deps)
            return warm, outcome, time.monotonic() - started
        finally:
            proxy.silent = False
            await live.close()
            await proxy.close()

    warm, outcome, seconds = run(go())
    assert warm.allowed
    assert not outcome.allowed and outcome.error.code == "MINT-DEPENDENCY-DB"
    assert outcome.error.retry_safe and seconds < 1.5, seconds


def test_the_loser_of_a_concurrent_consumption_is_always_blocked_as_already_consumed(
    scenario, plugin_dsn, tmp_path
):
    """복제본 둘이 같은 호출별 승인을 동시에 소비하면 진 쪽은 승인 요구로 막힌다."""
    rounds = 20

    def replica(name):
        live = database(plugin_dsn, max_size=4, acquire_timeout=0.5)
        recorder = EvidenceRecorder(
            live,
            LocalBuffer(tmp_path / name / "buffer", 1024 * 1024),
            budget_seconds=0.5,
            instance_id=scenario.iid,
            stderr=io.StringIO(),
        )
        deps = PipelineDeps(
            config=config(tmp_path / name, instance_id=scenario.iid, decision_budget_seconds=0.5),
            snapshots=live,
            recorder=recorder,
            evaluate=evaluator(
                "RequireApproval", policy_ids=("R2",), version="pv1", bundle="2" * 64
            ),
            verified=lambda: True,
        )
        return live, deps

    async def go():
        (first, deps_first), (second, deps_second) = replica("a"), replica("b")
        principal = user_principal(instance_id=scenario.iid)
        outcomes = []
        try:
            for _ in range(rounds):
                # 회차마다 승인 하나만 둔다. 한쪽이 먼저 끝나도 다른 쪽이 다음 승인을 고르지 못한다.
                scenario.add_call_approval(uuid.uuid4())
                outcomes.append(
                    await asyncio.gather(
                        evaluate_request(request(principal), deps_first),
                        evaluate_request(request(principal), deps_second),
                    )
                )
        finally:
            await first.close()
            await second.close()
        return outcomes

    outcomes = run(go())
    for pair in outcomes:
        assert sorted(o.allowed for o in pair) == [False, True]
        (loser,) = [o for o in pair if not o.allowed]
        assert loser.error.code == "MINT-CALL-APPROVAL-REQUIRED"
        assert not loser.error.retry_safe
    consumed = scenario.conn.execute(
        "SELECT count(*) FROM mint.call_approvals WHERE instance_id = %s AND status = 'consumed'",
        (scenario.iid,),
    ).fetchone()
    assert consumed == (rounds,)


def test_connections_the_server_closed_are_not_handed_to_a_call(scenario, plugin_dsn):
    """서버가 연결을 끊은 뒤에도 첫 조회가 끊어진 연결 때문에 실패하지 않는다."""
    role = conninfo_to_dict(plugin_dsn)["user"]

    async def go():
        db = database(plugin_dsn, max_size=4, acquire_timeout=2.0)
        try:
            await asyncio.gather(*(db.read_snapshot(scenario.query()) for _ in range(3)))
            scenario.conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = %s",
                (role,),
            )
            await asyncio.sleep(0.6)
            snap = await db.read_snapshot(scenario.query())
            stored = await db.insert_event(scenario.event())
            return snap, stored
        finally:
            await db.close()

    snap, stored = run(go())
    assert snap.server.status == "approved" and stored is True
