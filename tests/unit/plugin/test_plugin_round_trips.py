"""플러그인의 DB 왕복 횟수. 호출당 질의 수가 늘면 이벤트 루프를 기다리는 횟수가 그만큼 늘어난다."""

import asyncio
import contextlib
from datetime import UTC, datetime
from uuid import uuid4

from plugin_helpers import FP_KEY, INSTANCE, KEY

from mint_litellm.plugin import snapshot as snapshot_module
from mint_litellm.plugin.buffer import ConfirmationConsume, ConsumeRequest
from mint_litellm.plugin.snapshot import PluginDatabase, SnapshotQuery
from mint_litellm.types.events import Event, EventKind, call_source_key
from mint_litellm.types.fingerprint import argument_fingerprint
from mint_litellm.types.ids import new_uuid7


class Cursor:
    def __init__(self, row, rowcount=1):
        self.row, self.rowcount = row, rowcount

    async def fetchone(self):
        return self.row


class Connection:
    """문장과 트랜잭션 블록을 세는 연결 대역."""

    def __init__(self, replies):
        self.replies = replies
        self.statements: list[str] = []
        self.blocks = 0

    async def execute(self, sql, params=None):
        if sql == "":
            return Cursor(None)
        self.statements.append(" ".join(sql.split())[:40])
        for marker, row in self.replies.items():
            if marker in sql:
                return Cursor(row)
        return Cursor(("{}",))

    async def set_isolation_level(self, level):
        pass

    async def set_read_only(self, value):
        pass

    @contextlib.asynccontextmanager
    async def transaction(self):
        self.blocks += 1
        yield


class Pool:
    def __init__(self, conn):
        self.conn = conn

    @contextlib.asynccontextmanager
    async def connection(self):
        yield self.conn


def database(conn):
    db = PluginDatabase(dsn="postgresql://unused")
    db._pool = Pool(conn)
    return db


def query():
    return SnapshotQuery(
        instance_id=INSTANCE, server_id="srv", tool="t", principal_id="u", key_id=KEY,
        user_id="u", team_id="t",
    )


def event():
    invocation = new_uuid7()
    return Event(
        instance_id=INSTANCE, inserted_at=datetime.now(UTC), kind=EventKind.DECISION_EVALUATED,
        source_key=call_source_key(invocation, 1, EventKind.DECISION_EVALUATED),
        invocation_id=invocation, attempt_id=1, payload={"decision_ref": "r"},
    )


def test_a_snapshot_is_one_statement_once_the_confirmation_table_is_known(monkeypatch):
    monkeypatch.setattr(snapshot_module, "parse_snapshot", lambda doc: doc)
    conn = Connection({"to_regclass": ("mint.self_confirmations",), "SELECT jsonb": ('{"a": 1}',)})
    db = database(conn)
    asyncio.run(db.read_snapshot(query()))
    assert [s.split()[0] for s in conn.statements] == ["SELECT", "WITH"]
    conn.statements.clear()
    asyncio.run(db.read_snapshot(query()))
    assert len(conn.statements) == 1 and conn.statements[0].startswith("WITH")
    assert conn.blocks == 0


def test_a_database_without_the_confirmation_table_is_probed_every_time(monkeypatch):
    monkeypatch.setattr(snapshot_module, "parse_snapshot", lambda doc: doc)
    conn = Connection({"to_regclass": (None,)})
    db = database(conn)
    asyncio.run(db.read_snapshot(query()))
    asyncio.run(db.read_snapshot(query()))
    assert sum("to_regclass" in s for s in conn.statements) == 2


def test_an_event_without_a_consumption_is_one_statement_without_a_transaction_block():
    conn = Connection({})
    assert asyncio.run(database(conn).insert_event(event())) is True
    assert len(conn.statements) == 1 and conn.blocks == 0


def test_an_event_with_a_consumption_keeps_its_transaction_block():
    conn = Connection({})
    consume = ConsumeRequest(
        call_approval_id=uuid4(), invocation_id=uuid4(), principal_type="user", principal_id="u",
        server_id="srv", tool="t", args_fp=argument_fingerprint({}, FP_KEY),
        policy_version_id="pv1", state_version=1,
    )
    asyncio.run(database(conn).insert_event(event(), consume))
    assert conn.blocks == 1 and len(conn.statements) == 2
    conn = Connection({})
    confirmation = ConsumeRequest(
        call_approval_id=None, invocation_id=uuid4(), principal_type="user", principal_id="u",
        server_id="srv", tool="t", args_fp="f" * 64, policy_version_id="pv1", state_version=1,
        confirmation=ConfirmationConsume(uuid4(), "org", 1, 1),
    )
    asyncio.run(database(conn).insert_event(event(), confirmation))
    assert conn.blocks == 1 and len(conn.statements) == 2
