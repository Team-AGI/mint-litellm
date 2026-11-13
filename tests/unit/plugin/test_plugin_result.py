import asyncio
import io
from uuid import UUID

import pytest
from plugin_helpers import FakeStore, config

from mint_litellm.plugin.buffer import EvidenceRecorder, LocalBuffer
from mint_litellm.plugin.result import (
    ResultDeps,
    observe_response,
    observe_unknown_outcome,
    screen_result,
)
from mint_litellm.types.decision import RevocationCheck

INVOCATION = "0192f7a0-7c1e-7a10-8000-0123456789ab"


def context(**override):
    ctx = {
        "invocation_id": INVOCATION,
        "attempt_id": 1,
        "decision_ref": f"{INVOCATION}:1",
        "allowed": True,
        "state_epoch": 7,
        "server_id": "srv-1",
        "tool": "search",
        "approval_id": "a1",
        "relation_id": "r1",
        "key_id": "k" * 64,
        "user_id": "u1",
        "team_id": "t1",
        "org_id": "org1",
    }
    ctx.update(override)
    return ctx


class Database:
    def __init__(self, epoch=7, negative=False, fail=False, delay=0.0):
        self.epoch, self.negative, self.fail, self.delay = epoch, negative, fail, delay
        self.queries = []

    async def read_epoch(self, instance_id):
        if self.fail:
            raise ConnectionError("down")
        await asyncio.sleep(self.delay)
        return self.epoch

    async def has_negative_state(self, query):
        self.queries.append(query)
        return self.negative


def deps(tmp_path, database):
    store = FakeStore()
    recorder = EvidenceRecorder(
        store,
        LocalBuffer(tmp_path / "buf", 1024 * 1024),
        budget_seconds=1.0,
        instance_id="inst",
        stderr=io.StringIO(),
    )
    return ResultDeps(config=config(tmp_path), database=database, recorder=recorder), store


def response_event(store):
    (event,) = store.of_kind("call_response_received")
    return event


def test_an_unchanged_epoch_needs_no_state_lookup(tmp_path):
    database = Database(epoch=7)
    d, store = deps(tmp_path, database)
    ctx = context()
    screen_result(ctx, size=42, items=7, texts=[])  # 항목 수는 결과 검사가 남긴다
    asyncio.run(observe_response(ctx, is_error=False, size_bytes=42, deps=d))
    payload = response_event(store).payload
    assert (payload["items"], payload["server_id"]) == (7, "srv-1")
    assert payload["revocation_check"] == RevocationCheck.UNCHANGED.value
    assert payload["revoked_after_snapshot"] is False
    assert payload["snapshot_state_epoch"] == payload["current_state_epoch"] == 7
    assert payload["size_bytes"] == 42 and payload["is_error"] is False
    assert payload["decision_ref"] == f"{INVOCATION}:1"
    assert database.queries == []


@pytest.mark.parametrize("negative", [True, False])
def test_a_changed_epoch_looks_up_the_negative_state(tmp_path, negative):
    database = Database(epoch=9, negative=negative)
    d, store = deps(tmp_path, database)
    asyncio.run(observe_response(context(), is_error=False, size_bytes=None, deps=d))
    payload = response_event(store).payload
    assert payload["revocation_check"] == RevocationCheck.CHANGED.value
    assert payload["revoked_after_snapshot"] is negative
    assert payload["current_state_epoch"] == 9
    (query,) = database.queries
    assert (query.server_id, query.tool, query.approval_id, query.relation_id) == (
        "srv-1",
        "search",
        "a1",
        "r1",
    )
    assert (query.key_id, query.user_id, query.team_id, query.org_id) == (
        "k" * 64,
        "u1",
        "t1",
        "org1",
    )


def test_an_unreadable_database_is_recorded_as_unavailable(tmp_path):
    d, store = deps(tmp_path, Database(fail=True))
    asyncio.run(observe_response(context(), is_error=False, size_bytes=None, deps=d))
    payload = response_event(store).payload
    assert payload["revocation_check"] == RevocationCheck.UNAVAILABLE.value
    assert payload["revoked_after_snapshot"] is None and payload["current_state_epoch"] is None


def test_a_slow_database_is_recorded_as_unavailable(tmp_path):
    d, store = deps(tmp_path, Database(delay=2.0))
    d.config = config(tmp_path, decision_budget_seconds=0.05)
    asyncio.run(observe_response(context(), is_error=False, size_bytes=None, deps=d))
    assert response_event(store).payload["revocation_check"] == "unavailable"


def test_a_missing_epoch_row_compares_equal_to_itself(tmp_path):
    d, store = deps(tmp_path, Database(epoch=None))
    asyncio.run(
        observe_response(context(state_epoch=None), is_error=False, size_bytes=None, deps=d)
    )
    assert response_event(store).payload["revocation_check"] == "unchanged"


def test_an_error_result_is_marked(tmp_path):
    d, store = deps(tmp_path, Database())
    asyncio.run(observe_response(context(), is_error=True, size_bytes=None, deps=d))
    assert response_event(store).payload["is_error"] is True


def test_the_response_event_uses_the_call_source_key(tmp_path):
    d, store = deps(tmp_path, Database())
    asyncio.run(observe_response(context(), is_error=False, size_bytes=None, deps=d))
    event = response_event(store)
    assert event.source_key == f"call:{INVOCATION}:1:call_response_received"
    assert event.invocation_id == UUID(INVOCATION) and event.attempt_id == 1


def test_a_blocked_call_is_not_observed(tmp_path):
    d, store = deps(tmp_path, Database())
    ctx = context(allowed=False)
    asyncio.run(observe_response(ctx, is_error=False, size_bytes=None, deps=d))
    asyncio.run(observe_unknown_outcome(ctx, exception_type="X", http_status=None, deps=d))
    assert store.events == {}


@pytest.mark.parametrize(
    ("status", "cause"), [(504, "timeout"), (None, "failure"), (500, "failure")]
)
def test_a_call_that_never_answered_is_an_unknown_outcome(tmp_path, status, cause):
    d, store = deps(tmp_path, Database())
    asyncio.run(
        observe_unknown_outcome(
            context(), exception_type="HTTPException", http_status=status, deps=d
        )
    )
    (event,) = store.of_kind("call_outcome_unknown")
    assert event.payload == {
        "decision_ref": f"{INVOCATION}:1",
        "cause": cause,
        "exception_type": "HTTPException",
        "http_status": status,
        "outcome": "unknown",
    }
    assert event.source_key == f"call:{INVOCATION}:1:call_outcome_unknown"


def test_observation_falls_back_to_the_buffer_when_the_database_is_down(tmp_path):
    d, store = deps(tmp_path, Database())
    store.fail = ConnectionError("down")
    asyncio.run(observe_response(context(), is_error=False, size_bytes=None, deps=d))
    assert store.events == {}
    d.recorder._buffer.close()
    assert d.recorder._buffer.has_pending()
