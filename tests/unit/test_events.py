import re
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from mint_litellm.types.decision import RevocationCheck
from mint_litellm.types.events import (
    CALL_KINDS,
    CONTROL_ENTITY,
    SYSTEM_KINDS,
    Event,
    EventKind,
    Evidence,
    ResponseObservation,
    call_source_key,
    control_source_key,
)
from mint_litellm.types.ids import new_uuid7

INV = UUID("0192f7a0-7c1e-7a10-8000-0123456789ab")
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_every_event_kind_is_a_call_event_or_has_a_control_entity():
    for kind in EventKind:
        assert (kind in CALL_KINDS) != (kind in CONTROL_ENTITY), kind
        assert re.fullmatch(r"[a-z][a-z_]*", kind.value)


def test_call_source_key_rule():
    assert (
        call_source_key(INV, 1, EventKind.DECISION_EVALUATED) == f"call:{INV}:1:decision_evaluated"
    )
    assert (
        call_source_key(INV, 2, EventKind.CALL_RESPONSE_RECEIVED)
        == f"call:{INV}:2:call_response_received"
    )
    with pytest.raises(ValueError):
        call_source_key(INV, 1, EventKind.APPROVAL_GRANTED)
    with pytest.raises(ValueError):
        call_source_key(INV, 0, EventKind.DECISION_EVALUATED)


@pytest.mark.parametrize(
    ("kind", "entity"),
    [
        (EventKind.APPROVAL_GRANTED, "approval"),
        (EventKind.APPROVAL_REVOKED, "approval"),
        (EventKind.DENIAL_CREATED, "denial"),
        (EventKind.CALL_APPROVAL_CANCELLED, "call_approval"),
        (EventKind.CONSENT_GRANTED, "consent"),
        (EventKind.RELATION_CREATED, "relation"),
        (EventKind.SERVER_SUSPENDED, "server"),
        (EventKind.RELATION_TERMINATING, "relation"),
        (EventKind.SETTINGS_CHANGED, "settings"),
        (EventKind.POLICY_ACTIVATED, "policy_version"),
        (EventKind.ORG_BINDING_CREATED, "org_binding"),
        (EventKind.BUFFER_REPLAYED, "buffer"),
        (EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED, "selfcheck"),
    ],
)
def test_control_source_key_rule(kind, entity):
    assert control_source_key(kind, "abc-1", 4) == f"{entity}:abc-1:4:{kind.value}"


@pytest.mark.parametrize("bad_id", ["", "a:b", "a b", "-leading", "x" * 129])
def test_control_source_key_rejects_ids_that_break_the_format(bad_id):
    with pytest.raises(ValueError):
        control_source_key(EventKind.APPROVAL_GRANTED, bad_id, 1)


def test_control_source_key_rejects_call_events():
    with pytest.raises(ValueError):
        control_source_key(EventKind.DECISION_EVALUATED, "x", 1)


def test_discovery_uses_attempt_one_per_tool_hook_call():
    key = call_source_key(INV, 1, EventKind.DISCOVERY_EVALUATED)
    assert key == f"call:{INV}:1:discovery_evaluated"


def _call_event(**override):
    base = {
        "instance_id": "inst",
        "inserted_at": NOW,
        "kind": EventKind.DECISION_EVALUATED,
        "source_key": f"call:{INV}:1:decision_evaluated",
        "invocation_id": INV,
        "attempt_id": 1,
        "payload": {},
    }
    return Event(**{**base, **override})


def test_event_enforces_its_source_key():
    assert _call_event().evidence is Evidence.DB
    with pytest.raises(ValidationError):
        _call_event(source_key=f"call:{INV}:2:decision_evaluated")
    with pytest.raises(ValidationError):
        _call_event(invocation_id=None)
    with pytest.raises(ValidationError):
        _call_event(attempt_id=None)
    with pytest.raises(ValidationError):
        _call_event(source_key=f"call:{INV}:1:call_response_received")


def test_control_events_need_an_actor_but_system_events_do_not():
    key = control_source_key(EventKind.APPROVAL_GRANTED, "a1", 1)
    with pytest.raises(ValidationError):
        Event(
            instance_id="i",
            inserted_at=NOW,
            kind=EventKind.APPROVAL_GRANTED,
            source_key=key,
            payload={},
        )
    Event(
        instance_id="i",
        inserted_at=NOW,
        kind=EventKind.APPROVAL_GRANTED,
        source_key=key,
        actor="alice",
        payload={},
    )
    Event(
        instance_id="i",
        inserted_at=NOW,
        kind=EventKind.BUFFER_REPLAYED,
        source_key=control_source_key(EventKind.BUFFER_REPLAYED, "batch-1", 1),
        payload={"duplicates": 1},
    )
    Event(
        instance_id="i",
        inserted_at=NOW,
        kind=EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED,
        source_key=control_source_key(EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED, "srv-1", 1),
        payload={},
    )


def test_call_and_system_kinds_are_the_listed_ones_and_disjoint():
    assert CALL_KINDS == {
        EventKind.DECISION_EVALUATED,
        EventKind.DISCOVERY_EVALUATED,
        EventKind.CALL_RESPONSE_RECEIVED,
        EventKind.CALL_OUTCOME_UNKNOWN,
    }
    assert SYSTEM_KINDS == {
        EventKind.ENFORCEMENT_UNVERIFIED,
        EventKind.ENFORCEMENT_VERIFIED,
        EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED,
        EventKind.BUFFER_OVERFLOW,
        EventKind.BUFFER_REPLAYED,
    }
    assert not CALL_KINDS & SYSTEM_KINDS
    assert SYSTEM_KINDS <= set(CONTROL_ENTITY)


def test_control_source_key_must_match_the_kind():
    with pytest.raises(ValidationError):
        Event(
            instance_id="i",
            inserted_at=NOW,
            kind=EventKind.DENIAL_CREATED,
            source_key=control_source_key(EventKind.APPROVAL_GRANTED, "a1", 1),
            actor="alice",
            payload={},
        )


def test_evidence_locations():
    assert {e.value for e in Evidence} == {"db", "buffer", "stderr"}


def test_one_event_keeps_one_source_key_across_evidence_locations():
    event = _call_event()
    copies = [event.with_evidence(e) for e in Evidence]
    assert len({c.source_key for c in copies}) == 1
    assert {c.evidence for c in copies} == set(Evidence)


def test_json_line_round_trip_preserves_everything():
    event = _call_event(payload={"k": [1, 2]}, subject={"principal_id": "u1"}).with_evidence(
        Evidence.BUFFER
    )
    line = event.to_json_line()
    assert "\n" not in line
    assert Event.from_json_line(line) == event


def test_uuid7_is_versioned_and_time_ordered():
    first, second = new_uuid7(), new_uuid7()
    assert first.version == 7 and first.variant == "specified in RFC 4122"
    assert first != second
    assert (first.int >> 80) <= (second.int >> 80)


def test_response_observation_rules():
    ok = ResponseObservation(
        is_error=False, revocation_check=RevocationCheck.CHANGED, revoked_after_snapshot=True
    )
    assert ok.revoked_after_snapshot is True
    ResponseObservation(
        is_error=False, revocation_check=RevocationCheck.UNCHANGED, revoked_after_snapshot=False
    )
    ResponseObservation(is_error=True, revocation_check=RevocationCheck.UNAVAILABLE)
    with pytest.raises(ValidationError):
        ResponseObservation(
            is_error=False,
            revocation_check=RevocationCheck.UNAVAILABLE,
            revoked_after_snapshot=False,
        )
    with pytest.raises(ValidationError):
        ResponseObservation(is_error=False, revocation_check=RevocationCheck.CHANGED)
    with pytest.raises(ValidationError):
        ResponseObservation(
            is_error=False, revocation_check=RevocationCheck.UNCHANGED, revoked_after_snapshot=True
        )


def test_bootstrap_operator_event_uses_the_bootstrap_actor():
    event = Event(
        instance_id="i",
        inserted_at=NOW,
        kind=EventKind.OPERATOR_ADDED,
        source_key=control_source_key(EventKind.OPERATOR_ADDED, "first-admin", 1),
        actor="bootstrap",
        payload={},
    )
    assert event.actor == "bootstrap"


@pytest.mark.parametrize("bad_id", ["orgA\n", "orgA\r", "org\nA", "٣٣"])
def test_identifiers_must_match_completely(bad_id):
    with pytest.raises(ValueError):
        control_source_key(EventKind.ORG_CREATED, bad_id, 1)


def test_a_trailing_newline_in_a_stored_key_is_rejected():
    key = control_source_key(EventKind.APPROVAL_GRANTED, "a1", 1)
    with pytest.raises(ValidationError):
        Event(
            instance_id="i",
            inserted_at=NOW,
            kind=EventKind.APPROVAL_GRANTED,
            source_key=key + "\n",
            actor="alice",
            payload={},
        )
    with pytest.raises(ValidationError):
        Event(
            instance_id="i",
            inserted_at=NOW,
            kind=EventKind.APPROVAL_GRANTED,
            source_key=key.replace(":1:", ":١:"),
            actor="alice",
            payload={},
        )
