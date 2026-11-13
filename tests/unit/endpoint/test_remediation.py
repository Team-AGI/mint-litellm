"""폐기 서버 목록과 자동 제거 보고의 사건."""

from datetime import UTC, datetime

from mint_litellm.endpoint.remediation import (
    MAX_RETIRED,
    remediation_events,
    retired_names,
)
from mint_litellm.types.events import EventKind


def test_retired_names_are_the_registered_servers_that_are_not_live_plus_unknown_reported_ones():
    statuses = {"live": "approved", "paused": "suspended", "old": "terminated",
                "going": "terminating", "bad": "rejected", "new": "pending"}
    got = retired_names(statuses, ["live", "old", "ghost"])
    assert got == ["bad", "ghost", "going", "new", "old"]  # 일시 정지(suspended)는 폐기가 아니다.


def test_the_list_is_bounded():
    statuses = {f"s{i}": "terminated" for i in range(MAX_RETIRED + 50)}
    assert len(retired_names(statuses, [])) == MAX_RETIRED


def test_every_removed_item_becomes_one_event_with_a_stable_key():
    at = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
    removed = [{"kind": "config", "server": "old", "target": "claude"},
               {"kind": "process", "server": "old", "target": None}]
    events = remediation_events("inst", user_id="u1", key_alias="kit-1", removed=removed, at=at)
    assert [e.kind for e in events] == [EventKind.ENDPOINT_REMEDIATED] * 2
    assert len({e.source_key for e in events}) == 2
    again = remediation_events("inst", user_id="u1", key_alias="kit-1", removed=removed, at=at)
    assert [e.source_key for e in again] == [e.source_key for e in events]
    assert events[0].payload == {"kind": "config", "target": "claude", "server_id": "old"}
    assert events[0].subject == {"user_id": "u1", "key_alias": "kit-1", "server_id": "old"}
    assert events[0].actor
