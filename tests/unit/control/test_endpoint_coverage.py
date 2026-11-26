"""AI 도구 보장 집계와 장애 중 통과 호출 기록(데이터베이스 없이)."""

from datetime import UTC, datetime

from mint_litellm.control.endpoint_coverage import coverage_view
from mint_litellm.endpoint.remediation import merge_offline_calls, offline_call_events
from mint_litellm.types.events import EventKind

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def install(alias, *coverage):
    return {
        "state": "managed",
        "key_alias": alias,
        "reported_at": NOW,
        "ai_clients": [{"client": c, "coverage": cov} for c, cov in coverage],
        "plaintext_keys": [{"client": "cursor"}] if alias == "a" else [],
    }


def test_coverage_counts_clients_connected_devices_keys_and_user_excluded_servers():
    rows = [
        install("a", ("cursor", "pre_call"), ("windsurf", "unmanaged")),
        install("b", ("cursor", "local_only")),
        {
            "state": "revoked",
            "key_alias": "c",
            "ai_clients": [{"client": "x", "coverage": "pre_call"}],
        },
        {"state": "managed", "key_alias": "d", "reported_at": NOW, "ai_clients": None},
    ]
    view = coverage_view(rows, [{"ignored": False}, {"ignored": True}])
    assert view["found"] == 2 and view["reporting"] == 2 and view["connected"] == 1
    assert view["keys"] == 1 and view["unapproved"] == 1
    cursor = next(c for c in view["clients"] if c["client"] == "cursor")
    assert len(cursor["devices"]) == 2 and dict(cursor["coverage"]) == {
        "pre_call": 1,
        "local_only": 1,
    }


def test_offline_calls_become_one_event_each_and_the_same_report_is_the_same_event():
    call = {
        "server": "s",
        "tool": "t",
        "harness": "claude",
        "count": 2,
        "at": "2026-01-02T03:04:05+00:00",
    }
    first = offline_call_events("i", user_id="u", key_alias="mint-kit-1", calls=[call], at=NOW)
    again = offline_call_events("i", user_id="u", key_alias="mint-kit-1", calls=[call], at=NOW)
    assert [e.kind for e in first] == [EventKind.ENDPOINT_OFFLINE_CALL]
    assert first[0].source_key == again[0].source_key
    assert first[0].payload["server_id"] == "s" and first[0].payload["count"] == 2
    assert first[0].actor == "u" and first[0].payload["contract"] == "outage"


def test_kept_offline_calls_dedupe_and_survive_a_report_without_the_list():
    call = {"server": "s", "tool": "t", "harness": "h", "count": 1, "at": "x"}
    assert merge_offline_calls([call], None) == [call]
    assert merge_offline_calls([call], [call, call | {"tool": "u"}]) == [call, call | {"tool": "u"}]
    assert merge_offline_calls(None, None) is None
