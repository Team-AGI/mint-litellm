"""도구 목록의 「보임·통과」 반복 거르기와 판정 본문 2판."""

import asyncio
from dataclasses import replace

from plugin_helpers import (
    approval,
    denial,
    harness,
    request,
    snapshot,
    user_principal,
)

from mint_litellm.plugin.list_seen import ListSeen
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.snapshot import PolicyVersionRow, SettingsRow
from mint_litellm.types.decision import OperationType
from mint_litellm.types.events import decoded_decision

LIST = OperationType.RUNTIME_DISCOVERY


def listed(h, principal=None, **kw):
    return asyncio.run(evaluate_request(request(principal, operation=LIST, **kw), h.deps))


def with_seen(tmp_path, snap=None, ttl=100.0, clock=None):
    h = harness(tmp_path, snap)
    h.deps.list_seen = ListSeen(ttl, 10, clock or (lambda: 0.0))
    return h


def written(h):
    return len(h.store.of_kind("discovery_evaluated"))


def test_a_repeated_visible_tool_is_written_once(tmp_path):
    h = with_seen(tmp_path)
    assert listed(h).allowed and listed(h).allowed and listed(h).allowed
    assert written(h) == 1


def test_without_a_memory_every_list_is_written(tmp_path):
    h = harness(tmp_path)
    listed(h)
    listed(h)
    assert written(h) == 2


def test_a_new_state_epoch_settings_or_policy_version_is_written_again(tmp_path):
    h = with_seen(tmp_path)
    listed(h)
    for change in (
        {"epoch": 8},
        {"settings": SettingsRow(settings_version=4)},
        {"policy_version": PolicyVersionRow(id="pv2", bundle_sha256="b" * 64)},
    ):
        h.snapshots.snap = replace(snapshot(), **change)
        before = written(h)
        listed(h)
        listed(h)
        assert written(h) == before + 1, change


def test_another_principal_or_tool_is_written(tmp_path):
    h = with_seen(tmp_path, snapshot(approvals=(approval(tools=("a", "b")),)))
    listed(h, tool_name="a")
    listed(h, tool_name="b")
    listed(h, user_principal(user_id="u2"), tool_name="a")
    assert written(h) == 3


def test_a_hidden_tool_is_always_written(tmp_path):
    h = with_seen(tmp_path, snapshot(approvals=(), denials=(denial(),)))
    assert not listed(h).allowed and not listed(h).allowed
    assert written(h) == 2


def test_the_entry_expires(tmp_path):
    now = [0.0]
    h = with_seen(tmp_path, ttl=10, clock=lambda: now[0])
    listed(h)
    now[0] = 11
    listed(h)
    assert written(h) == 2


def test_the_memory_is_bounded():
    seen = ListSeen(100, 2, lambda: 0.0)
    for k in ("a", "b", "c"):
        seen.add((k,))
    assert not seen.seen(("a",)) and seen.seen(("c",))


def test_a_failed_write_is_not_remembered(tmp_path):
    h = with_seen(tmp_path)
    h.store.fail = RuntimeError("down")
    listed(h)
    h.store.fail = None
    listed(h)
    assert written(h) == 1


def test_a_broken_memory_writes_the_event(tmp_path):
    h = with_seen(tmp_path)

    class Broken(ListSeen):
        def seen(self, key):
            return super().seen(None)

    h.deps.list_seen = Broken(10, 10)
    listed(h)
    listed(h)
    assert written(h) == 2


def test_v2_body_is_smaller_and_readers_accept_both(tmp_path):
    h = harness(tmp_path)
    asyncio.run(evaluate_request(request(), h.deps))
    listed(h)
    for kind in ("decision_evaluated", "discovery_evaluated"):
        (event,) = h.store.of_kind(kind)
        body = event.payload
        assert body["v"] == 2
        assert "stages" not in body and "findings" not in body
        assert "provenance" not in body["principal"]
        assert "bundle_sha256" not in body and "mode" not in body
        assert body["enforced_action"] == "allow" and body["principal"]["principal_type"]
        full = decoded_decision(body)
        assert full["stages"] == [] and full["evaluated_decision"] == "allow"
    v1 = {"enforced_action": "allow", "stages": [1]}
    assert decoded_decision(v1) == v1


def test_a_stopped_decision_keeps_the_stage_that_stopped(tmp_path):
    h = harness(tmp_path, snapshot(approvals=()))
    asyncio.run(evaluate_request(request(), h.deps))
    (event,) = h.store.of_kind("decision_evaluated")
    body = event.payload
    assert body["findings"][0]["reason_code"] == "APPROVAL_ABSENT"
    assert [s["stage"] for s in body["stages"]] == ["denial_approval"]
    assert body["enforced_action"] == "block"

