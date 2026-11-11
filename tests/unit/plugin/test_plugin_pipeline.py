import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from plugin_helpers import (
    BUNDLE,
    FP_KEY,
    KEY,
    NOW,
    allowlist,
    approval,
    buffered,
    call_approval,
    config,
    consent,
    denial,
    evaluator,
    harness,
    request,
    resolved_server,
    server_row,
    snapshot,
    user_principal,
)

from mint_litellm.compat.litellm_1_106 import HookData, ServerResolutionError
from mint_litellm.plugin.pipeline import (
    Deadline,
    blocking_reason,
    build_policy_input,
    build_request,
    evaluate_request,
)
from mint_litellm.plugin.policy.input import has_only_policy_fields
from mint_litellm.plugin.snapshot import RelationRow, SettingsRow, ToolContractRow
from mint_litellm.types.decision import (
    Action,
    OperationType,
    Stage,
    StageResult,
    StageStatus,
    url_sha256,
)
from mint_litellm.types.errors import DispatchState
from mint_litellm.types.events import Event
from mint_litellm.types.fingerprint import argument_fingerprint
from mint_litellm.types.identity import OrgStatus, SubjectType
from mint_litellm.types.reason_codes import OBSERVATION_CANDIDATES, Reason
from mint_litellm.types.settings import Mode, ObservationSettings


def run(coro):
    return asyncio.run(coro)


def decide(h, req=None):
    return run(evaluate_request(req or request(), h.deps))


def code(outcome) -> str:
    assert outcome.error is not None, "expected a block"
    return outcome.error.code


def test_allow_records_exactly_one_decision_event_in_the_database(tmp_path):
    h = harness(tmp_path)
    outcome = decide(h)
    assert outcome.allowed and outcome.error is None
    assert outcome.evidence.value == "db"
    events = h.store.of_kind("decision_evaluated")
    assert len(events) == 1
    snap = outcome.snapshot
    assert snap.selected_approval_id == "00000000-0000-0000-0000-0000000000a1"
    assert snap.state_epoch == 7 and snap.settings_version == 3
    assert snap.policy_version_id == "pv1" and snap.bundle_sha256 == BUNDLE
    assert snap.principal.org_id == "org1" and snap.principal.org_source.value == "team"
    assert not h.buffer.has_pending() and h.stderr.getvalue() == ""


def test_context_document_carries_only_plain_values(tmp_path):
    outcome = decide(harness(tmp_path))
    ctx = outcome.context
    assert json.loads(json.dumps(ctx)) == ctx
    assert ctx["allowed"] is True and ctx["state_epoch"] == 7
    assert ctx["server_id"] == "srv-1" and ctx["tool"] == "search"
    assert ctx["approval_id"] == "00000000-0000-0000-0000-0000000000a1"
    assert ctx["relation_id"] == "r1" and ctx["org_id"] == "org1"
    assert "q" not in json.dumps(ctx)


class TestContext:
    def test_the_context_carries_plain_values_and_no_argument_value(self, tmp_path):
        outcome = decide(harness(tmp_path))
        ctx = outcome.context
        assert json.loads(json.dumps(ctx)) == ctx
        assert "arguments_digest" not in ctx and ctx["consumed_call_approval"] is None
        assert "x" not in {v for v in ctx.values() if isinstance(v, str) and len(v) == 1}

    def test_a_consumed_call_approval_is_named_in_the_context(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        h = harness(tmp_path, snapshot(call_approvals=(call_approval(),)), evaluate=evaluate)
        consumed = decide(h).context["consumed_call_approval"]
        assert consumed == {"id": str(call_approval().id), "state_version": 2}


class TestErrorReference:
    def blocked(self, tmp_path, attempt_id=1):
        h = harness(tmp_path, snapshot(approvals=()))
        req = replace(request(), attempt_id=attempt_id)
        return h, decide(h, req), req

    @pytest.mark.parametrize("attempt_id", [1, 3])
    def test_the_reference_is_the_invocation_and_attempt_of_the_recorded_decision(
        self, tmp_path, attempt_id
    ):
        h, outcome, req = self.blocked(tmp_path, attempt_id)
        reference = f"{req.invocation_id}:{attempt_id}"
        assert outcome.error.reference == reference == outcome.snapshot.decision_ref
        assert outcome.context["decision_ref"] == reference
        (event,) = h.store.of_kind("decision_evaluated")
        assert event.source_key == f"call:{reference}:decision_evaluated"

    def test_the_error_body_names_no_user_server_tool_or_argument(self, tmp_path):
        _, outcome, req = self.blocked(tmp_path)
        body = json.loads(outcome.error.detail())
        assert set(body) == {"code", "dispatch_state", "retry_safe", "reference"}
        text = outcome.error.detail()
        for secret in ("u1", "t1", "org1", "srv-1", "search", "mslearn", KEY):
            assert secret not in text.replace(str(req.invocation_id), "")


class TestContextStage:
    def test_unverified_blocks_without_reading_the_snapshot(self, tmp_path):
        h = harness(tmp_path, verified=False)
        outcome = decide(h)
        assert code(outcome) == "MINT-ENFORCEMENT-UNVERIFIED"
        assert h.snapshots.queries == []
        assert len(h.store.of_kind("decision_evaluated")) == 1
        assert outcome.snapshot.stop.reason_code == "ENFORCEMENT_UNVERIFIED"
        assert outcome.error.dispatch_state is DispatchState.NOT_DISPATCHED
        assert outcome.error.retry_safe is False

    def test_master_key_is_forbidden(self, tmp_path):
        h = harness(tmp_path)
        principal = user_principal(user_id="default_user_id", team_id=None, is_master_key=True)
        outcome = decide(h, request(principal))
        assert code(outcome) == "MINT-MASTER-KEY-FORBIDDEN"
        assert h.snapshots.queries == []

    def test_unresolved_server_stops(self, tmp_path):
        h = harness(tmp_path)
        failure = StageResult.stop(Reason.SERVER_UNRESOLVED, detail="ValueError")
        outcome = decide(h, request(resolved=None, failure=failure))
        assert code(outcome) == "MINT-SERVER-UNRESOLVED"
        snap = outcome.snapshot
        assert snap.resolved_server_id is None
        assert snap.missing_reasons["resolved_server_id"] == "server_unresolved"

    def test_two_candidates_with_the_same_name_are_ambiguous(self, tmp_path):
        h = harness(tmp_path)
        outcome = decide(h, request(resolved=resolved_server(candidates_with_same_name=2)))
        assert code(outcome) == "MINT-SERVER-IDENTITY-AMBIGUOUS"
        assert outcome.snapshot.candidates_with_same_name == 2

    def test_unverified_wins_over_master_key(self, tmp_path):
        h = harness(tmp_path, verified=False)
        principal = user_principal(is_master_key=True)
        assert code(decide(h, request(principal))) == "MINT-ENFORCEMENT-UNVERIFIED"


class TestSnapshotFailure:
    def test_database_failure_blocks_with_a_retry_safe_error_and_a_buffer_event(self, tmp_path):
        h = harness(tmp_path, RuntimeError("down"))
        h.store.fail = RuntimeError("down")
        outcome = decide(h)
        assert code(outcome) == "MINT-DEPENDENCY-DB"
        assert outcome.error.retry_safe is True
        assert outcome.evidence.value == "buffer"
        assert h.store.events == {}
        events = buffered(h)
        assert [e.kind.value for e in events] == ["decision_evaluated"]
        assert events[0].evidence.value == "buffer"

    def test_database_and_buffer_failure_writes_one_structured_stderr_line(self, tmp_path):
        h = harness(tmp_path, RuntimeError("down"))
        h.store.fail = RuntimeError("down")
        blocker = tmp_path / "blocked"
        blocker.write_text("file, not a directory")
        h.buffer._dir = blocker / "inner"
        outcome = decide(h)
        assert code(outcome) == "MINT-DEPENDENCY-DB" and outcome.evidence.value == "stderr"
        lines = h.stderr.getvalue().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["evidence"] == "stderr" and record["kind"] == "decision_evaluated"
        assert record["source_key"].startswith("call:")

    def test_snapshot_budget_exceeded_is_a_dependency_failure(self, tmp_path):
        h = harness(tmp_path, cfg=config(tmp_path, decision_budget_seconds=0.05))

        async def slow(query):
            await asyncio.sleep(1)

        h.snapshots.read_snapshot = slow
        assert code(decide(h)) == "MINT-DEPENDENCY-DB"


class TestStateStage:
    def test_anonymous_is_blocked(self, tmp_path):
        h = harness(tmp_path)
        anonymous = user_principal(user_id=None, team_id=None)
        outcome = decide(h, request(anonymous))
        assert code(outcome) == "MINT-ANONYMOUS"

    def test_a_key_without_user_or_team_is_anonymous(self, tmp_path):
        anonymous = user_principal(user_id=None, team_id=None)
        assert anonymous.principal_type.value == "anonymous"

    def test_no_binding_and_no_default_org_is_an_organization_boundary_stop(self, tmp_path):
        h = harness(tmp_path, snapshot(bindings={}))
        assert code(decide(h)) == "MINT-ORG-BOUNDARY"

    def test_a_closed_organization_is_an_organization_boundary_stop(self, tmp_path):
        h = harness(tmp_path, snapshot(org_status={"org1": OrgStatus.CLOSED}))
        assert code(decide(h)) == "MINT-ORG-BOUNDARY"

    def test_default_org_applies_when_no_binding_exists(self, tmp_path):
        snap = snapshot(
            bindings={},
            settings=SettingsRow(default_org_id="org1", settings_version=1),
        )
        outcome = decide(harness(tmp_path, snap))
        assert outcome.allowed
        assert outcome.snapshot.principal.org_source.value == "default"

    def test_user_binding_is_used_when_the_key_has_no_team(self, tmp_path):
        snap = snapshot(
            bindings={(SubjectType.USER, "u1"): "org1"},
            approvals=(approval(scope_type="user", scope_id="u1"),),
        )
        principal = user_principal(team_id=None)
        outcome = decide(harness(tmp_path, snap), request(principal))
        assert outcome.allowed
        assert outcome.snapshot.principal.org_source.value == "user"

    def test_a_team_binding_wins_over_a_user_binding(self, tmp_path):
        snap = snapshot(
            bindings={(SubjectType.TEAM, "t1"): "org1", (SubjectType.USER, "u1"): "org2"},
            org_status={"org1": OrgStatus.ACTIVE, "org2": OrgStatus.ACTIVE},
        )
        outcome = decide(harness(tmp_path, snap))
        assert outcome.snapshot.principal.org_id == "org1"

    def test_only_out_of_organization_approvals_is_a_boundary_stop(self, tmp_path):
        snap = snapshot(approvals=(approval(org_id="org2"),))
        assert code(decide(harness(tmp_path, snap))) == "MINT-ORG-BOUNDARY"

    def test_an_in_organization_approval_beats_an_out_of_organization_one(self, tmp_path):
        snap = snapshot(approvals=(approval(org_id="org2"), approval(id="a2")))
        outcome = decide(harness(tmp_path, snap))
        assert outcome.allowed and outcome.snapshot.selected_approval_id == "a2"

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            ("rejected", "MINT-SERVER-REJECTED"),
            ("suspended", "MINT-SERVER-SUSPENDED"),
            ("terminating", "MINT-SERVER-TERMINATED"),
            ("terminated", "MINT-SERVER-TERMINATED"),
        ],
    )
    def test_negative_server_states_stop_in_every_mode(self, tmp_path, status, expected):
        snap = snapshot(
            server=server_row(status=status),
            settings=SettingsRow(mode=Mode.OBSERVE, settings_version=1),
        )
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE))
        assert code(decide(h)) == expected

    @pytest.mark.parametrize("status", ["pending", "validating", "awaiting_approval"])
    def test_unapproved_server_is_a_finding_that_enforce_mode_blocks(self, tmp_path, status):
        h = harness(tmp_path, snapshot(server=server_row(status=status)))
        outcome = decide(h)
        assert code(outcome) == "MINT-SERVER-NOT-APPROVED"
        assert outcome.snapshot.stop is None
        assert outcome.snapshot.findings[0].reason_code == "SERVER_NOT_APPROVED"

    def test_unregistered_server_is_a_finding_and_the_pipeline_continues(self, tmp_path):
        snap = snapshot(server=None, approvals=())
        calls: list = []
        h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
        outcome = decide(h)
        assert code(outcome) == "MINT-SERVER-UNREGISTERED"
        reasons = [f.reason_code for f in outcome.snapshot.findings]
        assert reasons == ["SERVER_UNREGISTERED", "APPROVAL_ABSENT"]
        assert len(calls) == 1
        assert calls[0]["server"] == {
            "id": "srv-1",
            "status": "unregistered",
            "transport": "http",
            "auth_type": "none",
            "provider_allowed": False,
            "auth_server_allowed": False,
            "contract_status": "none",
        }

    def test_unregistered_server_is_allowed_in_observe_mode_with_findings_recorded(self, tmp_path):
        snap = snapshot(server=None, approvals=(), settings=SettingsRow(mode=Mode.OBSERVE))
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE))
        outcome = decide(h)
        assert outcome.allowed
        assert outcome.snapshot.evaluated_decision is Action.BLOCK
        assert outcome.snapshot.enforced_action is Action.ALLOW

    def test_the_environment_ceiling_keeps_enforce_over_a_stored_observe(self, tmp_path):
        snap = snapshot(server=None, approvals=(), settings=SettingsRow(mode=Mode.OBSERVE))
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.ENFORCE))
        outcome = decide(h)
        assert not outcome.allowed and outcome.snapshot.mode is Mode.ENFORCE

    @pytest.mark.parametrize(
        "field", ["url_sha256", "transport", "auth_type"], ids=["url", "transport", "auth"]
    )
    def test_any_contract_value_difference_is_an_identity_mismatch(self, tmp_path, field):
        other = {
            "url_sha256": url_sha256("https://other/"),
            "transport": "sse",
            "auth_type": "oauth2",
        }
        snap = snapshot(server=replace(server_row(), **{field: other[field]}))
        assert code(decide(harness(tmp_path, snap))) == "MINT-SERVER-IDENTITY-MISMATCH"

    def test_identity_mismatch_is_not_converted_in_observe_mode(self, tmp_path):
        snap = snapshot(server=server_row(transport="sse"), settings=SettingsRow(mode=Mode.OBSERVE))
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE))
        assert code(decide(h)) == "MINT-SERVER-IDENTITY-MISMATCH"


class TestDenialAndApproval:
    @pytest.mark.parametrize(
        "row",
        [
            denial(scope_type="team", scope_id="t1"),
            denial(scope_type="user", scope_id="u1"),
            denial(scope_type="key", scope_id="k" * 64),
            denial(scope_type="org", scope_id="org1"),
            denial(scope_type="server", scope_id="srv-1", server_id="srv-1"),
            denial(tools=("search", "other")),
            denial(org_id="org1"),
            denial(server_id="srv-1"),
        ],
    )
    def test_matching_denials_stop_the_call(self, tmp_path, row):
        assert code(decide(harness(tmp_path, snapshot(denials=(row,))))) == "MINT-DENIED"

    @pytest.mark.parametrize(
        "row",
        [
            denial(scope_type="team", scope_id="t2"),
            denial(tools=("other",)),
            denial(org_id="org2"),
            denial(server_id="srv-2"),
            denial(scope_type="org", scope_id="org2"),
        ],
    )
    def test_non_matching_denials_do_not_apply(self, tmp_path, row):
        assert decide(harness(tmp_path, snapshot(denials=(row,)))).allowed

    def test_a_denial_beats_a_valid_approval_in_observe_mode(self, tmp_path):
        snap = snapshot(denials=(denial(),), settings=SettingsRow(mode=Mode.OBSERVE))
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE))
        assert code(decide(h)) == "MINT-DENIED"

    def test_a_terminated_relation_stops_even_when_another_relation_has_a_valid_approval(
        self, tmp_path
    ):
        snap = snapshot(
            approvals=(
                approval(id="a-old", relation_id="r-old", scope_type="user", scope_id="u1"),
                approval(id="a-new", relation_id="r1"),
            ),
            relations={
                "r1": RelationRow("r1", "active"),
                "r-old": RelationRow("r-old", "terminating"),
            },
        )
        outcome = decide(harness(tmp_path, snap))
        assert code(outcome) == "MINT-RELATION-TERMINATED"

    def test_a_terminated_relation_stops_in_observe_mode(self, tmp_path):
        snap = snapshot(
            relations={"r1": RelationRow("r1", "terminated")},
            settings=SettingsRow(mode=Mode.OBSERVE),
        )
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE))
        assert code(decide(h)) == "MINT-RELATION-TERMINATED"

    @pytest.mark.parametrize(
        "entry",
        [
            allowlist(status="lifted"),
            allowlist(status="expired"),
            allowlist(valid_until=NOW),
            allowlist(valid_from=NOW + timedelta(seconds=1)),
            None,
        ],
        ids=["lifted", "expired-status", "ended", "not-yet-valid", "missing"],
    )
    def test_an_unusable_basis_allowlist_stops_the_call(self, tmp_path, entry):
        server = server_row(basis_allowlist_ids=("al1",))
        snap = snapshot(server=server, allowlists={"al1": entry} if entry else {})
        assert code(decide(harness(tmp_path, snap))) == "MINT-ALLOWLIST-EXPIRED"

    def test_a_usable_basis_allowlist_passes_and_fills_the_policy_input(self, tmp_path):
        server = server_row(basis_allowlist_ids=("al1",))
        calls: list = []
        h = harness(
            tmp_path,
            snapshot(server=server, allowlists={"al1": allowlist()}),
            evaluate=evaluator(calls=calls),
        )
        assert decide(h).allowed
        assert calls[0]["server"]["provider_allowed"] is True
        assert calls[0]["server"]["auth_server_allowed"] is False

    def test_no_matching_approval_is_a_finding(self, tmp_path):
        outcome = decide(harness(tmp_path, snapshot(approvals=())))
        assert code(outcome) == "MINT-APPROVAL-ABSENT"
        assert outcome.snapshot.stop is None

    def test_a_revoked_only_history_stops(self, tmp_path):
        snap = snapshot(approvals=(approval(status="revoked"),))
        assert code(decide(harness(tmp_path, snap))) == "MINT-APPROVAL-REVOKED"

    def test_a_revoked_and_expired_history_reports_revocation(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a1", status="revoked"),
                approval(id="a2", valid_until=NOW - timedelta(seconds=1)),
            )
        )
        assert code(decide(harness(tmp_path, snap))) == "MINT-APPROVAL-REVOKED"

    @pytest.mark.parametrize(
        "row",
        [
            approval(valid_until=NOW),
            approval(valid_until=NOW - timedelta(days=1)),
            approval(status="expired"),
        ],
        ids=["boundary", "past", "stored-status"],
    )
    def test_an_expired_only_history_stops(self, tmp_path, row):
        assert (
            code(decide(harness(tmp_path, snapshot(approvals=(row,))))) == "MINT-APPROVAL-EXPIRED"
        )

    def test_a_not_yet_valid_approval_is_not_a_grant_and_not_a_history(self, tmp_path):
        row = approval(valid_from=NOW + timedelta(seconds=1))
        outcome = decide(harness(tmp_path, snapshot(approvals=(row,))))
        assert code(outcome) == "MINT-APPROVAL-ABSENT" and outcome.snapshot.stop is None

    def test_valid_from_boundary_is_inclusive(self, tmp_path):
        row = approval(valid_from=NOW)
        assert decide(harness(tmp_path, snapshot(approvals=(row,)))).allowed

    def test_history_stops_in_observe_mode_but_absence_is_observable(self, tmp_path):
        cfg = config(tmp_path, mode_ceiling=Mode.OBSERVE)
        observe = SettingsRow(mode=Mode.OBSERVE)
        revoked = snapshot(approvals=(approval(status="revoked"),), settings=observe)
        assert code(decide(harness(tmp_path, revoked, cfg=cfg))) == "MINT-APPROVAL-REVOKED"
        absent = snapshot(approvals=(), settings=observe)
        assert decide(harness(tmp_path, absent, cfg=cfg)).allowed

    @pytest.mark.parametrize("mode", [Mode.ENFORCE, Mode.OBSERVE])
    def test_a_revocation_is_not_hidden_by_a_not_started_approval(self, tmp_path, mode):
        snap = snapshot(
            approvals=(
                approval(id="a1", status="revoked"),
                approval(id="a2", valid_from=NOW + timedelta(hours=1)),
            ),
            settings=SettingsRow(mode=mode),
        )
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=mode))
        outcome = decide(h)
        assert code(outcome) == "MINT-APPROVAL-REVOKED" and not outcome.allowed
        assert outcome.snapshot.stop is not None

    def test_not_started_and_pending_approvals_alone_are_only_an_absence(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a1", valid_from=NOW + timedelta(hours=1)),
                approval(id="a2", status="pending"),
            )
        )
        outcome = decide(harness(tmp_path, snap))
        assert code(outcome) == "MINT-APPROVAL-ABSENT" and outcome.snapshot.stop is None

    @pytest.mark.parametrize("mode", [Mode.ENFORCE, Mode.OBSERVE])
    def test_an_expiry_is_not_hidden_by_a_pending_approval(self, tmp_path, mode):
        snap = snapshot(
            approvals=(
                approval(id="a1", valid_until=NOW - timedelta(seconds=1)),
                approval(id="a2", status="pending"),
            ),
            settings=SettingsRow(mode=mode),
        )
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=mode))
        outcome = decide(h)
        assert code(outcome) == "MINT-APPROVAL-EXPIRED" and outcome.snapshot.stop is not None

    def test_revocation_outranks_expiry_next_to_not_started_and_pending_approvals(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a1", valid_until=NOW - timedelta(days=1)),
                approval(id="a2", status="revoked"),
                approval(id="a3", valid_from=NOW + timedelta(days=1)),
                approval(id="a4", status="pending"),
            )
        )
        assert code(decide(harness(tmp_path, snap))) == "MINT-APPROVAL-REVOKED"

    def test_a_tool_outside_every_valid_approval_is_a_finding(self, tmp_path):
        snap = snapshot(approvals=(approval(tools=("other",)),))
        outcome = decide(harness(tmp_path, snap))
        assert code(outcome) == "MINT-TOOL-NOT-IN-APPROVAL" and outcome.snapshot.stop is None

    def test_the_narrowest_scope_is_selected(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a-org", scope_type="org", scope_id="org1"),
                approval(id="a-team", scope_type="team", scope_id="t1"),
                approval(id="a-user", scope_type="user", scope_id="u1"),
                approval(id="a-key", scope_type="key", scope_id="k" * 64),
            )
        )
        assert decide(harness(tmp_path, snap)).snapshot.selected_approval_id == "a-key"

    def test_within_a_scope_the_latest_valid_from_wins_then_the_id(self, tmp_path):
        older = approval(id="a-9", valid_from=NOW - timedelta(days=2))
        newer_b = approval(id="a-2", valid_from=NOW - timedelta(hours=1))
        newer_a = approval(id="a-1", valid_from=NOW - timedelta(hours=1))
        snap = snapshot(approvals=(older, newer_b, newer_a))
        assert decide(harness(tmp_path, snap)).snapshot.selected_approval_id == "a-1"

    def test_a_broader_approval_allows_when_the_narrower_one_is_revoked(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a-user", scope_type="user", scope_id="u1", status="revoked"),
                approval(id="a-team"),
            )
        )
        outcome = decide(harness(tmp_path, snap))
        assert outcome.allowed and outcome.snapshot.selected_approval_id == "a-team"

    def test_a_narrower_scope_covers_a_broader_one(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a-key", scope_type="key", scope_id="k" * 64, tools=("a",)),
                approval(id="a-team", tools=("a", "b")),
            )
        )
        calls: list = []
        h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
        outcome = decide(h, request(tool_name="b"))
        assert code(outcome) == "MINT-TOOL-NOT-IN-APPROVAL"
        assert outcome.snapshot.stop is None and outcome.snapshot.selected_approval_id is None
        assert calls[0]["approval"] == {"present": False}
        listed = decide(harness(tmp_path, snap), request(tool_name="a"))
        assert listed.snapshot.selected_approval_id == "a-key"

    def test_the_broader_approval_applies_once_the_narrower_one_is_revoked(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(
                    id="a-key", scope_type="key", scope_id="k" * 64, tools=("a",), status="revoked"
                ),
                approval(id="a-team", tools=("a", "b")),
            )
        )
        outcome = decide(harness(tmp_path, snap), request(tool_name="b"))
        assert outcome.allowed and outcome.snapshot.selected_approval_id == "a-team"

    @pytest.mark.parametrize(
        "narrow",
        [
            {"status": "revoked"},
            {"valid_until": NOW - timedelta(seconds=1)},
            {"valid_from": NOW + timedelta(seconds=1)},
        ],
        ids=["revoked", "expired", "not-started"],
    )
    def test_an_invalid_narrower_approval_does_not_cover_the_broader_one(self, tmp_path, narrow):
        snap = snapshot(
            approvals=(
                approval(id="a-key", scope_type="key", scope_id="k" * 64, tools=("a",), **narrow),
                approval(id="a-team", tools=("a", "b")),
            )
        )
        outcome = decide(harness(tmp_path, snap), request(tool_name="b"))
        assert outcome.allowed and outcome.snapshot.selected_approval_id == "a-team"

    def test_a_broader_approval_applies_when_there_is_no_narrower_one(self, tmp_path):
        snap = snapshot(approvals=(approval(id="a-team", tools=("a", "b")),))
        outcome = decide(harness(tmp_path, snap), request(tool_name="b"))
        assert outcome.allowed and outcome.snapshot.selected_approval_id == "a-team"

    def test_within_one_scope_the_approval_that_lists_the_tool_is_chosen(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a-new", tools=("other",), valid_from=NOW - timedelta(hours=1)),
                approval(id="a-old", tools=("search",), valid_from=NOW - timedelta(days=5)),
            )
        )
        outcome = decide(harness(tmp_path, snap))
        assert outcome.allowed and outcome.snapshot.selected_approval_id == "a-old"

    def test_the_org_scope_is_consulted_only_when_nothing_narrower_is_valid(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a-org", scope_type="org", scope_id="org1", tools=("a", "b")),
                approval(id="a-user", scope_type="user", scope_id="u1", tools=("a",)),
            )
        )
        blocked = decide(harness(tmp_path, snap), request(tool_name="b"))
        assert code(blocked) == "MINT-TOOL-NOT-IN-APPROVAL"
        only_org = snapshot(approvals=(approval(id="a-org", scope_type="org", scope_id="org1"),))
        assert decide(harness(tmp_path, only_org)).snapshot.selected_approval_id == "a-org"

    def test_observe_mode_converts_the_missing_tool_finding_of_a_covering_scope(self, tmp_path):
        snap = snapshot(
            approvals=(
                approval(id="a-key", scope_type="key", scope_id="k" * 64, tools=("a",)),
                approval(id="a-team", tools=("a", "b")),
            ),
            settings=SettingsRow(mode=Mode.OBSERVE),
        )
        h = harness(tmp_path, snap, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE))
        outcome = decide(h, request(tool_name="b"))
        assert outcome.allowed and outcome.snapshot.selected_approval_id is None

    def test_approval_for_another_principal_scope_does_not_match(self, tmp_path):
        snap = snapshot(approvals=(approval(scope_id="t2"),))
        assert code(decide(harness(tmp_path, snap))) == "MINT-APPROVAL-ABSENT"

    def test_a_team_key_matches_key_and_team_scopes_but_not_user_scope(self, tmp_path):
        principal = user_principal(user_id=None)
        snap = snapshot(approvals=(approval(scope_type="user", scope_id="u1"),))
        assert code(decide(harness(tmp_path, snap), request(principal))) == "MINT-APPROVAL-ABSENT"
        assert decide(harness(tmp_path), request(principal)).allowed

    def test_a_service_account_marker_follows_the_team_key_rules(self, tmp_path):
        principal = user_principal(user_id=None, metadata={"service_account_id": "bot"})
        assert principal.principal_type.value == "service_account"
        assert decide(harness(tmp_path), request(principal)).allowed


class TestPolicyStage:
    def test_a_block_decision_is_a_policy_finding_that_enforce_mode_blocks(self, tmp_path):
        evaluate = evaluator("Block", policy_ids=("R3",), observable=True)
        outcome = decide(harness(tmp_path, evaluate=evaluate))
        assert code(outcome) == "MINT-POLICY-DETECT-R3"
        assert outcome.snapshot.stop is None
        assert outcome.snapshot.policy_decision.value == "Block"
        assert outcome.snapshot.policy_ids == ("R3",)

    def test_observe_mode_converts_only_policies_that_are_observable_and_selected(self, tmp_path):
        cfg = config(tmp_path, mode_ceiling=Mode.OBSERVE)
        for ids, observable, allowed in [
            (frozenset({"R3"}), True, True),
            (frozenset({"R3"}), False, False),
            (frozenset(), True, False),
            (frozenset({"R1"}), True, False),
        ]:
            settings = SettingsRow(
                mode=Mode.OBSERVE,
                observable_reasons=OBSERVATION_CANDIDATES,
                observable_policy_ids=ids,
            )
            evaluate = evaluator("Block", policy_ids=("R3",), observable=observable)
            h = harness(tmp_path, snapshot(settings=settings), evaluate=evaluate, cfg=cfg)
            assert decide(h).allowed is allowed, (ids, observable)

    def test_an_observe_reason_removed_from_the_settings_is_blocked(self, tmp_path):
        settings = SettingsRow(
            mode=Mode.OBSERVE, observable_reasons=frozenset({Reason.SERVER_UNREGISTERED})
        )
        h = harness(
            tmp_path,
            snapshot(approvals=(), settings=settings),
            cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE),
        )
        assert code(decide(h)) == "MINT-APPROVAL-ABSENT"

    def test_the_error_code_is_the_first_finding_that_was_not_converted(self, tmp_path):
        settings = SettingsRow(
            mode=Mode.OBSERVE,
            observable_reasons=frozenset({Reason.APPROVAL_ABSENT, Reason.POLICY_DETECT}),
            observable_policy_ids=frozenset(),
        )
        snap = snapshot(server=None, approvals=(), settings=settings)
        evaluate = evaluator("Block", policy_ids=("R1",), observable=True)
        h = harness(
            tmp_path, snap, evaluate=evaluate, cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE)
        )
        outcome = decide(h)
        reasons = [f.reason_code for f in outcome.snapshot.findings]
        assert reasons == ["SERVER_UNREGISTERED", "APPROVAL_ABSENT", "POLICY_DETECT_R1"]
        assert code(outcome) == "MINT-SERVER-UNREGISTERED"

    def test_a_stop_reason_wins_over_earlier_findings(self, tmp_path):
        snap = snapshot(server=None, approvals=(), denials=(denial(),))
        outcome = decide(harness(tmp_path, snap))
        assert code(outcome) == "MINT-DENIED"
        assert [f.reason_code for f in outcome.snapshot.findings] == ["SERVER_UNREGISTERED"]

    def test_blocking_reason_skips_converted_findings(self):
        findings = (
            StageResult.finding(Reason.APPROVAL_ABSENT),
            StageResult.finding(Reason.TOOL_NOT_IN_APPROVAL),
        )
        from mint_litellm.types.decision import conclude

        observation = ObservationSettings(observable_reasons=frozenset({Reason.APPROVAL_ABSENT}))
        conclusion = conclude(findings, mode=Mode.OBSERVE, observation=observation)
        reason = blocking_reason(
            conclusion, mode=Mode.OBSERVE, observation=observation, policy_observable=False
        )
        assert reason == "TOOL_NOT_IN_APPROVAL"

    def test_the_policy_decision_is_not_evaluated_when_an_earlier_stage_stops(self, tmp_path):
        calls: list = []
        h = harness(tmp_path, snapshot(denials=(denial(),)), evaluate=evaluator(calls=calls))
        outcome = decide(h)
        assert calls == []
        stages = {e.stage: e for e in outcome.snapshot.stages}
        assert stages[Stage.POLICY].status is StageStatus.SKIPPED
        assert stages[Stage.POLICY].missing_reason == "after_stop"
        assert outcome.snapshot.missing_reasons["policy_decision"] == "policy_not_evaluated"

    def test_the_contract_stage_is_recorded_as_skipped_but_does_not_stop(self, tmp_path):
        outcome = decide(harness(tmp_path))
        entry = next(e for e in outcome.snapshot.stages if e.stage is Stage.CONTRACT)
        assert entry.status is StageStatus.SKIPPED and entry.missing_reason == "unsupported_stage"

    def test_no_active_policy_version_stops(self, tmp_path):
        h = harness(tmp_path, snapshot(policy_version=None))
        assert code(decide(h)) == "MINT-POLICY-VERSION-MISMATCH"

    def test_an_evaluator_answering_for_another_version_stops(self, tmp_path):
        h = harness(tmp_path, evaluate=evaluator(version="pv2"))
        assert code(decide(h)) == "MINT-POLICY-VERSION-MISMATCH"
        h = harness(tmp_path, evaluate=evaluator(bundle="c" * 64))
        assert code(decide(h)) == "MINT-POLICY-VERSION-MISMATCH"

    def test_an_evaluation_failure_is_passed_through(self, tmp_path):
        failure = StageResult.stop(Reason.DEPENDENCY_FAILURE)
        outcome = decide(harness(tmp_path, evaluate=evaluator(failure=failure)))
        assert code(outcome) == "MINT-DEPENDENCY-OPA" and outcome.error.retry_safe is True

    def test_an_evaluator_exception_is_an_opa_dependency_failure(self, tmp_path):
        async def broken(policy_input, **kwargs):
            raise ConnectionError("opa down")

        outcome = decide(harness(tmp_path, evaluate=broken))
        assert code(outcome) == "MINT-DEPENDENCY-OPA"

    def test_an_evaluator_over_budget_is_an_opa_dependency_failure(self, tmp_path):
        async def slow(policy_input, **kwargs):
            await asyncio.sleep(1)

        h = harness(tmp_path, evaluate=slow, cfg=config(tmp_path, decision_budget_seconds=0.05))
        assert code(decide(h)) == "MINT-DEPENDENCY-OPA"

    def test_a_missing_evaluator_is_an_opa_dependency_failure(self, tmp_path):
        assert code(decide(harness(tmp_path, evaluate=None))) == "MINT-DEPENDENCY-OPA"

    def test_missing_policy_inputs_are_a_schema_error(self, tmp_path):
        h = harness(tmp_path, evaluate=evaluator(missing_inputs=("approval",)))
        assert code(decide(h)) == "MINT-SCHEMA-ERROR"

    def test_an_unknown_decision_is_a_schema_error(self, tmp_path):
        assert (
            code(decide(harness(tmp_path, evaluate=evaluator("Restrict")))) == "MINT-SCHEMA-ERROR"
        )

    def test_an_unsupported_obligation_stops_at_the_obligation_stage(self, tmp_path):
        evaluate = evaluator("Allow", obligations=({"type": "redact", "fields": ["a"]},))
        outcome = decide(harness(tmp_path, evaluate=evaluate))
        assert code(outcome) == "MINT-UNSUPPORTED"
        stages = {e.stage: e for e in outcome.snapshot.stages}
        assert stages[Stage.OBLIGATIONS].status is StageStatus.STOP

    def test_an_unexpected_exception_blocks_with_a_schema_error_and_still_records(self, tmp_path):
        snap = snapshot(approvals=(approval(conditions="not a mapping"),))
        h = harness(tmp_path, snap)
        outcome = decide(h)
        assert code(outcome) == "MINT-SCHEMA-ERROR"
        assert outcome.snapshot.stop.detail.startswith("internal ")
        assert len(h.store.of_kind("decision_evaluated")) == 1


class TestObligations:
    REQUIRE = ({"type": "require_call_approval"},)

    def approval_snapshot(self, **override):
        return snapshot(call_approvals=(call_approval(),), **override)

    def test_a_high_risk_decision_requires_a_matching_call_approval(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        outcome = decide(harness(tmp_path, snapshot(), evaluate=evaluate))
        assert code(outcome) == "MINT-CALL-APPROVAL-REQUIRED"
        assert outcome.snapshot.obligation_types[0].value == "require_call_approval"

    def test_a_matching_call_approval_allows_and_is_consumed_with_the_decision(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        h = harness(tmp_path, self.approval_snapshot(), evaluate=evaluate)
        outcome = decide(h)
        assert outcome.allowed
        assert len(h.store.consumed) == 1
        consumed = h.store.consumed[0]
        assert str(consumed.call_approval_id) == "00000000-0000-0000-0000-0000000000c1"
        assert consumed.invocation_id == outcome.snapshot.invocation_id
        assert consumed.state_version == 2
        assert outcome.snapshot.consumed_call_approval_id == str(consumed.call_approval_id)
        assert len(h.store.of_kind("decision_evaluated")) == 1

    def test_a_blocked_call_never_consumes_the_call_approval(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        snap = self.approval_snapshot(denials=(denial(),))
        h = harness(tmp_path, snap, evaluate=evaluate)
        assert code(decide(h)) == "MINT-DENIED"
        assert h.store.consumed == []

    def test_a_finding_that_blocks_does_not_consume_either(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        snap = self.approval_snapshot(approvals=())
        h = harness(tmp_path, snap, evaluate=evaluate)
        assert not decide(h).allowed
        assert h.store.consumed == []

    @pytest.mark.parametrize(
        "row",
        [
            call_approval(tool="other"),
            call_approval(args_fp="0" * 64),
            call_approval(principal_id="u2"),
            call_approval(principal_type="team_key"),
            call_approval(server_id="srv-2"),
            call_approval(org_id="org2"),
            call_approval(fp_key_version=2),
            call_approval(contract_version="v1"),
            call_approval(contract_id="c1"),
            call_approval(expires_at=NOW),
        ],
        ids=[
            "tool",
            "args",
            "principal",
            "principal-type",
            "server",
            "org",
            "key-version",
            "contract",
            "unmanaged-server-bound",
            "expired",
        ],
    )
    def test_a_call_approval_that_differs_in_any_condition_does_not_match(self, tmp_path, row):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        h = harness(tmp_path, snapshot(call_approvals=(row,)), evaluate=evaluate)
        assert code(decide(h)) == "MINT-CALL-APPROVAL-REQUIRED"

    def managed_snapshot(self, bound, *, contract="c1", **override):
        contracts = () if contract is None else (
            ToolContractRow(contract, "server", "search", "none", 1, "high"),)
        managed = server_row(contract_status="managed", approved_contracts=1, last_observed_at=NOW)
        return snapshot(
            server=managed, tool_contracts=contracts,
            call_approvals=(call_approval(contract_id=bound),), **override,
        )

    def test_a_call_approval_bound_to_the_current_contract_is_consumed_with_it(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        h = harness(tmp_path, self.managed_snapshot("c1"), evaluate=evaluate)
        assert decide(h).allowed
        assert h.store.consumed[0].contract_id == "c1"

    @pytest.mark.parametrize(
        ("bound", "contract"), [("c0", "c1"), (None, "c1"), ("c1", None), (None, None)],
        ids=["replaced", "unbound", "no-contract", "unbound-no-contract"],
    )
    def test_a_call_approval_not_bound_to_the_current_contract_does_not_match(
        self, tmp_path, bound, contract
    ):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        snap = self.managed_snapshot(bound, contract=contract)
        h = harness(tmp_path, snap, evaluate=evaluate)
        assert code(decide(h)) == "MINT-CALL-APPROVAL-REQUIRED"
        assert h.store.consumed == []

    def test_a_call_approval_from_another_policy_version_is_stale(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        snap = snapshot(call_approvals=(call_approval(policy_version_id="pv0"),))
        assert (
            code(decide(harness(tmp_path, snap, evaluate=evaluate))) == "MINT-CALL-APPROVAL-STALE"
        )

    def test_without_a_fingerprint_key_the_call_approval_cannot_match(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        cfg = config(tmp_path, fingerprint_key=None)
        h = harness(tmp_path, self.approval_snapshot(), evaluate=evaluate, cfg=cfg)
        assert code(decide(h)) == "MINT-CALL-APPROVAL-REQUIRED"

    def test_the_argument_fingerprint_is_stable_under_key_order(self):
        a = argument_fingerprint({"a": 1, "b": {"y": [1, 2], "x": "한글"}}, FP_KEY)
        b = argument_fingerprint({"b": {"x": "한글", "y": [1, 2]}, "a": 1}, FP_KEY)
        assert a == b and len(a) == 64
        assert a != argument_fingerprint({"a": 1, "b": {"y": [2, 1], "x": "한글"}}, FP_KEY)
        assert a != argument_fingerprint(
            {"a": 1, "b": {"y": [1, 2], "x": "한글"}}, bytes(range(1, 33))
        )

    def test_a_lost_consumption_blocks_and_records_the_block_without_consuming(self, tmp_path):
        evaluate = evaluator("RequireApproval", policy_ids=("R2",))
        h = harness(tmp_path, self.approval_snapshot(), evaluate=evaluate)
        h.store.lose_consumption = True
        outcome = decide(h)
        assert code(outcome) == "MINT-CALL-APPROVAL-REQUIRED"
        assert h.store.consumed == []
        events = h.store.of_kind("decision_evaluated")
        assert len(events) == 1 and events[0].payload["enforced_action"] == "block"
        assert outcome.snapshot.consumed_call_approval_id is None

    def converted_block(self, tmp_path, policy_id, *, snap=None, mode=Mode.OBSERVE):
        """Block이 관측 모드에서 허용으로 전환될 수 있고 호출별 승인·동의 의무가 함께 붙은 결과."""
        settings = SettingsRow(
            mode=mode,
            observable_reasons=OBSERVATION_CANDIDATES,
            observable_policy_ids=frozenset({policy_id}),
        )
        evaluate = evaluator(
            "Block",
            policy_ids=(policy_id,),
            observable=True,
            obligations=(
                {"type": "require_call_approval"},
                {"type": "require_consent", "purpose": "support"},
            ),
        )
        if snap is None:
            snap = snapshot(
                call_approvals=(call_approval(),), consents=(consent(),), settings=settings
            )
        else:
            snap = replace(snap, settings=settings)
        return harness(tmp_path, snap, evaluate=evaluate, cfg=config(tmp_path, mode_ceiling=mode))

    @pytest.mark.parametrize("policy_id", ["R3", "R1"])
    def test_a_converted_block_is_allowed_only_with_the_obligations_met(self, tmp_path, policy_id):
        h = self.converted_block(tmp_path, policy_id)
        outcome = decide(h)
        assert outcome.allowed and len(h.store.consumed) == 1
        assert [f.reason_code for f in outcome.snapshot.findings] == [f"POLICY_DETECT_{policy_id}"]
        assert outcome.snapshot.evaluated_decision is Action.BLOCK
        assert outcome.snapshot.enforced_action is Action.ALLOW
        assert [o.value for o in outcome.snapshot.obligation_types] == [
            "require_call_approval",
            "require_consent",
        ]

    @pytest.mark.parametrize("policy_id", ["R3", "R1"])
    def test_a_converted_block_without_a_call_approval_still_requires_one(
        self, tmp_path, policy_id
    ):
        snap = snapshot(consents=(consent(),))
        h = self.converted_block(tmp_path, policy_id, snap=snap)
        outcome = decide(h)
        assert code(outcome) == "MINT-CALL-APPROVAL-REQUIRED" and not outcome.allowed
        assert outcome.snapshot.stop.reason_code == "CALL_APPROVAL_REQUIRED"
        assert [f.reason_code for f in outcome.snapshot.findings] == [f"POLICY_DETECT_{policy_id}"]
        assert h.store.consumed == []

    def test_a_converted_block_with_a_stale_call_approval_is_blocked(self, tmp_path):
        snap = snapshot(
            call_approvals=(call_approval(policy_version_id="pv0"),), consents=(consent(),)
        )
        outcome = decide(self.converted_block(tmp_path, "R3", snap=snap))
        assert code(outcome) == "MINT-CALL-APPROVAL-STALE" and not outcome.allowed

    def test_a_converted_block_without_consent_is_blocked_and_consumes_nothing(self, tmp_path):
        snap = snapshot(call_approvals=(call_approval(),))
        h = self.converted_block(tmp_path, "R3", snap=snap)
        assert code(decide(h)) == "MINT-CONSENT-REQUIRED"
        assert h.store.consumed == []

    def test_an_unconverted_block_reports_the_obligation_stop_first(self, tmp_path):
        snap = snapshot(consents=(consent(),))
        h = self.converted_block(tmp_path, "R3", snap=snap, mode=Mode.ENFORCE)
        outcome = decide(h)
        assert code(outcome) == "MINT-CALL-APPROVAL-REQUIRED"
        assert [f.reason_code for f in outcome.snapshot.findings] == ["POLICY_DETECT_R3"]

    def test_consent_obligation_states(self, tmp_path):
        evaluate = evaluator(
            "Allow", obligations=({"type": "require_consent", "purpose": "support"},)
        )
        cases = [
            ((), "MINT-CONSENT-REQUIRED"),
            ((consent(valid_until=NOW),), "MINT-CONSENT-EXPIRED"),
            ((consent(revoked_at=NOW - timedelta(hours=1)),), "MINT-CONSENT-REVOKED"),
            ((consent(granted_at=NOW + timedelta(hours=1)),), "MINT-CONSENT-EXPIRED"),
            ((consent(purpose="other"),), "MINT-CONSENT-REQUIRED"),
            ((consent(org_id="org2"),), "MINT-CONSENT-REQUIRED"),
            ((consent(),), None),
        ]
        for rows, expected in cases:
            h = harness(tmp_path, snapshot(consents=rows), evaluate=evaluate)
            outcome = decide(h)
            assert (None if outcome.allowed else code(outcome)) == expected, rows

    def test_consent_cannot_be_granted_to_a_team_key(self, tmp_path):
        evaluate = evaluator(
            "Allow", obligations=({"type": "require_consent", "purpose": "support"},)
        )
        principal = user_principal(user_id=None)
        h = harness(tmp_path, snapshot(consents=(consent(),)), evaluate=evaluate)
        assert code(decide(h, request(principal))) == "MINT-CONSENT-REQUIRED"

    def test_a_revoked_consent_is_not_renewed_by_an_older_live_one(self, tmp_path):
        evaluate = evaluator(
            "Allow", obligations=({"type": "require_consent", "purpose": "support"},)
        )
        rows = (consent(id="c1"), consent(id="c2", revoked_at=NOW - timedelta(hours=1)))
        outcome = decide(harness(tmp_path, snapshot(consents=rows), evaluate=evaluate))
        assert outcome.allowed

    def test_conflicting_consent_purposes_are_unsupported(self, tmp_path):
        obligations = (
            {"type": "require_consent", "purpose": "a"},
            {"type": "require_consent", "purpose": "b"},
        )
        outcome = decide(harness(tmp_path, evaluate=evaluator("Allow", obligations=obligations)))
        assert code(outcome) == "MINT-UNSUPPORTED"

    def test_alert_obligation_is_recorded_by_type_only(self, tmp_path):
        evaluate = evaluator("Alert", obligations=({"type": "alert", "severity": "high"},))
        outcome = decide(harness(tmp_path, evaluate=evaluate))
        assert outcome.allowed
        assert [t.value for t in outcome.snapshot.obligation_types] == ["alert"]
        assert "high" not in json.dumps(outcome.snapshot.model_dump(mode="json"))


CONSENT_OBLIGATION = evaluator(
    "Allow", obligations=({"type": "require_consent", "purpose": "support"},)
)
CALL_APPROVAL_OBLIGATION = evaluator("RequireApproval", policy_ids=("R2",))
ONE_TICK = timedelta(microseconds=1)


def window_case(kind: str, *, start: datetime | None = None, end: datetime | None = None):
    """유효 기간이 있는 근거 하나를 시작·끝 시각으로 바꾼 스냅숏과 정책 결과 대역."""
    fields = {k: v for k, v in (("valid_from", start), ("valid_until", end)) if v is not None}
    if kind == "approval":
        return snapshot(approvals=(approval(**fields),)), evaluator()
    if kind == "allowlist":
        server = server_row(basis_allowlist_ids=("al1",))
        return snapshot(server=server, allowlists={"al1": allowlist(**fields)}), evaluator()
    if kind == "consent":
        fields = {("granted_at" if k == "valid_from" else k): v for k, v in fields.items()}
        return snapshot(consents=(consent(**fields),)), CONSENT_OBLIGATION
    return snapshot(call_approvals=(call_approval(expires_at=end),)), CALL_APPROVAL_OBLIGATION


class TestValidityWindow:
    """모든 유효 기간은 시작 시각을 포함하고 끝 시각은 포함하지 않는다."""

    @pytest.mark.parametrize(
        ("kind", "expected"),
        [
            ("approval", "MINT-APPROVAL-EXPIRED"),
            ("allowlist", "MINT-ALLOWLIST-EXPIRED"),
            ("consent", "MINT-CONSENT-EXPIRED"),
            ("call_approval", "MINT-CALL-APPROVAL-REQUIRED"),
        ],
    )
    def test_at_the_end_instant_the_basis_has_already_expired(self, tmp_path, kind, expected):
        snap, evaluate = window_case(kind, end=NOW)
        assert code(decide(harness(tmp_path, snap, evaluate=evaluate))) == expected

    @pytest.mark.parametrize("kind", ["approval", "allowlist", "consent", "call_approval"])
    def test_one_tick_before_the_end_instant_the_basis_is_valid(self, tmp_path, kind):
        snap, evaluate = window_case(kind, end=NOW + ONE_TICK)
        assert decide(harness(tmp_path, snap, evaluate=evaluate)).allowed

    @pytest.mark.parametrize("kind", ["approval", "allowlist", "consent"])
    def test_at_the_start_instant_the_basis_is_valid(self, tmp_path, kind):
        snap, evaluate = window_case(kind, start=NOW, end=NOW + timedelta(days=1))
        assert decide(harness(tmp_path, snap, evaluate=evaluate)).allowed

    @pytest.mark.parametrize("kind", ["approval", "allowlist", "consent"])
    def test_one_tick_before_the_start_instant_the_basis_is_not_valid_yet(self, tmp_path, kind):
        snap, evaluate = window_case(kind, start=NOW + ONE_TICK, end=NOW + timedelta(days=1))
        assert not decide(harness(tmp_path, snap, evaluate=evaluate)).allowed

    def test_the_expiry_in_the_policy_input_counts_whole_days_left_of_a_valid_approval(
        self, tmp_path
    ):
        calls: list = []
        snap, _ = window_case("approval", end=NOW)
        decide(harness(tmp_path, snap, evaluate=evaluator(calls=calls)))
        assert calls == []
        snap, _ = window_case("approval", end=NOW + ONE_TICK)
        decide(harness(tmp_path, snap, evaluate=evaluator(calls=calls)))
        assert calls[0]["approval"]["expires_in_days"] == 0
        snap, _ = window_case("approval", end=NOW + timedelta(days=2, seconds=1))
        decide(harness(tmp_path, snap, evaluate=evaluator(calls=calls)))
        assert calls[1]["approval"]["expires_in_days"] == 2


class TestCancellation:
    """판정 도중 외부 취소: 사건 한 건을 남기고 취소를 다시 전파한다."""

    @staticmethod
    def hang(h, where):
        entered = asyncio.Event()

        async def wait_forever(*args, **kwargs):
            entered.set()
            await asyncio.sleep(3600)

        if where == "snapshot":
            h.snapshots.read_snapshot = wait_forever
        elif where == "policy":
            h.deps.evaluate = wait_forever
        else:
            commit = h.store.insert_event
            calls = {"n": 0}

            async def first_insert_hangs(event, consume=None):
                calls["n"] += 1
                if calls["n"] == 1:
                    return await wait_forever()
                return await commit(event, consume)

            h.store.insert_event = first_insert_hangs
        return entered

    def cancel_during(self, h, where, req=None):
        entered = self.hang(h, where)

        async def main():
            task = asyncio.ensure_future(evaluate_request(req or request(), h.deps))
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())

    @staticmethod
    def one_cancelled_event(event):
        assert event.kind.value == "decision_evaluated"
        assert event.payload["enforced_action"] == "block"
        assert event.payload["stop"]["reason_code"] == "CANCELLED"
        assert event.payload["consumed_call_approval_id"] is None

    @pytest.mark.parametrize("where", ["snapshot", "policy", "insert"])
    def test_a_cancel_while_waiting_records_one_event_in_the_database(self, tmp_path, where):
        h = harness(tmp_path)
        self.cancel_during(h, where)
        (event,) = h.store.of_kind("decision_evaluated")
        self.one_cancelled_event(event)
        assert buffered(h) == [] and h.stderr.getvalue() == ""
        # 기록이 이미 시작된 뒤의 취소는 같은 키를 쓰지 않고 다음 시도로 남긴다.
        started = where == "insert"
        assert event.attempt_id == (2 if started else 1)
        assert (event.payload["original_decision_ref"] is not None) is started

    @pytest.mark.parametrize("where", ["snapshot", "policy", "insert"])
    def test_a_cancel_with_the_database_down_records_one_event_in_the_buffer(self, tmp_path, where):
        h = harness(tmp_path)
        entered = self.hang(h, where)
        commit = h.store.insert_event

        async def down_after_the_first(event, consume=None):
            if where == "insert" and not entered.is_set():
                return await commit(event, consume)
            if entered.is_set() and where != "insert":
                raise RuntimeError("database down")
            raise RuntimeError("database down")

        if where != "insert":
            h.store.insert_event = down_after_the_first
        else:
            first = h.store.insert_event

            async def hang_then_fail(event, consume=None):
                if not entered.is_set():
                    return await first(event, consume)
                raise RuntimeError("database down")

            h.store.insert_event = hang_then_fail

        async def main():
            task = asyncio.ensure_future(evaluate_request(request(), h.deps))
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())
        assert h.store.events == {}
        (event,) = buffered(h)
        self.one_cancelled_event(event)
        assert h.stderr.getvalue() == ""

    def test_a_cancel_with_neither_database_nor_buffer_goes_to_stderr_once(self, tmp_path):
        h = harness(tmp_path)
        h.store.fail = RuntimeError("database down")
        blocker = tmp_path / "plainfile"
        blocker.write_text("x")
        h.buffer._dir = blocker / "inner"
        self.cancel_during(h, "snapshot")
        (line,) = h.stderr.getvalue().strip().splitlines()
        self.one_cancelled_event(Event.model_validate_json(line))

    def test_an_exhausted_budget_still_writes_the_buffer(self, tmp_path, monkeypatch):
        h = harness(tmp_path)
        entered = self.hang(h, "policy")

        async def main():
            task = asyncio.ensure_future(evaluate_request(request(), h.deps))
            await asyncio.wait_for(entered.wait(), 2)
            monkeypatch.setattr(Deadline, "remaining", lambda self: 0.0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())
        events = list(h.store.events.values()) + buffered(h)
        assert len(events) == 1 and events[0].payload["stop"]["reason_code"] == "CANCELLED"

    def test_a_second_cancel_during_the_record_does_not_lose_it(self, tmp_path):
        h = harness(tmp_path)
        entered = self.hang(h, "snapshot")
        commit = h.store.insert_event

        async def slow_insert(event, consume=None):
            await asyncio.sleep(0.2)
            return await commit(event, consume)

        h.store.insert_event = slow_insert

        async def main():
            task = asyncio.ensure_future(evaluate_request(request(), h.deps))
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.4)

        run(main())
        (event,) = h.store.of_kind("decision_evaluated")
        self.one_cancelled_event(event)

    def test_a_cancel_during_the_audit_failure_write_is_the_attempt_after_it(self, tmp_path):
        h = harness(tmp_path)
        recorder = h.deps.recorder
        commit = h.store.insert_event
        state = {"inserts": 0, "writes": 0, "down": False}
        entered = asyncio.Event()

        async def commits_then_loses_the_response(event, consume=None):
            state["inserts"] += 1
            if state["down"]:
                raise RuntimeError("database down")
            inserted = await commit(event, consume)
            if state["inserts"] == 1:
                state["down"] = True
                raise RuntimeError("connection lost after the commit")
            return inserted

        h.store.insert_event = commits_then_loses_the_response
        write = recorder._write_local

        async def written_but_never_returns(event):
            state["writes"] += 1
            evidence = await write(event)
            if state["writes"] == 1:
                # 쓰기 스레드는 끝났지만 기다리는 쪽은 아직 돌아오지 못한 때
                entered.set()
                await asyncio.sleep(3600)
            return evidence

        recorder._write_local = written_but_never_returns

        async def main():
            task = asyncio.ensure_future(evaluate_request(request(), h.deps))
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            state["down"] = False
            await recorder.replay()

        run(main())
        events = sorted(h.store.of_kind("decision_evaluated"), key=lambda e: e.attempt_id)
        assert [e.attempt_id for e in events] == [1, 2, 3]
        assert events[0].payload["enforced_action"] == "allow"
        assert events[1].payload["stop"]["reason_code"] == "AUDIT_FAILURE"
        assert events[2].payload["stop"]["reason_code"] == "CANCELLED"
        first_ref = events[0].payload["decision_ref"]
        assert events[1].payload["original_decision_ref"] == first_ref
        assert events[2].payload["original_decision_ref"] == first_ref
        assert len({e.source_key for e in events}) == 3 and buffered(h) == []

    def test_a_cancel_after_the_decision_event_was_written_adds_nothing(self, tmp_path):
        h = harness(tmp_path)
        h.store.fail = RuntimeError("database down")
        entered = asyncio.Event()

        async def overflow_report_hangs():
            entered.set()
            await asyncio.sleep(3600)

        h.deps.recorder._report_overflow = overflow_report_hangs

        async def main():
            task = asyncio.ensure_future(evaluate_request(request(), h.deps))
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        run(main())
        (event,) = buffered(h)
        assert event.payload["stop"]["reason_code"] == "AUDIT_FAILURE" and event.attempt_id == 2

    def test_a_cancelled_discovery_is_not_recorded(self, tmp_path):
        h = harness(tmp_path)
        self.cancel_during(h, "snapshot", request(operation=OperationType.RUNTIME_DISCOVERY))
        assert h.store.events == {} and buffered(h) == [] and h.stderr.getvalue() == ""


class FlakySnapshots:
    def __init__(self, snap, failures, error):
        self.snap, self.failures, self.error, self.calls = snap, failures, error, 0

    async def read_snapshot(self, query):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        return self.snap


class TestSnapshotRetry:
    """조회는 읽기 전용이라 일시 오류를 같은 예산 안에서 한 번 다시 읽는다."""

    def decide_with(self, tmp_path, failures, error):
        h = harness(tmp_path)
        h.deps.snapshots = FlakySnapshots(h.snapshots.snap, failures, error)
        return decide(h), h.deps.snapshots

    def test_one_transient_failure_is_absorbed(self, tmp_path):
        outcome, source = self.decide_with(tmp_path, 1, ConnectionError("stale connection"))
        assert outcome.allowed and source.calls == 2

    def test_two_failures_are_a_dependency_failure_after_two_reads(self, tmp_path):
        outcome, source = self.decide_with(tmp_path, 2, ConnectionError("down"))
        assert code(outcome) == "MINT-DEPENDENCY-DB" and source.calls == 2

    def test_a_timeout_is_not_read_again(self, tmp_path):
        outcome, source = self.decide_with(tmp_path, 1, TimeoutError())
        assert code(outcome) == "MINT-DEPENDENCY-DB" and source.calls == 1

    def test_nothing_is_read_again_once_the_budget_is_gone(self, tmp_path, monkeypatch):
        h = harness(tmp_path)
        source = FlakySnapshots(h.snapshots.snap, 5, ConnectionError("down"))
        h.deps.snapshots = source
        monkeypatch.setattr(
            Deadline, "remaining", lambda self: 0.0001 if source.calls == 0 else 0.0
        )
        outcome = decide(h)
        assert code(outcome) == "MINT-DEPENDENCY-DB" and source.calls <= 1


class TestRecording:
    def test_a_database_failure_on_the_allow_path_blocks_with_audit_failure(self, tmp_path):
        h = harness(tmp_path)
        h.store.fail = RuntimeError("write failed")
        outcome = decide(h)
        assert code(outcome) == "MINT-AUDIT-FAILURE"
        assert outcome.evidence.value == "buffer"
        events = buffered(h)
        assert len(events) == 1
        recorded = events[0].payload
        assert (
            recorded["enforced_action"] == "block"
            and recorded["stop"]["reason_code"] == "AUDIT_FAILURE"
        )

    def test_allow_path_with_no_database_and_no_buffer_is_blocked_and_logged_to_stderr(
        self, tmp_path
    ):
        h = harness(tmp_path)
        h.store.fail = RuntimeError("write failed")
        blocker = tmp_path / "plainfile"
        blocker.write_text("x")
        h.buffer._dir = blocker / "inner"
        outcome = decide(h)
        assert code(outcome) == "MINT-AUDIT-FAILURE" and outcome.evidence.value == "stderr"
        lines = h.stderr.getvalue().strip().splitlines()
        assert len(lines) == 1 and json.loads(lines[0])["payload"]["enforced_action"] == "block"

    def test_a_block_path_database_failure_keeps_the_original_reason(self, tmp_path):
        h = harness(tmp_path, snapshot(denials=(denial(),)))
        h.store.fail = RuntimeError("write failed")
        outcome = decide(h)
        assert code(outcome) == "MINT-DENIED" and outcome.evidence.value == "buffer"

    def test_a_block_after_a_commit_with_a_lost_response_is_the_next_attempt_and_survives_replay(
        self, tmp_path
    ):
        h = harness(tmp_path)
        commit = h.store.insert_event
        seen = {"calls": 0}

        async def lose_the_response(event, consume=None):
            seen["calls"] += 1
            inserted = await commit(event, consume)
            if seen["calls"] == 1:
                raise RuntimeError("connection lost after the commit")
            return inserted

        h.store.insert_event = lose_the_response
        outcome = decide(h)
        assert code(outcome) == "MINT-AUDIT-FAILURE" and outcome.evidence.value == "buffer"
        (first,) = h.store.of_kind("decision_evaluated")
        assert first.payload["enforced_action"] == "allow" and first.attempt_id == 1
        (second,) = buffered(h)
        assert second.attempt_id == 2 and second.source_key != first.source_key
        assert second.source_key == f"call:{first.invocation_id}:2:decision_evaluated"

        asyncio.run(h.deps.recorder.replay())
        both = sorted(h.store.of_kind("decision_evaluated"), key=lambda e: e.attempt_id)
        assert [e.payload["enforced_action"] for e in both] == ["allow", "block"]
        assert both[1].payload["stop"]["reason_code"] == "AUDIT_FAILURE"
        assert both[1].payload["original_decision_ref"] == first.payload["decision_ref"]
        assert both[0].payload["original_decision_ref"] is None
        # 호출자가 받은 참조는 최종(차단) 사건을 가리킨다.
        assert outcome.error.reference == both[1].payload["decision_ref"]
        assert outcome.snapshot.attempt_id == 2 and outcome.context["attempt_id"] == 2
        assert buffered(h) == []

    def test_a_listing_decision_with_the_database_down_still_records_the_hide(self, tmp_path):
        h = harness(tmp_path)
        h.store.fail = RuntimeError("write failed")
        outcome = decide(h, request(operation=OperationType.RUNTIME_DISCOVERY))
        assert code(outcome) == "MINT-AUDIT-FAILURE" and outcome.evidence.value == "buffer"
        (event,) = buffered(h)
        assert event.kind.value == "discovery_evaluated" and event.attempt_id == 2
        assert event.payload["stop"]["reason_code"] == "AUDIT_FAILURE"
        assert event.payload["original_decision_ref"] == f"{event.invocation_id}:1"

    def test_a_listing_block_after_a_lost_commit_response_survives_replay(self, tmp_path):
        h = harness(tmp_path)
        commit = h.store.insert_event
        seen = {"calls": 0}

        async def lose_the_response(event, consume=None):
            seen["calls"] += 1
            inserted = await commit(event, consume)
            if seen["calls"] == 1:
                raise RuntimeError("connection lost after the commit")
            return inserted

        h.store.insert_event = lose_the_response
        outcome = decide(h, request(operation=OperationType.RUNTIME_DISCOVERY))
        assert code(outcome) == "MINT-AUDIT-FAILURE"
        (first,) = h.store.of_kind("discovery_evaluated")
        assert first.payload["enforced_action"] == "allow" and first.attempt_id == 1
        asyncio.run(h.deps.recorder.replay())
        both = sorted(h.store.of_kind("discovery_evaluated"), key=lambda e: e.attempt_id)
        assert [e.payload["enforced_action"] for e in both] == ["allow", "block"]
        assert both[1].payload["original_decision_ref"] == first.payload["decision_ref"]
        assert outcome.error.reference == both[1].payload["decision_ref"]
        assert buffered(h) == []

    def test_a_block_path_failure_keeps_the_first_attempt(self, tmp_path):
        h = harness(tmp_path, snapshot(denials=(denial(),)))
        h.store.fail = RuntimeError("write failed")
        outcome = decide(h)
        (event,) = buffered(h)
        assert event.attempt_id == 1 and outcome.snapshot.attempt_id == 1
        assert event.payload["original_decision_ref"] is None

    def test_recording_over_budget_counts_as_a_failure(self, tmp_path):
        h = harness(tmp_path, cfg=config(tmp_path))
        h.deps.recorder._budget = 0.05

        async def slow(event, consume=None):
            await asyncio.sleep(1)

        h.store.insert_event = slow
        outcome = decide(h)
        assert code(outcome) == "MINT-AUDIT-FAILURE" and outcome.evidence.value == "buffer"

    def test_every_path_records_one_decision_event_with_a_unique_source_key(self, tmp_path):
        h = harness(tmp_path)
        for _ in range(3):
            decide(h)
        decide(h, request(user_principal(user_id=None, team_id=None)))
        keys = {e.source_key for e in h.store.of_kind("decision_evaluated")}
        assert len(h.store.of_kind("decision_evaluated")) == 4 == len(keys)


class TestPolicyInput:
    def build(self, **override):
        snap = override.pop("snap", snapshot())
        principal = override.pop("principal", None)
        from mint_litellm.plugin.pipeline import derive_principal

        base = principal or user_principal()
        derived = derive_principal(snap, base)
        selected = override.pop("selected", snap.approvals[0] if snap.approvals else None)
        return build_policy_input(
            snapshot=snap,
            principal=derived,
            resolved=resolved_server(),
            tool="search",
            arguments=override.pop("arguments", {"q": "secret value", "n": 3}),
            selected=selected,
            mode=Mode.ENFORCE,
            operation=OperationType.TOOL_CALL,
            high_risk_tools=frozenset({"b", "a"}),
        )

    def test_the_input_has_exactly_the_contract_keys(self):
        doc = self.build()
        assert set(doc) == {
            "principal",
            "server",
            "tool",
            "arguments",
            "approval",
            "consent",
            "time",
            "settings",
            "mode",
            "operation",
        }
        assert doc["principal"] == {
            "type": "user",
            "id": "u1",
            "key_id": "k" * 64,
            "org_id": "org1",
            "org_source": "team",
            "team_id": "t1",
            "claimed_end_user_id": None,
        }
        assert set(doc["server"]) == {
            "id",
            "status",
            "transport",
            "auth_type",
            "provider_allowed",
            "auth_server_allowed",
            "contract_status",
        }
        assert doc["server"]["contract_status"] == "none"
        assert doc["tool"] == {"name": "search"}
        assert doc["settings"] == {"high_risk_tools": ["a", "b"]}
        assert doc["mode"] == "enforce" and doc["operation"] == "tool_call"

    def test_arguments_carry_keys_and_sizes_but_never_values(self):
        doc = self.build(arguments={"q": "secret value", "n": 3, "nested": {"k": "v"}})
        assert doc["arguments"]["keys"] == ["n", "nested", "q"]
        assert doc["arguments"]["sizes"]["q"] == len("secret value")
        assert "secret" not in json.dumps(doc)
        assert set(doc["arguments"]) == {"keys", "sizes"}

    def test_approval_summary_and_expiry_days(self):
        doc = self.build(snap=snapshot(approvals=(approval(conditions={"a": 1}),)))
        assert doc["approval"] == {
            "present": True,
            "id": "00000000-0000-0000-0000-0000000000a1",
            "class": "standard",
            "scope_type": "team",
            "expires_in_days": 30,
            "conditions": {"a": 1},
        }
        assert doc["consent"] == {"status": "not_applicable", "source": None}

    def test_without_an_approval_only_presence_is_reported(self):
        doc = self.build(snap=snapshot(approvals=()), selected=None)
        assert doc["approval"] == {"present": False}

    def test_time_is_the_snapshot_clock_in_utc_nanoseconds(self):
        doc = self.build()
        assert doc["time"]["iso"] == "2026-11-03T09:00:00+00:00"
        assert doc["time"]["ns"] == 1_793_696_400_000_000_000

    def test_consent_state_follows_the_selected_approvals_purpose(self):
        conditions = {"require_consent": "support"}
        snap = snapshot(approvals=(approval(conditions=conditions),), consents=(consent(),))
        assert self.build(snap=snap)["consent"] == {
            "status": "granted",
            "source": "operator_attested",
        }
        snap = snapshot(approvals=(approval(conditions=conditions),), consents=())
        assert self.build(snap=snap)["consent"] == {"status": "absent", "source": None}

    def test_a_non_string_consent_condition_is_rejected(self, tmp_path):
        snap = snapshot(approvals=(approval(conditions={"require_consent": True}),))
        outcome = decide(harness(tmp_path, snap))
        assert code(outcome) == "MINT-SCHEMA-ERROR"

    def test_the_claimed_end_user_is_passed_as_a_claim(self):
        principal = user_principal(claimed_end_user_id="visitor-9")
        assert self.build(principal=principal)["principal"]["claimed_end_user_id"] == "visitor-9"


class TestDiscoveryOperation:
    def test_a_listed_tool_with_a_grant_is_shown_and_recorded_as_a_discovery_event(self, tmp_path):
        h = harness(tmp_path)
        outcome = decide(h, request(operation=OperationType.RUNTIME_DISCOVERY))
        assert outcome.allowed
        assert len(h.store.of_kind("discovery_evaluated")) == 1
        assert h.store.of_kind("decision_evaluated") == []

    def test_discovery_does_not_evaluate_the_policy(self, tmp_path):
        calls: list = []
        h = harness(tmp_path, evaluate=evaluator("Block", policy_ids=("R1",), calls=calls))
        assert decide(h, request(operation=OperationType.RUNTIME_DISCOVERY)).allowed
        assert calls == []

    def test_a_tool_without_a_grant_is_hidden_in_enforce_mode(self, tmp_path):
        h = harness(tmp_path, snapshot(approvals=()))
        outcome = decide(h, request(operation=OperationType.RUNTIME_DISCOVERY))
        assert not outcome.allowed and code(outcome) == "MINT-APPROVAL-ABSENT"

    def test_observe_mode_shows_observable_findings_but_hides_stops(self, tmp_path):
        cfg = config(tmp_path, mode_ceiling=Mode.OBSERVE)
        settings = SettingsRow(mode=Mode.OBSERVE)
        shown = harness(tmp_path, snapshot(approvals=(), settings=settings), cfg=cfg)
        assert decide(shown, request(operation=OperationType.RUNTIME_DISCOVERY)).allowed
        hidden = harness(tmp_path, snapshot(denials=(denial(),), settings=settings), cfg=cfg)
        assert not decide(hidden, request(operation=OperationType.RUNTIME_DISCOVERY)).allowed

    @pytest.mark.parametrize("mode", [Mode.ENFORCE, Mode.OBSERVE])
    @pytest.mark.parametrize("failure", ["error", "timeout"])
    def test_a_tool_whose_decision_cannot_be_made_is_hidden(self, tmp_path, mode, failure):
        cfg = config(tmp_path, mode_ceiling=mode, decision_budget_seconds=0.05)
        h = harness(tmp_path, snapshot(settings=SettingsRow(mode=mode)), cfg=cfg)

        async def broken(query):
            if failure == "error":
                raise ConnectionError("down")
            await asyncio.sleep(1)

        h.snapshots.read_snapshot = broken
        outcome = decide(h, request(operation=OperationType.RUNTIME_DISCOVERY))
        assert not outcome.allowed and code(outcome) == "MINT-DEPENDENCY-DB"
        assert len(h.store.of_kind("discovery_evaluated")) == 1

    def test_every_listed_tool_gets_its_own_decision_budget(self, tmp_path):
        snap = snapshot(approvals=(approval(tools=("a", "b", "c")),))
        h = harness(tmp_path, snap, cfg=config(tmp_path, decision_budget_seconds=0.5))
        original = h.snapshots.read_snapshot

        async def slowly(query):
            await asyncio.sleep(0.25)
            return await original(query)

        h.snapshots.read_snapshot = slowly

        async def listing():
            return [
                await evaluate_request(
                    request(operation=OperationType.RUNTIME_DISCOVERY, tool_name=name), h.deps
                )
                for name in ("a", "b", "c")
            ]

        outcomes = run(listing())
        assert [o.allowed for o in outcomes] == [True, True, True]

    def test_a_tool_that_runs_out_of_budget_does_not_hide_the_others(self, tmp_path):
        snap = snapshot(approvals=(approval(tools=("first", "slow", "last")),))
        h = harness(tmp_path, snap, cfg=config(tmp_path, decision_budget_seconds=0.1))
        original = h.snapshots.read_snapshot

        async def only_one_is_slow(query):
            if query.tool == "slow":
                await asyncio.sleep(1)
            return await original(query)

        h.snapshots.read_snapshot = only_one_is_slow

        async def listing():
            return {
                name: (
                    await evaluate_request(
                        request(operation=OperationType.RUNTIME_DISCOVERY, tool_name=name), h.deps
                    )
                ).allowed
                for name in ("first", "slow", "last")
            }

        assert run(listing()) == {"first": True, "slow": False, "last": True}

    def test_a_listing_is_hidden_while_unverified(self, tmp_path):
        h = harness(tmp_path, verified=False)
        outcome = decide(h, request(operation=OperationType.RUNTIME_DISCOVERY))
        assert code(outcome) == "MINT-ENFORCEMENT-UNVERIFIED"


class TestDecisionBudget:
    """판정 하나의 시간 예산을 상태 조회, 정책 평가, 선기록이 나눠 쓴다."""

    def test_the_deadline_only_runs_down(self):
        deadline = Deadline(0.05)
        first = deadline.remaining()
        time_left = [first]
        for _ in range(3):
            asyncio.run(asyncio.sleep(0.02))
            time_left.append(deadline.remaining())
        assert time_left == sorted(time_left, reverse=True) and time_left[-1] == 0.0

    def test_the_policy_engine_only_gets_what_the_snapshot_left(self, tmp_path):
        cfg = config(tmp_path, decision_budget_seconds=0.3)
        seen = {}

        async def evaluate(policy_input, *, policy_version_id, bundle_sha256, budget_seconds=None):
            started = asyncio.get_running_loop().time()
            try:
                await asyncio.sleep(0.25)
            finally:
                seen["waited"] = asyncio.get_running_loop().time() - started
            raise AssertionError("must have been cancelled")

        h = harness(tmp_path, evaluate=evaluate, cfg=cfg)
        original = h.snapshots.read_snapshot

        async def slow_snapshot(query):
            await asyncio.sleep(0.15)
            return await original(query)

        h.snapshots.read_snapshot = slow_snapshot
        outcome = decide(h)
        assert code(outcome) == "MINT-DEPENDENCY-OPA"
        assert seen["waited"] < 0.2

    def test_an_insert_that_outlives_the_remaining_budget_is_unknown_and_blocks_the_call(
        self, tmp_path
    ):
        cfg = config(tmp_path, decision_budget_seconds=0.2)
        h = harness(tmp_path, cfg=cfg)
        h.deps.recorder._budget = 5.0

        async def slow_insert(event, consume=None):
            await asyncio.sleep(1)

        h.store.insert_event = slow_insert
        outcome = decide(h)
        assert code(outcome) == "MINT-AUDIT-FAILURE" and outcome.evidence.value == "buffer"
        (event,) = buffered(h)
        assert event.source_key.endswith(":decision_evaluated")
        assert event.payload["stop"]["reason_code"] == "AUDIT_FAILURE"

    def test_an_unsupported_answer_from_the_policy_engine_is_an_obligation_stage_stop(
        self, tmp_path
    ):
        failure = StageResult.stop(Reason.UNSUPPORTED)
        outcome = decide(harness(tmp_path, evaluate=evaluator(failure=failure)))
        assert code(outcome) == "MINT-UNSUPPORTED"
        stages = {e.stage: e for e in outcome.snapshot.stages}
        assert stages[Stage.OBLIGATIONS].status is StageStatus.STOP


def test_the_policy_input_passes_the_policy_modules_own_field_check(tmp_path):
    calls: list = []
    assert decide(harness(tmp_path, evaluate=evaluator(calls=calls))).allowed
    assert has_only_policy_fields(calls[0])
    unregistered = snapshot(server=None, approvals=())
    decide(harness(tmp_path, unregistered, evaluate=evaluator(calls=calls)))
    assert has_only_policy_fields(calls[1]) and calls[1]["approval"] == {"present": False}


def test_missing_principal_values_are_left_out_of_the_policy_input(tmp_path):
    calls: list = []
    principal = user_principal(user_id=None, claimed_end_user_id=None)
    assert decide(harness(tmp_path, evaluate=evaluator(calls=calls)), request(principal)).allowed
    sent = calls[0]["principal"]
    assert sent["type"] == "team_key" and sent["id"] == "k" * 64
    assert sent["claimed_end_user_id"] is None and sent["team_id"] == "t1"


class TestUnregisteredServer:
    """MINT 서버 행이 없어도 정책은 server 객체를 받아 관측 모드 전환이 막히지 않는다."""

    def block_r1(self):
        return evaluator("Block", policy_ids=("R1",), observable=True)

    def test_observe_mode_records_every_finding_and_allows(self, tmp_path):
        settings = SettingsRow(
            mode=Mode.OBSERVE, observable_policy_ids=frozenset({"R1"}), settings_version=2
        )
        snap = snapshot(server=None, approvals=(), settings=settings)
        h = harness(
            tmp_path,
            snap,
            evaluate=self.block_r1(),
            cfg=config(tmp_path, mode_ceiling=Mode.OBSERVE),
        )
        outcome = decide(h)
        assert outcome.allowed
        assert [f.reason_code for f in outcome.snapshot.findings] == [
            "SERVER_UNREGISTERED",
            "APPROVAL_ABSENT",
            "POLICY_DETECT_R1",
        ]
        assert outcome.snapshot.evaluated_decision is Action.BLOCK
        assert outcome.snapshot.enforced_action is Action.ALLOW
        assert outcome.snapshot.stop is None
        (event,) = h.store.of_kind("decision_evaluated")
        assert len(event.payload["findings"]) == 3

    def test_enforce_mode_reports_the_first_finding(self, tmp_path):
        snap = snapshot(server=None, approvals=())
        outcome = decide(harness(tmp_path, snap, evaluate=self.block_r1()))
        assert code(outcome) == "MINT-SERVER-UNREGISTERED"
        assert [f.reason_code for f in outcome.snapshot.findings][-1] == "POLICY_DETECT_R1"

    def test_the_policy_input_names_the_server_as_unregistered(self, tmp_path):
        calls: list = []
        snap = snapshot(server=None, approvals=())
        decide(harness(tmp_path, snap, evaluate=evaluator(calls=calls)))
        assert calls[0]["server"]["status"] == "unregistered"
        assert has_only_policy_fields(calls[0])

    def test_a_registered_server_reports_its_state_and_active_allowlist_kinds(self):
        server = server_row(basis_allowlist_ids=("al1", "al2"), status="suspended")
        allowlists = {
            "al1": allowlist(id="al1", kind="provider"),
            "al2": allowlist(id="al2", kind="auth_server"),
        }
        doc = TestPolicyInput().build(snap=snapshot(server=server, allowlists=allowlists))
        assert doc["server"]["status"] == "suspended"
        assert doc["server"]["provider_allowed"] is True
        assert doc["server"]["auth_server_allowed"] is True

    def test_a_contract_managed_server_reports_its_kind_and_every_pattern(self):
        server = server_row(contract_status="managed", approved_contracts=1)
        doc = TestPolicyInput().build(snap=snapshot(server=server))
        assert doc["server"]["contract_status"] == "managed"
        assert set(doc["arguments"]["patterns"]) == {
            "url_external", "private_host", "path_traversal", "secret_like"}

    def test_a_lifted_allowlist_entry_does_not_count(self):
        server = server_row(basis_allowlist_ids=("al1",))
        snap = snapshot(server=server, allowlists={"al1": allowlist(status="lifted")})
        assert TestPolicyInput().build(snap=snap)["server"]["provider_allowed"] is False

    def test_a_server_without_a_url_is_unsupported(self, tmp_path):
        def resolver(hook):
            raise ServerResolutionError(Reason.UNSUPPORTED, "server_without_url")

        req = build_request(
            {"mcp_server_name": "local", "mcp_tool_name": "t", "mcp_arguments": {}},
            None,
            operation=OperationType.TOOL_CALL,
            instance_id="inst",
            hook_parser=lambda d: HookData("local", "t", {}, None, None),
            resolver=resolver,
            principal_factory=lambda auth, instance_id: user_principal(),
        )
        h = harness(tmp_path)
        outcome = decide(h, req)
        assert code(outcome) == "MINT-UNSUPPORTED"
        assert outcome.snapshot.stop.detail == "server_without_url"
        assert h.snapshots.queries == []
        assert len(h.store.of_kind("decision_evaluated")) == 1
