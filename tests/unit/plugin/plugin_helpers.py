"""플러그인 시험이 함께 쓰는 값 생성기와 대역."""

from __future__ import annotations

import io
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from mint_litellm.compat.litellm_1_106 import HookData
from mint_litellm.plugin.buffer import (
    ConsumeRequest,
    ConsumptionLost,
    EvidenceRecorder,
    LocalBuffer,
)
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import CallRequest, PipelineDeps
from mint_litellm.plugin.policy.opa_client import Evaluation, PolicyOutput
from mint_litellm.plugin.snapshot import (
    AllowlistRow,
    ApprovalRow,
    CallApprovalRow,
    ConsentRow,
    DenialRow,
    PolicyVersionRow,
    RelationRow,
    ServerRow,
    SettingsRow,
    Snapshot,
)
from mint_litellm.types.decision import (
    OperationType,
    ResolvedServer,
    StageResult,
    normalize_auth_type,
    url_sha256,
)
from mint_litellm.types.events import Event
from mint_litellm.types.identity import (
    OrgStatus,
    Principal,
    SubjectType,
    classify_principal,
)

NOW = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
INSTANCE = "inst"
KEY = "k" * 64
URL = "https://mcp.example/api"
FP_KEY = bytes(range(32))
BUNDLE = "b" * 64


def config(tmp_path: Path | None = None, **override: Any) -> PluginConfig:
    base = PluginConfig(
        instance_id=INSTANCE,
        database_url="postgresql://unused",
        opa_url="http://opa.invalid:8181",
        buffer_dir=tmp_path if tmp_path is not None else Path("unused"),
        fingerprint_key=FP_KEY,
        decision_budget_seconds=1.0,
        gc_freeze=False,
    )
    return replace(base, **override)


def user_principal(**override: Any) -> Principal:
    args = {
        "instance_id": INSTANCE,
        "key_id": KEY,
        "user_id": "u1",
        "team_id": "t1",
        "metadata": None,
        "is_master_key": False,
    }
    args.update(override)
    return classify_principal(**args)


def resolved_server(**override: Any) -> ResolvedServer:
    args = {
        "server_id": "srv-1",
        "url_sha256": url_sha256(URL),
        "transport": "http",
        "auth_type": normalize_auth_type(None),
        "candidates_with_same_name": 1,
    }
    args.update(override)
    return ResolvedServer(**args)


def server_row(**override: Any) -> ServerRow:
    args = {
        "id": str(uuid4()),
        "server_id": "srv-1",
        "status": "approved",
        "url_sha256": url_sha256(URL),
        "transport": "http",
        "auth_type": "none",
        "basis_allowlist_ids": (),
    }
    args.update(override)
    return ServerRow(**args)


def approval(**override: Any) -> ApprovalRow:
    args = {
        "id": "00000000-0000-0000-0000-0000000000a1",
        "org_id": "org1",
        "relation_id": "r1",
        "approval_class": "standard",
        "tools": ("search",),
        "scope_type": "team",
        "scope_id": "t1",
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=30),
        "conditions": {},
        "status": "active",
    }
    args.update(override)
    return ApprovalRow(**args)


def call_approval(**override: Any) -> CallApprovalRow:
    from mint_litellm.types.fingerprint import argument_fingerprint

    args = {
        "id": UUID("00000000-0000-0000-0000-0000000000c1"),
        "org_id": "org1",
        "principal_type": "user",
        "principal_id": "u1",
        "server_id": "srv-1",
        "tool": "search",
        "args_fp": argument_fingerprint({"q": "x"}, FP_KEY),
        "fp_key_version": 1,
        "policy_version_id": "pv1",
        "contract_version": None,
        "expires_at": NOW + timedelta(hours=1),
        "state_version": 2,
    }
    args.update(override)
    return CallApprovalRow(**args)


def consent(**override: Any) -> ConsentRow:
    args = {
        "id": "consent-1",
        "org_id": "org1",
        "purpose": "support",
        "source": "operator_attested",
        "granted_at": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=10),
        "revoked_at": None,
    }
    args.update(override)
    return ConsentRow(**args)


def denial(**override: Any) -> DenialRow:
    args = {
        "id": "d1",
        "org_id": None,
        "scope_type": "team",
        "scope_id": "t1",
        "server_id": None,
        "tools": None,
    }
    args.update(override)
    return DenialRow(**args)


def snapshot(**override: Any) -> Snapshot:
    args: dict[str, Any] = {
        "now": NOW,
        "epoch": 7,
        "settings": SettingsRow(settings_version=3),
        "bindings": {(SubjectType.TEAM, "t1"): "org1"},
        "org_status": {"org1": OrgStatus.ACTIVE},
        "server": server_row(),
        "allowlists": {},
        "relations": {"r1": RelationRow(id="r1", status="active")},
        "approvals": (approval(),),
        "denials": (),
        "call_approvals": (),
        "consents": (),
        "policy_version": PolicyVersionRow(id="pv1", bundle_sha256=BUNDLE),
    }
    args.update(override)
    return Snapshot(**args)


def allowlist(**override: Any) -> AllowlistRow:
    args = {
        "id": "al1",
        "kind": "provider",
        "status": "active",
        "valid_from": NOW - timedelta(days=2),
        "valid_until": NOW + timedelta(days=2),
    }
    args.update(override)
    return AllowlistRow(**args)


def hook(**override: Any) -> HookData:
    args = {
        "server_name": "mslearn",
        "tool_name": "search",
        "arguments": {"q": "x"},
        "litellm_call_id": "call-1",
        "logging_obj": None,
    }
    args.update(override)
    return HookData(**args)


def request(
    principal: Principal | None = None,
    *,
    operation: OperationType = OperationType.TOOL_CALL,
    resolved: ResolvedServer | None | str = "default",
    failure: StageResult | None = None,
    **hook_override: Any,
) -> CallRequest:
    return CallRequest(
        operation=operation,
        principal=principal or user_principal(),
        hook=hook(**hook_override),
        resolved=resolved_server() if resolved == "default" else resolved,
        resolution_failure=failure,
    )


class FakeSnapshots:
    def __init__(self, snap: Snapshot | Exception) -> None:
        self.snap = snap
        self.queries: list[Any] = []

    async def read_snapshot(self, query: Any) -> Snapshot:
        self.queries.append(query)
        if isinstance(self.snap, Exception):
            raise self.snap
        return self.snap


class FakeStore:
    """사건 저장소 대역. 같은 ``(instance_id, source_key)``는 한 건으로 수렴한다."""

    def __init__(self) -> None:
        self.events: dict[tuple[str, str], Event] = {}
        self.consumed: list[ConsumeRequest] = []
        self.fail: Exception | None = None
        self.lose_consumption = False

    async def insert_event(self, event: Event, consume: ConsumeRequest | None = None) -> bool:
        if self.fail is not None:
            raise self.fail
        if consume is not None:
            if self.lose_consumption:
                raise ConsumptionLost
            self.consumed.append(consume)
        key = (event.instance_id, event.source_key)
        if key in self.events:
            return False
        self.events[key] = event
        return True

    def of_kind(self, kind: str) -> list[Event]:
        return [e for e in self.events.values() if e.kind.value == kind]


def evaluator(
    decision: str = "Allow",
    *,
    policy_ids: tuple[str, ...] = (),
    obligations: tuple[dict[str, Any], ...] = (),
    observable: bool = False,
    version: str = "pv1",
    bundle: str = BUNDLE,
    missing_inputs: tuple[str, ...] = (),
    failure: StageResult | None = None,
    calls: list[dict[str, Any]] | None = None,
):
    """정책 클라이언트 대역. 운영의 ``OPAClient.evaluate``와 같은 반환 형태를 돌려준다."""

    async def evaluate(policy_input, *, policy_version_id, bundle_sha256, budget_seconds=None):
        if calls is not None:
            calls.append(policy_input)
        if failure is not None:
            return Evaluation(failure=failure)
        return Evaluation(
            output=PolicyOutput(
                decision=decision,
                policy_ids=list(policy_ids),
                policy_version_id=version,
                bundle_sha256=bundle,
                obligations=list(obligations),
                observable=observable,
                missing_inputs=list(missing_inputs),
            )
        )

    return evaluate


@dataclass
class Harness:
    deps: PipelineDeps
    store: FakeStore
    buffer: LocalBuffer
    stderr: io.StringIO
    snapshots: FakeSnapshots
    verified: dict[str, bool] = field(default_factory=lambda: {"v": True})


def harness(
    tmp_path: Path,
    snap: Snapshot | Exception | None = None,
    *,
    evaluate: Any = "allow",
    cfg: PluginConfig | None = None,
    verified: bool = True,
) -> Harness:
    cfg = cfg or config(tmp_path)
    store = FakeStore()
    stderr = io.StringIO()
    buffer = LocalBuffer(tmp_path / "buffer", 1024 * 1024)
    recorder = EvidenceRecorder(
        store,
        buffer,
        budget_seconds=1.0,
        instance_id=INSTANCE,
        stderr=stderr,
        replay_interval_seconds=3600,
    )
    snapshots = FakeSnapshots(snap if snap is not None else snapshot())
    state = {"v": verified}
    deps = PipelineDeps(
        config=cfg,
        snapshots=snapshots,
        recorder=recorder,
        evaluate=evaluator() if evaluate == "allow" else evaluate,
        verified=lambda: state["v"],
        clock=lambda: NOW,
    )
    return Harness(deps, store, buffer, stderr, snapshots, state)


def buffered(h: Harness) -> list[Event]:
    """버퍼에 쌓인 사건을 모두 읽는다(열린 파일을 먼저 닫는다)."""
    h.buffer.close()
    events: list[Event] = []
    for path in sorted(h.buffer._dir.glob("*.jsonl")):
        events.extend(h.buffer.read(path)[0])
    return events
