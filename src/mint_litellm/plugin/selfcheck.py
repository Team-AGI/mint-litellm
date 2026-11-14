"""기동 자가 점검과 플러그인 실행 상태.

플러그인은 ``unverified`` 상태로 시작해 모든 MCP 호출을 차단하고, LiteLLM 앱이 기동을 마친 뒤
워커마다 8개 항목을 프로세스 안에서 확인한다. 모두 통과해야 ``verified``가 된다. 점검이
실패하면 사건을 남기고(``MINT_REQUIRED``가 참이면) 프로세스를 멈춘다. LiteLLM의 키나 관리
API는 쓰지 않는다.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import importlib.util
import logging
import multiprocessing
import os
import signal
import socket
import time
import urllib.request
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

import yaml

from mint_litellm.compat import capabilities
from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.compat.litellm_1_106 import RegistryEntry
from mint_litellm.plugin.buffer import EvidenceRecorder, LocalBuffer, SystemEventKeys
from mint_litellm.plugin.config import PluginConfig, configure_logging
from mint_litellm.plugin.discovery import DiscoveryResult, evaluate_listed_tool
from mint_litellm.plugin.list_seen import ListSeen
from mint_litellm.plugin.pipeline import (
    CallRequest,
    Outcome,
    PipelineDeps,
    PolicyEvaluate,
    build_request,
    evaluate_request,
)
from mint_litellm.plugin.policy.opa_client import Evaluation, OPAClient
from mint_litellm.plugin.restore_watch import RestoreWatch
from mint_litellm.plugin.result import ResultDeps
from mint_litellm.plugin.shadow import ShadowWatch
from mint_litellm.plugin.snapshot import PluginDatabase, RegisteredServer
from mint_litellm.plugin.timing import OFF, StageClock
from mint_litellm.types.canonical import sha256
from mint_litellm.types.decision import OperationType, StageResult
from mint_litellm.types.events import Event, EventKind
from mint_litellm.types.plaintext_secrets import plaintext_secret_paths
from mint_litellm.types.reason_codes import Reason
from mint_litellm.types.reuse_policy import DEFAULT_TOOL_TIMEOUT_SECONDS, reuse_violations
from mint_litellm.types.settings import SELF_CHECK_DESCRIPTIONS, SelfCheckItem, policies_of

log = logging.getLogger("mint_litellm.selfcheck")

REQUIRED_MODES = ("pre_call", "pre_mcp_call", "post_mcp_call")
# 통제 대상 서버 상태. 그 밖의 상태 서버는 LiteLLM에 없어도 기동을 막지 않는다.
CONTROLLED_SERVER_STATUSES = frozenset({"approved", "suspended"})
CONTRACT_FIELDS = ("url_sha256", "transport", "auth_type")
REGISTRY_MISSING = "registry_missing"
MODERN_MCP_VERSION = "2026-07-28"


@dataclass(frozen=True)
class CheckResult:
    item: SelfCheckItem
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class LiteLLMView:
    """점검 시점에 프로세스 안에서 읽은 LiteLLM 상태."""

    callbacks: Sequence[Any]
    general_settings: Mapping[str, Any]
    strict_guardrail_modes: bool
    store_prompts_in_spend_logs: bool
    user_url_validation: bool
    registry: Sequence[RegistryEntry]
    missing_symbols: Sequence[str]
    # LiteLLM 재사용 정책 점검이 읽는 값
    ssl_verify: bool = True
    allowed_hosts: Sequence[str] = ()
    default_timeout: float = DEFAULT_TOOL_TIMEOUT_SECONDS
    env: Mapping[str, str] = field(default_factory=dict, repr=False)
    # llm-sandbox가 설치되어 스킬 훅이 Docker 샌드박스에서 코드를 실행할 수 있다.
    sandbox_installed: bool = False
    # 저하 운용(등급 B·C)이 잃는 보장. 비어 있으면 모든 보장이 성립한다.
    degraded: Sequence[str] = ()
    result_guardrail: bool = True


def collect_view(env: Mapping[str, str] | None = None) -> LiteLLMView:
    missing = compat.missing_symbols(env=env)
    if not missing:
        witness = compat.arguments_witness_problem()
        missing = [witness] if witness else []
    if missing:
        return LiteLLMView((), {}, True, False, True, (), missing)
    env = os.environ if env is None else env
    found = compat.litellm_assessment()
    if not found.tested:
        log.warning("%s: 시험하지 않은 판본이다. 보장은 감지된 능력에만 근거한다.", found.summary)
    degraded = capabilities.degraded_findings(found)
    for finding in degraded:
        log.warning("%s: degraded operation: %s", found.summary, finding)
    return LiteLLMView(
        callbacks=compat.litellm_callbacks(),
        general_settings=compat.general_settings(),
        strict_guardrail_modes=compat.strict_guardrail_modes_enabled(env),
        store_prompts_in_spend_logs=compat.spend_logs_store_prompts(),
        user_url_validation=compat.litellm_attribute("user_url_validation", True) is not False,
        registry=compat.registry_entries(),
        missing_symbols=(),
        ssl_verify=compat.ssl_verification_enabled(env),
        allowed_hosts=tuple(compat.litellm_attribute("user_url_allowed_hosts", None) or ()),
        default_timeout=compat.mcp_default_timeout(),
        env=dict(env),
        sandbox_installed=importlib.util.find_spec("llm_sandbox") is not None,
        degraded=tuple(degraded),
        result_guardrail=capabilities.result_enforced(found.grade),
    )


def _hook_names(event_hook: Any) -> set[str]:
    if event_hook is None:
        return set()
    items = event_hook if isinstance(event_hook, (list, tuple, set)) else [event_hook]
    return {str(getattr(i, "value", i)) for i in items}


def _required_modes(view: LiteLLMView) -> tuple[str, ...]:
    """결과 단계 가드레일이 없는 LiteLLM(등급 C)에는 그 모드가 없다."""
    if view.result_guardrail:
        return REQUIRED_MODES
    return tuple(m for m in REQUIRED_MODES if m != "post_mcp_call")


def guardrail_definition_check(callbacks: Sequence[Any], guardrail: Any) -> tuple[bool, str]:
    """MINT 가드레일이 하나이고 병렬로 돌며 판정 재정의가 그대로인지. 콜백 순서는 보지 않는다."""
    if guardrail is None:
        return False, "the MINT guardrail is not registered"
    registered = [cb for cb in callbacks if type(cb) is type(guardrail)]
    if len(registered) != 1 or registered[0] is not guardrail:
        return False, "exactly one MINT guardrail must be registered"
    if getattr(guardrail, "run_in_parallel", None) is not True:
        return False, "the MINT guardrail must run in parallel"
    if getattr(guardrail, "scan_raw_request", None) is not False:
        return False, "the MINT guardrail must not scan the raw request"
    cls = type(guardrail)
    expected = getattr(cls, "mint_should_run_guardrail", None)
    if expected is None or getattr(cls, "should_run_guardrail", None) is not expected:
        return False, "the MINT guardrail's should_run_guardrail was replaced"
    for name in ("should_run_guardrail", "async_pre_call_hook"):
        if name in getattr(guardrail, "__dict__", {}):
            return False, f"the MINT guardrail's {name} was replaced on the instance"
    return True, ""


def _ws_passthrough_on(general_settings: Mapping[str, Any]) -> bool:
    setting = general_settings.get("enable_openai_websocket_passthrough")
    if isinstance(setting, str):
        return setting.strip().lower() in ("1", "true", "yes", "on")
    return setting is True


def _modern_mcp_on(general_settings: Mapping[str, Any]) -> bool:
    """새 MCP 규격을 내는지. 그 규격의 ``subscriptions/listen``은 MINT 훅을 거치지 않는다."""
    versions = general_settings.get("mcp_advertised_versions")
    if isinstance(versions, str):
        versions = [versions]
    return isinstance(versions, (list, tuple)) and MODERN_MCP_VERSION in [str(v) for v in versions]


def check_items(
    view: LiteLLMView,
    *,
    logger: Any,
    guardrail: Any,
    controlled: Sequence[RegisteredServer] | None,
    fingerprint_key_set: bool = True,
    allow_realtime: bool = False,
    allow_code_execution: bool = False,
) -> list[CheckResult]:
    """8개 항목을 확인한다. ``controlled``가 ``None``이면 MINT DB를 읽지 못한 것이다."""
    results: list[CheckResult] = []

    def add(item: SelfCheckItem, ok: bool, detail: str = "") -> None:
        results.append(CheckResult(item, ok, "" if ok else detail))

    callbacks = list(view.callbacks)
    positions = {id(cb): i for i, cb in enumerate(callbacks)}

    same_kind = [cb for cb in callbacks if logger is not None and type(cb) is type(logger)]
    add(
        SelfCheckItem.CALLBACK_REGISTERED,
        logger is not None and len(same_kind) == 1 and same_kind[0] is logger,
        "the MINT logger must be registered exactly once, by the MINT guardrail",
    )

    modes = _hook_names(getattr(guardrail, "event_hook", None)) if guardrail else set()
    add(
        SelfCheckItem.GUARDRAIL_MODES,
        guardrail is not None
        and id(guardrail) in positions
        and all(m in modes for m in _required_modes(view))
        and getattr(guardrail, "default_on", False) is True,
        "guardrail is missing, lacks a mode, or is not default_on",
    )

    definition_ok, definition_detail = guardrail_definition_check(callbacks, guardrail)
    add(SelfCheckItem.GUARDRAIL_ORDER, definition_ok, definition_detail)

    by_id = {entry.server_id: entry for entry in view.registry}
    if controlled is not None:
        controlled = registry_backed(controlled)
    if controlled is None:
        add(SelfCheckItem.KEY_ACCESS_STRICT, False, "MINT database unavailable")
        add(SelfCheckItem.SERVER_REGISTRY_MATCH, False, "MINT database unavailable")
    else:
        active = [s for s in controlled if s.status in CONTROLLED_SERVER_STATUSES]
        open_servers = [
            s.server_id for s in active if getattr(by_id.get(s.server_id), "allow_all_keys", False)
        ]
        strict = view.general_settings.get("require_key_mcp_access_defined") is True
        add(
            SelfCheckItem.KEY_ACCESS_STRICT,
            strict and not open_servers,
            "require_key_mcp_access_defined must be true"
            if not strict
            else f"allow_all_keys is set on {', '.join(open_servers[:5])}",
        )
        # 중지된 서버는 호출이 이미 막혀 있으므로, 레지스트리에서 지워졌어도 기동을 막지 않는다.
        absent = [
            s.server_id for s in active if s.status == "approved" and s.server_id not in by_id
        ]
        add(
            SelfCheckItem.SERVER_REGISTRY_MATCH,
            not absent,
            f"not in the registry: {', '.join(absent[:5])}",
        )

    owners: dict[str, set[str]] = {}
    for entry in view.registry:
        for name in entry.names:
            owners.setdefault(name.replace(" ", "_"), set()).add(entry.server_id)
    clashes = sorted(name for name, ids in owners.items() if len(ids) > 1)
    add(
        SelfCheckItem.NAME_ALIAS_UNIQUE,
        not clashes,
        f"names shared by several servers: {', '.join(clashes[:5])}",
    )

    add(
        SelfCheckItem.COMPAT_SYMBOLS,
        not view.missing_symbols,
        f"missing: {', '.join(view.missing_symbols[:5])}",
    )

    problems = []
    if not fingerprint_key_set:
        problems.append("MINT_FINGERPRINT_KEY is not set")
    if not view.strict_guardrail_modes:
        problems.append("LITELLM_STRICT_GUARDRAIL_MODES=false")
    if view.store_prompts_in_spend_logs:
        problems.append("store_prompts_in_spend_logs=true")
    if not view.user_url_validation:
        problems.append("user_url_validation=false")
    supported = view.general_settings.get("supported_db_objects")
    if isinstance(supported, list) and "mcp" not in [str(s) for s in supported]:
        problems.append("supported_db_objects lacks mcp")
    # LiteLLM의 OpenAI WebSocket 패스스루는 사전 훅을 거치지 않으므로 실시간 허용을 명시해야 한다.
    if _ws_passthrough_on(view.general_settings) and not allow_realtime:
        problems.append("enable_openai_websocket_passthrough needs MINT_ALLOW_REALTIME=true")
    # 코드 인터프리터 가로채기는 운영자가 켜는 콜백이라 허용을 명시해야 한다. 스킬 훅의 샌드박스
    # 패키지는 공식 이미지에 늘 들어 있으므로 기동을 막지 않고, 그 요청은 사전 단계에서 막는다.
    interception = any(type(cb).__name__ == "CodeInterpreterInterceptionLogger" for cb in callbacks)
    if interception and not allow_code_execution:
        problems.append(
            "LiteLLM can run model-generated code (code_interpreter_interception); "
            "set MINT_ALLOW_CODE_EXECUTION=true or remove it"
        )
    # 구독 중계(subscriptions/listen)는 훅을 거치지 않고 끄는 설정도 없어 새 규격을 막는다.
    if _modern_mcp_on(view.general_settings):
        problems.append(
            f"mcp_advertised_versions must not include {MODERN_MCP_VERSION} "
            "(the subscription relay bypasses MINT hooks)"
        )
    # LiteLLM이 구현하는 정책은 통제 서버와 전역 설정이 요구 값과 같을 때만 이행으로 센다.
    active = {s.server_id for s in controlled or () if s.status in CONTROLLED_SERVER_STATUSES}
    for violation in reuse_violations(
        general=view.general_settings,
        allowed_hosts=view.allowed_hosts,
        ssl_verify=view.ssl_verify,
        env=view.env,
        servers=[e.facts() for e in view.registry if e.server_id in active],
        default_timeout=view.default_timeout,
    ):
        problems.append(f"{', '.join(policies_of(violation.key))}: {violation.message}")
    add(SelfCheckItem.REQUIRED_SETTINGS, not problems, "; ".join(problems))
    return results


def warn_plaintext_secrets(env: Mapping[str, str]) -> list[str]:
    """LiteLLM 설정 파일에 평문으로 적힌 비밀의 항목 경로. 경고만 하고 기동은 막지 않는다.

    값은 로그에 남기지 않는다. 파일이 없거나 읽을 수 없으면 확인하지 못한 것이므로 비어 있다.
    """
    raw = env.get("MINT_LITELLM_CONFIG") or env.get("CONFIG_FILE_PATH")
    if not raw:
        return []
    try:
        with open(raw, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        paths = plaintext_secret_paths(document if isinstance(document, Mapping) else None)
    except Exception:  # 경고용 점검이 기동을 막지 않게 한다
        return []
    if paths:
        log.warning(
            "LiteLLM 설정에 비밀이 평문으로 적혀 있습니다(os.environ/ 참조로 바꾸십시오): %s",
            ", ".join(paths),
        )
    return paths


def registry_backed(servers: Sequence[RegisteredServer]) -> list[RegisteredServer]:
    """LiteLLM 레지스트리와 대조하는 서버. 로컬 실행(stdio) 서버는 MINT 표만으로 다룬다."""
    return [s for s in servers if s.identity_kind == "remote"]


def contract_mismatches(
    view: LiteLLMView, controlled: Sequence[RegisteredServer]
) -> list[tuple[str, str]]:
    """승인된 계약 값과 다른 통제 서버의 (서버, 항목). 기동을 막지 않는다.

    레지스트리에서 지워진 중지 서버는 항목 ``registry_missing``으로 센다. 승인된 서버가 지워진
    경우는 자가 점검 5번이 기동을 막는다.
    """
    by_id = {entry.server_id: entry for entry in view.registry}
    found = [
        # 로컬 서버와 같은 식별자가 레지스트리에 있으면 다른 서버로 오인될 수 있다.
        (server.server_id, "identity_kind")
        for server in controlled
        if server.identity_kind == "stdio" and server.server_id in by_id
    ]
    for server in registry_backed(controlled):
        if server.status not in CONTROLLED_SERVER_STATUSES:
            continue
        entry = by_id.get(server.server_id)
        if entry is None:
            if server.status == "suspended":
                found.append((server.server_id, REGISTRY_MISSING))
            continue
        found.extend(
            (server.server_id, name)
            for name in CONTRACT_FIELDS
            if getattr(entry, name) != getattr(server, name)
        )
    return found


EXIT_CODE = 3
EXIT_CODE_FILE_ENV = "MINT_EXIT_CODE_FILE"


def leave_exit_marker() -> None:
    """``MINT_EXIT_CODE_FILE``이 있으면 그 파일에 종료 코드 표식을 남긴다.

    uvicorn의 다중 워커 감독 프로세스는 워커가 몇 번으로 끝났든 0으로 끝난다. 진입점이 이 표식을
    읽어 종료 코드를 바꾼다.
    """
    path = os.environ.get(EXIT_CODE_FILE_ENV)
    if path:
        # 표식은 보조 수단이다. 어떤 이유로 쓰지 못해도 원래의 종료·예외 경로를 가리면 안 된다.
        with contextlib.suppress(Exception), open(path, "w", encoding="utf-8") as marker:
            marker.write(str(EXIT_CODE))


def leave_startup_failure_marker() -> None:
    """생성자 오류로 기동이 중단될 때 표식을 남긴다.

    구성 오류(RuntimeError)로 가드레일·로거를 만들지 못하면 LiteLLM이 워커를 끝내지만 자가 점검의
    종료 경로를 거치지 않는다. 이미 점검을 통과한 프로세스에서 이후에 만든 객체의 오류는 프록시를
    멈추지 않으므로 표식을 남기지 않는다.
    """
    runtime = _runtime
    if runtime is not None and runtime.verified:
        return
    leave_exit_marker()


def terminate_process() -> None:
    """프록시를 멈춘다. 워커이면 감독 프로세스에도 종료를 알려 컨테이너 재시작 정책이 받게 한다."""
    leave_exit_marker()
    parent = os.getppid()
    if multiprocessing.parent_process() is not None or parent > 1:
        with contextlib.suppress(OSError):
            os.kill(parent, signal.SIGTERM)
    os._exit(EXIT_CODE)


async def wait_for_readiness(url: str, timeout: float) -> bool:
    def probe() -> bool:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                return response.status == 200
        except Exception:
            return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await asyncio.to_thread(probe):
            return True
        await asyncio.sleep(0.25)
    return False


@dataclass
class PluginRuntime:
    """한 워커 프로세스의 플러그인 상태. 로거와 가드레일이 공유한다."""

    config: PluginConfig
    database: PluginDatabase
    recorder: EvidenceRecorder
    evaluate: PolicyEvaluate | None
    secret_markers: Callable[..., Awaitable[tuple[str, ...] | None]] | None = None
    view_collector: Callable[[], LiteLLMView] = collect_view
    terminate: Callable[[], None] = terminate_process
    readiness: Callable[[str, float], Awaitable[bool]] = wait_for_readiness
    retry_seconds: float = 1.0
    recheck_seconds: float = 30.0
    verified: bool = False
    restore_watch: Any = None
    shadow: Any = None
    logger: Any = None
    guardrail: Any = None
    last_results: list[CheckResult] = field(default_factory=list)
    last_mismatches: list[tuple[str, str]] = field(default_factory=list)
    last_degraded: list[str] = field(default_factory=list)
    keys: SystemEventKeys = field(default_factory=SystemEventKeys, repr=False)
    _reported: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    _observed_hashes: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    _list_seen: ListSeen | None = field(default=None, repr=False)
    _grade: str | None = field(default=None, repr=False)
    _secrets_checked: bool = field(default=False, repr=False)
    _task: asyncio.Task[None] | None = field(default=None, repr=False)
    _observe_task: asyncio.Task[None] | None = field(default=None, repr=False)
    _restore_task: asyncio.Task[None] | None = field(default=None, repr=False)
    _shadow_task: asyncio.Task[None] | None = field(default=None, repr=False)

    @property
    def grade(self) -> str:
        if self._grade is None:
            self._grade = compat.litellm_assessment().grade
        return self._grade

    @property
    def list_enforced(self) -> bool:
        return capabilities.list_enforced(self.grade)

    @property
    def result_enforced(self) -> bool:
        return capabilities.result_enforced(self.grade)

    @property
    def deps(self) -> PipelineDeps:
        if self._list_seen is None and self.list_enforced and self.config.list_dedup_seconds > 0:
            self._list_seen = ListSeen(self.config.list_dedup_seconds)
        return PipelineDeps(
            list_seen=self._list_seen,
            config=self.config,
            snapshots=self.database,
            recorder=self.recorder,
            evaluate=self.evaluate,
            secret_markers=self.secret_markers,
            shadow=None if self.shadow is None else self.shadow.submit,
            verified=lambda: self.verified and self._restore_cause() is None,
            unverified_cause=self._restore_cause,
        )

    def _restore_cause(self) -> str | None:
        """되돌림 판정이 호출을 막는 사유. 주기 판정이 메모리에 둔 값만 읽는다."""
        return None if self.restore_watch is None else self.restore_watch.blocked_cause

    @property
    def result_deps(self) -> ResultDeps:
        return ResultDeps(config=self.config, database=self.database, recorder=self.recorder)

    async def judge_call(
        self, data: Mapping[str, Any], auth: Any, timing: StageClock = OFF
    ) -> Outcome:
        started = timing.now()
        request = build_request(
            data,
            auth,
            operation=OperationType.TOOL_CALL,
            instance_id=self.config.instance_id,
            hook_parser=compat.parse_hook_data,
            resolver=compat.resolve_server,
            principal_factory=compat.principal_from_auth,
        )
        timing.since("hook", started)
        return await evaluate_request(request, self.deps, timing)

    async def judge_refused_request(
        self, data: Mapping[str, Any], auth: Any, reason: Reason, kind: str
    ) -> Outcome:
        """공급자 쪽 MCP가 담겼거나 실시간 경로인 모델 요청. 판정 사건을 남기고 항상 차단한다."""
        request = CallRequest(
            operation=OperationType.LLM_REQUEST,
            principal=compat.principal_from_auth(auth, instance_id=self.config.instance_id),
            hook=compat.parse_hook_data(data),
            resolved=None,
            resolution_failure=StageResult.stop(reason, detail=kind),
        )
        return await evaluate_request(request, self.deps)

    async def judge_listed_tool(self, data: Mapping[str, Any], auth: Any) -> DiscoveryResult:
        return await evaluate_listed_tool(
            data,
            auth,
            self.deps,
            hook_parser=compat.parse_hook_data,
            resolver=compat.resolve_listed_server,
            principal_factory=compat.principal_from_auth,
        )

    async def _report_verified(self) -> None:
        """이 워커가 점검을 통과해 호출을 받게 된 때 한 번 남긴다. 호출마다 남기지 않는다."""
        kind = EventKind.ENFORCEMENT_VERIFIED
        keys = self.keys
        await self.recorder.record(
            Event(
                instance_id=self.config.instance_id,
                inserted_at=datetime.now(UTC),
                kind=kind,
                source_key=keys.next(kind),
                payload={
                    "worker_id": worker_id(),
                    "litellm": litellm_summary(),
                    "checks": [
                        {"item": int(r.item), "name": r.item.name, "ok": r.ok}
                        for r in self.last_results
                    ],
                    **({"degraded": list(self.last_degraded)} if self.last_degraded else {}),
                },
            )
        )

    async def run_checks(self) -> list[CheckResult]:
        try:
            controlled: Sequence[RegisteredServer] | None = await asyncio.wait_for(
                self.database.registered_servers(self.config.instance_id),
                self.config.decision_budget_seconds * 10,
            )
        except Exception:
            controlled = None
        view = self.view_collector()
        if not self._secrets_checked:
            self._secrets_checked = True
            warn_plaintext_secrets(view.env or os.environ)
        await self._register_contract_tools(view)
        results = check_items(
            view,
            logger=self.logger,
            guardrail=self.guardrail,
            controlled=controlled,
            fingerprint_key_set=self.config.fingerprint_key is not None,
            allow_realtime=self.config.allow_realtime,
            allow_code_execution=self.config.allow_code_execution,
        )
        self.last_results = results
        self.last_degraded = list(view.degraded)
        self.last_mismatches = contract_mismatches(view, controlled or [])
        by_id = {entry.server_id: entry for entry in view.registry}
        for server in controlled or ():
            entry = by_id.get(server.server_id)
            if (
                server.contract_status == "managed"
                and entry is None
                and server.status in CONTROLLED_SERVER_STATUSES
                and (server.server_id, REGISTRY_MISSING) not in self.last_mismatches
            ):
                self.last_mismatches.append((server.server_id, REGISTRY_MISSING))
            if (
                server.contract_status == "managed"
                and entry is not None
                and entry.issuer != server.issuer
            ):
                self.last_mismatches.append((server.server_id, "issuer"))
        self._observed_hashes = {}
        managed = {s.server_id for s in controlled or () if s.contract_status == "managed"}
        for server_id, name in self.last_mismatches:
            if server_id not in managed:
                continue
            entry = by_id.get(server_id)
            value = getattr(entry, name, None) if entry else None
            self._observed_hashes.setdefault(server_id, {})[name] = sha256(value)
        return results

    async def _load_contract_tools(self) -> dict[str, tuple[str, ...]]:
        return await asyncio.wait_for(
            self.database.contract_tools(self.config.instance_id),
            self.config.decision_budget_seconds * 10,
        )

    async def _load_unmanaged(self) -> set[str]:
        servers = await asyncio.wait_for(
            self.database.registered_servers(self.config.instance_id),
            self.config.decision_budget_seconds * 10,
        )
        return {s.server_id for s in registry_backed(servers) if s.contract_status != "managed"}

    async def _register_contract_tools(self, view: LiteLLMView) -> None:
        """계약 도구를 이 워커의 도구 경로표에 올린다. 숨긴 도구의 직접 호출도 판정에 닿게 한다.

        기동 점검과 주기 관측이 돌 때마다 하고, 그 사이에 승인된 서버는 호출 진입의 재시도가 맡는다
        (``install_contract_retry``). 실패하면 이전 등록을 유지하고 다음 주기에 다시 한다.
        """
        if view.missing_symbols or self.grade != "A":
            return
        try:
            compat.register_contract_tools(await self._load_contract_tools())
        except Exception as exc:
            log.warning("계약 도구 경로 등록 실패: %s", type(exc).__name__)

    async def verify(self) -> bool:
        # 기동 점검의 재시도(30초)가 판정 주기(60초)를 앞지르지 않도록 첫 판정만 여기서 한다.
        if self.restore_watch is not None and not self.restore_watch.evaluated:
            await self.restore_watch.refresh()
        results = await self.run_checks()
        self.verified = all(r.ok for r in results)
        return self.verified

    def ensure_started(self) -> None:
        """실행 중인 이벤트 루프가 있으면 기동 후 점검을 예약한다(워커마다 한 번)."""
        if self._task is not None:
            return
        try:
            compat.install_contract_retry(self._load_contract_tools, self._load_unmanaged)
        except Exception as exc:
            log.warning("계약 도구 재시도 설치 실패: %s", type(exc).__name__)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._task = loop.create_task(self._startup())
        self._restore_task = loop.create_task(self._judge_loop())
        self._observe_task = loop.create_task(self._observe_contracts())
        if self.shadow is not None:
            self._shadow_task = loop.create_task(self.shadow.run())

    async def _judge_loop(self) -> None:
        """판정 주기마다 되돌림 판정을 갱신하고, 호출이 없어도 버퍼에 남은 사건을 DB에 올린다."""
        while True:
            try:
                await self.recorder.replay_pending()
            except Exception as exc:  # 재적재 실패가 되돌림 판정 갱신을 막지 않는다
                log.warning("버퍼 재적재 실패: %s", type(exc).__name__)
            if self.restore_watch is not None:
                await self.restore_watch.refresh()
            await asyncio.sleep(self.config.restore_interval_seconds)

    async def _observe_contracts(self) -> None:
        while True:
            await asyncio.sleep(self.config.observe_seconds)
            if not self.verified:
                continue
            try:
                await self.run_checks()
                await self._report_mismatches()
            except Exception as exc:
                log.warning("계약 관측 실패: %s", type(exc).__name__)

    async def _startup(self) -> None:
        self.keys = SystemEventKeys()
        grace = self.config.selfcheck_grace_seconds
        url = self.config.readiness_url or (
            f"http://localhost:{os.environ.get('PORT', '4000')}/health/readiness"
        )
        loop = asyncio.get_running_loop()
        deadline = loop.time() + grace
        try:
            error: str | None = "readiness_timeout"
            ready = False
            # 준비 신호와 8항목은 하나의 외부 시간 제한 안에서 모두 통과해야 한다. 다른 워커가 낸
            # 준비 신호로 시작했다면 이 워커의 레지스트리가 아직 비어 있을 수 있어 다시 확인한다.
            try:
                async with asyncio.timeout_at(deadline):
                    ready = await self.readiness(url, grace)
                    if ready:
                        error = None
                        while not await self.verify():
                            await asyncio.sleep(self.retry_seconds)
            except TimeoutError:
                pass
            if ready:
                if self.verified and loop.time() < deadline:
                    log.info("MINT 자가 점검 통과")
                    if self.config.gc_freeze:
                        freeze_collector()
                    await self._report_mismatches()
                    await self._report_verified()
                    return
                # 시간 제한이 지난 뒤에 끝난 점검은 통과로 치지 않는다.
                self.verified = False
                if not any(not r.ok for r in self.last_results):
                    error = "startup_timeout"
                await self._report_mismatches()
            await self._fail(error=error)
            if self.config.required:
                self.terminate()
                return
            while not await self.verify():
                await asyncio.sleep(self.recheck_seconds)
            await self._report_verified()
        except Exception as exc:
            log.error("자가 점검 실행 오류: %s", type(exc).__name__)
            await self._fail(error=type(exc).__name__)
            if self.config.required:
                self.terminate()

    async def _report_mismatches(self) -> None:
        """승인된 계약과 다른 서버마다 사건을 한 건 남긴다. 그 서버의 호출은 판정에서 차단된다."""
        by_server: dict[str, list[str]] = {}
        for server_id, name in self.last_mismatches:
            by_server.setdefault(server_id, []).append(name)
        for server_id, names in by_server.items():
            fields = tuple(names)
            hashes = self._observed_hashes.get(server_id)
            identity = hashes if hashes is not None else {name: "" for name in fields}
            if self._reported.get(server_id) == identity:
                continue
            kind = EventKind.SERVER_IDENTITY_MISMATCH_OBSERVED
            payload = {"server_id": server_id, "fields": list(fields)}
            if hashes is not None:
                payload["observed_hashes"] = hashes
            await self.recorder.record(
                Event(
                    instance_id=self.config.instance_id,
                    inserted_at=datetime.now(UTC),
                    kind=kind,
                    source_key=self.keys.next(kind),
                    payload=payload,
                )
            )
            self._reported[server_id] = identity
        self._reported = {key: value for key, value in self._reported.items() if key in by_server}

    async def _fail(self, error: str | None = None) -> None:
        failed = [
            {"item": int(r.item), "name": r.item.name, "detail": r.detail}
            for r in self.last_results
            if not r.ok
        ]
        payload: dict[str, Any] = {
            "worker_id": worker_id(),
            "litellm": litellm_summary(),
            "failed": failed,
        }
        if error is not None:
            payload["error"] = error
        event = Event(
            instance_id=self.config.instance_id,
            inserted_at=datetime.now(UTC),
            kind=EventKind.ENFORCEMENT_UNVERIFIED,
            source_key=self.keys.next(EventKind.ENFORCEMENT_UNVERIFIED),
            payload=payload,
        )
        await self.recorder.record(event)
        log.error(
            "MINT 자가 점검 실패: %s",
            ", ".join(f"{SELF_CHECK_DESCRIPTIONS[r.item]}" for r in self.last_results if not r.ok)
            or (error or "unknown"),
        )


def freeze_collector() -> None:
    """기동까지 만들어진 객체를 가비지 수거 대상에서 뺀다.

    LiteLLM은 기동하며 수백만 개의 객체를 만든다. 가장 오래된 세대를 수거할 때마다 그 객체를 모두
    훑느라 이벤트 루프가 0.5~1초 멈추고, 그동안 판정이 예산을 넘겨 차단된다. 기동 직후 한 번 수거한
    뒤 얼려 두면 이후 수거는 얼린 뒤에 만들어진 객체만 훑는다. 얼린 객체는 이후 수거되지 않는다.
    """
    gc.collect()
    gc.freeze()


def litellm_summary() -> dict[str, Any]:
    """이 복제본의 LiteLLM 보장 등급. 점검 결과와 함께 한 번 남기므로 호출 경로에 DB 접근이 없다."""
    found = compat.litellm_assessment()
    return {
        "version": found.version,
        "grade": found.grade,
        "tested": found.tested,
        "missing": list(found.missing),
    }


def worker_id() -> str:
    """이 워커를 가리키는 값. 복제본마다 호스트 이름이 다르므로 프로세스 번호가 겹쳐도 구분된다."""
    return f"{socket.gethostname()}:{os.getpid()}"


class PolicyEngine:
    """OPA 클라이언트를 이벤트 루프마다 하나씩 만들어 쓰고, 그 루프가 끝나면 닫는다.

    클라이언트는 만든 프로세스·루프 밖에서 쓰면 ``RuntimeError``를 내므로, 프로세스나 루프가
    바뀌면 새로 만든다. 클라이언트를 닫는 일은 그 루프에 남겨 둔 작업이 맡는다. 루프가 끝나며
    남은 작업을 취소할 때 그 작업이 연결을 닫는다.
    """

    def __init__(self, base_url: str, timeout_seconds: float) -> None:
        self._base_url = base_url
        self._timeout = timeout_seconds
        self._client: OPAClient | None = None
        self._owner: tuple[int, asyncio.AbstractEventLoop] | None = None
        self._guard: asyncio.Task[None] | None = None

    def _opa(self) -> OPAClient:
        loop = asyncio.get_running_loop()
        owner = (os.getpid(), loop)
        if self._client is None or self._owner != owner:
            client = OPAClient(self._base_url, self._timeout)
            self._client, self._owner = client, owner
            self._guard = loop.create_task(self._close_with_loop(client))
        return self._client

    async def secret_markers(
        self, *, policy_version_id: str, bundle_sha256: str, budget_seconds: float | None = None
    ) -> tuple[str, ...] | None:
        return await self._opa().secret_markers(
            policy_version_id=policy_version_id,
            bundle_sha256=bundle_sha256,
            budget_seconds=budget_seconds,
        )

    async def evaluate(
        self,
        policy_input: dict[str, Any],
        *,
        policy_version_id: str,
        bundle_sha256: str,
        budget_seconds: float | None = None,
    ) -> Evaluation:
        return await self._opa().evaluate(
            policy_input,
            policy_version_id=policy_version_id,
            bundle_sha256=bundle_sha256,
            budget_seconds=budget_seconds,
        )

    @staticmethod
    async def _close_with_loop(client: OPAClient) -> None:
        try:
            await asyncio.Event().wait()
        finally:
            await client.aclose()

    async def aclose(self) -> None:
        client, guard = self._client, self._guard
        self._client = self._owner = self._guard = None
        if guard is not None:
            guard.cancel()
        if client is not None:
            await client.aclose()


_runtime: PluginRuntime | None = None


def _audience_capability(config: PluginConfig, probe) -> PluginConfig:
    """호출자 토큰이 훅에 오지 않는 LiteLLM이면 aud 대조를 끈다(``off``). 이 능력은 선택이라
    기동은 막지 않지만, 집행(``enforce``)을 요청했는데 확인할 수 없으면 조용히 풀지 않고 멈춘다."""
    problem = probe()
    if problem is None:
        return config
    if config.token_audience == "enforce":
        raise RuntimeError(f"MINT_TOKEN_AUDIENCE=enforce cannot be honored: {problem}")
    log.warning("호출자 토큰이 훅에 전달되지 않아 토큰 대상(aud) 확인을 끕니다: %s", problem)
    return replace(config, token_audience="off")


def _scope_capability(config: PluginConfig, probe) -> PluginConfig:
    """호출자 토큰이 훅에 오지 않는 LiteLLM이면 범위 대조를 끈다(``off``). 집행을 요청했는데
    확인할 수 없으면 조용히 풀지 않고 기동을 멈춘다."""
    problem = probe()
    if problem is None or config.token_scope == "off":
        return config
    if config.token_scope == "enforce":
        raise RuntimeError(f"MINT_TOKEN_SCOPE=enforce cannot be honored: {problem}")
    log.warning("호출자 토큰이 훅에 전달되지 않아 토큰 범위 확인을 끕니다: %s", problem)
    return replace(config, token_scope="off")


def get_runtime(env: Mapping[str, str] | None = None) -> PluginRuntime:
    """프로세스 전역 실행 상태. 처음 부를 때 환경 변수에서 설정을 읽는다."""
    global _runtime
    if _runtime is None:
        config = PluginConfig.from_env(os.environ if env is None else env)
        configure_logging(config.log_level)
        config = _audience_capability(config, compat.bearer_passthrough_problem)
        config = _scope_capability(config, compat.bearer_passthrough_problem)
        database = PluginDatabase(
            config.database_url,
            max_size=config.db_pool_size,
            acquire_timeout=config.decision_budget_seconds,
        )
        recorder = EvidenceRecorder(
            database,
            LocalBuffer(config.buffer_dir, config.buffer_max_bytes),
            budget_seconds=config.decision_budget_seconds,
            instance_id=config.instance_id,
        )
        engine = PolicyEngine(config.opa_url, config.decision_budget_seconds)
        shadow = None
        if config.shadow_opa_url:
            shadow = ShadowWatch(
                config.instance_id, database,
                PolicyEngine(config.shadow_opa_url, config.decision_budget_seconds).evaluate,
                sample_percent=config.shadow_sample_percent,
                max_per_second=config.shadow_max_per_second,
            )
        _runtime = PluginRuntime(
            config=config,
            database=database,
            recorder=recorder,
            restore_watch=RestoreWatch(config, database),
            shadow=shadow,
            evaluate=engine.evaluate,
            secret_markers=engine.secret_markers,
        )
    return _runtime
