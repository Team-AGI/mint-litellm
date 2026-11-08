import asyncio
import io
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest
from plugin_helpers import FakeStore, config

from mint_litellm.compat.litellm_1_106 import RegistryEntry
from mint_litellm.plugin.buffer import EvidenceRecorder, LocalBuffer, SystemEventKeys
from mint_litellm.plugin.selfcheck import (
    LiteLLMView,
    PluginRuntime,
    PolicyEngine,
    check_items,
    collect_view,
    contract_mismatches,
    guardrail_definition_check,
    terminate_process,
    worker_id,
)
from mint_litellm.plugin.snapshot import RegisteredServer
from mint_litellm.types.decision import url_sha256
from mint_litellm.types.events import EventKind
from mint_litellm.types.settings import SELF_CHECK_DESCRIPTIONS, SelfCheckItem

URL = "https://mcp.example/api"
HASH = url_sha256(URL)


def entry(server_id="srv-1", names=("mslearn",), **override):
    args = {
        "server_id": server_id,
        "names": names,
        "url_sha256": HASH,
        "transport": "http",
        "auth_type": "none",
        "allow_all_keys": False,
    }
    args.update(override)
    return RegistryEntry(**args)


class FakeLogger:
    pass


def _always_judges(self, data, event_type):
    return True


class FakeGuardrail:
    should_run_guardrail = _always_judges
    mint_should_run_guardrail = _always_judges

    def __init__(self, **attributes):
        self.__dict__.update(attributes)


class OtherGuardrail(FakeGuardrail):
    """MINT가 아닌 다른 가드레일 대역."""


def guardrail(**override):
    args = {
        "guardrail_name": "mint",
        "event_hook": ["pre_call", "pre_mcp_call", "post_mcp_call"],
        "default_on": True,
        "run_in_parallel": True,
        "scan_raw_request": False,
    }
    args.update(override)
    return FakeGuardrail(**args)


LOGGER = FakeLogger()
GUARDRAIL = guardrail()


def view(**override):
    args = {
        "callbacks": [LOGGER, GUARDRAIL],
        "general_settings": {"require_key_mcp_access_defined": True},
        "strict_guardrail_modes": True,
        "store_prompts_in_spend_logs": False,
        "user_url_validation": True,
        "registry": [entry()],
        "missing_symbols": [],
    }
    args.update(override)
    return LiteLLMView(**args)


def registered(**override):
    args = {
        "server_id": "srv-1",
        "status": "approved",
        "url_sha256": HASH,
        "transport": "http",
        "auth_type": "none",
    }
    args.update(override)
    return RegisteredServer(**args)


def run_checks(v=None, *, logger=LOGGER, guard=GUARDRAIL, controlled="default"):
    return check_items(
        v or view(),
        logger=logger,
        guardrail=guard,
        controlled=[registered()] if controlled == "default" else controlled,
    )


def event_kinds(store):
    return sorted(e.kind.value for e in store.events.values())


def failed(results):
    return {r.item for r in results if not r.ok}


def test_all_eight_items_are_reported_and_a_good_setup_passes():
    results = run_checks()
    assert [r.item for r in results] == list(SelfCheckItem)
    assert failed(results) == set()


def test_item_1_logger_must_be_registered_exactly_once():
    assert failed(run_checks(view(callbacks=[GUARDRAIL]))) >= {SelfCheckItem.CALLBACK_REGISTERED}
    assert SelfCheckItem.CALLBACK_REGISTERED in failed(run_checks(logger=None))
    twice = view(callbacks=[FakeLogger(), LOGGER, GUARDRAIL])
    assert SelfCheckItem.CALLBACK_REGISTERED in failed(run_checks(twice))


def test_item_2_guardrail_modes_and_default_on():
    other = (
        SimpleNamespace(value="pre_call"),
        SimpleNamespace(value="pre_mcp_call"),
        SimpleNamespace(value="post_mcp_call"),
    )
    enum_style = guardrail(event_hook=list(other))
    assert failed(run_checks(view(callbacks=[LOGGER, enum_style]), guard=enum_style)) == set()
    for bad in (
        guardrail(event_hook=["pre_mcp_call"]),
        guardrail(event_hook=["post_mcp_call"]),
        guardrail(event_hook=["pre_mcp_call", "post_mcp_call"]),
        guardrail(event_hook=["pre_call"]),
        guardrail(event_hook="pre_mcp_call"),
        guardrail(event_hook=None),
        guardrail(default_on=False),
    ):
        results = run_checks(view(callbacks=[LOGGER, bad]), guard=bad)
        assert SelfCheckItem.GUARDRAIL_MODES in failed(results)
    results = run_checks(view(callbacks=[LOGGER]))
    assert SelfCheckItem.GUARDRAIL_MODES in failed(results)
    assert SelfCheckItem.GUARDRAIL_MODES in failed(run_checks(guard=None))


def definition_failed(callbacks, *, guard=GUARDRAIL):
    results = run_checks(view(callbacks=callbacks), guard=guard)
    return SelfCheckItem.GUARDRAIL_ORDER in failed(results)


def test_item_3_one_parallel_guardrail_with_its_judgment_intact_passes():
    assert not definition_failed([LOGGER, GUARDRAIL])
    assert guardrail_definition_check([LOGGER, GUARDRAIL], GUARDRAIL) == (True, "")


def test_item_3_the_order_of_the_callbacks_does_not_matter():
    assert not definition_failed([GUARDRAIL, LOGGER])
    assert not definition_failed([object(), GUARDRAIL, object(), LOGGER])
    assert not definition_failed([OtherGuardrail(guardrail_name="pii"), LOGGER, GUARDRAIL])


def test_item_3_a_missing_guardrail_fails():
    assert definition_failed([LOGGER], guard=None)


def test_item_3_a_second_guardrail_of_the_same_kind_fails():
    second = FakeGuardrail(**GUARDRAIL.__dict__)
    assert definition_failed([LOGGER, GUARDRAIL, second])


def test_item_3_the_guardrail_must_run_in_parallel_and_skip_the_raw_request():
    sequential = guardrail(run_in_parallel=False)
    assert definition_failed([LOGGER, sequential], guard=sequential)
    unset = guardrail(run_in_parallel=None)
    assert definition_failed([LOGGER, unset], guard=unset)
    scanning = guardrail(scan_raw_request=True)
    assert definition_failed([LOGGER, scanning], guard=scanning)


@pytest.mark.parametrize("name", ["should_run_guardrail", "async_pre_call_hook"])
def test_item_3_a_method_replaced_on_the_instance_fails(name):
    replaced = FakeGuardrail(**GUARDRAIL.__dict__)
    assert not definition_failed([LOGGER, replaced], guard=replaced)
    setattr(replaced, name, lambda *args, **kwargs: True)
    assert definition_failed([LOGGER, replaced], guard=replaced)
    ok, detail = guardrail_definition_check([LOGGER, replaced], replaced)
    assert not ok and name in detail and "instance" in detail


def test_item_3_a_replaced_judgment_override_fails():
    class Replaced(FakeGuardrail):
        def should_run_guardrail(self, data, event_type):
            return False

    replaced = Replaced(**GUARDRAIL.__dict__)
    assert definition_failed([LOGGER, replaced], guard=replaced)
    assert guardrail_definition_check([LOGGER, replaced], replaced)[1].endswith("replaced")

    class Missing:
        run_in_parallel = True
        scan_raw_request = False

        def should_run_guardrail(self, data, event_type):
            return True

    missing = Missing()
    assert definition_failed([LOGGER, missing], guard=missing)


def test_item_4_key_access_is_strict_for_controlled_servers():
    assert SelfCheckItem.KEY_ACCESS_STRICT in failed(run_checks(view(general_settings={})))
    assert SelfCheckItem.KEY_ACCESS_STRICT in failed(
        run_checks(view(general_settings={"require_key_mcp_access_defined": "true"}))
    )
    open_server = view(registry=[entry(allow_all_keys=True)])
    assert SelfCheckItem.KEY_ACCESS_STRICT in failed(run_checks(open_server))
    uncontrolled_open = view(registry=[entry(), entry("srv-9", ("other",), allow_all_keys=True)])
    assert SelfCheckItem.KEY_ACCESS_STRICT not in failed(run_checks(uncontrolled_open))


@pytest.mark.parametrize(
    "mutation",
    [
        {"url_sha256": url_sha256("https://changed/")},
        {"transport": "sse"},
        {"auth_type": "bearer_token"},
    ],
    ids=["url", "transport", "auth"],
)
def test_item_5_does_not_fail_when_a_contract_value_differs(mutation):
    changed = view(registry=[entry(**mutation)])
    assert SelfCheckItem.SERVER_REGISTRY_MATCH not in failed(run_checks(changed))
    (field,) = mutation
    assert contract_mismatches(changed, [registered()]) == [("srv-1", field)]


def test_contract_mismatches_cover_only_controlled_servers_present_in_the_registry():
    changed = view(registry=[entry(transport="sse", auth_type="oauth2")])
    assert contract_mismatches(changed, [registered()]) == [
        ("srv-1", "transport"),
        ("srv-1", "auth_type"),
    ]
    assert contract_mismatches(changed, [registered(status="pending")]) == []
    # 승인된 서버가 레지스트리에서 지워진 경우는 자가 점검 5번이 막으므로 세지 않는다.
    assert contract_mismatches(view(registry=[]), [registered()]) == []
    assert contract_mismatches(view(), [registered()]) == []
    assert contract_mismatches(view(registry=[]), [registered(status="suspended")]) == [
        ("srv-1", "registry_missing")
    ]


def test_item_5_registry_must_contain_every_controlled_server():
    assert SelfCheckItem.SERVER_REGISTRY_MATCH in failed(run_checks(view(registry=[])))
    results = run_checks(view(registry=[]), controlled=[registered(status="approved")])
    assert SelfCheckItem.SERVER_REGISTRY_MATCH in failed(results)
    other_states = (
        "suspended",
        "pending",
        "validating",
        "awaiting_approval",
        "rejected",
        "terminating",
        "terminated",
    )
    for status in other_states:
        results = run_checks(view(registry=[]), controlled=[registered(status=status)])
        assert SelfCheckItem.SERVER_REGISTRY_MATCH not in failed(results)


def test_items_4_and_5_fail_when_the_mint_database_cannot_be_read():
    assert {SelfCheckItem.KEY_ACCESS_STRICT, SelfCheckItem.SERVER_REGISTRY_MATCH} <= failed(
        run_checks(controlled=None)
    )


def test_item_6_names_and_aliases_are_unique_across_servers():
    clash = view(registry=[entry(), entry("srv-2", ("mslearn", "other"))])
    assert failed(run_checks(clash)) >= {SelfCheckItem.NAME_ALIAS_UNIQUE}
    spaced = view(registry=[entry(names=("my server",)), entry("srv-2", ("my_server",))])
    assert SelfCheckItem.NAME_ALIAS_UNIQUE in failed(run_checks(spaced))
    same_server = view(registry=[entry(names=("mslearn", "mslearn", "ms"))])
    assert SelfCheckItem.NAME_ALIAS_UNIQUE not in failed(run_checks(same_server))


def test_item_7_symbols():
    results = run_checks(view(missing_symbols=["litellm.x:y"]))
    assert SelfCheckItem.COMPAT_SYMBOLS in failed(results)
    assert (
        "litellm.x:y" in next(r for r in results if r.item is SelfCheckItem.COMPAT_SYMBOLS).detail
    )


@pytest.mark.parametrize(
    "override",
    [
        {"strict_guardrail_modes": False},
        {"store_prompts_in_spend_logs": True},
        {"user_url_validation": False},
        {
            "general_settings": {
                "require_key_mcp_access_defined": True,
                "supported_db_objects": ["models"],
            }
        },
    ],
)
def test_item_8_required_settings(override):
    assert failed(run_checks(view(**override))) == {SelfCheckItem.REQUIRED_SETTINGS}


def test_item_8_requires_the_fingerprint_key():
    results = check_items(
        view(),
        logger=LOGGER,
        guardrail=GUARDRAIL,
        controlled=[registered()],
        fingerprint_key_set=False,
    )
    assert failed(results) == {SelfCheckItem.REQUIRED_SETTINGS}
    (detail,) = [r.detail for r in results if not r.ok]
    assert "MINT_FINGERPRINT_KEY" in detail


def test_a_runtime_without_the_fingerprint_key_does_not_start(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path)
    runtime.config = replace(runtime.config, fingerprint_key=None)
    asyncio.run(runtime._startup())
    assert stopped == [1] and not runtime.verified
    (event,) = store.of_kind("enforcement_unverified")
    assert [f["name"] for f in event.payload["failed"]] == [SelfCheckItem.REQUIRED_SETTINGS.name]


def test_item_8_accepts_a_supported_db_objects_list_with_mcp():
    settings = {"require_key_mcp_access_defined": True, "supported_db_objects": ["models", "mcp"]}
    assert failed(run_checks(view(general_settings=settings))) == set()


def test_failure_details_never_contain_credentials_or_urls():
    results = run_checks(view(registry=[entry(transport="sse")]))
    text = " ".join(r.detail for r in results)
    assert "mcp.example" not in text


def make_runtime(
    tmp_path,
    *,
    v=None,
    controlled=None,
    required=True,
    retry=0.01,
    ready=True,
    store=None,
    stopped=None,
    grace=0.05,
    ready_delay=0.0,
    database_delay=0.0,
):
    store = store if store is not None else FakeStore()
    recorder = EvidenceRecorder(
        store,
        LocalBuffer(tmp_path / "buf", 1024 * 1024),
        budget_seconds=1.0,
        instance_id="inst",
        stderr=io.StringIO(),
    )

    class Database:
        async def registered_servers(self, instance_id):
            await asyncio.sleep(database_delay)
            if controlled is Exception:
                raise ConnectionError("down")
            return [registered()] if controlled is None else controlled

    stopped = stopped if stopped is not None else []
    state = {"view": v or view()}

    waited: list[float] = []

    async def readiness(url, timeout):
        waited.append(timeout)
        await asyncio.sleep(ready_delay)
        return ready

    runtime = PluginRuntime(
        config=config(tmp_path, required=required, selfcheck_grace_seconds=grace),
        database=Database(),
        recorder=recorder,
        evaluate=None,
        view_collector=lambda: state["view"],
        terminate=lambda: stopped.append(1),
        readiness=readiness,
        retry_seconds=retry,
        recheck_seconds=retry,
    )
    runtime.logger, runtime.guardrail = LOGGER, GUARDRAIL
    runtime.readiness_waits = waited
    return runtime, store, stopped, state


def test_a_runtime_is_unverified_until_every_item_passes(tmp_path):
    runtime, _, _, state = make_runtime(tmp_path)
    assert runtime.verified is False
    assert asyncio.run(runtime.verify()) is True and runtime.verified is True
    state["view"] = view(strict_guardrail_modes=False)
    assert asyncio.run(runtime.verify()) is False and runtime.verified is False


def test_a_passing_startup_verifies_without_stopping(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path)
    asyncio.run(runtime._startup())
    assert runtime.verified and stopped == [] and event_kinds(store) == ["enforcement_verified"]


def test_a_failing_startup_records_the_failure_and_stops_the_process(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path, v=view(callbacks=[GUARDRAIL]))
    asyncio.run(runtime._startup())
    assert not runtime.verified and stopped == [1]
    (event,) = store.of_kind("enforcement_unverified")
    assert event.source_key.startswith("selfcheck:") and event.source_key.endswith(
        ":1:enforcement_unverified"
    )
    assert event.payload["failed"][0]["item"] == 1
    assert event.payload["failed"][0]["name"] == SelfCheckItem.CALLBACK_REGISTERED.name


def test_a_failure_that_resolves_within_the_grace_period_does_not_stop(tmp_path):
    runtime, store, stopped, state = make_runtime(tmp_path, v=view(strict_guardrail_modes=False))
    runtime.config = replace(runtime.config, selfcheck_grace_seconds=5.0)

    async def scenario():
        task = asyncio.create_task(runtime._startup())
        await asyncio.sleep(0.05)
        state["view"] = view()
        await task

    asyncio.run(scenario())
    assert runtime.verified and stopped == [] and event_kinds(store) == ["enforcement_verified"]


def test_a_non_required_runtime_stays_blocked_and_recovers_later(tmp_path):
    runtime, store, stopped, state = make_runtime(
        tmp_path, v=view(strict_guardrail_modes=False), required=False
    )

    async def scenario():
        task = asyncio.create_task(runtime._startup())
        await asyncio.sleep(0.3)
        assert not runtime.verified
        state["view"] = view()
        await task

    asyncio.run(scenario())
    assert runtime.verified and stopped == []
    assert len(store.of_kind("enforcement_unverified")) == 1


def test_an_unreadable_mint_database_fails_the_startup_checks(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path, controlled=Exception)
    asyncio.run(runtime._startup())
    assert stopped == [1]
    names = {f["name"] for f in store.of_kind("enforcement_unverified")[0].payload["failed"]}
    assert {"KEY_ACCESS_STRICT", "SERVER_REGISTRY_MATCH"} <= names


def test_an_error_while_checking_also_stops_the_process(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path)

    def broken():
        raise KeyError("x")

    runtime.view_collector = broken
    asyncio.run(runtime._startup())
    assert stopped == [1]
    assert store.of_kind("enforcement_unverified")[0].payload["error"] == "KeyError"


def test_startup_is_scheduled_once_and_only_inside_a_running_loop(tmp_path):
    runtime, _, _, _ = make_runtime(tmp_path)
    runtime.ensure_started()
    assert runtime._task is None

    async def scenario():
        runtime.ensure_started()
        first = runtime._task
        runtime.ensure_started()
        assert runtime._task is first
        await first

    asyncio.run(scenario())
    assert runtime.verified


def test_descriptions_exist_for_every_item():
    assert set(SELF_CHECK_DESCRIPTIONS) == set(SelfCheckItem)


def test_view_reports_missing_symbols_when_litellm_is_absent_or_other(monkeypatch):
    from mint_litellm.compat import litellm_1_106 as compat

    monkeypatch.setattr(compat, "missing_symbols", lambda: ["litellm: not installed"])
    collected = collect_view({})
    assert collected.missing_symbols == ["litellm: not installed"]
    assert SelfCheckItem.COMPAT_SYMBOLS in failed(
        check_items(collected, logger=LOGGER, guardrail=GUARDRAIL, controlled=[])
    )


class FakeOPAClient:
    """OPAClient 대역: 만들어진 개수와 닫힘, 받은 시간 예산을 센다."""

    created: list = []

    def __init__(self, base_url, timeout_seconds):
        self.closed = False
        self.budgets: list = []
        FakeOPAClient.created.append(self)

    async def evaluate(
        self, policy_input, *, policy_version_id, bundle_sha256, budget_seconds=None
    ):
        self.budgets.append(budget_seconds)
        return "evaluated"

    async def aclose(self):
        self.closed = True


class TestPolicyEngine:
    @pytest.fixture(autouse=True)
    def fake_client(self, monkeypatch):
        from mint_litellm.plugin import selfcheck

        FakeOPAClient.created = []
        monkeypatch.setattr(selfcheck, "OPAClient", FakeOPAClient)

    @staticmethod
    async def ask(engine, budget=None):
        return await engine.evaluate(
            {}, policy_version_id="v", bundle_sha256="b", budget_seconds=budget
        )

    def test_one_client_serves_a_loop_and_gets_the_remaining_budget(self):
        engine = PolicyEngine("http://opa", 0.3)

        async def scenario():
            await self.ask(engine, 0.2)
            await self.ask(engine, 0.1)

        asyncio.run(scenario())
        (client,) = FakeOPAClient.created
        assert client.budgets == [0.2, 0.1]

    def test_the_client_is_closed_when_its_loop_ends(self):
        engine = PolicyEngine("http://opa", 0.3)
        asyncio.run(self.ask(engine))
        (client,) = FakeOPAClient.created
        assert client.closed

    def test_a_new_loop_gets_a_new_client_and_the_old_one_stays_closed(self):
        engine = PolicyEngine("http://opa", 0.3)
        asyncio.run(self.ask(engine))
        asyncio.run(self.ask(engine))
        first, second = FakeOPAClient.created
        assert first.closed and second.closed and first is not second

    def test_closing_the_engine_closes_the_client_once(self):
        engine = PolicyEngine("http://opa", 0.3)

        async def scenario():
            await self.ask(engine)
            await engine.aclose()
            return FakeOPAClient.created[0].closed

        assert asyncio.run(scenario()) is True
        asyncio.run(self.ask(engine))
        assert len(FakeOPAClient.created) == 2


def test_the_runtime_is_built_from_the_environment_with_the_policy_client(tmp_path, monkeypatch):
    from mint_litellm.plugin import selfcheck

    monkeypatch.setattr(selfcheck, "_runtime", None)
    env = {
        "MINT_INSTANCE_ID": "prod",
        "MINT_DATABASE_URL": "postgresql://mint@db/mint",
        "MINT_OPA_URL": "http://opa:8181",
        "MINT_BUFFER_DIR": str(tmp_path / "buffer"),
        "MINT_DECISION_BUDGET_MS": "250",
    }
    runtime = selfcheck.get_runtime(env)
    assert runtime is selfcheck.get_runtime(env)
    assert runtime.config.decision_budget_seconds == 0.25
    assert isinstance(runtime.evaluate.__self__, PolicyEngine)
    assert runtime.database.acquire_timeout == 0.25 and runtime.verified is False
    monkeypatch.setattr(selfcheck, "_runtime", None)


def test_a_runtime_without_the_required_environment_raises_runtime_error(monkeypatch):
    from mint_litellm.plugin import selfcheck

    monkeypatch.setattr(selfcheck, "_runtime", None)
    with pytest.raises(RuntimeError):
        selfcheck.get_runtime({})


def test_a_contract_mismatch_does_not_stop_startup_and_is_recorded_once_per_server(tmp_path):
    changed = view(registry=[entry(transport="sse", url_sha256=url_sha256("https://moved/"))])
    runtime, store, stopped, _ = make_runtime(tmp_path, v=changed)
    asyncio.run(runtime._startup())
    assert runtime.verified and stopped == []
    (event,) = store.of_kind("server_identity_mismatch_observed")
    assert event.payload == {"server_id": "srv-1", "fields": ["url_sha256", "transport"]}
    assert event.actor is None and event.invocation_id is None
    assert (
        event.source_key == f"selfcheck:{runtime.keys.run_id}:1:server_identity_mismatch_observed"
    )
    asyncio.run(runtime._report_mismatches())
    assert len(store.of_kind("server_identity_mismatch_observed")) == 1


def test_same_mismatch_field_with_new_value_emits_new_observation(tmp_path):
    runtime, store, _, state = make_runtime(
        tmp_path, v=view(registry=[entry(transport="sse")]),
        controlled=[registered(contract_status="managed")],
    )

    async def observe():
        await runtime.run_checks()
        await runtime._report_mismatches()

    asyncio.run(observe())
    asyncio.run(observe())
    assert len(store.of_kind("server_identity_mismatch_observed")) == 1
    state["view"] = view(registry=[entry(transport="streamable_http")])
    asyncio.run(observe())
    observed = store.of_kind("server_identity_mismatch_observed")
    assert len(observed) == 2
    assert observed[0].payload["observed_hashes"] != observed[1].payload["observed_hashes"]
    assert "streamable_http" not in str(observed[1].payload)


def test_managed_issuer_changes_are_observed_without_calls(tmp_path):
    runtime, store, _, _ = make_runtime(tmp_path,
        v=view(registry=[entry(issuer="https://changed.test")]),
        controlled=[registered(contract_status="managed", issuer="https://approved.test")])
    asyncio.run(runtime.run_checks())
    asyncio.run(runtime._report_mismatches())
    event, = store.of_kind("server_identity_mismatch_observed")
    assert event.payload["fields"] == ["issuer"]
    assert "https://changed.test" not in str(event.payload)


def test_legacy_mismatch_keeps_its_payload_and_field_based_deduplication(tmp_path):
    runtime, store, _, state = make_runtime(tmp_path, v=view(registry=[entry(transport="sse")]))

    async def observe():
        await runtime.run_checks()
        await runtime._report_mismatches()

    asyncio.run(observe())
    state["view"] = view(registry=[entry(transport="streamable_http")])
    asyncio.run(observe())
    event, = store.of_kind("server_identity_mismatch_observed")
    assert event.payload == {"server_id": "srv-1", "fields": ["transport"]}


def test_a_suspended_server_missing_from_the_registry_does_not_stop_startup(tmp_path):
    runtime, store, stopped, state = make_runtime(
        tmp_path, v=view(registry=[]), controlled=[registered(status="suspended")]
    )
    asyncio.run(runtime._startup())
    assert runtime.verified and stopped == []
    (event,) = store.of_kind("server_identity_mismatch_observed")
    assert event.payload == {"server_id": "srv-1", "fields": ["registry_missing"]}
    asyncio.run(runtime._report_mismatches())
    assert len(store.of_kind("server_identity_mismatch_observed")) == 1


def test_an_approved_server_missing_from_the_registry_still_stops_startup(tmp_path):
    runtime, store, stopped, _ = make_runtime(
        tmp_path, v=view(registry=[]), controlled=[registered(status="approved")]
    )
    asyncio.run(runtime._startup())
    assert not runtime.verified and stopped == [1]
    assert store.of_kind("server_identity_mismatch_observed") == []


def test_two_servers_with_a_mismatch_leave_two_events_with_their_own_keys(tmp_path):
    changed = view(
        registry=[
            entry("srv-1", names=("one",), transport="sse"),
            entry("srv-2", names=("two",), auth_type="bearer"),
        ]
    )
    controlled = [registered(server_id="srv-1"), registered(server_id="srv-2")]
    runtime, store, stopped, _ = make_runtime(tmp_path, v=changed, controlled=controlled)
    asyncio.run(runtime._startup())
    assert runtime.verified and stopped == []
    events = store.of_kind("server_identity_mismatch_observed")
    assert sorted((e.payload["server_id"], tuple(e.payload["fields"])) for e in events) == [
        ("srv-1", ("transport",)),
        ("srv-2", ("auth_type",)),
    ]
    run_id = runtime.keys.run_id
    assert sorted(e.source_key for e in events) == [
        f"selfcheck:{run_id}:1:server_identity_mismatch_observed",
        f"selfcheck:{run_id}:2:server_identity_mismatch_observed",
    ]


def test_a_run_issues_keys_from_one_and_another_run_gets_other_keys():
    first, second = SystemEventKeys(), SystemEventKeys()
    kind = EventKind.ENFORCEMENT_UNVERIFIED
    keys = [first.next(kind), first.next(kind), second.next(kind)]
    assert keys[0].endswith(":1:enforcement_unverified")
    assert keys[1].endswith(":2:enforcement_unverified")
    assert keys[2].endswith(":1:enforcement_unverified")
    assert len(set(keys)) == 3


def test_failures_of_two_startups_in_one_database_both_remain(tmp_path):
    store = FakeStore()
    stopped: list[int] = []
    for index in range(2):
        runtime, _, _, _ = make_runtime(
            tmp_path / str(index), v=view(callbacks=[GUARDRAIL]), store=store, stopped=stopped
        )
        asyncio.run(runtime._startup())
    keys = [e.source_key for e in store.of_kind("enforcement_unverified")]
    assert len(keys) == 2 and len(set(keys)) == 2
    assert all(key.endswith(":1:enforcement_unverified") for key in keys)


def test_a_mismatch_is_also_recorded_when_another_item_stops_the_startup(tmp_path):
    changed = view(registry=[entry(transport="sse")], strict_guardrail_modes=False)
    runtime, store, stopped, _ = make_runtime(tmp_path, v=changed)
    asyncio.run(runtime._startup())
    assert stopped == [1]
    assert len(store.of_kind("server_identity_mismatch_observed")) == 1
    assert len(store.of_kind("enforcement_unverified")) == 1


class TestVerifiedEvent:
    def test_every_worker_that_passes_records_one_event_of_its_own(self, tmp_path):
        store = FakeStore()
        for index in range(2):
            runtime, _, _, _ = make_runtime(tmp_path / str(index), store=store)
            asyncio.run(runtime._startup())
        events = store.of_kind("enforcement_verified")
        assert len(events) == 2 and len({e.source_key for e in events}) == 2
        for event in events:
            assert event.source_key.startswith("selfcheck:")
            assert event.source_key.endswith(":1:enforcement_verified")
            assert event.payload["worker_id"] == worker_id()
            assert [c["item"] for c in event.payload["checks"]] == list(range(1, 9))
            assert all(c["ok"] for c in event.payload["checks"])
            assert event.payload["checks"][2]["name"] == SelfCheckItem.GUARDRAIL_ORDER.name

    def test_a_failed_startup_records_no_verification(self, tmp_path):
        runtime, store, _, _ = make_runtime(tmp_path, v=view(callbacks=[LOGGER]))
        asyncio.run(runtime._startup())
        assert store.of_kind("enforcement_verified") == []

    def test_a_worker_that_passes_later_records_the_verification_once(self, tmp_path):
        runtime, store, stopped, state = make_runtime(
            tmp_path, v=view(strict_guardrail_modes=False), required=False
        )

        async def scenario():
            task = asyncio.create_task(runtime._startup())
            await asyncio.sleep(0.3)
            assert store.of_kind("enforcement_verified") == []
            state["view"] = view()
            await task

        asyncio.run(scenario())
        assert runtime.verified and stopped == []
        assert event_kinds(store) == ["enforcement_unverified", "enforcement_verified"]

    def test_a_copy_that_went_through_the_buffer_converges_into_one_row(self, tmp_path):
        class CommitsThenFails(FakeStore):
            armed = True

            async def insert_event(self, event, consume=None):
                inserted = await super().insert_event(event, consume)
                if self.armed and event.kind.value == "enforcement_verified":
                    self.armed = False
                    raise ConnectionResetError("response lost")
                return inserted

        store = CommitsThenFails()
        runtime, _, _, _ = make_runtime(tmp_path, store=store)

        async def scenario():
            await runtime._startup()
            runtime.recorder._buffer.close()
            await runtime.recorder.replay()

        asyncio.run(scenario())
        assert len(store.of_kind("enforcement_verified")) == 1
        (report,) = store.of_kind("buffer_replayed")
        assert report.payload["duplicates"] == 1 and report.payload["replayed"] == 0


def test_readiness_is_awaited_for_at_most_the_grace_period(tmp_path):
    runtime, _, _, _ = make_runtime(tmp_path)
    asyncio.run(runtime._startup())
    assert runtime.readiness_waits == [runtime.config.selfcheck_grace_seconds]


def test_without_readiness_in_time_the_startup_is_recorded_and_stopped(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path, ready=False)
    runtime.view_collector = lambda: pytest.fail("no check runs before readiness")
    asyncio.run(runtime._startup())
    assert stopped == [1] and not runtime.verified
    (event,) = store.of_kind("enforcement_unverified")
    assert event.payload == {"worker_id": worker_id(), "failed": [], "error": "readiness_timeout"}


def test_readiness_and_checks_share_one_time_limit(tmp_path):
    runtime, store, stopped, _ = make_runtime(
        tmp_path, grace=0.3, ready_delay=0.15, database_delay=0.4
    )
    asyncio.run(runtime._startup())
    assert stopped == [1] and not runtime.verified
    (event,) = store.of_kind("enforcement_unverified")
    assert event.payload == {"worker_id": worker_id(), "failed": [], "error": "startup_timeout"}


def test_a_check_that_finishes_after_the_limit_is_not_a_pass(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path, grace=0.2)
    collect = runtime.view_collector

    def slow_collect():
        time.sleep(0.3)
        return collect()

    runtime.view_collector = slow_collect
    asyncio.run(runtime._startup())
    assert stopped == [1] and not runtime.verified
    (event,) = store.of_kind("enforcement_unverified")
    assert event.payload["error"] == "startup_timeout"


def test_readiness_that_uses_most_of_the_limit_still_leaves_time_for_the_checks(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path, grace=0.5, ready_delay=0.2)
    asyncio.run(runtime._startup())
    assert runtime.verified and stopped == [] and event_kinds(store) == ["enforcement_verified"]


def test_without_readiness_a_non_required_runtime_stays_blocked_and_recovers(tmp_path):
    runtime, store, stopped, _ = make_runtime(tmp_path, ready=False, required=False)

    async def scenario():
        await runtime._startup()

    asyncio.run(scenario())
    assert stopped == [] and runtime.verified
    assert store.of_kind("enforcement_unverified")[0].payload["error"] == "readiness_timeout"


class TestTerminateProcess:
    @staticmethod
    def stubbed(monkeypatch):
        import os

        calls = {"killed": [], "exited": []}
        monkeypatch.setattr(os, "kill", lambda pid, sig: calls["killed"].append((pid, sig)))
        monkeypatch.setattr(os, "_exit", lambda code: calls["exited"].append(code))
        monkeypatch.setattr(os, "getppid", lambda: 4242)
        return calls

    def test_it_leaves_the_exit_marker_tells_the_parent_and_exits_with_3(
        self, tmp_path, monkeypatch
    ):
        import signal

        marker = tmp_path / "exit-code"
        monkeypatch.setenv("MINT_EXIT_CODE_FILE", str(marker))
        calls = self.stubbed(monkeypatch)
        terminate_process()
        assert marker.read_text(encoding="utf-8") == "3"
        assert calls == {"killed": [(4242, signal.SIGTERM)], "exited": [3]}

    def test_without_a_marker_file_setting_it_only_exits(self, tmp_path, monkeypatch):
        monkeypatch.delenv("MINT_EXIT_CODE_FILE", raising=False)
        calls = self.stubbed(monkeypatch)
        terminate_process()
        assert calls["exited"] == [3] and list(tmp_path.iterdir()) == []

    def test_an_unwritable_marker_does_not_stop_the_exit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MINT_EXIT_CODE_FILE", str(tmp_path / "missing" / "dir" / "code"))
        calls = self.stubbed(monkeypatch)
        terminate_process()
        assert calls["exited"] == [3] and len(calls["killed"]) == 1
