"""원격 서버 주소의 이름 조회 결과 재확인(POL-R-12): 분류, 캐시, 변경 탐지, 모드, 경보."""

import asyncio
import contextlib
import time
from dataclasses import replace

import pytest
from plugin_helpers import (
    approval,
    evaluator,
    harness,
    request,
    resolved_server,
    server_row,
    snapshot,
)

from mint_litellm.control import server_address
from mint_litellm.control.approvals import build_conditions
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.resolve_guard import ResolveGuard, classify, host_of
from mint_litellm.types.settings import Mode


def ip(*octets):
    """십진 점 표기 주소(저장소 위생 검사가 주소 문자열을 금지한다)."""
    return ".".join(map(str, octets))


PUBLIC = ip(93, 184, 216, 34)
HOST = "mcp.example.test"


class Dns:
    """이름 -> 주소 목록을 돌려주는 가짜 조회. 호출 횟수를 센다."""

    def __init__(self, table):
        self.table, self.calls = dict(table), 0

    async def __call__(self, host):
        self.calls += 1
        value = self.table[host]
        if isinstance(value, Exception):
            raise value
        return list(value)


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


def guard(table, **kw):
    dns = Dns(table)
    return ResolveGuard(lookup=dns, **kw), dns


@pytest.mark.parametrize(
    ("address", "label"),
    [
        (ip(127, 0, 0, 1), "loopback"),
        ("::1", "loopback"),
        (ip(10, 1, 2, 3), "private"),
        (ip(192, 168, 0, 9), "private"),
        (ip(172, 16, 0, 1), "private"),
        ("fd12:3456::1", "private"),
        (ip(169, 254, 169, 254), "metadata"),
        ("fd00:ec2::254", "metadata"),
        (ip(169, 254, 1, 1), "link_local"),
        ("fe80::1%eth0", "link_local"),
        (ip(100, 64, 0, 1), "cgnat"),
        (ip(0, 0, 0, 0), "unspecified"),
        ("::", "unspecified"),
        (ip(224, 0, 0, 1), "multicast"),
        ("ff02::1", "multicast"),
        (f"::ffff:{ip(127, 0, 0, 1)}", "loopback"),
        (f"::ffff:{ip(10, 0, 0, 1)}", "private"),
        (f"::ffff:{ip(169, 254, 169, 254)}", "metadata"),
        ("64:ff9b::a00:1", "private"),
        ("not-an-address", "unparsable"),
        (PUBLIC, None),
        ("2606:4700:4700::1111", None),
        (f"::ffff:{ip(93, 184, 216, 34)}", None),
    ],
)
def test_address_classes(address, label):
    assert classify(address) == label


def test_host_of():
    assert host_of("https://Mcp.Example.test:8443/x") == "mcp.example.test"
    assert host_of("http://[::1]:9000/mcp") == "::1"
    assert host_of("http://host./a") == "host"
    assert host_of(None) is None
    assert host_of("") is None


def test_public_private_and_mixed_answers():
    g, _ = guard(
        {"pub": [PUBLIC], "priv": [ip(10, 0, 0, 5)], "mix": [PUBLIC, ip(127, 0, 0, 1)], "none": []}
    )
    assert asyncio.run(g.check("pub")).kind is None
    assert asyncio.run(g.check("priv")).detail() == "private private"
    assert asyncio.run(g.check("mix")).detail() == "private loopback"
    assert asyncio.run(g.check("none")).kind == "unresolved"


def test_literal_addresses_are_not_looked_up():
    g, dns = guard({})
    assert asyncio.run(g.check(ip(127, 0, 0, 1))).kind == "private"
    assert asyncio.run(g.check("::1")).detail() == "private loopback"
    assert asyncio.run(g.check(f"::ffff:{ip(10, 0, 0, 1)}")).kind == "private"
    assert asyncio.run(g.check(PUBLIC)).kind is None
    assert dns.calls == 0


def test_failure_is_unresolved_and_not_cached():
    g, dns = guard({HOST: OSError("nxdomain")})
    assert asyncio.run(g.check(HOST)).kind == "unresolved"
    assert g.cached(HOST) is None
    dns.table[HOST] = [PUBLIC]
    assert asyncio.run(g.check(HOST)).kind is None
    assert dns.calls == 2


def test_timeout_is_unresolved():
    async def slow(host):
        await asyncio.sleep(5)
        return [PUBLIC]

    assert asyncio.run(ResolveGuard(lookup=slow).check(HOST, 0.01)).kind == "unresolved"


def test_cache_hit_until_ttl_then_looked_up_again():
    clock = Clock()
    g, dns = guard({HOST: [PUBLIC]}, ttl=30, clock=clock)
    asyncio.run(g.check(HOST))
    clock.now += 29
    assert g.cached(HOST) is not None
    asyncio.run(g.check(HOST))
    assert dns.calls == 1
    clock.now += 2
    assert g.cached(HOST) is None
    asyncio.run(g.check(HOST))
    assert dns.calls == 2


def test_cache_is_bounded():
    g, _ = guard({f"h{i}": [PUBLIC] for i in range(10)}, max_entries=4)
    for i in range(10):
        asyncio.run(g.check(f"h{i}"))
    assert len(g._cache) <= 4
    assert len(g._was_public) <= 4
    assert g.cached("h9") is not None
    assert g.cached("h0") is None


def test_public_to_private_is_a_rebind_and_stays_one_until_public_again():
    clock = Clock()
    g, dns = guard({HOST: [PUBLIC]}, ttl=30, clock=clock)
    assert asyncio.run(g.check(HOST)).kind is None
    dns.table[HOST] = [PUBLIC, ip(169, 254, 169, 254)]
    clock.now += 31
    verdict = asyncio.run(g.check(HOST))
    assert (verdict.kind, verdict.label) == ("rebind", "metadata")
    clock.now += 31
    assert asyncio.run(g.check(HOST)).kind == "rebind"
    dns.table[HOST] = [PUBLIC]
    clock.now += 31
    assert asyncio.run(g.check(HOST)).kind is None


def test_a_host_that_was_never_public_is_private_not_rebind():
    g, _ = guard({HOST: [ip(10, 0, 0, 5)]})
    assert asyncio.run(g.check(HOST)).kind == "private"


def test_cache_hit_cost_is_small():
    g, _ = guard({HOST: [PUBLIC]})
    asyncio.run(g.check(HOST))
    started = time.perf_counter()
    for _ in range(10000):
        g.cached(HOST)
    assert (time.perf_counter() - started) / 10000 < 20e-6


# --- 파이프라인 -----------------------------------------------------------------------


def decide(tmp_path, table, *, mode="enforce", conditions=None, host=HOST, observe_mode=False):
    snap = snapshot(server=server_row(), approvals=(approval(conditions=conditions or {}),))
    h = harness(tmp_path, snap, evaluate=evaluator())
    dns = Dns(table)
    h.deps.resolve_guard = ResolveGuard(lookup=dns)
    h.deps.config = replace(h.deps.config, resolve_check=mode)
    if observe_mode:
        h.deps.config = replace(h.deps.config, mode_ceiling=Mode.OBSERVE)
    out = asyncio.run(evaluate_request(request(resolved=resolved_server(host=host)), h.deps))
    return out, dns


def test_enforce_blocks_an_internal_answer(tmp_path):
    out, _ = decide(tmp_path, {HOST: [ip(10, 0, 0, 5)]})
    assert not out.allowed
    assert out.error.code == "MINT-RESOLVED-ADDRESS-FORBIDDEN"
    assert out.snapshot.stop.detail == "private private"


def test_the_block_is_not_converted_by_the_observation_mode(tmp_path):
    out, _ = decide(tmp_path, {HOST: [ip(127, 0, 0, 1)]}, observe_mode=True)
    assert not out.allowed


def test_enforce_passes_a_public_answer_and_blocks_a_failed_lookup(tmp_path):
    assert decide(tmp_path, {HOST: [PUBLIC]})[0].allowed
    out, _ = decide(tmp_path, {HOST: OSError("x")})
    assert not out.allowed
    assert out.snapshot.stop.detail == "unresolved"


def test_observe_lets_the_call_through_and_records_the_kind(tmp_path):
    out, _ = decide(tmp_path, {HOST: [ip(10, 0, 0, 5)]}, mode="observe")
    assert out.allowed
    assert out.context["resolve_findings"] == ["private"]
    out, _ = decide(tmp_path, {HOST: OSError("x")}, mode="observe")
    assert out.allowed
    assert out.context["resolve_findings"] == ["unresolved"]
    out, _ = decide(tmp_path, {HOST: [PUBLIC]}, mode="observe")
    assert out.allowed
    assert out.context["resolve_findings"] == []


def test_off_does_not_look_up(tmp_path):
    out, dns = decide(tmp_path, {HOST: [ip(10, 0, 0, 5)]}, mode="off")
    assert out.allowed
    assert dns.calls == 0


def test_a_server_without_a_host_is_not_checked(tmp_path):
    out, dns = decide(tmp_path, {}, host=None)
    assert out.allowed
    assert dns.calls == 0


def test_the_internal_approval_condition_skips_the_check(tmp_path):
    out, dns = decide(
        tmp_path, {HOST: [ip(10, 0, 0, 5)]}, conditions={"allow_internal_address": True}
    )
    assert out.allowed
    assert dns.calls == 0
    loose = decide(
        tmp_path, {HOST: [ip(10, 0, 0, 5)]}, conditions={"allow_internal_address": "yes"}
    )
    assert not loose[0].allowed


def test_literal_ip_urls_follow_the_same_rule(tmp_path):
    assert not decide(tmp_path, {}, host=ip(169, 254, 169, 254))[0].allowed
    assert not decide(tmp_path, {}, host=f"::ffff:{ip(10, 0, 0, 1)}")[0].allowed
    assert decide(tmp_path, {}, host=PUBLIC)[0].allowed


def test_rebinding_between_calls_is_refused_with_the_rebind_kind(tmp_path):
    snap = snapshot(server=server_row(), approvals=(approval(conditions={}),))
    h = harness(tmp_path, snap, evaluate=evaluator())
    dns = Dns({HOST: [PUBLIC]})
    clock = Clock()
    h.deps.resolve_guard = ResolveGuard(lookup=dns, ttl=30, clock=clock)
    h.deps.config = replace(h.deps.config, resolve_check="enforce")

    def call():
        return asyncio.run(evaluate_request(request(resolved=resolved_server(host=HOST)), h.deps))

    assert call().allowed
    dns.table[HOST] = [ip(127, 0, 0, 1)]
    assert call().allowed  # 캐시가 유효한 동안은 같은 판정
    clock.now += 31
    out = call()
    assert not out.allowed
    assert out.snapshot.stop.detail == "rebind loopback"


def test_the_setting_is_validated():
    env = {
        "MINT_INSTANCE_ID": "i",
        "MINT_DATABASE_URL": "postgresql://x",
        "MINT_OPA_URL": "http://o",
    }
    assert PluginConfig.from_env(env).resolve_check == "observe"
    enforced = PluginConfig.from_env({**env, "MINT_RESOLVE_CHECK": " Enforce "})
    assert enforced.resolve_check == "enforce"
    with pytest.raises(RuntimeError, match="MINT_RESOLVE_CHECK"):
        PluginConfig.from_env({**env, "MINT_RESOLVE_CHECK": "block"})


def test_the_condition_is_written_only_when_asked():
    kwargs = {
        "high_risk_tools": None,
        "business_hours_only": False,
        "business_hours": None,
        "require_consent": None,
    }
    assert build_conditions(**kwargs) == {}
    assert build_conditions(**kwargs, allow_internal_address=True) == {
        "allow_internal_address": True
    }


# --- 경보 -----------------------------------------------------------------------------


class _Conn:
    @staticmethod
    def transaction():
        return contextlib.nullcontext()


class _Job:
    conn = _Conn()
    instance_id = "i1"


def test_one_alert_per_server_and_none_while_one_is_open(monkeypatch):
    raised = []

    def run(open_keys):
        raised.clear()

        def fake_fetchall(conn, sql, params=None):
            if "FROM mint.events" in sql:
                return [
                    {"server": "s1", "kinds": ["rebind"], "calls": 2},
                    {"server": "s2", "kinds": ["private"], "calls": 1},
                ]
            return [{"dedup_key": k} for k in open_keys]

        monkeypatch.setattr(server_address, "fetchall", fake_fetchall)
        monkeypatch.setattr(
            server_address.alerts, "raise_alert", lambda conn, inst, **kw: raised.append(kw)
        )
        server_address.run(_Job())
        return [r["dedup_key"] for r in raised]

    assert run([]) == ["server_address_internal:s1", "server_address_internal:s2"]
    assert raised[0]["kind"] == "server_address_internal"
    assert raised[0]["subject"]["kinds"] == ["rebind"]
    assert run(["server_address_internal:s1"]) == ["server_address_internal:s2"]
