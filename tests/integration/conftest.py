"""통합 시험 공통 픽스처.

스택은 ``docker compose -f tests/integration/compose.yaml up --wait``로 미리 띄운다.
스택이 없으면 통합 시험은 건너뛴다. 플러그인이 없는 순정 이미지(프로필 ``plain``)가 필요한
시험은 그 서비스가 떠 있을 때만 실행된다.
"""

import json
import os
import uuid
from pathlib import Path

import httpx
import pytest
import support


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: 실제 스택이 필요한 통합 시험")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "tests/integration" in item.nodeid.replace("\\", "/"):
            item.add_marker(pytest.mark.integration)


def _readiness() -> dict[str, bool]:
    checks = {}
    for index, port in enumerate(support.LITELLM_PORTS, 1):
        checks[f"litellm{index}"] = (port, "/health/readiness")
    checks["counting-proxy"] = (support.PROXY_PORT, "/__health")
    checks["toxiproxy"] = (support.TOXIPROXY_PORT, "/proxies")
    checks["toxiproxy-db"] = (support.TOXIPROXY_DB_PORT, "/proxies")
    checks["opa"] = (support.OPA_PORT, "/health")
    for name, port in support.UPSTREAM_CONTROL_PORT.items():
        checks[f"testserver-{name}"] = (port, "/health")
    result = {}
    for name, (port, path) in checks.items():
        try:
            result[name] = httpx.get(support.url(port, path), timeout=3).status_code == 200
        except httpx.HTTPError:
            result[name] = False
    try:
        import psycopg

        with psycopg.connect(support.mint_database_url(), connect_timeout=3) as conn:
            conn.execute("select 1")
        result["postgres"] = True
    except Exception:
        result["postgres"] = False
    return result


def _unready(message: str) -> None:
    """준비 실패: CI(MINT_INTEGRATION_REQUIRED)에서는 실패, 로컬에서는 건너뛰기."""
    if os.environ.get("MINT_INTEGRATION_REQUIRED"):
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


@pytest.fixture(scope="session")
def stack():
    status = _readiness()
    missing = [name for name, ok in status.items() if not ok]
    if missing:
        _unready(f"통합 스택이 준비되지 않음: {', '.join(missing)}")
    return status


@pytest.fixture
def upstreams(stack):
    servers = {name: support.Upstream(name) for name in support.UPSTREAM_CONTROL_PORT}
    for upstream in servers.values():
        upstream.reset()
    yield servers
    for upstream in servers.values():
        upstream.reset()


@pytest.fixture
def proxy_log(stack):
    return support.ProxyLog()


@pytest.fixture
def evidence(upstreams, proxy_log):
    return support.Evidence(upstreams, proxy_log)


@pytest.fixture
def toxics(stack):
    created = [
        support.Toxics(support.TOXIPROXY_PORT, "a"),
        support.Toxics(support.TOXIPROXY_PORT, "b"),
        support.Toxics(support.TOXIPROXY_DB_PORT, "postgres"),
    ]
    for toxic in created:
        toxic.clear()
        toxic.enable()
    yield {"a": created[0], "b": created[1], "postgres": created[2]}
    for toxic in created:
        toxic.clear()
        toxic.enable()


@pytest.fixture(scope="session")
def plain(stack):
    port = support.PLAIN_PORT
    try:
        ready = httpx.get(support.url(port, "/health/readiness"), timeout=3).status_code == 200
    except httpx.HTTPError:
        ready = False
    if not ready:
        _unready("순정 LiteLLM(프로필 plain)이 떠 있지 않음")
    return port


@pytest.fixture(scope="session")
def multiworker(stack):
    """워커가 둘인 복제본(litellm-mw)의 포트. 떠 있지 않으면 CI에서는 실패, 로컬에서는 건너뛴다."""
    port = support.MULTIWORKER_PORT
    try:
        ready = httpx.get(support.url(port, "/health/readiness"), timeout=3).status_code == 200
    except httpx.HTTPError:
        ready = False
    if not ready:
        _unready("워커가 둘인 LiteLLM 복제본(litellm-mw)이 떠 있지 않음")
    return port


def _bootstrap(mint, helper) -> None:
    """제어 평면 키, 첫 관리자, 첫 정책 판본, 서버 a·b의 첫 승인을 만든다."""
    suffix = uuid.uuid4().hex[:8]
    reply = httpx.post(
        support.url(support.LITELLM_PORTS[0], "/user/new"),
        headers=support.master_headers(),
        json={"user_id": f"it-control-{suffix}", "user_role": "proxy_admin"},
        timeout=30,
    )
    reply.raise_for_status()
    reply = httpx.post(
        support.url(support.LITELLM_PORTS[0], "/key/generate"),
        headers=support.master_headers(),
        json={
            "user_id": f"it-control-{suffix}",
            "key_alias": f"it-control-key-{suffix}",
            "allowed_routes": support.CONTROL_ROUTES,
        },
        timeout=30,
    )
    reply.raise_for_status()
    helper.control_key = reply.json()["key"]
    mint.env["MINT_LITELLM_KEY"] = helper.control_key
    mint.env["MINT_LITELLM_URL"] = "http://litellm1:4000"
    helper.admin_user = helper.litellm_user()
    mint.token = mint.data(
        "operator", "bootstrap", "--name", "it-admin", "--user-id", helper.admin_user
    )["token"]
    mint.run("policy", "activate", "it-v1")
    # 서버 a·b의 첫 승인을 미리 만들어 서버 상태가 승인됨이 되게 한다(서버 c는 시험이 직접 다룬다).
    seed = helper.subject(("a", "b"))
    helper.approve(seed, helper.prepare(seed, "a"))
    helper.approve(seed, helper.relate(seed, "b"))


@pytest.fixture(scope="session")
def world(stack):
    """운영자·제어 평면 키·정책이 준비된 시나리오 도구. 같은 스택에서 다시 실행해도 재사용한다.

    ``MINT_E_STATE``가 가리키는 파일에 준비 결과를 남겨 두면(반복 실행용) 다시 만들지 않는다.
    """
    import scenario

    mint = scenario.Mint()
    helper = scenario.World(mint)
    state = Path(os.environ["MINT_E_STATE"]) if os.environ.get("MINT_E_STATE") else None
    if state is not None and state.exists():
        saved = json.loads(state.read_text(encoding="utf-8"))
        mint.token, helper.admin_user = saved["token"], saved["admin_user"]
        helper.control_key = saved["control_key"]
        mint.env.update(saved["env"])
        helper.registered.update(saved["registered"])
        return helper
    _bootstrap(mint, helper)
    if state is not None:
        state.write_text(
            json.dumps(
                {
                    "token": mint.token,
                    "admin_user": helper.admin_user,
                    "control_key": helper.control_key,
                    "env": mint.env,
                    "registered": sorted(helper.registered),
                }
            ),
            encoding="utf-8",
        )
    return helper
