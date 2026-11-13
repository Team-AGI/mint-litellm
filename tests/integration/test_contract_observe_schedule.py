"""계약 관측 일정: 판본을 교체한 업스트림의 도구 변화가 관측 주기 두 번 안에 드리프트로 잡힌다.

작업 실행기를 프로세스 안에서 돌리고 실제 LiteLLM의 시험 목록 API와 시험 서버 a를 쓴다. 작업
실행기를 긴 주기로 한 번 돌린 뒤 짧은 주기로 다시 여는 것은 운영에서 관측 주기를 줄여 재기동하는
경우와 같다.
"""

import json
import os
import time
import uuid

import httpx
import psycopg
import pytest
import support
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from mint_litellm.control.contract_observe import normalize_tools
from mint_litellm.control.db import migrate
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.litellm_control import STAGE2_ALLOWED_ROUTES, LiteLLMControl
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.control.worker import Worker
from mint_litellm.types.canonical import canonical_text, pin_sha256, sha256
from mint_litellm.types.decision import url_sha256
from mint_litellm.types.ids import new_uuid7

INSTANCE = "obs-it"
UPSTREAM_URL = "http://counting-proxy:8080/a/mcp"
OBSERVE_SECONDS = 20


def _admin_url() -> str:
    password = os.environ.get("MINT_E_DB_PASSWORD", "integration-db")
    return f"postgresql://postgres:{password}@{support.HOST}:{support.POSTGRES_PORT}/postgres"


def _worker_url(database: str) -> str:
    # 로그인 역할은 스택의 init이 만든 것을 쓴다(역할은 클러스터 전체에 속한다).
    params = conninfo_to_dict(_admin_url())
    params.update(
        dbname=database,
        user="mint_worker_app",
        password=os.environ.get("MINT_E_WORKER_PASSWORD", "integration-worker"),
    )
    return make_conninfo(**params)


def _post(path: str, body: dict) -> dict:
    reply = httpx.post(
        support.url(support.LITELLM_PORTS[0], path),
        headers=support.master_headers(),
        json=body,
        timeout=30,
    )
    reply.raise_for_status()
    return reply.json()


@pytest.fixture
def control_client(stack):
    user = f"obs-ctl-{uuid.uuid4().hex[:8]}"
    _post("/user/new", {"user_id": user, "user_role": "proxy_admin"})
    key = _post("/key/generate", {"user_id": user, "allowed_routes": list(STAGE2_ALLOWED_ROUTES)})
    return LiteLLMControl(support.url(support.LITELLM_PORTS[0]), key["key"])


@pytest.fixture
def litellm_server(stack):
    """LiteLLM 레지스트리(DB)에 등록한 서버. 시험 서버 a를 계수 프록시 너머로 가리킨다."""
    name = f"obs_{uuid.uuid4().hex[:8]}"
    created = _post(
        "/v1/mcp/server",
        {
            "server_name": name,
            "alias": name,
            "url": UPSTREAM_URL,
            "transport": "http",
            "auth_type": "none",
        },
    )
    yield created["server_id"]
    httpx.delete(
        support.url(support.LITELLM_PORTS[0], f"/v1/mcp/server/{created['server_id']}"),
        headers=support.master_headers(),
        timeout=30,
    )


@pytest.fixture
def observed_server(stack, control_client, litellm_server):
    """승인된 계약을 가진 관리 서버가 들어 있는 일회용 데이터베이스."""
    name = f"mint_obs_{uuid.uuid4().hex[:10]}"
    server_id = litellm_server
    with psycopg.connect(_admin_url(), autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    params = conninfo_to_dict(_admin_url())
    params["dbname"] = name
    url = make_conninfo(**params)
    try:
        with psycopg.connect(url, autocommit=True) as conn:
            migrate.apply_migrations(conn)
            conn.execute(
                "INSERT INTO mint.orgs(instance_id,org_id,name) VALUES (%s,'o','org')", (INSTANCE,)
            )
            conn.execute(
                "INSERT INTO mint.servers(id,instance_id,server_id,status,url_sha256,transport,"
                "auth_type,registered_by,contract_status) VALUES (%s,%s,%s,'pending',%s,'http',"
                "'none','it','managed')",
                (new_uuid7(), INSTANCE, server_id, url_sha256(UPSTREAM_URL)),
            )
            for status in ("validating", "awaiting_approval", "approved"):
                conn.execute(
                    "UPDATE mint.servers SET status=%s WHERE server_id=%s", (status, server_id)
                )
            deployment = {"url": UPSTREAM_URL, "transport": "http", "auth_type": "none"}
            did = new_uuid7()
            conn.execute(
                "INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,"
                "sha256,url,url_sha256,transport,auth_type)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,'http','none')",
                (did, INSTANCE, server_id, canonical_text(deployment), sha256(deployment),
                 UPSTREAM_URL, url_sha256(UPSTREAM_URL)),
            )
            conn.execute(
                "UPDATE mint.deployment_contracts SET status='approved' WHERE id=%s", (did,)
            )
            listing = control_client.test_tools_list({"server_id": server_id, **deployment})
            tools = normalize_tools(listing)
            assert "mutable" in tools
            for tool, value in tools.items():
                cid = new_uuid7()
                conn.execute(
                    "INSERT INTO mint.tool_contracts(id,instance_id,server_id,credential_scope,"
                    "tool,canonical_text,sha256,pin_sha256,risk_grade,action_type,source)"
                    " VALUES (%s,%s,%s,'server',%s,%s,%s,%s,'low','read','intake')",
                    (cid, INSTANCE, server_id, tool, canonical_text(value), sha256(value),
                     pin_sha256(value)),
                )
                conn.execute("UPDATE mint.tool_contracts SET status='approved' WHERE id=%s", (cid,))
        yield url, name
    finally:
        with psycopg.connect(_admin_url(), autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _settings(seconds: int, export_dir) -> Stage2Settings:
    return Stage2Settings.from_env(
        {
            "MINT_EXPORT_DIR": str(export_dir),
            "MINT_EXPORT_HMAC_KEY": "A" * 43,
            "MINT_OBSERVE_SECONDS": str(seconds),
        }
    )


def _drift(url: str) -> str:
    with psycopg.connect(url, autocommit=True) as conn:
        return fetchone(
            conn,
            "SELECT drift FROM mint.tool_contracts WHERE instance_id=%s AND tool='mutable'"
            " AND status='approved'",
            (INSTANCE,),
        )["drift"]


def test_a_replaced_upstream_version_is_observed_within_two_periods(
    observed_server, control_client, upstreams, tmp_path
):
    url, database = observed_server
    login = _worker_url(database)
    long_period = Worker(login, INSTANCE, _settings(3600, tmp_path), litellm=control_client)
    long_period.open()
    try:
        while long_period.step():  # 긴 주기의 첫 관측이 끝난다
            pass
    finally:
        long_period.close()
    assert _drift(url) == "none"
    upstreams["a"].mutate("v2", "changed description")
    short_period = Worker(
        login, INSTANCE, _settings(OBSERVE_SECONDS, tmp_path), litellm=control_client
    )
    short_period.open()
    try:
        deadline = time.monotonic() + 2 * OBSERVE_SECONDS + 2
        while _drift(url) == "none" and time.monotonic() < deadline:
            if not short_period.step():
                time.sleep(0.5)
    finally:
        short_period.close()
    assert _drift(url) != "none"
    with psycopg.connect(url, autocommit=True) as conn:
        kinds = {r[0] for r in conn.execute("SELECT kind FROM mint.events")}
    assert "contract_drift_detected" in kinds


def _alert_kinds(url: str) -> set[str]:
    with psycopg.connect(url, autocommit=True) as conn:
        return {
            r[0]
            for r in conn.execute(
                "SELECT kind FROM mint.alerts WHERE instance_id=%s AND status <> 'resolved'",
                (INSTANCE,),
            )
        }


def _run_worker(login, settings, control_client, until) -> None:
    worker = Worker(login, INSTANCE, settings, litellm=control_client)
    worker.open()
    try:
        deadline = time.monotonic() + 60
        while not until() and time.monotonic() < deadline:
            if not worker.step():
                time.sleep(0.5)
    finally:
        worker.close()


def test_a_new_tool_raises_a_contract_drift_alert(observed_server, control_client, tmp_path):
    url, database = observed_server
    # 승인된 계약에서 한 도구를 빼면 다음 관측에서 새 도구로 보인다
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(
            "UPDATE mint.tool_contracts SET status='superseded'"
            " WHERE instance_id=%s AND tool='echo' AND status='approved'",
            (INSTANCE,),
        )
    _run_worker(
        _worker_url(database), _settings(3600, tmp_path), control_client,
        lambda: "contract_drift" in _alert_kinds(url),
    )
    assert "contract_drift" in _alert_kinds(url)
    with psycopg.connect(url, autocommit=True) as conn:
        opened = conn.execute(
            "SELECT count(*) FROM mint.events WHERE kind='alert_opened'"
            " AND payload->>'kind'='contract_drift'"
        ).fetchone()[0]
    assert opened >= 1


def test_a_burst_of_calls_raises_a_call_spike_alert_and_recovery_closes_it(
    observed_server, control_client, tmp_path
):
    url, database = observed_server
    with psycopg.connect(url, autocommit=True) as conn:
        server = conn.execute(
            "SELECT server_id FROM mint.servers WHERE instance_id=%s", (INSTANCE,)
        ).fetchone()[0]
        for _ in range(6):  # 시험용 낮은 기준(5건 이상, 기준선 없음)에서 6건
            invocation = new_uuid7()
            conn.execute(
                "INSERT INTO mint.events(event_id,instance_id,kind,source_key,invocation_id,"
                "attempt_id,payload) VALUES (%s,%s,'decision_evaluated',%s,%s,1,%s::jsonb)",
                (new_uuid7(), INSTANCE, f"call:{invocation}:1", invocation,
                 json.dumps({"operation": "tool_call", "resolved_server_id": server,
                             "tool": "echo"})),
            )
    settings = Stage2Settings.from_env(
        {
            "MINT_EXPORT_DIR": str(tmp_path),
            "MINT_EXPORT_HMAC_KEY": "A" * 43,
            "MINT_SPIKE_MIN_CALLS": "5",
        }
    )
    _run_worker(
        _worker_url(database), settings, control_client,
        lambda: "call_spike" in _alert_kinds(url),
    )
    assert "call_spike" in _alert_kinds(url)
    # 평소 수준으로 돌아온 것과 같게, 최소 호출 수를 올려 다음 점검에서 경보가 닫히는지 본다.
    quiet = Stage2Settings.from_env(
        {
            "MINT_EXPORT_DIR": str(tmp_path),
            "MINT_EXPORT_HMAC_KEY": "A" * 43,
            "MINT_SPIKE_MIN_CALLS": "1000",
        }
    )
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("UPDATE mint.schedules SET next_run_at = now() WHERE kind='call_spike_scan'")
    _run_worker(
        _worker_url(database), quiet, control_client,
        lambda: "call_spike" not in _alert_kinds(url),
    )
    assert "call_spike" not in _alert_kinds(url)
