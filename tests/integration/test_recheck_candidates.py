"""드리프트 → 자동 재검사로 후보 계약 → 재승인 → 차단 해제 (실제 LiteLLM·시험 서버 a).

작업 실행기를 프로세스 안에서 돌린다. 승인된 서버의 도구 정의를 시험 서버에서 바꾸면 계약 관측이
입력 스키마 드리프트(그 도구 차단)를 기록하고, 같은 트랜잭션에 등록된 재검사 작업이 후보 계약과
후보에 결속된 증거를 만들며, 다른 사용자의 `contract reapprove`가 작업 실행기의 재pin으로
끝나 드리프트가 풀린다.
"""

import json
import time
import uuid

import httpx
import psycopg
import pytest
import support
import test_contract_observe_schedule as schedule
from test_contract_observe_schedule import INSTANCE, OBSERVE_SECONDS, _post, _worker_url

from mint_litellm.control import settings_store
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.intake_checks import PolicyDataSource
from mint_litellm.control.litellm_control import STAGE2_ALLOWED_ROUTES, LiteLLMControl
from mint_litellm.control.services import contracts
from mint_litellm.control.services import intakes as intake_service
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.control.worker import Worker
from mint_litellm.types.cli_commands import CONTROL_PLANE_ALLOWED_ROUTES

# 같은 일회용 데이터베이스 픽스처를 쓴다(스택 연결·승인된 계약 심기)
observed_server = schedule.observed_server
litellm_server = schedule.litellm_server

OPA = support.url(support.OPA_PORT)
HOST = "counting-proxy"


@pytest.fixture
def control_client(stack):  # 재pin·서버 조회 경로까지 허용한 제어 평면 키)
    user = f"rck-ctl-{uuid.uuid4().hex[:8]}"
    _post("/user/new", {"user_id": user, "user_role": "proxy_admin"})
    routes = [*CONTROL_PLANE_ALLOWED_ROUTES, *STAGE2_ALLOWED_ROUTES]
    key = _post("/key/generate", {"user_id": user, "allowed_routes": routes})
    return LiteLLMControl(support.url(support.LITELLM_PORTS[0]), key["key"])


@pytest.fixture
def exempt_key(control_client):
    """재pin이 되려면 LiteLLM 쪽 플러그인이 이 키를 제어 평면 키(목록 면제)로 알아야 한다.

    스택의 MINT 데이터베이스(인스턴스 integration)에 토큰을 두고, 끝나면 이전 값으로 돌린다.
    """
    with psycopg.connect(support.mint_database_url(), autocommit=True) as conn:
        ctx = Context(conn, "integration", Operator("root", "admin", None))
        previous = settings_store.load(conn, "integration")["control_key_token"]
        settings_store.set_control_key(ctx, control_client._key)
    yield
    with psycopg.connect(support.mint_database_url(), autocommit=True) as conn:
        conn.execute(
            "UPDATE mint.settings SET control_key_token = %s WHERE instance_id = 'integration'",
            (previous,),
        )


def _stage2(export_dir, seconds) -> Stage2Settings:
    return Stage2Settings.from_env(
        {
            "MINT_EXPORT_DIR": str(export_dir),
            "MINT_EXPORT_HMAC_KEY": "A" * 43,
            "MINT_OBSERVE_SECONDS": str(seconds),
            "MINT_INTAKE_ALLOWED_PORTS": "8080",
        }
    )


def _seed_review(url, server_id) -> str:
    """승인된 서버를 승인한 신청, 허용 목록, 활성 정책 판본, 다른 사용자인 승인자를 심는다."""
    meta = json.loads(httpx.get(f"{OPA}/v1/data/mint/meta", timeout=10).text)["result"]
    with psycopg.connect(url, autocommit=True) as conn:
        for status in ("staged", "active"):
            if status == "staged":
                conn.execute(
                    "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256,"
                    " bundle_sha256) VALUES (%s, %s, %s, %s)",
                    (INSTANCE, meta["policy_version_id"], "cd" * 32, meta["bundle_sha256"]),
                )
            conn.execute(
                "UPDATE mint.policy_versions SET status = %s, activated_at = now(),"
                " activated_by = 'root' WHERE id = %s",
                (status, meta["policy_version_id"]),
            )
        for kind in ("provider", "egress_target"):
            conn.execute(
                "INSERT INTO mint.allowlists (id, instance_id, kind, value, valid_from,"
                " valid_until, created_by) VALUES (gen_random_uuid(), %s, %s, %s,"
                " now() - interval '1 day', now() + interval '30 days', 'root')",
                (INSTANCE, kind, HOST),
            )
        conn.execute(
            "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
            " VALUES (%s, 'reviewer', 'approver', repeat('d', 64), 'reviewer-1')",
            (INSTANCE,),
        )
        readiness = json.dumps(
            {"credential_notice": "mail", "revocation_record": "log", "audit_access_days": 90}
        )
        row = fetchone(
            conn,
            "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source)"
            " VALUES (gen_random_uuid(), %s, 'o', %s, 'operator') RETURNING id",
            (INSTANCE, server_id),
        )
        conn.execute(
            "UPDATE mint.intakes SET status = 'checking', purpose = 'it', data_grade = 'internal',"
            " allowed_resources = '[]', provider = 'Test', owner_user_id = 'requester-1',"
            " readiness = %s::jsonb, data_return_terms = 'delete', requested_by = 'requester-1'"
            " WHERE id = %s",
            (readiness, row["id"]),
        )
        conn.execute("UPDATE mint.intakes SET status = 'passed' WHERE id = %s", (row["id"],))
        conn.execute(
            "UPDATE mint.intakes SET status = 'decided', decision = 'approved',"
            " decided_by = 'root', decision_reason = 'seed', decided_at = now() WHERE id = %s",
            (row["id"],),
        )
        return str(row["id"])


def _step_until(worker, done, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if done():
            return True
        if not worker.step():
            time.sleep(0.5)
    return done()


def test_drift_to_candidates_to_reapproval_clears_the_block(
    observed_server, control_client, exempt_key, litellm_server, upstreams, tmp_path
):
    url, database = observed_server
    server_id = litellm_server
    intake_id = _seed_review(url, server_id)
    login = _worker_url(database)
    policy = PolicyDataSource(OPA)

    def start(seconds):
        worker = Worker(
            login, INSTANCE, _stage2(tmp_path, seconds), litellm=control_client, policy_data=policy
        )
        worker.open()
        return worker

    def fetch(sql, params=()):
        with psycopg.connect(url, autocommit=True) as conn:
            return fetchall(conn, sql, params)

    first = start(3600)
    try:
        while first.step():  # 변화 없는 첫 관측
            pass
    finally:
        first.close()
    assert fetch("SELECT 1 FROM mint.tool_contracts WHERE drift <> 'none'") == []
    assert fetch("SELECT 1 FROM mint.jobs WHERE kind = 'intake_run'") == []

    upstreams["a"].mutate("v2")  # mutable 도구의 입력 스키마와 설명이 바뀐다
    worker = start(OBSERVE_SECONDS)
    try:
        assert _step_until(
            worker,
            lambda: fetch("SELECT 1 FROM mint.tool_contracts WHERE status = 'candidate'") != [],
            3 * OBSERVE_SECONDS + 30,
        ), "후보 계약이 생기지 않았다"
        while worker.step():
            pass
        drifted = fetch(
            "SELECT tool, drift FROM mint.tool_contracts WHERE status = 'approved' ORDER BY tool"
        )
        assert {r["tool"]: r["drift"] for r in drifted}["mutable"] == "input_schema"
        runs = fetch("SELECT target_ref, status FROM mint.jobs WHERE kind = 'intake_run'")
        assert [(r["target_ref"], r["status"]) for r in runs] == [(f"{intake_id}/evidence", "done")]
        with psycopg.connect(url, autocommit=True) as conn:
            intake = fetchone(conn, "SELECT status, decision FROM mint.intakes")
            bound = intake_service.contract_binding(conn, INSTANCE, server_id)
            checks = intake_service.latest_checks(conn, INSTANCE, intake_id)
        assert (intake["status"], intake["decision"]) == ("decided", "approved")
        for check in checks:
            if check["check"] in ("connection", "definitions", "description_scan", "risk_grade"):
                assert check["result"] == "pass", check["check"]
                assert check["inputs"]["contract_sha256"] == bound
        candidates = fetch(
            "SELECT id, tool FROM mint.tool_contracts WHERE status = 'candidate' ORDER BY tool"
        )
        assert [c["tool"] for c in candidates] == ["echo", "mutable", "slow"]

        # 다른 사용자가 후보 전체를 재승인하면 작업 실행기의 재pin으로 끝난다.
        with psycopg.connect(url) as conn:
            ctx = Context(conn, INSTANCE, Operator("reviewer", "approver", "reviewer-1"))
            contracts.reapprove(ctx, server_id, intake_id, [str(c["id"]) for c in candidates])
            conn.commit()
        assert _step_until(
            worker,
            lambda: fetch("SELECT 1 FROM mint.servers WHERE deployment_drift") == [],
            60,
        ), "재승인이 끝나지 않았다"
    finally:
        worker.close()

    approved = fetch(
        "SELECT id, tool, drift FROM mint.tool_contracts WHERE status = 'approved' ORDER BY tool"
    )
    assert [(a["id"], a["drift"]) for a in approved] == [(c["id"], "none") for c in candidates]
    assert fetch("SELECT 1 FROM mint.litellm_grants WHERE item = 'pin' AND observed") != []
    kinds = {r["kind"] for r in fetch("SELECT kind FROM mint.events")}
    assert {"contract_drift_detected", "alert_opened", "contract_approved"} <= kinds
