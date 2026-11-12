"""수용검증(신청 → 검사 → 승인)을 실제 LiteLLM 1.106.6으로 시험한다.

필요한 것: LiteLLM(마스터 키), LiteLLM이 닿을 수 있는 MCP 시험 서버, MINT 시험 데이터베이스.
환경 변수가 없으면 건너뛴다.

    MINT_G2_LITELLM_URL        LiteLLM 주소(시험이 닿는 주소)
    MINT_G2_MASTER_KEY         LiteLLM 마스터 키(제어 평면 키·팀 키를 만드는 데만 쓴다)
    MINT_G2_UPSTREAM_URL       LiteLLM이 닿을 수 있는 시험 서버의 MCP 주소
    MINT_G2_OPA_URL            활성 번들(`description_markers`·`risk`)을 가진 정책 엔진 주소
    MINT_TEST_DATABASE_URL     MINT 시험용 슈퍼유저 접속 주소

통합 스택(``compose.yaml``)을 쓰면 LiteLLM은 ``http://localhost:4101``, 마스터 키는 스택의
키, 시험 서버는 ``http://counting-proxy:8080/a/mcp``이다.
"""

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))

LITELLM = os.environ.get("MINT_G2_LITELLM_URL")
MASTER = os.environ.get("MINT_G2_MASTER_KEY")
UPSTREAM = os.environ.get("MINT_G2_UPSTREAM_URL")
OPA = os.environ.get("MINT_G2_OPA_URL")
pytestmark = pytest.mark.skipif(
    not (LITELLM and MASTER and UPSTREAM and OPA and os.environ.get("MINT_TEST_DATABASE_URL")),
    reason="MINT_G2_LITELLM_URL, MINT_G2_MASTER_KEY, MINT_G2_UPSTREAM_URL, "
    "MINT_G2_OPA_URL, MINT_TEST_DATABASE_URL이 필요합니다",
)

from ctl_fixtures import INSTANCE, LOGIN_PASSWORDS, make_ctx, seed_approval_evidence  # noqa: E402

pytest_plugins = ("ctl_fixtures",)  # fresh_db, login_roles 고정 장치

psycopg = pytest.importorskip("psycopg")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.db.roles import LOGIN_ROLES  # noqa: E402
from mint_litellm.control.intake_checks import PolicyDataSource  # noqa: E402
from mint_litellm.control.litellm_admin import LiteLLMAdmin  # noqa: E402
from mint_litellm.control.litellm_control import STAGE2_ALLOWED_ROUTES, LiteLLMControl  # noqa: E402
from mint_litellm.control.services import base, settings  # noqa: E402
from mint_litellm.control.services import intakes as svc  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402
from mint_litellm.control.worker import Worker  # noqa: E402
from mint_litellm.types.cli_commands import CONTROL_PLANE_ALLOWED_ROUTES  # noqa: E402

READINESS = {"credential_notice": "mail", "revocation_record": "log", "audit_access_days": 90}
INPUTS = dict(
    purpose="통합 시험",
    data_grade="internal",
    allowed_resources=["docs"],
    provider="Test",
    owner_user_id="g2-user",
    readiness=READINESS,
    data_return_terms="종료 후 삭제",
)


def call(method, path, body=None, key=None):
    request = urllib.request.Request(
        f"{LITELLM}{path}",
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={"Authorization": f"Bearer {key or MASTER}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


@pytest.fixture
def lite():
    """시험마다 새 사용자·팀·팀 키와 제한된 제어 평면 키를 만든다."""
    tag = uuid.uuid4().hex[:8]
    user, team, admin = f"g2-user-{tag}", f"g2-team-{tag}", f"g2-ctl-{tag}"
    assert call("POST", "/user/new", {"user_id": user, "user_role": "internal_user"})[0] == 200
    assert call("POST", "/team/new", {"team_id": team})[0] == 200
    call("POST", "/team/member_add", {"team_id": team, "member": {"user_id": user, "role": "user"}})
    team_key = call("POST", "/key/generate", {"user_id": user, "team_id": team})[1]["key"]
    assert call("POST", "/user/new", {"user_id": admin, "user_role": "proxy_admin"})[0] == 200
    routes = [*CONTROL_PLANE_ALLOWED_ROUTES, *STAGE2_ALLOWED_ROUTES]
    ctl_key = call("POST", "/key/generate", {"user_id": admin, "allowed_routes": routes})[1]["key"]
    return {"user": user, "team_key": team_key, "ctl_key": ctl_key}


@pytest.fixture
def world(fresh_db, login_roles, lite):
    parts = urlsplit(UPSTREAM)
    ports = f"{parts.port or 443}"
    settings_ = Stage2Settings.from_env(
        {
            "MINT_EXPORT_DIR": "/tmp/mint-export",
            "MINT_EXPORT_HMAC_KEY": "A" * 43,
            "MINT_INTAKE_ALLOWED_PORTS": f"{ports},9998",
        }
    )
    params = conninfo_to_dict(fresh_db)
    params.update(user=LOGIN_ROLES["mint_worker"], password=LOGIN_PASSWORDS["mint_worker"])
    client = LiteLLMControl(LITELLM, lite["ctl_key"])
    worker = Worker(
        make_conninfo(**params),
        INSTANCE,
        settings_,
        litellm=client,
        policy_data=PolicyDataSource(OPA),
    )
    worker.open()
    admin = psycopg.connect(fresh_db, autocommit=True)
    admin.execute("DELETE FROM mint.schedules")
    with psycopg.connect(fresh_db) as conn:
        settings.initialize(make_ctx(conn), "acme", "ACME")
        conn.commit()
    meta = json.loads(urllib.request.urlopen(f"{OPA}/v1/data/mint/meta", timeout=10).read())[
        "result"
    ]
    admin.execute(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, %s, %s, %s)",
        (INSTANCE, meta["policy_version_id"], "cd" * 32, meta["bundle_sha256"]),
    )
    for status in ("staged", "active"):
        admin.execute(
            "UPDATE mint.policy_versions SET status = %s, activated_at = now(),"
            " activated_by = 'root' WHERE id = %s",
            (status, meta["policy_version_id"]),
        )
    for kind in ("provider", "egress_target"):
        admin.execute(
            "INSERT INTO mint.allowlists (id, instance_id, kind, value, valid_from, valid_until,"
            " created_by) VALUES (gen_random_uuid(), %s, %s, %s, now() - interval '1 day',"
            " now() + interval '30 days', 'root')",
            (INSTANCE, kind, parts.hostname),
        )
    yield {"url": fresh_db, "worker": worker, "admin": admin, "lite": lite, "client": client}
    worker.close()
    admin.close()


def submit(lite, name, url):
    status, body = call(
        "POST",
        "/v1/mcp/server/register",
        {
            "server_name": name,
            "alias": name,
            "url": url,
            "transport": "http",
            "auth_type": "none",
            "description": "통합 시험 제출",
        },
        key=lite["team_key"],
    )
    assert status == 201, body
    assert body["approval_status"] == "pending_review"
    return body["server_id"]


def run_jobs(world):
    while world["worker"].step():
        pass


def poll(world):
    with psycopg.connect(world["url"]) as conn:
        base.enqueue_job(
            make_ctx(conn), "submission_poll", "poll", f"submission_poll:{uuid.uuid4()}"
        )
        conn.commit()
    run_jobs(world)


def test_submission_to_checks_to_approval_against_real_litellm(world):
    server_id = submit(world["lite"], f"g2_ok_{uuid.uuid4().hex[:6]}", UPSTREAM)
    poll(world)
    admin = world["admin"]
    intake = fetchone(admin, "SELECT * FROM mint.intakes WHERE server_id = %s", (server_id,))
    assert (intake["status"], intake["source"], intake["requested_by"]) == (
        "received",
        "submission",
        world["lite"]["user"],
    )
    reader = LiteLLMAdmin(LITELLM, world["lite"]["ctl_key"])
    with psycopg.connect(world["url"]) as conn:
        svc.create(make_ctx(conn), reader, server_id, **INPUTS)
        conn.commit()
    run_jobs(world)
    intake = fetchone(admin, "SELECT * FROM mint.intakes WHERE server_id = %s", (server_id,))
    assert intake["status"] == "passed"
    checks = {
        c["check"]: c
        for c in fetchall(
            admin, "SELECT * FROM mint.intake_checks WHERE intake_id = %s", (intake["id"],)
        )
    }
    assert {c["result"] for c in checks.values()} == {"pass"} and len(checks) == 8
    assert checks["connection"]["evidence_ref"] == "litellm:/mcp-rest/test/connection"
    tools = fetchall(admin, "SELECT tool FROM mint.tool_contracts ORDER BY tool")
    assert [t["tool"] for t in tools] == ["echo", "mutable", "slow"]
    with psycopg.connect(world["url"]) as conn:
        seed_approval_evidence(conn, intake["id"])
        ctx = make_ctx(conn, "boss", "approver", "boss-1")
        result = svc.decide(
            ctx,
            str(intake["id"]),
            "approve",
            valid_until=datetime.now(UTC) + timedelta(days=30),
            scope_type="team",
            scope_id="team-x",
            reason="통합 시험",
        )
        conn.commit()
    row = fetchone(admin, "SELECT * FROM mint.intakes WHERE id = %s", (intake["id"],))
    assert (row["status"], row["decision"]) == ("decided", "approved")
    server = fetchone(admin, "SELECT * FROM mint.servers WHERE server_id = %s", (server_id,))
    assert server["contract_status"] == "managed" and server["status"] == "awaiting_approval"
    approval = fetchone(
        admin, "SELECT * FROM mint.approvals WHERE id = %s", (result["approval_id"],)
    )
    assert approval["status"] == "pending" and approval["tools"] == ["echo", "mutable", "slow"]
    # 승인 단계는 LiteLLM을 건드리지 않는다(제출 승인·pin은 동기화 단계).
    status, listing = call("GET", "/v1/mcp/server/submissions")
    state = {i["server_id"]: i["approval_status"] for i in listing["items"]}
    assert state[server_id] == "pending_review"


def test_a_failed_check_rejects_the_litellm_submission_automatically(world):
    parts = urlsplit(UPSTREAM)
    dead = f"{parts.scheme}://{parts.hostname}:9998/mcp"  # 허용 포트이지만 아무것도 듣지 않는다
    server_id = submit(world["lite"], f"g2_bad_{uuid.uuid4().hex[:6]}", dead)
    poll(world)
    reader = LiteLLMAdmin(LITELLM, world["lite"]["ctl_key"])
    with psycopg.connect(world["url"]) as conn:
        svc.create(make_ctx(conn), reader, server_id, **INPUTS)
        conn.commit()
    run_jobs(world)
    admin = world["admin"]
    intake = fetchone(admin, "SELECT * FROM mint.intakes WHERE server_id = %s", (server_id,))
    assert (intake["status"], intake["decision"]) == ("decided", "rejected")
    assert intake["decision_reason"] == "check_failed:connection:CONNECTION_FAILED"
    checks = fetchall(
        admin,
        'SELECT "check", result FROM mint.intake_checks WHERE intake_id = %s ORDER BY ran_at',
        (intake["id"],),
    )
    assert [c["check"] for c in checks] == ["url_guard", "oauth_issuer_allowlist", "connection"]
    status, listing = call("GET", "/v1/mcp/server/submissions")
    item = next(i for i in listing["items"] if i["server_id"] == server_id)
    assert item["approval_status"] == "rejected"
    assert item["review_notes"].startswith("check_failed:connection")
    assert (
        fetchone(admin, "SELECT status FROM mint.servers WHERE server_id = %s", (server_id,))[
            "status"
        ]
        == "rejected"
    )
    # 거절된 제출은 다음 조회에서 다시 신청이 되지 않는다
    poll(world)
    count = fetchone(
        admin, "SELECT count(*) AS n FROM mint.intakes WHERE server_id = %s", (server_id,)
    )["n"]
    assert count == 1


def test_registry_first_closes_allow_all_keys_on_the_real_litellm(world):
    """제출을 레지스트리에 올리면(승인) allow_all_keys가 같은 작업에서 꺼지고 다시 읽어 확인된다.

    자격 필요 상태는 시험 장치로 표시한다(업스트림이 인증을 요구하지 않는 시험 서버이므로).
    """
    status, body = call(
        "POST",
        "/v1/mcp/server/register",
        {
            "server_name": f"g2_all_{uuid.uuid4().hex[:6]}",
            "url": UPSTREAM,
            "transport": "http",
            "auth_type": "bearer_token",
            "allow_all_keys": True,
        },
        key=world["lite"]["team_key"],
    )
    assert status == 201 and body["allow_all_keys"] is True
    server_id = body["server_id"]
    poll(world)
    reader = LiteLLMAdmin(LITELLM, world["lite"]["ctl_key"])
    with psycopg.connect(world["url"]) as conn:
        svc.create(make_ctx(conn), reader, server_id, **INPUTS)
        conn.commit()
    admin = world["admin"]
    intake = fetchone(admin, "SELECT * FROM mint.intakes WHERE server_id = %s", (server_id,))
    run_jobs(world)
    admin.execute(
        "UPDATE mint.intakes SET needs_registry_credentials = true WHERE id = %s", (intake["id"],)
    )
    with psycopg.connect(world["url"]) as conn:
        svc.recheck(make_ctx(conn), str(intake["id"]), registry_first=True)
        conn.commit()
    run_jobs(world)
    status, listing = call("GET", "/v1/mcp/server/submissions")
    item = next(i for i in listing["items"] if i["server_id"] == server_id)
    assert (item["approval_status"], item["allow_all_keys"]) == ("active", False)
    assert fetchall(admin, "SELECT * FROM mint.alerts") == []
