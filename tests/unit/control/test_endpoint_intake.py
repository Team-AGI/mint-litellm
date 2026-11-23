"""단말 신청(키로 올리는 로컬 서버 신청): 신청 함수의 불변조건, 키별 범위, 로컬 승인 전이.

실 Postgres와 mint_plugin_app 로그인으로 함수를 직접 부른다(DB 주소가 없으면 건너뜀).
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, as_login
from psycopg.types.json import Jsonb

from mint_litellm.control.context import Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import intakes as svc
from mint_litellm.control.services import staff, staff_intakes
from mint_litellm.types.exec_contract import ExecContract

from . import test_intakes as base

world = base.world
strict = base.strict
HEX = "ab" * 32
USER, TEAM, KEY, GATEWAY = "emp-1", "team-1", "key-1", "gw-1"


def install(world, token=KEY, user=USER, team=TEAM, gateway=GATEWAY, **changes):
    values = {"revoked_at": None, "expires_at": None, **changes}
    ttl = None if values["expires_at"] is None else 30
    world.conn.execute(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, team_id, key_alias,"
        " issued_by, revoked_at, expires_at, ttl_days, mcp_key_token)"
        " VALUES (%s, %s, %s, %s, %s, 'root', %s, %s, %s, %s)",
        (INSTANCE, token, user, team, "alias-" + token, values["revoked_at"],
         values["expires_at"], ttl, gateway),
    )


def payload(**changes):
    body = {
        "server_id": "pyg", "purpose": "분석 보조", "data_grade": "internal",
        "resources": ["/data"],
        "spec": {"index": "pypi", "name": "pyghidra-mcp", "version": "0.3.1", "extras": [],
                 "command": "pyghidra-mcp", "argv": ["--stdio"]},
        "file_access": [{"path": "/data", "mode": "ro"}], "network": "none",
        "allowed_hosts": [], "env_names": [],
        "observed_tools": [{"name": "decompile"}, {"name": "list_functions"}],
    }
    return {**body, **changes}


def submit(world, body=None, token=KEY, request_id=None):
    request_id = request_id or uuid.uuid4()
    with as_login(world.url, "mint_plugin") as conn:
        row = conn.execute("SELECT mint.endpoint_submit_intake(%s, %s, %s)",
                           (token, request_id, Jsonb(body or payload()))).fetchone()
    return row[0]


def fails(world, match, body=None, token=KEY, request_id=None):
    with pytest.raises(Exception, match=match):
        submit(world, body, token, request_id)


def rows(world, table):
    return fetchall(world.conn, f"SELECT * FROM mint.{table}")


@pytest.fixture
def seeded(world):
    install(world)
    return world


# --- 신청 함수 ------------------------------------------------------------------------------


def test_a_submission_takes_identity_from_the_key_and_creates_only_the_request_records(seeded):
    world = seeded
    request_id = uuid.uuid4()
    body = payload(user_id="evil", owner_user_id="evil", org_id="other", requested_by="evil",
                   status="approved")
    assert submit(world, body, request_id=request_id) == request_id
    row = world.intake(request_id)
    assert (row["source"], row["status"], row["requested_by"], row["owner_user_id"],
            row["org_id"], row["endpoint_key_token"]) == (
        "endpoint", "received", USER, USER, "acme", KEY)
    server = world.server("pyg")
    assert (server["status"], server["identity_kind"], server["exec_contract_sha256"]) == (
        "pending", "stdio", None)
    candidate = fetchone(world.conn, "SELECT * FROM mint.deployment_contracts")
    assert (candidate["transport"], candidate["url"], candidate["status"]) == (
        "stdio", None, "candidate")
    assert candidate["pack_spec"]["name"] == "pyghidra-mcp"
    assert "evil" not in str(candidate["pack_spec"])
    job = world.jobs("intake_run")[0]
    assert job["target_ref"] == f"{request_id}/endpoint"
    assert world.events("intake_received")[0]["payload"]["requested_by"] == USER
    assert rows(world, "approvals") == [] and rows(world, "usage_relations") == []
    quota = rows(world, "endpoint_intake_quota")
    assert [(q["user_id"], q["count"]) for q in quota] == [(USER, 1)]


@pytest.mark.parametrize("change", [
    {"revoked_at": datetime.now(UTC)},
    {"expires_at": datetime.now(UTC) - timedelta(minutes=1)},
])
def test_a_revoked_or_expired_key_cannot_submit(world, change):
    install(world, **change)
    fails(world, "MINT-KEY")
    assert rows(world, "intakes") == [] and rows(world, "servers") == []


def test_an_unknown_key_cannot_submit(seeded):
    fails(seeded, "MINT-KEY", token="nope")


def test_the_same_request_with_the_same_body_returns_the_same_intake_once(seeded):
    world = seeded
    request_id = uuid.uuid4()
    assert submit(world, request_id=request_id) == submit(world, request_id=request_id)
    assert len(rows(world, "intakes")) == 1 and len(world.jobs("intake_run")) == 1
    assert rows(world, "endpoint_intake_quota")[0]["count"] == 1


def test_a_reused_request_identifier_with_another_body_or_user_conflicts(seeded):
    world = seeded
    install(world, token="key-2", user="emp-2", team=None, gateway="gw-2")
    request_id = uuid.uuid4()
    submit(world, request_id=request_id)
    fails(world, "MINT-CONFLICT", payload(purpose="다른 목적"), request_id=request_id)
    fails(world, "MINT-CONFLICT", token="key-2", request_id=request_id)
    assert len(rows(world, "intakes")) == 1


def test_a_server_in_progress_or_already_registered_is_refused(seeded):
    world = seeded
    submit(world)
    fails(world, "MINT-CONFLICT: server request in progress")
    world.conn.execute("UPDATE mint.servers SET status = 'validating'")
    world.conn.execute("UPDATE mint.servers SET status = 'awaiting_approval'")
    fails(world, "MINT-CONFLICT: server request in progress")
    world.conn.execute(  # 같은 이름의 원격 서버
        "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
        " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'srv-a', 'pending', %s,"
        " 'http', 'none', 'root')", (INSTANCE, HEX))
    fails(world, "MINT-CONFLICT: server already registered", payload(server_id="srv-a"))


def test_the_daily_user_and_organization_limits_and_three_at_a_time(seeded):
    world = seeded
    for n in range(3):
        submit(world, payload(server_id=f"s{n}"))
    fails(world, "MINT-QUOTA", payload(server_id="s3"))  # 동시 진행 3건
    world.conn.execute("UPDATE mint.intakes SET status = 'checking'")
    fails(world, "MINT-QUOTA", payload(server_id="s3"))  # 검사 중도 진행 중이다
    world.conn.execute("DELETE FROM mint.endpoint_intake_quota")
    world.conn.execute(
        "UPDATE mint.intakes SET status = 'failed'")  # 진행 중이 아니면 다시 받는다
    world.conn.execute(
        "INSERT INTO mint.endpoint_intake_quota (instance_id, org_id, user_id, day, count)"
        " VALUES (%s, 'acme', %s, (now() AT TIME ZONE 'UTC')::date, 20)", (INSTANCE, USER))
    fails(world, "MINT-QUOTA", payload(server_id="s9"))  # 사용자 하루 20건
    world.conn.execute("DELETE FROM mint.endpoint_intake_quota")
    world.conn.execute(
        "INSERT INTO mint.endpoint_intake_quota (instance_id, org_id, user_id, day, count)"
        " VALUES (%s, 'acme', 'someone-else', (now() AT TIME ZONE 'UTC')::date, 100)", (INSTANCE,))
    fails(world, "MINT-QUOTA", payload(server_id="s9"))  # 조직 하루 100건
    assert len(rows(world, "intakes")) == 3  # 거절된 시도는 아무것도 남기지 않는다


@pytest.mark.parametrize("change", [
    {"server_id": "bad id"}, {"purpose": ""}, {"data_grade": "secret"},
    {"network": "any"}, {"network": "hosts"}, {"network": "none", "allowed_hosts": ["a.b"]},
    {"file_access": [{"path": "", "mode": "ro"}]}, {"env_names": ["1BAD"]},
    {"observed_tools": [{}] * 201}, {"resources": "x"},
])
def test_malformed_input_is_refused_before_any_write(seeded, change):
    fails(seeded, "MINT-INVALID", payload(**change))
    spec = payload()["spec"]
    for bad in ({**spec, "index": "npm"}, {**spec, "version": ""}, {**spec, "name": "a b"},
                {**spec, "argv": "x"}):
        fails(seeded, "MINT-INVALID", payload(spec=bad))
    assert rows(seeded, "intakes") == []


# --- 키별 범위 ------------------------------------------------------------------------------


def pass_the_checks(world, request_id, pack=True, final="passed", **extra):
    """검사 파이프라인이 끝낸 상태를 만든다(묶음 열 채움, 서버·신청 전이)."""
    if pack:
        contract = ExecContract(
            schema_version=2, executable="/usr/bin/python3", argv=("--stdio",),
            pack={"sha256": HEX, "runtime": "python3", "python": "3.12",
                  "entry": "pyghidra_mcp.server:main"}, **extra)
        world.conn.execute(
            "UPDATE mint.deployment_contracts SET pack_sha256 = %s, pack_manifest = %s,"
            " exec_contract = %s WHERE id = %s",
            (HEX, Jsonb({"schema": 1}), Jsonb(contract.document()), request_id))
    world.conn.execute("UPDATE mint.intakes SET status = 'checking' WHERE id = %s", (request_id,))
    world.conn.execute("UPDATE mint.servers SET status = 'validating'")
    world.conn.execute("UPDATE mint.servers SET status = 'awaiting_approval'")
    world.conn.execute("UPDATE mint.intakes SET status = %s WHERE id = %s", (final, request_id))


def approved_local(world, **scope):
    request_id = submit(world)
    pass_the_checks(world, request_id)
    result = world.decide(str(request_id), "approve", **scope)
    return request_id, result


def scope(world, key=KEY):
    with as_login(world.url, "mint_plugin") as conn:
        return conn.execute(
            "SELECT * FROM mint.endpoint_scope(%s, %s)", (INSTANCE, key)).fetchall()


def test_a_local_approval_runs_registration_server_scope_and_sync_in_one_step(seeded):
    world = seeded
    request_id, result = approved_local(world)
    assert world.intake(request_id)["decision"] == "approved"
    server = world.server("pyg")
    contract = fetchone(world.conn, "SELECT * FROM mint.deployment_contracts")
    assert server["status"] == "approved" and server["exec_contract_version"] == 2
    assert server["exec_contract_sha256"] == contract["exec_contract_sha256"]
    assert contract["status"] == "approved" and contract["pack_sha256"] == HEX
    approval = fetchone(world.conn, "SELECT * FROM mint.approvals")
    assert (approval["status"], approval["scope_type"], approval["scope_id"]) == (
        "active", "user", USER)  # 기본 범위는 신청자 본인
    assert approval["tools"] == ["decompile", "list_functions"]  # 후보가 없어 보고 이름이 상한
    assert str(approval["id"]) == result["approval_id"]
    assert [j["status"] for j in world.jobs("kit_key_sync")] == ["pending"]
    assert world.jobs("sync_server") == []  # LiteLLM에 서버가 없다
    assert len(world.events("server_registered")) == 1 and len(world.events("server_approved")) == 1
    (row,) = scope(world)
    assert (row[0], row[1]) == ("pyg", HEX) and row[3]["pack"]["sha256"] == HEX


def test_a_local_approval_needs_a_ready_pack_and_known_tools(seeded):
    world = seeded
    request_id = submit(world, payload(observed_tools=[]))
    pass_the_checks(world, request_id, pack=False)
    held = world.decide(str(request_id), "approve")  # 묶음이 없어도 승인은 받는다
    assert held["approval_pending"] and world.intake(request_id)["decision"] is None
    assert world.call(lambda ctx: svc.apply_deferred_approval(ctx, str(request_id))) is None
    pass_the_checks_pack_only(world, request_id)
    assert world.call(
        lambda ctx: svc.apply_deferred_approval(ctx, str(request_id))) == "applied"
    assert world.intake(request_id)["approve_when_ready"] is None
    assert world.server("pyg")["status"] == "approved"
    assert rows(world, "approvals")[0]["tools"] == ["*"]


def pass_the_checks_pack_only(world, request_id):
    contract = ExecContract(
        schema_version=2, executable="/usr/bin/python3",
        pack={"sha256": HEX, "runtime": "python3", "python": "3.12", "entry": "a.b:c"})
    world.conn.execute(
        "UPDATE mint.deployment_contracts SET pack_sha256 = %s, exec_contract = %s WHERE id = %s",
        (HEX, Jsonb(contract.document()), request_id))


def test_an_indeterminate_local_request_uses_the_exception_approval_with_a_second_approver(
    seeded, strict
):
    world = seeded
    request_id = submit(world)
    pass_the_checks(world, request_id, final="indeterminate")
    second = Operator("boss2", "approver", "boss-2")
    with pytest.raises(Exception, match="두 번째"):
        world.call(lambda ctx: svc.decide(ctx, str(request_id), "except", reason="예외"),
                   name="boss", user="boss-1", role="approver")
    world.call(lambda ctx: svc.decide(ctx, str(request_id), "except", reason="예외",
                                      second=second), name="boss", user="boss-1", role="approver")
    approval = fetchone(world.conn, "SELECT * FROM mint.approvals")
    assert approval["class"] == "exception" and approval["status"] == "active"
    assert world.server("pyg")["status"] == "approved"


def test_a_remote_request_is_unchanged_by_local_approval(world):
    intake_id = base.passed(world)
    world.decide(intake_id, "approve", valid_until=base.FUTURE)
    assert world.server()["status"] == "awaiting_approval"
    assert fetchone(world.conn, "SELECT status FROM mint.approvals")["status"] == "pending"


@pytest.mark.parametrize("scope_type,scope_id", [
    ("user", USER), ("team", TEAM), ("key", KEY), ("key", GATEWAY)])
def test_scope_reaches_the_key_through_user_team_and_key(seeded, scope_type, scope_id):
    approved_local(seeded, scope_type=scope_type, scope_id=scope_id)
    assert [r[0] for r in scope(seeded)] == ["pyg"]


def test_scope_by_organization_and_not_for_other_users_or_teams(seeded):
    world = seeded
    approved_local(world, scope_type="user", scope_id="someone-else")
    assert scope(world) == []
    approved_local_org(world)
    assert [r[0] for r in scope(world)] == ["pyg"]
    install(world, token="key-2", user="emp-2", team=None, gateway="gw-2")
    assert [r[0] for r in scope(world, "key-2")] == ["pyg"]  # 같은 조직


def approved_local_org(world):
    world.conn.execute(
        "UPDATE mint.approvals SET status = 'revoked', revoked_at = now(), revoke_reason = 'x'"
        " WHERE status = 'active'")
    relation = fetchone(world.conn, "SELECT * FROM mint.usage_relations")
    world.conn.execute(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by,"
        " status) VALUES (gen_random_uuid(), %s, 'acme', %s, 'standard', 'pyg', ARRAY['decompile'],"
        " 'org', 'acme', now(), now() + interval '30 days', '{}', 'root', 'x', 'active')",
        (INSTANCE, relation["id"]))


@pytest.mark.parametrize("how", ["revoked", "expired", "suspended", "denied", "key_revoked",
                                 "relation_closed", "recert_held"])
def test_scope_drops_the_server_when_the_approval_lapses(seeded, how):
    world = seeded
    approved_local(world)
    assert len(scope(world)) == 1
    sql = {
        "revoked": "UPDATE mint.approvals SET status = 'revoked', revoked_at = now(),"
                   " revoke_reason = 'x'",
        "expired": "UPDATE mint.approvals SET status = 'expired'",
        "suspended": "UPDATE mint.servers SET status = 'suspended'",
        "denied": "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id,"
                  " server_id, reason, created_by) VALUES (gen_random_uuid(), '" + INSTANCE
                  + "', 'acme', 'server', 'pyg', 'pyg', 'x', 'root')",
        "key_revoked": "UPDATE mint.endpoint_installs SET revoked_at = now()",
        "relation_closed": "UPDATE mint.usage_relations SET status = 'terminating'",
        "recert_held": "UPDATE mint.approvals SET recert_held_at = now()",
    }[how]
    world.conn.execute(sql)
    assert scope(world) == []


def test_a_tool_scoped_denial_keeps_the_server_and_an_unknown_key_sees_nothing(seeded):
    world = seeded
    approved_local(world)
    world.conn.execute(
        "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, server_id,"
        " tools, reason, created_by) VALUES (gen_random_uuid(), %s, 'acme', 'user', %s, 'pyg',"
        " ARRAY['decompile'], 'x', 'root')", (INSTANCE, USER))
    assert len(scope(world)) == 1 and scope(world, "nope") == []


def test_the_permit_ends_with_the_approval_or_after_the_configured_hours(seeded):
    world = seeded
    approved_local(world, valid_until=datetime.now(UTC) + timedelta(hours=2))
    until = scope(world)[0][4]
    assert abs((until - (datetime.now(UTC) + timedelta(hours=2))).total_seconds()) < 60
    approved_local_org(world)
    until = scope(world)[0][4]
    assert abs((until - (datetime.now(UTC) + timedelta(hours=24))).total_seconds()) < 60


def test_a_first_version_local_server_is_scoped_with_its_registered_contract(seeded):
    world = seeded
    contract = ExecContract(executable="/usr/bin/node", argv=("/opt/srv/index.js",),
                            executable_sha256=HEX)
    world.call(lambda ctx: __import__("mint_litellm.control.servers", fromlist=["x"])
               .register_local(ctx, "old-local", contract))
    world.conn.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'old-local'")
    world.conn.execute(
        "INSERT INTO mint.usage_relations (id, instance_id, org_id, purpose, server_id)"
        " VALUES (gen_random_uuid(), %s, 'acme', 'p', 'old-local')", (INSTANCE,))
    relation = fetchone(world.conn, "SELECT id FROM mint.usage_relations")
    world.conn.execute(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by,"
        " status) VALUES (gen_random_uuid(), %s, 'acme', %s, 'standard', 'old-local',"
        " ARRAY['t'], 'user', %s, now(), now() + interval '5 days', '{}', 'root', 'x', 'active')",
        (INSTANCE, relation["id"], USER))
    (row,) = scope(world)
    assert row[0] == "old-local" and row[1] is None and row[2] is None
    assert row[3]["executable_sha256"] == HEX


# --- 읽기와 철회 ----------------------------------------------------------------------------


def test_my_intakes_lists_only_the_key_owners_staff_and_endpoint_requests(seeded):
    world = seeded
    install(world, token="key-2", user="emp-2", team=None, gateway="gw-2")
    mine = submit(world)
    submit(world, payload(server_id="theirs"), token="key-2")
    with as_login(world.url, "mint_plugin") as conn:
        got = conn.execute("SELECT * FROM mint.endpoint_my_intakes(%s, %s)",
                           (INSTANCE, KEY)).fetchall()
        assert [(r[0], r[1], r[2]) for r in got] == [(mine, "pyg", "received")]
        world.conn.execute("UPDATE mint.endpoint_installs SET revoked_at = now()"
                           " WHERE key_token = %s", (KEY,))
    with pytest.raises(Exception, match="MINT-KEY"), as_login(world.url, "mint_plugin") as conn:
        conn.execute("SELECT * FROM mint.endpoint_my_intakes(%s, %s)", (INSTANCE, KEY))


def test_my_intakes_names_the_blocking_check_and_whether_the_pack_exists(seeded):
    world = seeded
    mine = submit(world)
    world.conn.execute(
        "INSERT INTO mint.intake_checks (id, instance_id, intake_id, \"check\", attempt, result,"
        " reason_code, method) VALUES (gen_random_uuid(), %s, %s, 'pack_build', 1,"
        " 'indeterminate', 'PACK_SDIST_ONLY', 'm')", (INSTANCE, mine))
    with as_login(world.url, "mint_plugin") as conn:
        row = conn.execute("SELECT check_name, reason_code, pack_ready"
                           " FROM mint.endpoint_my_intakes(%s, %s)", (INSTANCE, KEY)).fetchone()
    assert row == ("pack_build", "PACK_SDIST_ONLY", False)


def test_the_employee_pages_and_withdrawal_cover_endpoint_requests(seeded):
    world = seeded
    request_id = submit(world)
    with as_login(world.url, "mint_staff") as sc, as_login(world.url, "mint_control") as control:
        sctx = staff.StaffContext(sc, control, INSTANCE, USER)
        assert [str(r["id"]) for r in staff_intakes.listing(sctx)] == [str(request_id)]
        assert staff_intakes.detail(sctx, str(request_id))["server_id"] == "pyg"
        other = staff.StaffContext(sc, control, INSTANCE, "emp-2")
        assert staff_intakes.listing(other) == []
        version = world.intake(request_id)["state_version"]
        result = control.execute(
            "SELECT mint.withdraw_intake_row(%s, %s, %s, %s, '취소', %s)",
            (INSTANCE, request_id, USER, version, USER)).fetchone()[0]
        control.commit()
    assert result["changed"] is True
    assert world.intake(request_id)["decision"] == "withdrawn"
    assert fetchone(world.conn, "SELECT status FROM mint.deployment_contracts")["status"] == (
        "superseded")
    assert submit(world) is not None  # 철회한 서버는 다시 신청할 수 있다


def test_the_approver_can_only_narrow_the_declared_permissions(seeded):
    world = seeded
    request_id = submit(world, payload(file_access=[{"path": "/data", "mode": "ro"},
                                                    {"path": "/logs", "mode": "rw"}],
                                       network="hosts", allowed_hosts=["api.example.com"]))
    pass_the_checks(world, request_id, file_access=[{"path": "/data", "mode": "ro"},
                                                    {"path": "/logs", "mode": "rw"}],
                    network="hosts", allowed_hosts=["api.example.com"])
    before = fetchone(world.conn, "SELECT exec_contract FROM mint.deployment_contracts")
    for bad in ({"narrow_network": "any"}, {"narrow_file_access": ["/etc"]}):
        with pytest.raises(ControlError):
            world.decide(str(request_id), "approve", **bad)
    assert world.server("pyg")["status"] == "awaiting_approval"
    world.decide(str(request_id), "approve", narrow_network="none", narrow_file_access=["/data"])
    deployment = fetchone(world.conn, "SELECT * FROM mint.deployment_contracts")
    doc = deployment["exec_contract"]
    assert doc["network"] == "none" and "allowed_hosts" not in doc
    assert [f["path"] for f in doc["file_access"]] == ["/data"]
    assert before["exec_contract"] != doc
    stored = ExecContract.model_validate({k: v for k, v in doc.items() if k != "identity_kind"})
    assert world.server("pyg")["exec_contract_sha256"] == stored.sha256()
    assert deployment["exec_contract_sha256"] == stored.sha256()


# --- 원격 주소 신청(키로 올리는 직원 원격 신청) ------------------------------------------------


def remote_payload(**changes):
    from mint_litellm.endpoint.decide import RemoteIntakeBody

    body = RemoteIntakeBody(request_id=uuid.uuid4(), server_id="docs",
                            url="https://mcp.example.com/mcp", purpose="문서 조회")
    return {**body.payload(), **changes}


def submit_remote(world, body=None, token=KEY, request_id=None):
    request_id = request_id or uuid.uuid4()
    with as_login(world.url, "mint_plugin") as conn:
        row = conn.execute("SELECT mint.endpoint_submit_remote_intake(%s, %s, %s)",
                           (token, request_id, Jsonb(body or remote_payload()))).fetchone()
    return row[0]


def test_a_remote_request_from_a_key_is_the_same_request_a_staff_member_would_make(seeded):
    world = seeded
    request_id = uuid.uuid4()
    assert submit_remote(world, request_id=request_id) == request_id
    row = world.intake(request_id)
    assert (row["source"], row["status"], row["requested_by"], row["org_id"],
            row["staff_registry_required"], row["endpoint_key_token"]) == (
        "staff", "received", USER, "acme", True, None)
    server = world.server("docs")
    assert (server["status"], server["identity_kind"], server["transport"]) == (
        "pending", "remote", "http")
    contract = fetchone(world.conn, "SELECT url, transport FROM mint.deployment_contracts"
                        " WHERE id = %s", (request_id,))
    assert contract == {"url": "https://mcp.example.com/mcp", "transport": "http"}
    assert submit_remote(world, request_id=request_id) == request_id  # 재전송은 같은 번호


def test_a_second_request_for_the_same_address_joins_the_one_in_progress(seeded):
    world = seeded
    first = submit_remote(world)
    assert submit_remote(world) == first
    assert len(rows(world, "intakes")) == 1


def test_a_remote_request_refuses_a_bad_key_a_bad_address_and_another_users_server(seeded):
    world = seeded
    with pytest.raises(Exception, match="MINT-KEY"):
        submit_remote(world, token="nope")
    with pytest.raises(Exception, match="MINT-INVALID"):
        submit_remote(world, remote_payload(url="ftp://x.example.com/", contract="{}"))
    with pytest.raises(Exception, match="MINT-INVALID"):
        submit_remote(world, remote_payload(contract='{"url":"https://other.example.com/"}'))
    first = submit_remote(world)
    assert first
    install(world, token="key-2", user="emp-2", gateway="gw-2")
    with pytest.raises(Exception, match="MINT-CONFLICT"):
        submit_remote(world, token="key-2")


def test_official_package_hosts_are_seeded_once_and_a_lift_is_respected(seeded):
    from mint_litellm.control import allowlists

    world = seeded
    world.call(allowlists.ensure_defaults)
    world.call(allowlists.ensure_defaults)
    hosts = sorted(r["value"] for r in rows(world, "allowlists")
                   if r["status"] == "active" and r["created_by"] == "mint-default")
    assert hosts == ["files.pythonhosted.org", "pypi.org", "registry.npmjs.org"]
    world.conn.execute("ALTER TABLE mint.allowlists DISABLE TRIGGER allowlists_1_status")
    world.conn.execute("UPDATE mint.allowlists SET status = 'lifted' WHERE value = 'pypi.org'")
    world.conn.execute("ALTER TABLE mint.allowlists ENABLE TRIGGER allowlists_1_status")
    world.call(allowlists.ensure_defaults)
    assert "pypi.org" not in [r["value"] for r in rows(world, "allowlists")
                              if r["status"] == "active"]
