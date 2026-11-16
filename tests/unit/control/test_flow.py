"""운영자 명령의 상태 변경과 사건 기록. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, make_ctx
from litellm_stub import ALIAS_KEY, GOOD_KEY

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import (  # noqa: E402
    allowlists,
    approvals,
    consents,
    orgs,
    policy_versions,
    relations,
    servers,
    settings_store,
)
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.types.decision import url_sha256  # noqa: E402
from mint_litellm.types.identity import SubjectType  # noqa: E402
from mint_litellm.types.settings import Mode  # noqa: E402

URL = "http://upstream.test/mcp"
HEX = "ab" * 32
NOW = datetime.now(UTC)
LATER = NOW + timedelta(days=30)


def events(conn, kind=None):
    sql = "SELECT * FROM mint.events WHERE instance_id = %s"
    params = [INSTANCE]
    if kind:
        sql += " AND kind = %s"
        params.append(kind)
    return fetchall(conn, sql + " ORDER BY inserted_at, event_id", tuple(params))


def count(conn, kind):
    return len(events(conn, kind))


def prepare(ctx, litellm, org="acme", team=None):
    orgs.add(ctx, org, "ACME")
    orgs.bind(ctx, org, SubjectType.USER, "human-1")  # 시험 키의 소유 사용자
    servers.register(ctx, litellm, "ctl-everything", URL)
    return relations.add(ctx, org, "ctl-everything", "ops", team)


def approve(ctx, litellm, relation, **overrides):
    values = dict(
        relation_id=relation, scope_type="key", scope_id=GOOD_KEY, tools=["echo"],
        valid_from=NOW, valid_until=LATER, approval_class="standard", basis_text="티켓",
        requested_by="requester", allowlist_ids=[], second=None,
    )
    values.update(overrides)
    return approvals.approve(ctx, litellm, **values)


def fails(conn, message=None):
    return pytest.raises((ControlError, psycopg.Error))


# --- 서버·관계 --------------------------------------------------------------


def test_register_stores_contract_values_from_the_registry_rules(ctx, litellm, conn, stub):
    orgs.add(ctx, "acme", "ACME")
    body = {**stub.routes[("/v1/mcp/server/ctl-everything", frozenset())][1],
            "url": URL, "auth_type": "bearer_token"}
    stub.set("/v1/mcp/server/ctl-everything", body)
    servers.register(ctx, litellm, "ctl-everything")
    row = fetchone(conn, "SELECT * FROM mint.servers WHERE server_id = 'ctl-everything'")
    assert row["status"] == "awaiting_approval"
    assert row["url_sha256"] == url_sha256(URL)
    assert (row["transport"], row["auth_type"]) == ("http", "bearer_token")
    assert events(conn, "server_registered")[0]["payload"]["url_source"] == "registry"


def test_register_without_auth_uses_none_and_requires_a_url(ctx, litellm, conn):
    with pytest.raises(ControlError, match="--url"):
        servers.register(ctx, litellm, "ctl-everything")
    servers.register(ctx, litellm, "ctl-everything", URL)
    row = fetchone(conn, "SELECT * FROM mint.servers")
    assert row["auth_type"] == "none"
    assert events(conn, "server_registered")[0]["payload"]["url_source"] == "operator"


def test_register_rejects_unknown_pending_and_duplicate_servers(ctx, litellm, stub):
    with pytest.raises(ControlError, match="없습니다"):
        servers.register(ctx, litellm, "nonexistent", URL)
    body = dict(stub.routes[("/v1/mcp/server/ctl-everything", frozenset())][1])
    stub.set("/v1/mcp/server/ctl-everything", {**body, "approval_status": "pending_review"})
    with pytest.raises(ControlError, match="승인되지"):
        servers.register(ctx, litellm, "ctl-everything", URL)
    stub.set("/v1/mcp/server/ctl-everything", body)
    servers.register(ctx, litellm, "ctl-everything", URL)


def test_register_url_conflicting_with_the_registry_is_rejected(ctx, litellm, stub):
    body = dict(stub.routes[("/v1/mcp/server/ctl-everything", frozenset())][1])
    stub.set("/v1/mcp/server/ctl-everything", {**body, "url": URL})
    with pytest.raises(ControlError, match="다릅니다"):
        servers.register(ctx, litellm, "ctl-everything", "http://other.test/mcp")


def test_first_approval_activates_the_server_in_one_transaction(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    before = fetchone(conn, "SELECT epoch FROM mint.state_epoch WHERE instance_id = %s",
                      (INSTANCE,))["epoch"]
    approval_id, _ = approve(ctx, litellm, relation)
    server = fetchone(conn, "SELECT * FROM mint.servers")
    assert server["status"] == "approved"
    granted, activated = events(conn, "approval_granted"), events(conn, "server_approved")
    assert len(granted) == 1 and len(activated) == 1
    assert granted[0]["source_key"] == f"approval:{approval_id}:1:approval_granted"
    assert activated[0]["source_key"] == f"server:{server['id']}:{server['state_version']}:" \
        "server_approved"
    after = fetchone(conn, "SELECT epoch FROM mint.state_epoch WHERE instance_id = %s",
                     (INSTANCE,))["epoch"]
    assert after > before


def test_second_approval_does_not_change_the_server(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    approve(ctx, litellm, relation)
    approve(ctx, litellm, relation, tools=["fetch"])
    assert count(conn, "server_approved") == 1
    assert count(conn, "approval_granted") == 2


def test_allowlist_reference_is_only_accepted_on_the_first_approval(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    entry = allowlists.add(ctx, "provider", "example.test", NOW, LATER, None, None)
    approve(ctx, litellm, relation, allowlist_ids=[entry])
    server = fetchone(conn, "SELECT basis_allowlist_ids FROM mint.servers")
    assert [str(x) for x in server["basis_allowlist_ids"]] == [entry]
    with pytest.raises(ControlError, match="첫 승인"):
        approve(ctx, litellm, relation, allowlist_ids=[entry])


def test_approve_validations(ctx, litellm):
    relation = prepare(ctx, litellm)
    cases = [
        ({"scope_type": "robot"}, "scope"),
        ({"tools": []}, "도구"),
        ({"basis_text": " "}, "근거"),
        ({"valid_until": NOW - timedelta(days=1), "valid_from": NOW - timedelta(days=2)}, "지났"),
        ({"valid_from": LATER, "valid_until": NOW}, "뒤여야"),
        ({"allowlist_ids": ["00000000-0000-0000-0000-000000000000"]}, "허용 목록"),
    ]
    for override, message in cases:
        with pytest.raises(ControlError, match=message):
            approve(ctx, litellm, relation, **override)


def test_approve_needs_an_active_relation_and_a_usable_server(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    approve(ctx, litellm, relation)
    servers.suspend(ctx, "ctl-everything")
    with pytest.raises(ControlError, match="suspended"):
        approve(ctx, litellm, relation, tools=["fetch"])
    servers.resume(ctx, "ctl-everything")
    relations.terminate(ctx, relation)
    with pytest.raises(ControlError, match="이용 관계"):
        approve(ctx, litellm, relation, tools=["fetch"])


def test_approve_rejects_an_alias_formatted_permission_and_explains(ctx, litellm):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError) as raised:
        approve(ctx, litellm, relation, scope_id=ALIAS_KEY)
    assert "server_id" in str(raised.value) and "everything" in str(raised.value)


def test_approve_rejects_an_alias_formatted_team_permission(ctx, litellm):
    relation = prepare(ctx, litellm, team="team-op")
    with pytest.raises(ControlError, match="서버 식별자가 아닌"):
        approve(ctx, litellm, relation, scope_type="team", scope_id="team-op")


def test_approve_requires_the_target_to_exist_in_litellm(ctx, litellm):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError, match="찾을 수 없습니다"):
        approve(ctx, litellm, relation, scope_type="user", scope_id="nobody")


def test_user_approval_uses_litellm_v2_permission_detail(ctx, litellm, stub, conn):
    relation = prepare(ctx, litellm)
    body = json.loads(
        json.dumps(stub.routes[("/user/info", frozenset({("user_id", "human-1")}))][1])
    )
    body["user_info"].update(object_permission_id="perm-1", object_permission=None)
    stub.set("/user/info", body, user_id="human-1")
    stub.set(
        "/v2/user/info",
        {
            "user_id": "human-1",
            "object_permission": {
                "object_permission_id": "perm-1",
                "mcp_servers": ["ctl-everything"],
            },
        },
        user_id="human-1",
    )
    approve(ctx, litellm, relation, scope_type="user", scope_id="human-1")
    assert fetchone(conn, "SELECT scope_type FROM mint.approvals")["scope_type"] == "user"


def test_approve_is_refused_when_litellm_has_not_granted_the_server(ctx, litellm, stub, conn):
    relation = prepare(ctx, litellm)
    info = json.loads(json.dumps(stub.routes[("/key/info", frozenset({("key", GOOD_KEY)}))][1]))
    info["info"]["object_permission"]["mcp_servers"] = []
    stub.set("/key/info", info, key=GOOD_KEY)
    with pytest.raises(ControlError, match="권한이 부여되어 있지 않아"):
        approve(ctx, litellm, relation)
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.approvals")["n"] == 0
    assert fetchone(conn, "SELECT status FROM mint.servers")["status"] == "awaiting_approval"
    assert count(conn, "approval_granted") == 0


def test_approve_accepts_a_permission_given_through_a_shared_access_group(ctx, litellm, stub):
    relation = prepare(ctx, litellm)
    info = json.loads(json.dumps(stub.routes[("/key/info", frozenset({("key", GOOD_KEY)}))][1]))
    info["info"]["object_permission"].update(mcp_servers=[], mcp_access_groups=["g1"])
    stub.set("/key/info", info, key=GOOD_KEY)
    listing = json.loads(json.dumps(stub.routes[("/v1/mcp/server", frozenset())][1]))
    next(s for s in listing if s["server_id"] == "ctl-everything")["mcp_access_groups"] = ["g1"]
    stub.set("/v1/mcp/server", listing)
    approve(ctx, litellm, relation)


def test_org_scope_approvals_are_unsupported(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError, match="MINT-UNSUPPORTED.*team"):
        approve(ctx, litellm, relation, scope_type="org", scope_id="acme")
    assert count(conn, "approval_granted") == 0


def test_key_scope_needs_the_derived_org_to_match_the_relation(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    orgs.add(ctx, "other", "OTHER")
    orgs.unbind(ctx, SubjectType.USER, "human-1")
    orgs.bind(ctx, "other", SubjectType.USER, "human-1")
    with pytest.raises(ControlError, match="조직 유도 결과"):
        approve(ctx, litellm, relation)
    orgs.unbind(ctx, SubjectType.USER, "human-1")
    with pytest.raises(ControlError, match="조직 유도 결과"):  # 기본 조직도 없다
        approve(ctx, litellm, relation)
    settings_store.set_default_org(ctx, "acme")
    approve(ctx, litellm, relation)  # 바인딩이 없으면 기본 조직으로 유도된다


def test_team_scope_without_a_relation_team_needs_a_binding_to_the_relation_org(ctx, litellm):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError, match="묶여 있지 않습니다"):
        approve(ctx, litellm, relation, scope_type="team", scope_id="team-op")


def test_user_scope_needs_litellm_user_permission_and_org(ctx, litellm, stub):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError, match="권한이 부여되어 있지 않아"):
        approve(ctx, litellm, relation, scope_type="user", scope_id="human-1")


def test_relation_team_scope_is_enforced_for_keys_and_teams(ctx, litellm):
    relation = prepare(ctx, litellm, team="team-x")
    with pytest.raises(ControlError, match="팀"):
        approve(ctx, litellm, relation)
    with pytest.raises(ControlError, match="팀"):
        approve(ctx, litellm, relation, scope_type="team", scope_id="team-y")


def test_segregation_of_duties_by_user_id(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    same_person = make_ctx(conn, "second-token", "approver", user_id="requester")
    with pytest.raises(ControlError, match="요청자와 같은 사용자"):
        approve(same_person, litellm, relation)
    from mint_litellm.control.context import Operator

    other = Operator("other", "approver", "someone-else")
    approval_id, _ = approve(same_person, litellm, relation, second=other)
    payload = fetchone(conn, "SELECT payload FROM mint.events WHERE kind = 'approval_granted'")
    assert payload["payload"]["second_approver"] == "other"
    assert payload["payload"]["granted_by"] == "second-token"
    assert approval_id
    # 두 번째 승인자도 요청자와 같은 사용자이거나 권한이 낮으면 거부
    for bad in (Operator("b", "approver", "requester"), Operator("v", "viewer", "x"),
                Operator("n", "approver", None)):
        with pytest.raises(ControlError, match="두 번째 승인자"):
            approve(same_person, litellm, relation, second=bad)


def test_revoke_records_one_event_and_rejects_a_second_revoke(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    approval_id, _ = approve(ctx, litellm, relation)
    approvals.revoke(ctx, approval_id, "종료", deny=False)
    assert count(conn, "approval_revoked") == 1 and count(conn, "denial_created") == 0
    row = fetchone(conn, "SELECT status, revoked_at FROM mint.approvals")
    assert row["status"] == "revoked" and row["revoked_at"] is not None
    with pytest.raises(ControlError, match="활성 상태"):
        approvals.revoke(ctx, approval_id, "again", deny=False)
    with pytest.raises(ControlError, match="--reason"):
        approvals.revoke(ctx, approval_id, " ", deny=False)


def test_revoke_with_deny_creates_a_denial_of_the_same_scope(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    approval_id, _ = approve(ctx, litellm, relation)
    approvals.revoke(ctx, approval_id, "사고", deny=True)
    denial = fetchone(conn, "SELECT * FROM mint.denials")
    assert (denial["scope_type"], denial["scope_id"], denial["server_id"]) == (
        "key", GOOD_KEY, "ctl-everything")
    assert denial["tools"] == ["echo"] and denial["lifted_at"] is None
    assert count(conn, "approval_revoked") == 1 and count(conn, "denial_created") == 1


def test_deny_and_lift(ctx, litellm, conn):
    prepare(ctx, litellm)
    denial = approvals.create_denial(ctx, scope_type="server", scope_id="ctl-everything",
                                     server_id=None, tools=None, reason="점검", org_id=None)
    row = fetchone(conn, "SELECT * FROM mint.denials")
    assert row["server_id"] == "ctl-everything"
    approvals.lift_denial(ctx, denial)
    assert fetchone(conn, "SELECT lifted_by FROM mint.denials")["lifted_by"] == "root"
    assert count(conn, "denial_created") == 1 and count(conn, "denial_lifted") == 1
    with pytest.raises(ControlError, match="해제되지 않은"):
        approvals.lift_denial(ctx, denial)
    with pytest.raises(ControlError, match="등록되지 않은 서버"):
        approvals.create_denial(ctx, scope_type="user", scope_id="u", server_id="ghost",
                                tools=None, reason="r", org_id=None)
    with pytest.raises(ControlError, match="--reason"):
        approvals.create_denial(ctx, scope_type="user", scope_id="u", server_id=None,
                                tools=None, reason="", org_id=None)


def test_server_state_transitions_are_enforced(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError, match="approved 상태"):
        servers.suspend(ctx, "ctl-everything")  # 승인 전 중지는 허용 전이가 아니다
    approve(ctx, litellm, relation)
    servers.suspend(ctx, "ctl-everything")
    with pytest.raises(ControlError):
        servers.suspend(ctx, "ctl-everything")
    servers.resume(ctx, "ctl-everything")
    with pytest.raises(ControlError):
        servers.resume(ctx, "ctl-everything")
    assert count(conn, "server_suspended") == 1 and count(conn, "server_resumed") == 1
    keys = {e["source_key"] for e in events(conn)}
    assert len(keys) == len(events(conn))


def test_relation_lifecycle(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    with pytest.raises(ControlError, match="이미 있습니다"):
        relations.add(ctx, "acme", "ctl-everything", "ops", None)
    with pytest.raises(ControlError, match="등록되지 않은"):
        relations.add(ctx, "acme", "ghost", "ops", None)
    relations.terminate(ctx, relation)
    assert fetchone(conn, "SELECT status FROM mint.usage_relations")["status"] == "terminating"
    with pytest.raises(ControlError, match="활성 상태의 이용 관계"):
        relations.terminate(ctx, relation)
    assert count(conn, "relation_terminating") == 1


# --- 조직·바인딩·설정 ------------------------------------------------------------


def test_org_binding_rules(ctx, conn):
    orgs.add(ctx, "a", "A")
    orgs.add(ctx, "b", "B")
    with pytest.raises(ControlError, match="이미 있습니다"):
        orgs.add(ctx, "a", "A")
    orgs.bind(ctx, "a", SubjectType.TEAM, "team-1")
    with pytest.raises(ControlError, match="이미 조직 a에"):
        orgs.bind(ctx, "b", SubjectType.TEAM, "team-1")
    orgs.bind(ctx, "b", SubjectType.USER, "team-1")  # 같은 문자열이라도 종류가 다르면 별개
    orgs.unbind(ctx, SubjectType.TEAM, "team-1")
    with pytest.raises(ControlError, match="바인딩이 없습니다"):
        orgs.unbind(ctx, SubjectType.TEAM, "team-1")
    orgs.bind(ctx, "b", SubjectType.TEAM, "team-1")
    assert count(conn, "org_binding_created") == 3 and count(conn, "org_binding_removed") == 1
    orgs.close(ctx, "a")
    with pytest.raises(ControlError, match="닫혀"):
        orgs.bind(ctx, "a", SubjectType.TEAM, "team-2")
    with pytest.raises(ControlError, match="활성 상태의 조직"):
        orgs.close(ctx, "a")


def test_default_org_mode_and_observable_settings(ctx, conn):
    orgs.add(ctx, "a", "A")
    settings_store.set_default_org(ctx, "a")
    assert settings_store.load(conn, INSTANCE)["default_org_id"] == "a"
    settings_store.set_default_org(ctx, None)
    with pytest.raises(ControlError, match="없습니다"):
        settings_store.set_default_org(ctx, "ghost")
    settings_store.set_mode(ctx, Mode.OBSERVE, Mode.OBSERVE)
    assert settings_store.load(conn, INSTANCE)["mode"] == "observe"
    with pytest.raises(ControlError, match="MINT_MODE"):
        settings_store.set_mode(ctx, Mode.OBSERVE, Mode.ENFORCE)
    settings_store.set_observable(ctx, ["APPROVAL_ABSENT"], ["R1"])
    row = settings_store.load(conn, INSTANCE)
    assert row["observable_reasons"] == ["APPROVAL_ABSENT"]
    assert row["observable_policy_ids"] == ["R1"]
    with pytest.raises(ControlError, match="관측으로 전환할 수 없는"):
        settings_store.set_observable(ctx, ["DENIED"], None)
    with pytest.raises(ControlError, match="하나는 지정"):
        settings_store.set_observable(ctx, None, None)
    assert count(conn, "settings_changed") == 4


def test_default_policy_ids_are_seeded_without_changing_the_ddl_default(conn):
    row = settings_store.load(conn, INSTANCE)
    assert row["observable_policy_ids"] == ["R1", "R3"]
    other = fetchone(conn, "INSERT INTO mint.settings (instance_id) VALUES ('inst2')"
                           " RETURNING observable_policy_ids")
    assert other["observable_policy_ids"] == []


# --- 호출별 승인 ------------------------------------------------------------------


def setup_policy(conn, version="v1"):
    """정책 엔진 없이 활성 판본 한 건을 만든다(호출별 승인이 판본 식별자를 참조한다)."""
    conn.execute(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, %s, %s, %s)", (INSTANCE, version, HEX, HEX))
    for status in ("staged", "active"):
        conn.execute("UPDATE mint.policy_versions SET status = %s, activated_at = now(),"
                     " activated_by = 'x' WHERE id = %s", (status, version))


def request_call(ctx, **overrides):
    values = dict(org_id="acme", principal_type="user", principal_id="alice",
                  server_id="ctl-everything", tool="echo", args_fp=HEX, fp_key_version=1,
                  policy_version_id=None, expires_in_minutes=30, requested_by="alice-boss")
    values.update(overrides)
    return approvals.call_request(ctx, **values)


def test_call_approval_lifecycle_and_events(ctx, litellm, conn):
    prepare(ctx, litellm)
    with pytest.raises(ControlError, match="활성 정책 판본"):
        request_call(ctx)
    setup_policy(conn)
    call_id = request_call(ctx)
    row = fetchone(conn, "SELECT * FROM mint.call_approvals")
    assert (row["status"], row["policy_version_id"]) == ("pending", "v1")
    approver = make_ctx(conn, "carol", "approver", user_id="carol")
    approvals.call_approve(approver, call_id, None)
    assert fetchone(conn, "SELECT approved_by FROM mint.call_approvals")["approved_by"] == "carol"
    approvals.call_cancel(ctx, call_id)
    with pytest.raises(ControlError, match="상태이고"):
        approvals.call_cancel(ctx, call_id)
    other = request_call(ctx)
    approvals.call_reject(approver, other)
    assert [count(conn, k) for k in (
        "call_approval_requested", "call_approval_approved", "call_approval_cancelled",
        "call_approval_rejected")] == [2, 1, 1, 1]


def test_call_approval_cannot_be_approved_by_the_calling_user(ctx, litellm, conn):
    prepare(ctx, litellm)
    setup_policy(conn)
    call_id = request_call(ctx)
    subject = make_ctx(conn, "alice-op", "approver", user_id="alice")
    with pytest.raises(ControlError, match="호출 주체와 같은 사용자"):
        approvals.call_approve(subject, call_id, None)
    # 호출 주체와 같은 사용자는 두 번째 승인자를 붙여도 승인할 수 없다
    from mint_litellm.control.context import Operator

    with pytest.raises(ControlError, match="호출 주체와 같은 사용자"):
        approvals.call_approve(subject, call_id, Operator("x", "approver", "xx"))


def test_call_approval_requester_needs_a_second_person(ctx, litellm, conn):
    prepare(ctx, litellm)
    setup_policy(conn)
    call_id = request_call(ctx, requested_by="carol")
    carol = make_ctx(conn, "carol-op", "approver", user_id="carol")
    with pytest.raises(ControlError, match="요청자와 같은 사용자"):
        approvals.call_approve(carol, call_id, None)
    from mint_litellm.control.context import Operator

    approvals.call_approve(carol, call_id, Operator("dave", "approver", "dave"))
    assert fetchone(conn, "SELECT status FROM mint.call_approvals")["status"] == "approved"


def test_call_approval_input_validation(ctx, litellm, conn):
    prepare(ctx, litellm)
    setup_policy(conn)
    for override, message in (
        ({"principal_type": "robot"}, "principal-type"),
        ({"args_fp": "xyz"}, "args-fp"),
        ({"expires_in_minutes": 0}, "expires-in-minutes"),
    ):
        with pytest.raises(ControlError, match=message):
            request_call(ctx, **override)


def test_expired_call_approval_cannot_be_approved(ctx, litellm, conn):
    prepare(ctx, litellm)
    setup_policy(conn)
    call_id = request_call(ctx)
    conn.execute("ALTER TABLE mint.call_approvals DISABLE TRIGGER call_approvals_2_frozen")
    conn.execute("UPDATE mint.call_approvals SET expires_at = now() - interval '1 minute'")
    approver = make_ctx(conn, "carol", "approver", user_id="carol")
    with pytest.raises(ControlError, match="만료되지 않은"):
        approvals.call_approve(approver, call_id, None)


# --- 동의·허용 목록·정책 ---------------------------------------------------------


def add_consent(ctx, litellm, **overrides):
    values = dict(org_id="acme", human_user_id="human-1", server_id="ctl-everything",
                  purpose="업무", data_scope="이름", text_version="v1", granted_at=NOW,
                  valid_until=LATER, evidence_ref="서명본-1", evidence_sha256=HEX)
    values.update(overrides)
    return consents.add(ctx, litellm, **values)


def test_consent_requires_evidence_and_a_human_user(ctx, litellm, conn):
    prepare(ctx, litellm)
    with pytest.raises(ControlError, match="증거 참조"):
        add_consent(ctx, litellm, evidence_ref=" ")
    with pytest.raises(ControlError, match="증거 해시"):
        add_consent(ctx, litellm, evidence_sha256="abc")
    with pytest.raises(ControlError, match="사람 사용자"):
        add_consent(ctx, litellm, human_user_id="nobody")
    with pytest.raises(ControlError, match="등록되지 않은 서버"):
        add_consent(ctx, litellm, server_id="ghost")
    consent_id = add_consent(ctx, litellm)
    row = fetchone(conn, "SELECT source, evidence_sha256 FROM mint.consents")
    assert (row["source"], row["evidence_sha256"]) == ("operator_attested", HEX)
    consents.revoke(ctx, consent_id)
    with pytest.raises(ControlError, match="철회되지 않은"):
        consents.revoke(ctx, consent_id)
    assert count(conn, "consent_granted") == 1 and count(conn, "consent_revoked") == 1


def test_allowlist_add_and_lift(ctx, conn):
    with pytest.raises(ControlError, match="kind"):
        allowlists.add(ctx, "other", "x", NOW, LATER, None, None)
    with pytest.raises(ControlError, match="뒤여야"):
        allowlists.add(ctx, "provider", "x", LATER, NOW, None, None)
    entry = allowlists.add(ctx, "provider", " example.test ", NOW, LATER, None, "비고")
    assert fetchone(conn, "SELECT value FROM mint.allowlists")["value"] == "example.test"
    with pytest.raises(ControlError, match="이미 활성"):
        allowlists.add(ctx, "provider", "example.test", NOW, LATER, None, None)
    allowlists.lift(ctx, entry)
    with pytest.raises(ControlError, match="활성 상태의 허용"):
        allowlists.lift(ctx, entry)
    allowlists.add(ctx, "provider", "example.test", NOW, LATER, None, None)  # 해제 뒤 재등록
    assert count(conn, "allowlist_added") == 2 and count(conn, "allowlist_lifted") == 1


def test_policy_activation_is_refused_for_settled_versions_and_bad_sources(conn, tmp_path):
    source = policy_versions.PolicySource(
        root=tmp_path, opa="opa", bundle_path=tmp_path / "mint.tar.gz",
        opa_url="http://opa.test:8181", timeout_seconds=1,
    )
    with pytest.raises(ControlError, match="정책 번들이 올바르지"):
        policy_versions.activate(conn, "unused", INSTANCE, "root", "v1", source)
    setup_policy(conn)
    with pytest.raises(ControlError, match="active 상태"):
        policy_versions.activate(conn, "unused", INSTANCE, "root", "v1", source)
    with pytest.raises(ControlError, match="정책 번들이 올바르지"):
        policy_versions.activate(conn, "unused", INSTANCE, "root", "v-new", source)
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.policy_versions")["n"] == 1


def test_an_approver_cannot_grant_their_own_key_or_user_even_with_another_requester(
    ctx, litellm
):
    import dataclasses

    from mint_litellm.control.context import Operator

    relation = prepare(ctx, litellm)
    owner = dataclasses.replace(ctx, operator=Operator("self-approver", "approver", "human-1"))
    for scope_type, scope_id in (("key", GOOD_KEY), ("user", "human-1")):
        with pytest.raises(ControlError, match="자신이 쓰는"):
            approve(owner, litellm, relation, scope_type=scope_type, scope_id=scope_id,
                    requested_by="someone-else")
