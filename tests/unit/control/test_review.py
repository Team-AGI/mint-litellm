"""리뷰에서 지적된 결함의 회귀 시험과 경쟁·실패 주입 시험."""

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from ctl_fixtures import INSTANCE, make_ctx
from litellm_stub import GOOD_KEY, fixture

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import (  # noqa: E402
    approvals,
    operators,
    orgs,
    relations,
    servers,
    settings_store,
)
from mint_litellm.control.context import Operator  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.litellm_admin import LiteLLMError  # noqa: E402
from mint_litellm.types.identity import SubjectType  # noqa: E402
from mint_litellm.types.ids import new_uuid7  # noqa: E402

URL = "http://upstream.test/mcp"
HEX = "ab" * 32
NOW = datetime.now(UTC)
LATER = NOW + timedelta(days=30)


@pytest.fixture(autouse=True)
def _distinct_approver(monkeypatch):
    """직무 분리는 설정을 켰을 때만 건다."""
    monkeypatch.setenv("MINT_REQUIRE_DISTINCT_APPROVER", "1")



def events(conn, kind):
    return fetchall(
        conn, "SELECT * FROM mint.events WHERE instance_id = %s AND kind = %s"
        " ORDER BY inserted_at, event_id",
        (INSTANCE, kind),
    )


def prepare(ctx, litellm):
    orgs.add(ctx, "acme", "ACME")
    orgs.bind(ctx, "acme", SubjectType.USER, "human-1")
    servers.register(ctx, litellm, "ctl-everything", URL)
    return relations.add(ctx, "acme", "ctl-everything", "ops", None)


def approve(ctx, litellm, relation, **overrides):
    values = dict(
        relation_id=relation, scope_type="key", scope_id=GOOD_KEY, tools=["echo"],
        valid_from=NOW, valid_until=LATER, approval_class="standard", basis_text="티켓",
        requested_by="requester", allowlist_ids=[], second=None,
    )
    values.update(overrides)
    return approvals.approve(ctx, litellm, **values)


# --- 승인 조건 ----------------------------------------------------------------


def test_conditions_are_validated_stored_and_recorded(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    conditions = approvals.build_conditions(
        high_risk_tools=["delete", "deploy"], business_hours_only=True,
        business_hours="Asia/Seoul,1-5,09:00,18:00", require_consent="상담",
    )
    approval_id, _ = approve(ctx, litellm, relation, conditions=conditions)
    row = fetchone(conn, "SELECT conditions FROM mint.approvals WHERE id = %s", (approval_id,))
    assert row["conditions"] == {
        "high_risk_tools": ["delete", "deploy"],
        "business_hours_only": True,
        "business_hours": {"tz": "Asia/Seoul", "days": [1, 2, 3, 4, 5], "start": "09:00",
                           "end": "18:00"},
        "require_consent": "상담",
    }
    assert events(conn, "approval_granted")[0]["payload"]["conditions"] == row["conditions"]


def test_no_condition_flags_keep_the_conditions_empty(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    approve(ctx, litellm, relation, conditions=approvals.build_conditions(
        high_risk_tools=None, business_hours_only=False, business_hours=None,
        require_consent=None))
    assert fetchone(conn, "SELECT conditions FROM mint.approvals")["conditions"] == {}


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"business_hours": "Asia/Seoul,1-5,09:00,18:00"}, "함께 써야"),
        ({"business_hours_only": True, "business_hours": "Asia/Seoul,1-5,09:00"}, "형식"),
        ({"business_hours_only": True, "business_hours": "Nowhere/City,1-5,09:00,18:00"},
         "시간대"),
        ({"business_hours_only": True, "business_hours": "Asia/Seoul,0-5,09:00,18:00"}, "요일"),
        ({"business_hours_only": True, "business_hours": "Asia/Seoul,x,09:00,18:00"}, "요일"),
        ({"business_hours_only": True, "business_hours": "Asia/Seoul,1-5,18:00,09:00"}, "HH:MM"),
        ({"business_hours_only": True, "business_hours": "Asia/Seoul,1-5,9:00,18:00"}, "HH:MM"),
        ({"require_consent": " "}, "목적"),
        ({"require_consent": "x" * 129}, "목적"),
    ],
)
def test_invalid_conditions_are_rejected(kwargs, message):
    base = dict(high_risk_tools=None, business_hours_only=False, business_hours=None,
                require_consent=None)
    with pytest.raises(ControlError, match=message):
        approvals.build_conditions(**{**base, **kwargs})


# --- 호출별 승인 ----------------------------------------------------------------


def request_call(ctx, **overrides):
    values = dict(org_id="acme", principal_type="user", principal_id="alice",
                  server_id="ctl-everything", tool="echo", args_fp=HEX, fp_key_version=1,
                  policy_version_id="v1", expires_in_minutes=30, requested_by="requester-user")
    values.update(overrides)
    return approvals.call_request(ctx, **values)


def with_policy(conn):
    conn.execute(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s)", (INSTANCE, HEX, HEX))


def test_only_the_requester_or_an_admin_can_cancel_a_call_approval(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    call_id = request_call(ctx)
    other = make_ctx(conn, "other-approver", "approver", user_id="someone-else")
    with pytest.raises(ControlError, match="요청자 본인이나 admin"):
        approvals.call_cancel(other, call_id)
    assert fetchone(conn, "SELECT status FROM mint.call_approvals")["status"] == "pending"
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.events"
                          " WHERE kind = 'call_approval_cancelled'")["n"] == 0
    requester = make_ctx(conn, "req-approver", "approver", user_id="requester-user")
    approvals.call_cancel(requester, call_id)
    assert fetchone(conn, "SELECT status FROM mint.call_approvals")["status"] == "cancelled"
    second = request_call(ctx)
    approvals.call_cancel(ctx, second)  # root는 admin
    no_user = make_ctx(conn, "viewerish", "approver", user_id=None)
    third = request_call(ctx)
    with pytest.raises(ControlError, match="요청자 본인이나 admin"):
        approvals.call_cancel(no_user, third)


def test_the_second_approver_of_a_call_approval_is_recorded(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    call_id = request_call(ctx, requested_by="carol")
    carol = make_ctx(conn, "carol-op", "approver", user_id="carol")
    approvals.call_approve(carol, call_id, Operator("dave", "approver", "dave"))
    payload = events(conn, "call_approval_approved")[0]["payload"]
    assert payload["second_approver"] == "dave"
    assert payload["second_approver_user_id"] == "dave"
    assert payload["approved_by"] == "carol-op"
    plain = request_call(ctx, requested_by="someone")
    approvals.call_approve(carol, plain, None)
    latest = [e for e in events(conn, "call_approval_approved")
              if e["payload"]["call_approval_id"] == plain][0]
    assert latest["payload"]["second_approver"] is None


# --- 허용 목록 근거와 서버 재등록 ---------------------------------------------------------


def test_a_not_yet_valid_allowlist_entry_is_not_a_basis(ctx, litellm, conn):
    from mint_litellm.control import allowlists

    relation = prepare(ctx, litellm)
    future = allowlists.add(ctx, "provider", "later.test", NOW + timedelta(days=1),
                            NOW + timedelta(days=9), None, None)
    with pytest.raises(ControlError, match="유효한 허용 목록"):
        approve(ctx, litellm, relation, allowlist_ids=[future])


def test_server_url_sources_are_compared_and_recorded(ctx, litellm, conn, stub):
    orgs.add(ctx, "acme", "ACME")
    config = {"mcp_servers": {"everything": {"server_id": "ctl-everything", "url": URL}}}
    servers.register(ctx, litellm, "ctl-everything", None, config)
    assert events(conn, "server_registered")[0]["payload"]["url_source"] == "config_file"
    # 같은 값이면 운영자 지정이 우선 출처로 기록되고, 다르면 거부한다.
    servers.register(ctx, litellm, "ctl-everything", URL, config)
    assert events(conn, "server_registered")[1]["payload"]["url_source"] == "operator"
    with pytest.raises(ControlError, match="출처가 서로 다릅니다"):
        servers.register(ctx, litellm, "ctl-everything", "http://other.test/mcp", config)
    body = dict(fixture("server_get"), url="http://registry.test/mcp")
    stub.set("/v1/mcp/server/ctl-everything", body)
    with pytest.raises(ControlError, match="출처가 서로 다릅니다"):
        servers.register(ctx, litellm, "ctl-everything", None, config)
    servers.register(ctx, litellm, "ctl-everything", "http://registry.test/mcp", None)
    assert events(conn, "server_registered")[2]["payload"]["url_source"] == "operator"


def test_registry_visible_url_is_the_source_when_nothing_else_is_given(ctx, litellm, conn, stub):
    stub.set("/v1/mcp/server/ctl-everything", dict(fixture("server_get"), url=URL))
    servers.register(ctx, litellm, "ctl-everything")
    assert events(conn, "server_registered")[0]["payload"]["url_source"] == "registry"


def test_registering_again_updates_the_contract_and_keeps_the_status(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    approve(ctx, litellm, relation)
    before = fetchone(conn, "SELECT url_sha256, status, state_version FROM mint.servers")
    servers.register(ctx, litellm, "ctl-everything", "http://moved.test/mcp")
    after = fetchone(conn, "SELECT url_sha256, status, state_version FROM mint.servers")
    assert after["status"] == "approved" == before["status"]
    assert after["url_sha256"] != before["url_sha256"]
    assert after["state_version"] == before["state_version"] + 1
    assert events(conn, "server_registered")[-1]["payload"]["updated"] is True


# --- 관리 API 응답 형식 -----------------------------------------------------------------


ROUTES = (
    ("/v1/mcp/server", {}), ("/team/list", {}), ("/key/list", {}), ("/guardrails/list", {}),
    ("/user/info", {"user_id": "human-1"}), ("/key/info", {"key": GOOD_KEY}),
    ("/team/info", {"team_id": "team-op"}), ("/v1/mcp/server/ctl-everything", {}),
)
CALLS = {
    "/v1/mcp/server": lambda c: c.list_servers(),
    "/team/list": lambda c: c.list_teams(),
    "/key/list": lambda c: c.list_keys(),
    "/guardrails/list": lambda c: c.list_guardrails(),
    "/user/info": lambda c: c.get_user("human-1"),
    "/key/info": lambda c: c.get_key(GOOD_KEY),
    "/team/info": lambda c: c.get_team("team-op"),
    "/v1/mcp/server/ctl-everything": lambda c: c.get_server("ctl-everything"),
}


@pytest.mark.parametrize("body", ["text", None, 3, {"unexpected": True}, []])
@pytest.mark.parametrize("path", sorted(CALLS))
def test_malformed_successful_responses_are_control_errors(stub, litellm, path, body):
    params = dict(ROUTES)[path]
    stub.set(path, body, **params)
    # 올바른 형식이 아닌 본문만 시험한다: 객체 응답 경로의 빈 객체나 목록 경로의 빈 목록은 정상이다.
    valid_empty = {"/v1/mcp/server": [], "/team/list": []}
    if path in valid_empty and valid_empty[path] == body:
        CALLS[path](litellm)
        return
    if path.startswith("/v1/mcp/server/") and body == {"unexpected": True}:
        CALLS[path](litellm)  # 서버 상세는 객체이면 형식이 맞다
        return
    with pytest.raises(LiteLLMError, match="형식"):
        CALLS[path](litellm)


# --- 동시성 ---------------------------------------------------------------------------


def connect(url):
    return psycopg.connect(url)


def test_concurrent_settings_changes_do_not_overwrite_each_other(fresh_db):
    a, b = connect(fresh_db), connect(fresh_db)
    settings_store.ensure(a, INSTANCE)
    a.commit()
    ctx_a, ctx_b = make_ctx(a), make_ctx(b)
    settings_store.set_observable(ctx_a, ["APPROVAL_ABSENT"], None)
    result = {}

    def other():
        settings_store.set_observable(ctx_b, None, ["R2"])
        b.commit()
        result["done"] = True

    thread = threading.Thread(target=other)
    thread.start()
    # 상대가 첫 연결의 행 잠금을 기다리는 것을 확인한 뒤에 커밋한다. 잠금이 없으면 상대는
    # 기다리지 않고 지나가 이 확인이 시간 초과로 실패한다.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        waiting = fetchone(
            a, "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
            (b.info.backend_pid,),
        )
        if waiting and waiting["wait_event_type"] == "Lock":
            break
        time.sleep(0.02)
    else:
        pytest.fail("두 번째 변경이 첫 변경의 잠금을 기다리지 않았다")
    a.commit()
    thread.join(10)
    assert result == {"done": True}
    row = fetchone(a, "SELECT observable_reasons, observable_policy_ids FROM mint.settings")
    assert row["observable_reasons"] == ["APPROVAL_ABSENT"]
    assert row["observable_policy_ids"] == ["R2"]
    a.close()
    b.close()


def test_concurrent_bootstrap_creates_exactly_one_operator(fresh_db, litellm):
    results: list[object] = []

    def run(name):
        with connect(fresh_db) as conn:
            try:
                results.append(operators.bootstrap(conn, INSTANCE, litellm, name, "human-1"))
            except ControlError as error:
                results.append(error)

    threads = [threading.Thread(target=run, args=(f"boss{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    tokens = [r for r in results if isinstance(r, str)]
    errors = [r for r in results if isinstance(r, ControlError)]
    assert len(tokens) == 1 and len(errors) == 3
    with connect(fresh_db) as conn:
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.operators")["n"] == 1
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.events"
                              " WHERE kind = 'operator_added'")["n"] == 1


def test_concurrent_first_approvals_activate_the_server_once(fresh_db, litellm):
    with connect(fresh_db) as conn:
        settings_store.ensure(conn, INSTANCE)
        relation = prepare(make_ctx(conn), litellm)
    outcomes: list[object] = []

    def run(i):
        with connect(fresh_db) as conn:
            try:
                outcomes.append(approve(make_ctx(conn, f"op{i}"), litellm, relation,
                                        tools=[f"tool{i}"]))
            except Exception as error:  # noqa: BLE001
                outcomes.append(error)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert all(isinstance(o, tuple) for o in outcomes), outcomes
    with connect(fresh_db) as conn:
        assert fetchone(conn, "SELECT status FROM mint.servers")["status"] == "approved"
        assert len(events(conn, "server_approved")) == 1
        assert len(events(conn, "approval_granted")) == 4


def test_call_approval_approve_and_cancel_race_leaves_consistent_records(fresh_db, litellm):
    with connect(fresh_db) as conn:
        settings_store.ensure(conn, INSTANCE)
        root = make_ctx(conn)
        prepare(root, litellm)
        conn.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
            " VALUES (%s, 'v1', %s, %s)", (INSTANCE, HEX, HEX))
        call_id = request_call(root, requested_by="carol")
    outcomes: dict[str, object] = {}

    def approve_it():
        with connect(fresh_db) as conn:
            try:
                approvals.call_approve(make_ctx(conn, "dave", "approver", "dave"), call_id, None)
                outcomes["approve"] = True
            except ControlError as error:
                outcomes["approve"] = error

    def cancel_it():
        with connect(fresh_db) as conn:
            try:
                approvals.call_cancel(make_ctx(conn, "root"), call_id)
                outcomes["cancel"] = True
            except ControlError as error:
                outcomes["cancel"] = error

    threads = [threading.Thread(target=approve_it), threading.Thread(target=cancel_it)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    with connect(fresh_db) as conn:
        status = fetchone(conn, "SELECT status FROM mint.call_approvals")["status"]
        approved = len(events(conn, "call_approval_approved"))
        cancelled = len(events(conn, "call_approval_cancelled"))
    assert outcomes["cancel"] is True  # 취소는 대기·승인 어느 상태에서도 성립한다
    assert status == "cancelled" and cancelled == 1
    assert approved == (1 if outcomes["approve"] is True else 0)


def test_a_failed_event_insert_rolls_back_the_state_and_the_epoch(fresh_db, litellm):
    with connect(fresh_db) as conn:
        settings_store.ensure(conn, INSTANCE)
        conn.commit()
        epoch = fetchone(conn, "SELECT coalesce(max(epoch), 0) AS e FROM mint.state_epoch")["e"]
        # 같은 사건 키가 이미 있으면 상태 변경 뒤의 사건 삽입이 실패한다.
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
            " VALUES (gen_random_uuid(), %s, 'org_created', 'org:acme:1:org_created', 'x', '{}')",
            (INSTANCE,),
        )
        conn.commit()
    with connect(fresh_db) as conn:
        with pytest.raises(psycopg.errors.UniqueViolation):
            orgs.add(make_ctx(conn), "acme", "ACME")
    with connect(fresh_db) as conn:
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.orgs")["n"] == 0
        now_epoch = fetchone(conn, "SELECT coalesce(max(epoch), 0) AS e FROM mint.state_epoch")
        assert now_epoch["e"] == epoch


# --- 유효 기간 경계: valid_from <= now < valid_until ------------------------------------


def test_an_allowlist_entry_ending_exactly_now_is_expired(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    entry = new_uuid7()
    conn.execute(
        "INSERT INTO mint.allowlists (id, instance_id, kind, value, valid_from, valid_until,"
        " created_by) VALUES (%s, %s, 'provider', 'edge.test', now() - interval '1 day', now(),"
        " 'x')", (entry, INSTANCE))
    with pytest.raises(ControlError, match="유효한 허용 목록"):
        approve(ctx, litellm, relation, allowlist_ids=[str(entry)])


def test_an_allowlist_entry_starting_exactly_now_is_valid(ctx, litellm, conn):
    relation = prepare(ctx, litellm)
    entry = new_uuid7()
    conn.execute(
        "INSERT INTO mint.allowlists (id, instance_id, kind, value, valid_from, valid_until,"
        " created_by) VALUES (%s, %s, 'provider', 'edge.test', now(), now() + interval '1 day',"
        " 'x')", (entry, INSTANCE))
    approve(ctx, litellm, relation, allowlist_ids=[str(entry)])


def test_a_call_approval_expiring_exactly_now_cannot_be_approved(ctx, litellm, conn):
    prepare(ctx, litellm)
    with_policy(conn)
    call_id = request_call(ctx)
    conn.execute("ALTER TABLE mint.call_approvals DISABLE TRIGGER call_approvals_2_frozen")
    conn.execute("UPDATE mint.call_approvals SET expires_at = now()")
    approver = make_ctx(conn, "carol", "approver", user_id="carol")
    with pytest.raises(ControlError, match="만료되지 않은"):
        approvals.call_approve(approver, call_id, None)


def test_an_egress_range_broader_than_eight_bits_is_refused(ctx):
    from mint_litellm.control import allowlists

    with pytest.raises(ControlError, match="/8보다 좁아야"):
        allowlists.add(ctx, "egress_target", "0" + ".0.0.0/0", NOW, NOW + timedelta(days=9),
                       None, None)
    allowlists.add(ctx, "egress_target", "100" + ".81.203.0/24", NOW, NOW + timedelta(days=9),
                   None, None)
