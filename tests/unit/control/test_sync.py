"""권한 동기화: 대상 수렴, 소유와 원래 있던 항목, 팀 -> 키 순서, 외부 삭제와 보류·재개, 읽어 확인,
활성화 완결, 서버 확인. 실 Postgres(``mint_worker_app`` 로그인)와 상태를 가진 LiteLLM 모의 서버로
돌린다(MINT_TEST_DATABASE_URL이 없으면 건너뜀).
"""

import pytest
from ctl_fixtures import INSTANCE, LOGIN_PASSWORDS, make_ctx
from fake_litellm import CONTROL_KEY, FakeLiteLLM

psycopg = pytest.importorskip("psycopg")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm.control import approvals as approvals_domain  # noqa: E402
from mint_litellm.control import jobs, sync_state  # noqa: E402
from mint_litellm.control import relations as relations_domain  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.db.roles import LOGIN_ROLES  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.litellm_write import LiteLLMSync  # noqa: E402
from mint_litellm.control.services import base  # noqa: E402
from mint_litellm.control.services import sync as sync_service  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402
from mint_litellm.control.sync_state import Desired, make_plan  # noqa: E402
from mint_litellm.control.worker import Worker  # noqa: E402

KEY = "A" * 43
SETTINGS = Stage2Settings.from_env({"MINT_EXPORT_DIR": "/tmp/mint-export",
                                    "MINT_EXPORT_HMAC_KEY": KEY})
HEX = "ab" * 32


# --- 장치 -----------------------------------------------------------------------


@pytest.fixture
def url(fresh_db, login_roles):
    return fresh_db


def login_url(url: str) -> str:
    params = conninfo_to_dict(url)
    params.update(user=LOGIN_ROLES["mint_worker"], password=LOGIN_PASSWORDS["mint_worker"])
    return make_conninfo(**params)


@pytest.fixture
def admin(url):
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("INSERT INTO mint.settings (instance_id) VALUES (%s)", (INSTANCE,))
        conn.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, 'acme', 'A')",
                     (INSTANCE,))
        yield conn


@pytest.fixture
def fake():
    server = FakeLiteLLM()
    yield server
    server._server.shutdown()
    server._server.server_close()


@pytest.fixture
def make_worker(url, admin, fake):
    made: list[Worker] = []

    def make(**kwargs) -> Worker:
        kwargs.setdefault("litellm", LiteLLMSync(fake.url, CONTROL_KEY))
        worker = Worker(login_url(url), INSTANCE, SETTINGS, **kwargs)
        worker.open()
        admin.execute("DELETE FROM mint.schedules")
        made.append(worker)
        return worker

    yield make
    for worker in made:
        worker.close()


@pytest.fixture
def worker(make_worker):
    return make_worker()


def add_server(admin, server_id="srv-1", status="awaiting_approval", team=None) -> None:
    admin.execute(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
        " auth_type, registered_by) VALUES (gen_random_uuid(), %s, %s, 'awaiting_approval', %s,"
        " 'http', 'none', 't')", (INSTANCE, server_id, HEX))
    admin.execute(
        "INSERT INTO mint.usage_relations (id, instance_id, org_id, purpose, server_id, team_id)"
        " VALUES (gen_random_uuid(), %s, 'acme', 'ops', %s, %s)", (INSTANCE, server_id, team))
    if status != "awaiting_approval":
        admin.execute("UPDATE mint.servers SET status = %s WHERE server_id = %s",
                      (status, server_id))


def add_approval(admin, scope_type, scope_id, server_id="srv-1", tools=("a",), status="active",
                 valid_from="now() - interval '1 minute'",
                 valid_until="now() + interval '1 day'") -> str:
    row = fetchone(
        admin,
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by,"
        f" status) SELECT gen_random_uuid(), %s, 'acme', r.id, 'standard', %s, %s, %s, %s,"
        f" {valid_from}, {valid_until}, '{{\"text\": \"t\", \"allowlist_ids\": []}}', 'op', 'req',"
        " %s FROM mint.usage_relations r WHERE r.server_id = %s RETURNING id",
        (INSTANCE, server_id, list(tools), scope_type, scope_id, status, server_id),
    )
    return str(row["id"])


def revoke(admin, approval_id) -> None:
    admin.execute("UPDATE mint.approvals SET status = 'revoked', revoked_at = now(),"
                  " revoke_reason = 'r' WHERE id = %s", (approval_id,))


def enqueue(admin, kind, ref, key=None) -> str:
    return base.enqueue_job(make_ctx(admin), kind, ref, key)


_counter = iter(range(10_000))


def reconcile(admin) -> None:
    enqueue(admin, "sync_reconcile", "sync_reconcile", f"sync_reconcile:{next(_counter)}")


def drain(worker: Worker, limit: int = 40) -> int:
    ran = 0
    while worker.step():
        ran += 1
        assert ran < limit, "작업이 끝나지 않습니다"
    return ran


def past(admin) -> None:
    admin.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'"
                  " WHERE status = 'pending'")


def grants(admin, **where) -> list[dict]:
    return fetchall(admin, "SELECT * FROM mint.litellm_grants ORDER BY target_type, item,"
                           " server_id")


def grant(admin, item, kind="key", target="k1", server="srv-1"):
    return fetchone(
        admin,
        "SELECT * FROM mint.litellm_grants WHERE target_type = %s AND target_id = %s"
        " AND item = %s AND server_id = %s", (kind, target, item, server))


def alerts(admin, kind=None):
    return fetchall(admin, "SELECT * FROM mint.alerts WHERE (%s::text IS NULL OR kind = %s)"
                           " ORDER BY first_at", (kind, kind))


def events(admin, kind):
    return fetchall(admin, "SELECT * FROM mint.events WHERE kind = %s ORDER BY inserted_at",
                    (kind,))


def job_rows(admin, kind=None):
    return fetchall(admin, "SELECT * FROM mint.jobs WHERE (%s::text IS NULL OR kind = %s)"
                           " ORDER BY created_at", (kind, kind))


def key_world(admin, fake, **key_fields):
    """서버 하나와 키 하나, 그 키의 활성 승인 하나."""
    add_server(admin)
    fake.add_server("srv-1")
    fake.add_key("k1", **key_fields)
    return add_approval(admin, "key", "k1", tools=("a", "b"))


# --- 계획(순수 함수) --------------------------------------------------------------


def row(item, server, *, observed=True, preexisting=False, tools=None, held=False):
    return {"item": item, "server_id": server, "observed": observed,
            "preexisting": preexisting, "tools": tools, "held": held}


def test_the_plan_adds_owned_items_and_keeps_everything_else():
    desired = Desired(frozenset({"s1"}), {"s1": frozenset({"a"})})
    plan = make_plan(["x"], {"x": ["t"]}, desired, [])
    assert plan.servers == ["x", "s1"] and plan.tools == {"x": ["t"], "s1": ["a"]}
    assert plan.changed
    assert make_plan(plan.servers, plan.tools, desired, []).changed is False


def test_the_plan_tracks_only_what_mint_adds_to_an_entry_that_was_already_there():
    desired = Desired(frozenset({"s1"}), {"s1": frozenset({"a", "z"})})
    plan = make_plan(["s1"], {"s1": ["z"]}, desired, [])
    assert plan.tools == {"s1": ["a", "z"]}
    tool_item = next(i for i in plan.items if i.item == "tool_permission")
    server_item = next(i for i in plan.items if i.item == "mcp_server")
    assert (tool_item.tools, tool_item.preexisting) == (["a"], True)
    assert server_item.preexisting is True


def test_the_plan_removes_only_what_mint_owns():
    rows = [row("mcp_server", "s1"), row("tool_permission", "s1", tools=["a"]),
            row("mcp_server", "s2", preexisting=True)]
    plan = make_plan(["s1", "s2", "s3"], {"s1": ["a", "z"], "s2": ["q"]}, Desired(frozenset(), {}),
                     rows)
    assert plan.servers == ["s2", "s3"]  # s2는 원래 있던 것, s3는 MINT와 무관
    assert plan.tools == {"s1": ["z"], "s2": ["q"]}
    assert not any(i.want for i in plan.items)


def test_a_server_entry_mint_created_disappears_with_its_last_tool():
    rows = [row("mcp_server", "s1"), row("tool_permission", "s1", tools=["a"])]
    plan = make_plan(["s1"], {"s1": ["a"]}, Desired(frozenset(), {}), rows)
    assert plan.servers == [] and plan.tools == {}


def test_held_and_withdrawn_rows_are_left_alone():
    rows = [row("mcp_server", "s1", observed=False, held=True),
            row("mcp_server", "s2", observed=None)]
    desired = Desired(frozenset({"s1"}), {})
    plan = make_plan(["s2"], {}, desired, rows)
    assert plan.servers == ["s2"] and plan.items == [] and not plan.changed


# --- sync_target --------------------------------------------------------------------


def test_a_key_gets_the_full_lists_and_the_read_back_confirms_them(admin, fake, worker):
    key_world(admin, fake, servers=["other"], tools={"other": ["x"]})
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1") == (["other", "srv-1"],
                                            {"other": ["x"], "srv-1": ["a", "b"]})
    [(_, path, body)] = fake.writes()
    assert path == "/key/update"  # 사건은 전체 목록으로 한 번에 썼다
    assert body["object_permission"] == {"mcp_servers": ["other", "srv-1"],
                                         "mcp_tool_permissions": {"other": ["x"],
                                                                  "srv-1": ["a", "b"]}}
    server, tools = grant(admin, "mcp_server"), grant(admin, "tool_permission")
    assert (server["observed"], server["preexisting"]) == (True, False)
    assert (tools["observed"], tools["tools"], tools["preexisting"]) == (True, ["a", "b"], False)
    assert server["last_applied_at"] is not None
    assert len(events(admin, "sync_applied")) == 2
    assert [j["status"] for j in job_rows(admin, "sync_target")] == ["done"]


def test_resending_is_idempotent_and_a_converged_target_is_not_written_again(
    admin, fake, worker
):
    key_world(admin, fake)
    for _ in range(3):
        enqueue(admin, "sync_target", "key:k1")
        drain(worker)
    assert len(fake.writes()) == 1
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a", "b"]})
    assert len(events(admin, "sync_applied")) == 2  # 두 번째부터는 바뀐 것이 없다


def test_a_team_key_that_gets_403_is_failed_with_an_alert_and_the_team_is_synced(
    admin, fake, worker
):
    add_server(admin)
    fake.add_server("srv-1")
    fake.add_team("t1")
    fake.add_key("k1", team_id="t1")
    add_approval(admin, "team", "t1")
    add_approval(admin, "key", "k1")
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    # 키는 403을 받아 재시도 없이 실패로 끝났고, 팀 작업이 등록되어 먼저 끝났다
    assert [p for _, p, _ in fake.writes()] == ["/key/update", "/team/update"]
    assert fake.permission("team", "t1")[0] == ["srv-1"]
    [key_job] = [j for j in job_rows(admin, "sync_target") if j["target_ref"] == "key:k1"]
    assert (key_job["status"], key_job["attempts"], key_job["last_error_code"]) == (
        "failed", 0, "litellm_forbidden")
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "forbidden" and alert["subject"]["team_id"] == "t1"
    assert alerts(admin, "job_failed") == []
    reconcile(admin)  # 재조회가 키를 다시 맞춘다
    drain(worker)
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a"]})
    assert alerts(admin, "sync_divergence")[0]["status"] == "resolved"


def test_a_403_for_a_key_without_a_team_fails_at_once(admin, fake, worker):
    key_world(admin, fake)
    fake.fail_writes["/key/update"] = 403
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    [job] = job_rows(admin, "sync_target")
    assert (job["status"], job["attempts"], job["last_error_code"]) == (
        "failed", 0, "litellm_forbidden")
    assert job_rows(admin) == [job]  # 팀 작업은 만들지 않았다
    assert alerts(admin, "sync_divergence")[0]["subject"]["reason"] == "forbidden"


def test_items_that_were_already_there_are_kept_when_the_approval_goes_away(
    admin, fake, worker
):
    approval = key_world(admin, fake, servers=["srv-1"], tools={"srv-1": ["z"]})
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a", "b", "z"]})
    assert grant(admin, "mcp_server")["preexisting"] is True
    assert grant(admin, "tool_permission")["tools"] == ["a", "b"]
    revoke(admin, approval)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["z"]})
    assert grants(admin)[0]["observed"] is None and grants(admin)[1]["observed"] is None


def test_what_mint_added_is_removed_when_the_approval_is_revoked(admin, fake, worker):
    approval = key_world(admin, fake, servers=["other"], tools={"other": ["x"]})
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    revoke(admin, approval)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1") == (["other"], {"other": ["x"]})
    assert [g["observed"] for g in grants(admin)] == [None, None]
    assert len(events(admin, "sync_applied")) == 4  # 부여 둘, 거둠 둘


def test_revoking_an_approval_registers_the_sync_and_clears_the_counters(admin, fake, worker):
    approval = key_world(admin, fake)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    admin.execute("UPDATE mint.litellm_grants SET missing_count = 1,"
                  " missing_window_start = now(), held = true, held_at = now()"
                  " WHERE item = 'mcp_server'")
    approvals_domain.revoke(make_ctx(admin), approval, "end of project", False)
    assert grant(admin, "mcp_server")["held"] is False
    assert grant(admin, "mcp_server")["missing_count"] == 0
    [pending] = [j for j in job_rows(admin, "sync_target") if j["status"] == "pending"]
    assert pending["target_ref"] == "key:k1"
    drain(worker)
    assert fake.permission("key", "k1") == ([], {})


def test_approvals_outside_their_validity_or_without_a_matching_pin_open_nothing(
    admin, fake, worker, monkeypatch
):
    add_server(admin)
    fake.add_server("srv-1")
    fake.add_key("k1")
    add_approval(admin, "key", "k1", tools=("future",), valid_from="now() + interval '1 hour'",
                 valid_until="now() + interval '2 hours'")
    add_approval(admin, "key", "k1", tools=("past",), valid_from="now() - interval '2 hours'",
                 valid_until="now() - interval '1 hour'")
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.writes() == []
    add_approval(admin, "key", "k1", tools=("a",), status="pending")
    monkeypatch.setattr(sync_state, "pin_satisfied", lambda *args: False)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.writes() == []  # 고정이 맞지 않은 대기 승인
    monkeypatch.setattr(sync_state, "pin_satisfied", lambda *args: True)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a"]})


def test_scopes_other_than_key_and_team_change_nothing_in_litellm(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    add_approval(admin, "user", "u1")
    with pytest.raises(ValueError):
        sync_state.split_ref("user:u1")
    assert fake.writes() == []


def test_a_missing_target_raises_an_alert_instead_of_failing(admin, fake, worker):
    add_server(admin)
    add_approval(admin, "key", "gone")
    enqueue(admin, "sync_target", "key:gone")
    drain(worker)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "target_missing"
    assert job_rows(admin)[0]["status"] == "done"


def test_a_read_back_that_disagrees_raises_an_alert_and_a_later_match_resolves_it(
    admin, fake, worker
):
    key_world(admin, fake)

    def overwrite(method, path, body):  # 응답 직후 다른 관리자가 덮어썼다
        fake.keys["k1"]["object_permission"]["mcp_servers"] = []

    fake.after_write = overwrite
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "readback_mismatch" and alert["status"] == "open"
    assert grant(admin, "mcp_server")["observed"] is False
    fake.after_write = None
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert grant(admin, "mcp_server")["observed"] is True
    assert alerts(admin, "sync_divergence")[0]["status"] == "resolved"


def test_a_concurrent_edit_of_fields_mint_does_not_own_raises_an_alert(admin, fake, worker):
    key_world(admin, fake)

    def other_admin(method, path, body):
        fake.keys["k1"]["blocked"] = True

    fake.before_write = other_admin
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    [alert] = alerts(admin, "sync_foreign_change")
    assert alert["subject"] == {"target": "key:k1", "fields": ["blocked"]}


def test_a_worker_without_litellm_settings_fails_the_job_with_a_code(admin, make_worker):
    add_server(admin)
    add_approval(admin, "key", "k1")
    worker = make_worker(litellm=None)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    [job] = job_rows(admin)
    assert (job["status"], job["last_error_code"]) == ("pending", "litellm_not_configured")


def test_three_failed_reaches_open_the_unreachable_alert_and_a_success_closes_it(
    admin, fake, make_worker
):
    key_world(admin, fake)
    dead = make_worker(litellm=LiteLLMSync("http://localhost:9", CONTROL_KEY, timeout=1))
    for attempt in range(3):
        enqueue(admin, "sync_target", "key:k1")
        drain(dead)
        past(admin)
        assert len(alerts(admin, "litellm_unreachable")) == (1 if attempt == 2 else 0)
    live = make_worker()
    drain(live)
    assert alerts(admin, "litellm_unreachable")[0]["status"] == "resolved"


def test_a_restored_database_stops_the_write_before_it_leaves(
    admin, fake, make_worker, monkeypatch
):
    from mint_litellm.control import sync_jobs
    from mint_litellm.restore.judge import BLOCKED, Verdict

    key_world(admin, fake)
    worker = make_worker()
    read = sync_jobs._read

    def read_then_restore(*args):  # 읽은 직후, 쓰기 전에 되돌림이 감지된다
        result = read(*args)
        worker.verdict = Verdict(BLOCKED, "restore_pending")
        return result

    monkeypatch.setattr(sync_jobs, "_read", read_then_restore)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.writes() == []
    [job] = job_rows(admin)
    assert (job["status"], job["attempts"], job["last_error_code"]) == (
        "pending", 0, "restore_blocked")


# --- sync_reconcile, 보류, 재개 --------------------------------------------------------


def delete_server_from_key(fake) -> None:
    fake.keys["k1"]["object_permission"]["mcp_servers"] = []


def synced_key(admin, fake, worker):
    key_world(admin, fake)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert len(fake.writes()) == 1


def test_an_unsynced_target_is_registered_by_the_reconcile_without_counting(
    admin, fake, worker
):
    key_world(admin, fake)
    reconcile(admin)
    drain(worker)
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a", "b"]})
    assert grant(admin, "mcp_server")["missing_count"] == 0


def test_one_external_deletion_is_restored_and_the_second_one_holds_the_item(
    admin, fake, worker
):
    synced_key(admin, fake, worker)
    delete_server_from_key(fake)
    reconcile(admin)
    drain(worker)
    first = grant(admin, "mcp_server")
    assert fake.permission("key", "k1")[0] == ["srv-1"]  # 복구되었다
    assert (first["missing_count"], first["held"], first["observed"]) == (1, False, True)
    assert first["missing_window_start"] is not None
    assert events(admin, "sync_held") == [] and alerts(admin, "sync_divergence") == []

    delete_server_from_key(fake)  # 한 시간 안의 두 번째 삭제
    reconcile(admin)
    drain(worker)
    held = grant(admin, "mcp_server")
    assert (held["missing_count"], held["held"], held["observed"]) == (2, True, False)
    assert fake.permission("key", "k1")[0] == []  # 다시 부여하지 않는다
    [event] = events(admin, "sync_held")
    assert event["payload"]["server_id"] == "srv-1"
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "held" and alert["severity"] == "high"
    writes = len(fake.writes())

    reconcile(admin)  # 보류된 항목은 다시 세지도 부여하지도 않는다
    drain(worker)
    assert len(fake.writes()) == writes
    assert grant(admin, "mcp_server")["missing_count"] == 2
    assert len(events(admin, "sync_held")) == 1
    assert [g["id"] for g in sync_service.status(make_ctx(admin), held_only=True)] == [held["id"]]


def test_resume_clears_the_hold_and_grants_the_item_again(admin, fake, worker):
    synced_key(admin, fake, worker)
    for _ in range(2):
        delete_server_from_key(fake)
        reconcile(admin)
        drain(worker)
    held = grant(admin, "mcp_server")
    assert held["held"] is True
    sync_service.resume(make_ctx(admin), str(held["id"]), expected_version=held["state_version"])
    after = grant(admin, "mcp_server")
    assert (after["held"], after["missing_count"], after["missing_window_start"]) == (
        False, 0, None)
    assert any(j["status"] == "pending" and j["target_ref"] == "key:k1"
               for j in job_rows(admin, "sync_target"))
    drain(worker)
    assert fake.permission("key", "k1")[0] == ["srv-1"]
    assert grant(admin, "mcp_server")["observed"] is True
    resumed = [e for e in events(admin, "sync_applied") if e["payload"].get("action") == "resume"]
    assert len(resumed) == 1
    with pytest.raises(ControlError, match="보류"):
        sync_service.resume(make_ctx(admin), str(held["id"]))


def test_a_deletion_after_the_window_opens_a_new_window_instead_of_holding(
    admin, fake, worker
):
    synced_key(admin, fake, worker)
    delete_server_from_key(fake)
    reconcile(admin)
    drain(worker)
    admin.execute("UPDATE mint.litellm_grants SET missing_window_start = now() - interval"
                  " '2 hours' WHERE item = 'mcp_server'")
    delete_server_from_key(fake)
    reconcile(admin)
    drain(worker)
    again = grant(admin, "mcp_server")
    assert (again["missing_count"], again["held"], again["observed"]) == (1, False, True)
    assert fake.permission("key", "k1")[0] == ["srv-1"]


def test_a_deleted_tool_entry_counts_like_a_deleted_server(admin, fake, worker):
    synced_key(admin, fake, worker)
    fake.keys["k1"]["object_permission"]["mcp_tool_permissions"] = {}
    reconcile(admin)
    drain(worker)
    row_ = grant(admin, "tool_permission")
    assert (row_["missing_count"], row_["held"]) == (1, False)
    assert fake.permission("key", "k1")[1] == {"srv-1": ["a", "b"]}


def test_a_still_pending_restore_is_not_counted_twice(admin, fake, worker):
    """복구 작업이 아직 돌지 않은 채 다음 재조회가 와도 같은 삭제를 두 번으로 세지 않는다."""
    synced_key(admin, fake, worker)
    delete_server_from_key(fake)
    fake.fail_writes["/key/update"] = 500
    reconcile(admin)
    drain(worker)  # 복구 쓰기가 실패한다
    reconcile(admin)
    drain(worker)
    assert grant(admin, "mcp_server")["missing_count"] == 1
    assert grant(admin, "mcp_server")["held"] is False


def test_the_reconcile_removes_items_whose_approval_is_gone(admin, fake, worker):
    approval = key_world(admin, fake)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    revoke(admin, approval)
    reconcile(admin)
    drain(worker)
    assert fake.permission("key", "k1") == ([], {})


def test_a_server_missing_or_not_active_in_the_registry_is_reported(admin, fake, worker):
    add_server(admin)
    add_approval(admin, "user", "u1")  # 사용자 범위도 서버가 LiteLLM에 있어야 쓸 수 있다
    reconcile(admin)
    drain(worker)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "registry_missing"
    fake.add_server("srv-1", "rejected")
    reconcile(admin)
    drain(worker)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["count"] == 2  # 같은 서버의 같은 경보라 횟수만 올랐다
    fake.servers["srv-1"]["approval_status"] = "active"
    reconcile(admin)
    drain(worker)
    assert alerts(admin, "sync_divergence")[0]["status"] == "resolved"


def test_an_activation_that_does_not_finish_in_an_hour_raises_a_job_failed_alert(
    admin, fake, worker
):
    add_server(admin)
    fake.add_server("srv-1", "pending_review")
    approval = add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "activation_finalize", approval)
    admin.execute("SET session_replication_role = replica")  # 생성 시각 고정 트리거를 건너뛴다
    admin.execute("UPDATE mint.jobs SET created_at = now() - interval '2 hours'")
    admin.execute("SET session_replication_role = origin")
    reconcile(admin)
    drain(worker)
    overdue = [a for a in alerts(admin, "job_failed")
               if a["subject"].get("reason") == "not_completed_within_one_hour"]
    assert len(overdue) == 1 and overdue[0]["subject"]["target_ref"] == approval


# --- sync_server, activation_finalize ---------------------------------------------------


def test_a_submitted_server_is_approved_and_an_active_one_is_left_alone(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1", "pending_review")
    add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.writes() == [("PUT", "/v1/mcp/server/srv-1/approve", None)]
    server = grant(admin, "server_approval", "server", "srv-1")
    assert (server["observed"], server["preexisting"]) == (True, False)
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert len(fake.writes()) == 1  # 이미 active면 건너뛴다
    assert len(events(admin, "sync_applied")) == 1


def test_a_local_server_absent_from_the_registry_opens_no_divergence_alert(admin, fake, worker):
    admin.execute(
        "INSERT INTO mint.servers (id, instance_id, server_id, status, identity_kind,"
        " exec_contract_sha256, exec_contract_version, transport, auth_type, registered_by)"
        " VALUES (gen_random_uuid(), %s, 'local-1', 'awaiting_approval', 'stdio', %s, 1, 'stdio',"
        " 'none', 't')", (INSTANCE, HEX))
    admin.execute(
        "INSERT INTO mint.usage_relations (id, instance_id, org_id, purpose, server_id)"
        " VALUES (gen_random_uuid(), %s, 'acme', 'ops', 'local-1')", (INSTANCE,))
    admin.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'local-1'")
    add_approval(admin, "user", "u1", server_id="local-1")
    enqueue(admin, "sync_server", "local-1")
    reconcile(admin)
    drain(worker)
    assert alerts(admin, "sync_divergence") == []


def test_a_server_that_was_already_active_is_recorded_as_preexisting(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.writes() == []
    assert grant(admin, "server_approval", "server", "srv-1")["preexisting"] is True


def test_a_server_missing_from_the_registry_is_reported_and_not_recreated(admin, fake, worker):
    add_server(admin)
    add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.writes() == []
    assert alerts(admin, "sync_divergence")[0]["subject"]["reason"] == "registry_missing"
    assert grant(admin, "server_approval", "server", "srv-1")["observed"] is False


def test_a_rejected_server_is_not_overridden(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1", "rejected")
    add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fake.writes() == []
    assert alerts(admin, "sync_divergence")[0]["subject"]["status"] == "rejected"


def test_a_pending_approval_becomes_active_only_after_both_sides_are_confirmed(
    admin, fake, worker
):
    add_server(admin)
    fake.add_server("srv-1", "pending_review")
    fake.add_key("k1")
    approval = add_approval(admin, "key", "k1", status="pending")

    def state():
        return fetchone(admin, "SELECT a.status AS approval, s.status AS server,"
                               " s.last_observed_at FROM mint.approvals a, mint.servers s"
                               " WHERE a.id = %s", (approval,))

    enqueue(admin, "sync_target", "key:k1")
    drain(worker)  # 대상은 맞췄지만 서버 승인이 아직이다
    assert fake.permission("key", "k1") == (["srv-1"], {"srv-1": ["a"]})
    assert state()["approval"] == "pending"
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    done = state()
    assert (done["approval"], done["server"]) == ("active", "approved")
    assert done["last_observed_at"] is not None
    assert [e["payload"]["first_approval_id"] for e in events(admin, "server_approved")] == [
        approval]
    granted = fetchone(admin, "SELECT granted_by FROM mint.approvals WHERE id = %s", (approval,))
    assert granted["granted_by"] == "op"  # 승인한 사람은 그대로 둔다


def test_a_user_scope_approval_needs_only_the_server_side(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1", "pending_review")
    approval = add_approval(admin, "user", "u1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    drain(worker)
    assert fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (approval,))["status"] == "active"
    assert fake.writes() == [("PUT", "/v1/mcp/server/srv-1/approve", None)]


def test_an_already_active_approval_is_not_finalized_again(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    fake.add_key("k1")
    approval = add_approval(admin, "key", "k1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (approval,))["status"] == "active"
    before = fetchone(admin, "SELECT state_version FROM mint.approvals WHERE id = %s", (approval,))
    enqueue(admin, "activation_finalize", approval)
    drain(worker)
    assert fetchone(admin, "SELECT state_version FROM mint.approvals WHERE id = %s",
                    (approval,)) == before


def test_finalize_rechecks_the_target_and_waits_for_a_second_approvals_tools(
    admin, fake, worker
):
    """같은 대상·서버의 두 번째 승인이 새 도구를 요구하면 그 도구가 LiteLLM에 올 때까지 대기한다."""
    add_server(admin)
    fake.add_server("srv-1")
    fake.add_key("k1")
    add_approval(admin, "key", "k1", tools=("a",), status="pending")
    enqueue(admin, "sync_server", "srv-1")
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    second = add_approval(admin, "key", "k1", tools=("c",), status="pending")
    enqueue(admin, "activation_finalize", second)  # 아직 새 도구를 쓰기 전의 완결 요청
    drain(worker)
    assert fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (second,))["status"] == "pending"
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1")[1] == {"srv-1": ["a", "c"]}
    assert fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (second,))["status"] == "active"


def test_every_sync_kind_has_a_handler_and_the_reconcile_has_a_schedule():
    for kind in ("sync_server", "sync_target", "sync_reconcile", "activation_finalize"):
        assert kind in jobs.HANDLERS
    assert "sync_reconcile" in jobs.SCHEDULES


# --- 승인 서비스: 팀 소속 키 ---------------------------------------------------------


def test_a_team_key_cannot_be_approved_before_its_team_has_the_same_server(admin, fake):
    from mint_litellm.control.litellm_admin import LiteLLMAdmin

    add_server(admin, team="t1")
    fake.add_server("srv-1")
    fake.add_team("t1", servers=["srv-1"])
    fake.add_key("k1", team_id="t1", servers=["srv-1"])
    litellm = LiteLLMAdmin(fake.url, CONTROL_KEY)
    relation = fetchone(admin, "SELECT id FROM mint.usage_relations")["id"]
    from datetime import UTC, datetime, timedelta

    def approve():
        return approvals_domain.approve(
            make_ctx(admin), litellm, relation_id=str(relation), scope_type="key",
            scope_id="k1", tools=["a"], valid_from=datetime.now(UTC),
            valid_until=datetime.now(UTC) + timedelta(days=1), approval_class="standard",
            basis_text="b", requested_by="req", allowlist_ids=[], second=None)

    with pytest.raises(ControlError, match="팀 범위 승인"):
        approve()
    add_approval(admin, "team", "t1", status="pending")
    approval_id, _ = approve()
    assert approval_id


# --- allow_all_keys, observed=false 행, 쓰기 전 기록 ---------------------------------------


def test_a_controlled_server_opened_to_all_keys_is_closed_and_reported(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    fake.servers["srv-1"]["allow_all_keys"] = True
    add_approval(admin, "user", "u1")
    reconcile(admin)
    drain(worker)
    assert fake.servers["srv-1"]["allow_all_keys"] is False
    assert fake.writes() == [("PUT", "/v1/mcp/server",
                              {"server_id": "srv-1", "allow_all_keys": False})]
    [alert] = alerts(admin, "sync_foreign_change")
    assert alert["subject"] == {"server_id": "srv-1", "fields": ["allow_all_keys"]}
    assert alerts(admin, "sync_divergence") == []
    reconcile(admin)  # 이미 닫혔으면 쓰지 않고, 돌아온 값을 보면 외부 변경 경보를 닫는다
    drain(worker)
    assert len(fake.writes()) == 1
    assert alerts(admin, "sync_foreign_change")[0]["status"] == "resolved"


def test_an_allow_all_keys_that_cannot_be_closed_raises_a_divergence(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    fake.servers["srv-1"]["allow_all_keys"] = True
    add_approval(admin, "user", "u1")
    fake.ignore_allow_all_keys = True
    reconcile(admin)
    drain(worker)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"]["reason"] == "allow_all_keys_still_enabled"
    fake.ignore_allow_all_keys = False
    fake.fail_writes["/v1/mcp/server"] = 403
    reconcile(admin)
    drain(worker)
    assert alerts(admin, "sync_divergence")[0]["subject"]["reason"] == (
        "allow_all_keys_still_enabled")  # 같은 경보에 횟수만 오른다
    assert alerts(admin, "sync_divergence")[0]["count"] == 2
    fake.fail_writes.clear()
    reconcile(admin)
    drain(worker)
    assert fake.servers["srv-1"]["allow_all_keys"] is False
    assert alerts(admin, "sync_divergence")[0]["status"] == "resolved"


def test_empty_call_limits_are_filled_and_operator_values_are_kept(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    fake.servers["srv-1"].update(rpm=30, max_concurrent_requests=None)
    add_approval(admin, "user", "u1")
    reconcile(admin)
    drain(worker)
    assert fake.servers["srv-1"]["rpm"] == 30  # 운영자 값은 덮지 않는다
    assert fake.servers["srv-1"]["max_concurrent_requests"] == 8
    assert fake.writes() == [("PUT", "/v1/mcp/server",
                              {"server_id": "srv-1", "max_concurrent_requests": 8})]
    reconcile(admin)
    drain(worker)
    assert len(fake.writes()) == 1  # 채워진 뒤에는 쓰지 않는다


def test_call_limits_that_cannot_be_filled_raise_a_divergence_without_blocking(
    admin, fake, worker
):
    add_server(admin)
    fake.add_server("srv-1")
    fake.servers["srv-1"].update(rpm=None, max_concurrent_requests=None)
    add_approval(admin, "user", "u1")
    fake.fail_writes["/v1/mcp/server"] = 403
    reconcile(admin)
    drain(worker)
    [alert] = alerts(admin, "sync_divergence")
    assert alert["subject"] == {"server_id": "srv-1", "reason": "call_limits_write_failed"}
    fake.fail_writes.clear()
    reconcile(admin)
    drain(worker)
    assert fake.servers["srv-1"]["rpm"] == 600
    assert alerts(admin, "sync_divergence")[0]["status"] == "resolved"


def test_an_uncontrolled_server_with_allow_all_keys_is_left_alone(admin, fake, worker):
    add_server(admin)
    fake.add_server("srv-1")
    fake.servers["srv-1"]["allow_all_keys"] = True
    reconcile(admin)  # 승인이 하나도 없는 서버는 재조회 대상이 아니다
    drain(worker)
    assert fake.writes() == []


def test_a_row_left_unobserved_is_fixed_by_the_reconcile_and_the_approval_activates(
    admin, fake, worker
):
    add_server(admin)
    fake.add_server("srv-1")
    fake.add_key("k1")
    approval = add_approval(admin, "key", "k1", status="pending")
    enqueue(admin, "sync_server", "srv-1")
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (approval,))["status"] == "active"
    # 쓰기는 됐는데 확인이 늦어 행이 observed=false로 남고 승인은 아직 대기인 상태를 만든다
    admin.execute("SET session_replication_role = replica")
    admin.execute("UPDATE mint.approvals SET status = 'pending' WHERE id = %s", (approval,))
    admin.execute("SET session_replication_role = origin")
    admin.execute("UPDATE mint.litellm_grants SET observed = false WHERE target_type = 'key'")
    reconcile(admin)
    drain(worker)
    assert [g["observed"] for g in grants(admin) if g["target_type"] == "key"] == [True, True]
    late = [e for e in events(admin, "sync_applied") if e["payload"].get("late_confirmation")]
    assert len(late) == 2  # 늦게 확인한 두 행의 반영이 사건으로 남았다
    assert all(g["last_applied_at"] is not None for g in grants(admin)
               if g["target_type"] == "key")
    assert fetchone(admin, "SELECT status FROM mint.approvals WHERE id = %s",
                    (approval,))["status"] == "active"
    assert len(fake.writes()) == 1  # 이미 있는 항목은 다시 쓰지 않는다


def test_an_unobserved_row_whose_item_is_missing_is_synced_again(admin, fake, worker):
    synced_key(admin, fake, worker)
    admin.execute("UPDATE mint.litellm_grants SET observed = false WHERE target_type = 'key'")
    delete_server_from_key(fake)
    reconcile(admin)
    drain(worker)
    assert fake.permission("key", "k1")[0] == ["srv-1"]
    assert grant(admin, "mcp_server")["observed"] is True
    assert grant(admin, "mcp_server")["missing_count"] == 0  # 이미 없다고 본 항목은 세지 않는다


def test_rows_are_recorded_before_the_write_so_a_crash_keeps_mint_ownership(
    admin, fake, worker, monkeypatch
):
    from mint_litellm.control import sync_jobs

    key_world(admin, fake)
    monkeypatch.setattr(sync_jobs, "_record", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("crash after the write")))
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1")[0] == ["srv-1"]  # 쓰기는 나갔다
    row_ = grant(admin, "mcp_server")
    assert (row_["observed"], row_["preexisting"]) == (False, False)
    monkeypatch.undo()
    past(admin)
    drain(worker)
    row_ = grant(admin, "mcp_server")
    # 쓰기 전에 적어 둔 덕에 MINT가 넣은 항목을 원래 있던 것으로 오판하지 않는다
    assert (row_["observed"], row_["preexisting"]) == (True, False)
    assert grant(admin, "tool_permission")["tools"] == ["a", "b"]


# --- 이용 관계 종료: 승인 철회, 권한 회수 확인, 결과 기록 ---------------------------------


def relation_row(admin) -> dict:
    return fetchone(admin, "SELECT id::text AS id, status FROM mint.usage_relations")


def termination_done(admin) -> list[dict]:
    return [e["payload"] for e in events(admin, "relation_terminating")
            if e["payload"].get("phase") == "revocation_confirmed"]


def test_terminating_a_relation_revokes_withdraws_confirms_and_records(admin, fake, worker):
    key_world(admin, fake)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    assert fake.permission("key", "k1")[0] == ["srv-1"]
    relations_domain.terminate(make_ctx(admin), relation_row(admin)["id"])
    assert fetchone(admin, "SELECT status FROM mint.approvals")["status"] == "revoked"
    drain(worker)
    reconcile(admin)
    drain(worker)
    servers, tools = fake.permission("key", "k1")
    assert "srv-1" not in servers and not tools.get("srv-1")
    assert relation_row(admin)["status"] == "terminating"  # 닫기는 증빙을 확인하는 finish의 몫
    (done,) = termination_done(admin)
    assert done["targets"] == ["key:k1"] and done["retained"] == []
    assert alerts(admin, "termination_unconfirmed") == []


def test_access_that_mint_did_not_grant_is_reported_as_retained_not_withdrawn(
    admin, fake, worker
):
    key_world(admin, fake, servers=["srv-1"])
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    relations_domain.terminate(make_ctx(admin), relation_row(admin)["id"])
    drain(worker)
    reconcile(admin)
    drain(worker)
    assert "srv-1" in fake.permission("key", "k1")[0]
    assert relation_row(admin)["status"] == "terminating"  # 닫기는 증빙을 확인하는 finish의 몫
    (done,) = termination_done(admin)
    assert done["retained"] == [{"target": "key:k1", "item": "mcp_server"}]


def test_unwithdrawn_grants_keep_the_relation_terminating_until_the_sync_confirms(
    admin, fake, worker
):
    approval = key_world(admin, fake)
    enqueue(admin, "sync_target", "key:k1")
    drain(worker)
    revoke(admin, approval)  # 동기화를 요청하지 않고 승인만 철회한다
    admin.execute("UPDATE mint.usage_relations SET status = 'terminating'")
    enqueue(admin, "relation_finalize", relation_row(admin)["id"])
    drain(worker)  # 마무리 확인이 거두지 못한 항목을 보고 동기화를 요청하고, 동기화가 거둔다
    assert relation_row(admin)["status"] == "terminating"
    reconcile(admin)
    drain(worker)
    assert [a["status"] for a in alerts(admin, "termination_unconfirmed")] == ["resolved"]
    assert len(termination_done(admin)) == 1


# --- 서버 폐기: 사용자별 자격 삭제와 읽어 확인 -----------------------------------------------


def terminating_server(admin, fake, credentials) -> None:
    add_server(admin, status="approved")
    fake.add_server("srv-1")
    fake.credentials["srv-1"] = list(credentials)
    admin.execute("UPDATE mint.servers SET status = 'terminating'")


def revocation_evidence(admin) -> None:
    admin.execute(
        "INSERT INTO mint.policy_evidence (id, instance_id, kind, subject_kind, subject_id,"
        " result, summary, attached_by) SELECT gen_random_uuid(), instance_id, 'access_revocation',"
        " 'server', server_id, 'confirmed', '계정·공유 권한 회수', 'boss' FROM mint.servers"
    )


def server_status(admin) -> str:
    return fetchone(admin, "SELECT status FROM mint.servers")["status"]


CREDS = [{"user_id": "u1", "credential_type": "oauth2"},
         {"user_id": "u2", "credential_type": "byok"},
         {"user_id": "u3", "credential_type": "oauth2"}]


def test_terminating_a_server_deletes_its_user_credentials_reads_back_and_closes(
    admin, fake, worker
):
    terminating_server(admin, fake, CREDS)
    revocation_evidence(admin)
    enqueue(admin, "server_finalize", "srv-1")
    drain(worker)
    assert fake.credentials["srv-1"] == []
    assert server_status(admin) == "terminated"
    (done,) = events(admin, "server_terminated")
    assert done["payload"]["deleted"] == {"oauth2": 2, "byok": 1}
    assert done["payload"]["remaining"] == 0
    assert "user_env_vars" in done["payload"]["not_covered"]
    assert alerts(admin, "server_credentials_remain") == []


def test_credentials_that_remain_keep_the_server_terminating_retry_and_alert(admin, fake, worker):
    terminating_server(admin, fake, CREDS)
    revocation_evidence(admin)
    fake.sticky_credentials = True
    enqueue(admin, "server_finalize", "srv-1")
    drain(worker)
    assert server_status(admin) == "terminating"
    assert events(admin, "server_terminated") == []
    (alert,) = alerts(admin, "server_credentials_remain")
    assert alert["status"] == "open"
    job = fetchone(admin, "SELECT status, attempts FROM mint.jobs WHERE kind = 'server_finalize'")
    assert job["status"] == "pending" and job["attempts"] == 1  # 보통 백오프로 다시 시도한다
    fake.sticky_credentials = False  # 다음 시도에서 지워진다
    admin.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'"
                  " WHERE status = 'pending'")
    drain(worker)
    assert server_status(admin) == "terminated"
    assert [a["status"] for a in alerts(admin, "server_credentials_remain")] == ["resolved"]


def test_a_litellm_without_the_credential_list_cannot_confirm_and_keeps_the_server_open(
    admin, fake, worker
):
    terminating_server(admin, fake, CREDS)
    fake.credentials_api = False
    enqueue(admin, "server_finalize", "srv-1")
    drain(worker)
    assert server_status(admin) == "terminating"
    assert fake.writes() == []  # 읽을 수 없으면 지우지도 않는다
    assert [a["kind"] for a in alerts(admin, "server_credentials_unverifiable")] == [
        "server_credentials_unverifiable"]
    assert events(admin, "server_terminated") == []


def test_the_reconcile_pass_requests_the_credential_check_for_terminating_servers(
    admin, fake, worker
):
    terminating_server(admin, fake, CREDS)
    revocation_evidence(admin)
    reconcile(admin)
    drain(worker)
    assert server_status(admin) == "terminated"


def test_without_access_revocation_evidence_the_server_stays_terminating_with_an_alert(
    admin, fake, worker
):
    terminating_server(admin, fake, CREDS)
    enqueue(admin, "server_finalize", "srv-1")
    drain(worker)
    assert fake.credentials["srv-1"] == []  # 자격 삭제는 먼저 끝난다
    assert server_status(admin) == "terminating"
    assert events(admin, "server_terminated") == []
    (alert,) = alerts(admin, "evidence_missing")
    assert alert["status"] == "open"
    job = fetchone(admin, "SELECT status, attempts FROM mint.jobs WHERE kind = 'server_finalize'")
    assert job["status"] == "pending" and job["attempts"] == 1
    revocation_evidence(admin)
    admin.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'"
                  " WHERE status = 'pending'")
    drain(worker)
    assert server_status(admin) == "terminated"
    assert [a["status"] for a in alerts(admin, "evidence_missing")] == ["resolved"]

