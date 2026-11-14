"""키 차단 제안: 신호별 제안, 키 없는 주체 건너뛰기, 승인 흐름(차단 뒤 다시 읽어 확인), 이미 차단됨,
중복 승인, 해제 경고, 직무 분리. MINT_TEST_DATABASE_URL이 없으면 건너뛴다."""

import json
from datetime import timedelta

import pytest
from ctl_fixtures import INSTANCE, make_ctx
from fake_litellm import CONTROL_KEY, FakeLiteLLM

from mint_litellm.control import alerts, jobs, key_block
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminError, ControlError
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.litellm_write import LiteLLMSync
from mint_litellm.types.ids import new_uuid7


@pytest.fixture
def fake():
    server = FakeLiteLLM()
    server.add_team("team-a", members_with_roles=[{"user_id": "member-1"}])
    server.add_key("tok1", team_id="team-a", user_id="alice", key_alias="alice-key")
    server.add_key("tok2", user_id="bob", key_alias="bob-key")
    yield server
    server._server.shutdown()
    server._server.server_close()


def decision(
    conn, key_id, ptype="user", enforced="block", policy=("POL-X",), findings=(), inv=None
):
    inv = inv or new_uuid7()
    principal = {"principal_type": ptype, "principal_id": "u1"}
    if key_id:
        principal["key_id"] = key_id
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, payload) VALUES (%s, %s, 'decision_evaluated', %s, %s, 1, %s)",
        (new_uuid7(), INSTANCE, f"t:{new_uuid7()}", inv,
         json.dumps({"principal": principal, "enforced_action": enforced,
                     "operation": "tool_call", "policy_ids": list(policy),
                     "findings": list(findings)})),
    )
    return inv


def response(conn, inv, user="u1", **payload):
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, subject, payload) VALUES (%s, %s, 'call_response_received', %s, %s, 1,"
        " %s, %s)",
        (new_uuid7(), INSTANCE, f"t:{new_uuid7()}", inv,
         json.dumps({"principal_type": "user", "principal_id": user}),
         json.dumps({"server_id": "srv", **payload})),
    )


def scan(conn, fake):
    client = LiteLLMSync(fake.url, CONTROL_KEY)
    key_block.run(jobs.JobContext(conn, INSTANCE, {}, None, litellm=client))


def proposals(conn):
    return fetchall(conn, "SELECT * FROM mint.key_block_proposals ORDER BY created_at")


def apply(conn, fake, proposal_id, action):
    job = {"kind": "key_block_apply", "target_ref": f"{proposal_id}:{action}"}
    key_block.apply(jobs.JobContext(conn, INSTANCE, job, None,
                                    litellm=LiteLLMSync(fake.url, CONTROL_KEY)))


def secret_proposal(conn, fake, key="tok2"):
    response(conn, decision(conn, key, enforced="allow", policy=()),
             sensitive_findings={"private_key": 1, "email": 3})
    scan(conn, fake)
    (row,) = [p for p in proposals(conn) if p["key_token"] == key]
    return row


def approver(conn, name="carol"):
    return make_ctx(conn, name, "approver", f"{name}-user")


def reader(fake):
    return LiteLLMAdmin(fake.url, CONTROL_KEY)


# --- 제안 만들기 -----------------------------------------------------------------------------


def test_secret_in_a_result_opens_a_proposal_with_labels_only(conn, fake):
    row = secret_proposal(conn, fake)
    assert row["signal"] == "secret_exposure" and row["status"] == "proposed"
    assert row["evidence"]["labels"] == ["private_key"]  # 개인정보 종류는 제안 근거가 아니다
    assert (row["key_alias"], row["user_id"], row["team_id"]) == ("bob-key", "bob", None)
    assert len(row["evidence"]["event_ids"]) == 1
    (alert,) = fetchall(conn, "SELECT kind, severity FROM mint.alerts WHERE kind = %s",
                        (key_block.ALERT,))
    assert alert["severity"] == "high"
    assert fetchone(conn, "SELECT 1 AS x FROM mint.events WHERE kind = 'key_block_proposed'")
    scan(conn, fake)  # 같은 증거로 다시 만들지 않는다
    assert len(proposals(conn)) == 1


def test_a_blocked_input_secret_counts_and_team_impact_is_recorded(conn, fake):
    fake.add_key("tok3", team_id="team-a", user_id="dave")
    decision(conn, "tok3", findings=[{"status": "finding", "detail": "input private_key=1"}])
    scan(conn, fake)
    (row,) = proposals(conn)
    assert row["evidence"]["labels"] == ["input_secret"]
    assert (row["team_key_count"], row["team_member_count"]) == (2, 1)


def test_repeated_policy_denials_need_the_threshold(conn, fake):
    for _ in range(key_block.DENIAL_THRESHOLD - 1):
        decision(conn, "tok1")
    scan(conn, fake)
    assert proposals(conn) == []
    decision(conn, "tok1")
    scan(conn, fake)
    (row,) = proposals(conn)
    assert (row["signal"], row["key_token"]) == ("repeated_denials", "tok1")
    assert row["evidence"]["denials"] == key_block.DENIAL_THRESHOLD


def bulk_alert(conn, user="u1"):
    alerts.raise_alert(
        conn, INSTANCE, kind="bulk_extraction", severity="high", dedup_key=f"bulk:{user}",
        subject={"server_id": "srv", "principal_id": user, "bytes": 9, "items": 9,
                 "window_seconds": 900},
    )


def test_bulk_extraction_proposes_only_when_one_key_is_behind_it(conn, fake):
    bulk_alert(conn)
    response(conn, decision(conn, "tok1", enforced="allow", policy=()), size_bytes=5)
    response(conn, decision(conn, "tok2", enforced="allow", policy=()), size_bytes=5)
    scan(conn, fake)
    assert proposals(conn) == []  # 두 키에 걸치면 어느 키인지 확정할 수 없다
    bulk_alert(conn, "u2")  # 다른 호출 주체는 키 하나만 썼다
    response(conn, decision(conn, "tok1", enforced="allow", policy=()), user="u2", size_bytes=5)
    scan(conn, fake)
    (row,) = proposals(conn)
    assert (row["signal"], row["key_token"]) == ("bulk_extraction", "tok1")


def test_endpoint_alert_maps_to_the_install_key(conn, fake):
    conn.execute(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
        " issued_by) VALUES (%s, 'tok2', 'bob', 'mint-kit-bob', 'root')", (INSTANCE,))
    alerts.raise_alert(
        conn, INSTANCE, kind="endpoint_outside_unapproved", severity="high",
        dedup_key="e1", subject={"key_alias": "mint-kit-bob", "package": "evil"},
    )
    scan(conn, fake)
    (row,) = proposals(conn)
    assert (row["signal"], row["key_token"]) == ("endpoint_compromise", "tok2")


def test_no_key_no_proposal(conn, fake):
    decision(conn, None, ptype="anonymous")  # 키 없는 주체(JWT 등)
    for _ in range(key_block.DENIAL_THRESHOLD):
        decision(conn, None)
        decision(conn, "tok-gone")  # LiteLLM에 없는 키
        decision(conn, "tok-master", ptype="master_key")
    fake.add_key("tok-blocked", blocked=True)
    for _ in range(key_block.DENIAL_THRESHOLD):
        decision(conn, "tok-blocked")
    scan(conn, fake)
    assert proposals(conn) == []


def test_expired_and_cooldown(conn, fake):
    row = secret_proposal(conn, fake)
    conn.execute("UPDATE mint.key_block_proposals SET expires_at = now() - interval '1 minute'")
    scan(conn, fake)
    assert proposals(conn)[0]["status"] == "expired" and len(proposals(conn)) == 1
    assert fetchall(conn, "SELECT 1 FROM mint.alerts WHERE kind = %s AND status <> 'resolved'",
                    (key_block.ALERT,)) == []
    assert row["created_at"] + key_block.COOLDOWN > row["created_at"] + timedelta(hours=1)


# --- 승인 흐름 -------------------------------------------------------------------------------


def test_approval_blocks_once_and_confirms_by_reading_back(conn, fake):
    row = secret_proposal(conn, fake)
    ctx = approver(conn)
    out = key_block.approve(ctx, reader(fake), str(row["id"]), reason="확인함")
    assert out["status"] == "approved"
    again = key_block.approve(ctx, reader(fake), str(row["id"]))  # 두 번 눌러도 작업은 하나
    assert again["repeated"] is True
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.jobs WHERE kind = 'key_block_apply'")[
        "n"] == 1
    assert fake.writes() == []  # 승인만으로는 LiteLLM을 쓰지 않는다
    apply(conn, fake, row["id"], "block")
    apply(conn, fake, row["id"], "block")  # 작업이 다시 돌아도 한 번만 쓴다
    assert [w[1] for w in fake.writes()] == ["/key/block"]
    assert fake.writes()[0][2] == {"key": "tok2"}
    done = proposals(conn)[0]
    assert (done["status"], done["mint_blocked"], done["decided_by"]) == ("applied", True, "carol")
    assert done["marker_updated_at"] == fake.keys["tok2"]["updated_at"]
    kinds = [r["kind"] for r in fetchall(conn, "SELECT kind FROM mint.events WHERE kind LIKE"
                                         " 'key_block_%%' ORDER BY inserted_at")]
    assert kinds == ["key_block_proposed", "key_block_approved", "key_block_applied"]
    assert fetchall(conn, "SELECT 1 FROM mint.alerts WHERE kind = %s AND status <> 'resolved'",
                    (key_block.ALERT,)) == []


def test_already_blocked_at_approval_is_not_claimed_as_ours(conn, fake):
    row = secret_proposal(conn, fake)
    fake.keys["tok2"]["blocked"] = True  # 제안 뒤 누군가 먼저 막았다
    out = key_block.approve(approver(conn), reader(fake), str(row["id"]))
    assert out["already_blocked"] is True
    done = proposals(conn)[0]
    assert (done["status"], done["mint_blocked"]) == ("applied", False)
    assert fake.writes() == []
    assert fetchone(conn, "SELECT count(*) AS n FROM mint.jobs WHERE kind = 'key_block_apply'")[
        "n"] == 0


def test_block_that_cannot_be_confirmed_or_is_refused_is_recorded(conn, fake):
    row = secret_proposal(conn, fake)
    key_block.approve(approver(conn), reader(fake), str(row["id"]))
    fake.ignore_block = True  # 호출은 성공하지만 상태는 그대로
    apply(conn, fake, row["id"], "block")
    failed = proposals(conn)[0]
    assert (failed["status"], failed["last_error"], failed["mint_blocked"]) == (
        "failed", "not_confirmed", False)

    other = secret_proposal(conn, fake, key="tok1")
    key_block.approve(approver(conn), reader(fake), str(other["id"]))
    fake.ignore_block = False
    fake.fail_writes["/key/block"] = 403  # 제어 키에 경로 권한이 없다
    apply(conn, fake, other["id"], "block")
    assert fetchone(conn, "SELECT last_error FROM mint.key_block_proposals WHERE id = %s",
                    (other["id"],))["last_error"] == "route_forbidden"


def test_team_block_uses_the_team_route(conn, fake):
    row = secret_proposal(conn, fake, key="tok1")
    key_block.approve(approver(conn), reader(fake), str(row["id"]), scope="team")
    apply(conn, fake, row["id"], "block")
    assert [w[1:] for w in fake.writes()] == [("/team/block", {"team_id": "team-a"})]
    assert fake.teams["team-a"]["blocked"] is True and fake.keys["tok1"]["blocked"] is None


def test_separation_of_duties_and_roles(conn, fake):
    row = secret_proposal(conn, fake, key="tok1")
    pid = str(row["id"])
    with pytest.raises(AdminError) as own:
        key_block.approve(make_ctx(conn, "alice", "approver", "alice"), reader(fake), pid)
    assert own.value.code == "MINT-ADMIN-SEPARATION-OF-DUTIES"
    with pytest.raises(AdminError):  # 팀 구성원은 팀 차단을 승인할 수 없다
        key_block.approve(make_ctx(conn, "m", "approver", "member-1"), reader(fake), pid,
                          scope="team")
    with pytest.raises(AdminError):
        key_block.approve(make_ctx(conn, "v", "viewer", "v-user"), reader(fake), pid)
    with pytest.raises(AdminError):
        key_block.approve(make_ctx(conn, "nobody", "approver", None), reader(fake), pid)
    assert proposals(conn)[0]["status"] == "proposed"
    out = key_block.reject(approver(conn), pid, reason="오탐")
    assert out["status"] == "rejected"
    assert key_block.reject(approver(conn), pid)["repeated"] is True
    with pytest.raises(ControlError):
        key_block.approve(approver(conn), reader(fake), pid)


# --- 해제 ------------------------------------------------------------------------------------


def blocked_proposal(conn, fake):
    row = secret_proposal(conn, fake)
    key_block.approve(approver(conn), reader(fake), str(row["id"]))
    apply(conn, fake, row["id"], "block")
    return str(row["id"])


def test_unblock_is_admin_only_and_never_automatic(conn, fake):
    pid = blocked_proposal(conn, fake)
    scan(conn, fake)
    assert fake.writes("/key/unblock") == []
    with pytest.raises(AdminError):
        key_block.request_unblock(approver(conn), reader(fake), pid, reason="x")
    ctx = make_ctx(conn)
    with pytest.raises(ControlError):
        key_block.request_unblock(ctx, reader(fake), pid, reason=" ")
    assert key_block.request_unblock(ctx, reader(fake), pid, reason="확인")["status"] == (
        "unblocking")
    assert key_block.request_unblock(ctx, reader(fake), pid, reason="확인")["repeated"] is True
    apply(conn, fake, pid, "unblock")
    apply(conn, fake, pid, "unblock")
    assert [w[1] for w in fake.writes()] == ["/key/block", "/key/unblock"]
    done = proposals(conn)[0]
    assert (done["status"], done["unblocked_by"]) == ("unblocked", "root")
    assert fake.keys["tok2"]["blocked"] is False


def test_unblock_warns_when_the_key_changed_after_our_block(conn, fake):
    pid = blocked_proposal(conn, fake)
    fake.keys["tok2"]["updated_at"] = "someone-else"  # 다른 관리자가 건드렸다
    ctx = make_ctx(conn)
    with pytest.raises(AdminError) as warned:
        key_block.request_unblock(ctx, reader(fake), pid, reason="확인")
    assert "바뀐 것으로 보입니다" in str(warned.value)
    assert proposals(conn)[0]["status"] == "applied"
    out = key_block.request_unblock(ctx, reader(fake), pid, reason="확인", acknowledge=True)
    assert out["status"] == "unblocking"
    assert proposals(conn)[0]["unblock_acknowledged"] is True


def test_only_our_block_can_be_unblocked_here(conn, fake):
    row = secret_proposal(conn, fake)
    fake.keys["tok2"]["blocked"] = True
    key_block.approve(approver(conn), reader(fake), str(row["id"]))  # 이미 차단: 우리 것이 아니다
    with pytest.raises(ControlError):
        key_block.request_unblock(make_ctx(conn), reader(fake), str(row["id"]), reason="x")
