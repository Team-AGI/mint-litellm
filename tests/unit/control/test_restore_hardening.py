"""2단계 보강: 복원 요청의 외부 기준 결속과 부정 상태 행 내용 대조. 실 Postgres."""

import uuid

import pytest
from ctl_fixtures import make_ctx

from control import test_restore_acceptance as base
from control.test_restore_acceptance import (
    INSTANCE,
    KEY,
    add_admins,
    attest_restored,
    overtake_epoch,
    revoke_and_export,
    run_worker,
)

world = base.world  # 같은 시험 세계(픽스처)를 쓴다

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import exports  # noqa: E402
from mint_litellm.control.context import Operator  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.services import restore  # noqa: E402
from mint_litellm.restore import files, judge  # noqa: E402


def _publish_once(world):
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    assert run_worker(world).state == judge.OK
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        request = fetchone(conn, "SELECT * FROM mint.restore_requests")
    assert request["status"] == "published" and request["bound_latest"] != "absent"
    return request


def _snapshot_dir(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file()}


# --- -----------------------------------------------------------------------------


def test_a_completed_request_revived_as_pending_does_not_rewrite_the_evidence(
    world, monkeypatch
):
    """DB가 복구돼 완료 요청이 pending으로 되살아나도 최신 증거를 덮지 않는다(.done 표지)."""
    request = _publish_once(world)
    settings = world["settings"]
    done = settings.export_dir / INSTANCE / "restored" / str(request["id"]) / ".done"
    assert done.exists()
    before = _snapshot_dir(settings.export_dir / INSTANCE)
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")  # 복구 DB의 옛 행을 흉내 낸다
        conn.execute("UPDATE mint.restore_requests SET status = 'pending', published_at = NULL")
        conn.execute("UPDATE mint.jobs SET status = 'pending', run_after = now() - interval"
                     " '1 second', lease_owner = NULL, lease_until = NULL"
                     " WHERE kind = 'restore_publish'")

    def forbidden(*args, **kwargs):
        raise AssertionError("완료 표지가 있는 요청은 다시 게시하지 않는다")

    monkeypatch.setattr(exports, "write_export", forbidden)
    monkeypatch.setattr(exports, "write_latest_file", forbidden)
    run_worker(world)
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "published"
        assert fetchone(conn, "SELECT status FROM mint.jobs WHERE kind = 'restore_publish'"
                        )["status"] == "done"
    assert _snapshot_dir(settings.export_dir / INSTANCE) == before


def test_a_request_is_rejected_when_latest_changed_after_it_was_made(world):
    """요청 뒤에 latest.json이 바뀌면 게시하지 않고 거절·경보한다."""
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    settings = world["settings"]
    path = files.latest_path(settings.export_dir, INSTANCE)
    doc = files.read_verified(path, exports.keys(settings))
    doc["written_at"] = "2031-01-01T00:00:00Z"  # 다른 곳에서 최신 증거가 게시됐다
    files.atomic_write(path, files.sign(doc, KEY.encode()))
    before = _snapshot_dir(settings.export_dir / INSTANCE)
    run_worker(world)
    assert _snapshot_dir(settings.export_dir / INSTANCE) == before  # 보관도 게시도 없다
    assert not (settings.export_dir / INSTANCE / "restored").exists()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "rejected"
        job = fetchone(conn, "SELECT status, last_error_code FROM mint.jobs"
                       " WHERE kind = 'restore_publish'")
        assert job["status"] == "failed" and job["last_error_code"] == "restore_binding_mismatch"
        alert = fetchone(conn, "SELECT severity FROM mint.alerts"
                         " WHERE kind = 'restore_request_rejected'")
        assert alert["severity"] == "critical"


def test_a_pending_restore_request_holds_the_evidence_jobs_until_it_is_published(
    world,
):
    """대기 중인 복원 요청이 있는 동안 정상 체크포인트가 latest.json을 바꾸지 않는다."""
    from control.test_restore_acceptance import url_for
    from mint_litellm.control.worker import RestoreCheck, Worker

    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    settings = world["settings"]
    worker = Worker(url_for(world["restored"], world["clone"], "mint_worker"), INSTANCE,
                    settings, restore_check=RestoreCheck(settings, 0))
    try:
        worker.open()
        assert worker._restore_in_flight() is True
        while worker.step():
            pass
        assert worker._restore_in_flight() is False
    finally:
        worker.close()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "published"


def test_a_crash_between_archive_and_publish_keeps_the_block_without_exports_rows(
    world, monkeypatch
):
    """복구 DB에 내보내기 행이 없어도 복원 진행 중 파일 없음은 첫 설치가 아니라 차단이다."""
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    settings = world["settings"]

    def dying(*args, **kwargs):
        raise OSError("killed")

    monkeypatch.setattr(exports, "write_export", dying)
    run_worker(world)
    assert not files.latest_path(settings.export_dir, INSTANCE).exists()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.exports"
                        " WHERE status = 'written'")["n"] == 0
        verdict = judge.Judge().evaluate(conn, settings.export_dir, INSTANCE,
                                         exports.keys(settings))
    assert verdict.blocked and verdict.cause == judge.EXPORT_MISSING
    monkeypatch.undo()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'")
    assert run_worker(world).state == judge.OK


# --- -----------------------------------------------------------------------------


def _verdicts(url, settings, count=2):
    with psycopg.connect(url, autocommit=True) as conn:
        j = judge.Judge()
        keys = exports.keys(settings)
        return [j.evaluate(conn, settings.export_dir, INSTANCE, keys) for _ in range(count)]


def test_same_version_with_different_row_content_is_a_mismatch_even_with_the_same_anchor(
    world,
):
    revoke_and_export(world)
    settings = world["settings"]
    assert _verdicts(world["live"], settings, 1)[0].state == judge.OK
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")  # 판본을 올리지 않는 변조
        conn.execute("UPDATE mint.orgs SET name = '다른 이름' WHERE org_id = 'acme'")
    first, second = _verdicts(world["live"], settings)
    assert first.state == judge.HOLD and second.blocked
    assert second.detail["anchor_ok"] is True and second.detail["missing_items"] == 1


def test_a_higher_version_that_is_still_negative_is_not_a_mismatch(world):
    revoke_and_export(world)
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("UPDATE mint.orgs SET name = name WHERE org_id = 'acme'")
        assert fetchone(conn, "SELECT state_version FROM mint.orgs")["state_version"] > 2
    assert _verdicts(world["live"], world["settings"])[1].state == judge.OK


def test_a_version_overtake_that_leaves_the_negative_state_is_a_mismatch(world):
    revoke_and_export(world)
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("UPDATE mint.orgs SET status = 'active', state_version = state_version + 5"
                     " WHERE org_id = 'acme'")
    first, second = _verdicts(world["live"], world["settings"])
    assert first.state == judge.HOLD and second.blocked


def _release_event(conn, kind, entity, version):
    conn.execute(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
        " VALUES (gen_random_uuid(), %s, %s, %s, 'root', '{}')",
        (INSTANCE, kind, f"{kind.split('_')[0]}:{entity}:{version}:{kind}"))


def _denial_world(world):
    with psycopg.connect(world["live"], autocommit=True) as conn:
        denial = fetchone(conn, "INSERT INTO mint.denials (id, instance_id, org_id, scope_type,"
                          " scope_id, reason, created_by) VALUES (gen_random_uuid(), %s, 'acme',"
                          " 'org', 'acme', '유출 의심', 'root') RETURNING id", (INSTANCE,))["id"]
        exports.write_export(conn, INSTANCE, world["settings"], "negative_state")
        exports.write_export(conn, INSTANCE, world["settings"], "checkpoint")
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
        conn.execute("UPDATE mint.denials SET lifted_at = now(), lifted_by = 'root'"
                     " WHERE id = %s", (denial,))
        version = fetchone(conn, "SELECT state_version FROM mint.denials WHERE id = %s",
                           (denial,))["state_version"]
    return denial, version


@pytest.mark.parametrize("case", ["unsealed_event", "no_event", "old_version", "other_id"])
def test_a_lifted_denial_needs_a_release_event_bound_to_its_id_and_version(world, case):
    denial, version = _denial_world(world)
    with psycopg.connect(world["live"], autocommit=True) as conn:
        if case == "unsealed_event":
            _release_event(conn, "denial_lifted", denial, version)
        elif case == "old_version":
            _release_event(conn, "denial_lifted", denial, 1)  # 파일 판본 이전의 사건
        elif case == "other_id":
            _release_event(conn, "denial_lifted", uuid.uuid4(), version)
    first, second = _verdicts(world["live"], world["settings"])  # 두 판정기: 재시작해도 같다
    if case == "unsealed_event":  # 봉인 전이어도 재시작 직후 보류가 남지 않는다
        assert first.state == judge.OK and second.state == judge.OK
    else:
        assert first.state == judge.HOLD and second.blocked


@pytest.mark.parametrize("key", ["uuid", "server_id"])
def test_a_resumed_server_is_matched_by_the_servers_uuid_in_the_event_key(world, key):
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'srv-1',"
            " 'awaiting_approval', repeat('a', 64), 'http', 'none', 'x')", (INSTANCE,))
        conn.execute("UPDATE mint.servers SET status = 'approved'")
        conn.execute("UPDATE mint.servers SET status = 'suspended'")
        exports.write_export(conn, INSTANCE, world["settings"], "negative_state")
        exports.write_export(conn, INSTANCE, world["settings"], "checkpoint")
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
        conn.execute("UPDATE mint.servers SET status = 'approved'")
        row = fetchone(conn, "SELECT id, state_version FROM mint.servers")
        _release_event(conn, "server_resumed", row["id"] if key == "uuid" else "srv-1",
                       row["state_version"])
    first, second = _verdicts(world["live"], world["settings"])
    if key == "uuid":
        assert first.state == judge.OK and second.state == judge.OK
    else:
        assert first.state == judge.HOLD and second.blocked


@pytest.mark.parametrize("negative", ["rejected", "suspended"])
def test_a_rejected_server_registered_again_by_a_new_intake_is_not_a_rollback(world, negative):
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by) VALUES (gen_random_uuid(), %s, 'srv-1',"
            " 'awaiting_approval', repeat('a', 64), 'http', 'none', 'x')", (INSTANCE,))
        for status in (["rejected"] if negative == "rejected" else ["approved", "suspended"]):
            conn.execute("UPDATE mint.servers SET status = %s", (status,))
        exports.write_export(conn, INSTANCE, world["settings"], "negative_state")
        exports.write_export(conn, INSTANCE, world["settings"], "checkpoint")
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
        for status in (["validating", "awaiting_approval"] if negative == "rejected" else []):
            conn.execute("UPDATE mint.servers SET status = %s", (status,))
        row = fetchone(conn, "SELECT id, state_version FROM mint.servers")
        _release_event(conn, "server_registered", row["id"], row["state_version"] + 1)
        conn.execute("UPDATE mint.servers SET status = 'approved'")
    first, second = _verdicts(world["live"], world["settings"])
    if negative == "rejected":
        assert first.state == judge.OK and second.state == judge.OK
    else:  # 중지된 서버는 재개 사건으로만 풀린다
        assert first.state == judge.HOLD and second.blocked


def test_an_old_archived_request_is_rejected_after_another_restore_finished(
    world, monkeypatch
):
    """A 요청이 보관하다 중단 -> B 복원 완료 -> A 재실행은 보관본 해시가 맞아도 거부한다."""
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)  # A
    settings = world["settings"]

    def dying(*args, **kwargs):
        raise OSError("killed")

    monkeypatch.setattr(exports, "write_export", dying)
    run_worker(world)  # A: 보관은 끝났고 새 파일은 없다
    monkeypatch.undo()
    add_admins(world["restored"])
    with psycopg.connect(world["restored"]) as conn:
        restore.accept_stale(make_ctx(conn), settings, "B 복원",
                             Operator("second", "admin", "u2"))
        conn.commit()
    assert run_worker(world).state == judge.OK  # B가 끝난다(A 작업은 재시도 대기)
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'"
                     " WHERE status = 'pending'")
        a_id, b_id = [str(r["id"]) for r in fetchall(
            conn, "SELECT id FROM mint.restore_requests ORDER BY created_at")]
    run_worker(world)
    restored = settings.export_dir / INSTANCE / "restored"
    assert (restored / b_id / ".done").exists() and not (restored / a_id / ".done").exists()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        statuses = [r["status"] for r in fetchall(
            conn, "SELECT status FROM mint.restore_requests ORDER BY created_at")]
        assert statuses == ["rejected", "published"]
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.alerts"
                        " WHERE kind = 'restore_request_rejected'")["n"] == 1


def test_attest_refuses_a_content_difference_without_a_second_admin_and_accepts_with_two(
    world,
):
    revoke_and_export(world)
    settings = world["settings"]
    add_admins(world["live"])
    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute("UPDATE mint.orgs SET name = '다른 이름' WHERE org_id = 'acme'")
    with psycopg.connect(world["live"]) as conn:
        report = restore.check(conn, INSTANCE, settings)
        assert [(i["id"], i["problem"]) for i in report["items"]] == [("acme", "content")]
        with pytest.raises(ControlError, match="두 번째 승인"):
            restore.attest(make_ctx(conn), settings, "내용 차이 확인")
        conn.rollback()
        out = restore.attest(make_ctx(conn), settings, "내용 차이 확인",
                             Operator("second", "admin", "u2"))
        conn.commit()
    assert out["reapplied"] == []
    with psycopg.connect(world["live"], autocommit=True) as conn:
        row = fetchone(conn, "SELECT cause, second_approver FROM mint.restore_requests")
    assert row == {"cause": "content", "second_approver": "second"}


def test_a_higher_version_with_a_changed_denial_scope_is_a_mismatch(world):
    denial, _ = None, None
    with psycopg.connect(world["live"], autocommit=True) as conn:
        denial = fetchone(conn, "INSERT INTO mint.denials (id, instance_id, org_id, scope_type,"
                          " scope_id, reason, created_by) VALUES (gen_random_uuid(), %s, 'acme',"
                          " 'org', 'acme', '유출 의심', 'root') RETURNING id", (INSTANCE,))["id"]
        exports.write_export(conn, INSTANCE, world["settings"], "negative_state")
        exports.write_export(conn, INSTANCE, world["settings"], "checkpoint")
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
        conn.execute("UPDATE mint.denials SET reason = reason WHERE id = %s", (denial,))
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK  # 같은 신원
        conn.execute("SET session_replication_role = replica")  # 범위만 바꾸고 판본을 올린다
        conn.execute("UPDATE mint.denials SET scope_id = 'other', state_version = state_version"
                     " + 1 WHERE id = %s", (denial,))
    first, second = _verdicts(world["live"], world["settings"])
    assert first.state == judge.HOLD and second.blocked


def _allowlist(conn):
    return fetchone(conn, "INSERT INTO mint.allowlists (id, instance_id, kind, value, valid_from,"
                    " valid_until, created_by) VALUES (gen_random_uuid(), %s, 'provider', 'x.test',"
                    " now() - interval '1 day', now() + interval '30 days', 'root') RETURNING id",
                    (INSTANCE,))["id"]


def test_terminal_state_machines_accept_forward_moves_and_refuse_a_forged_reopening(world):
    """조직·허용 목록·이용 관계에는 해제 전이도 해제 사건도 없다: 부정 상태 안의 이동은 통과하고
    되돌려 여는 것은 사건이 없으므로 막힌다."""
    from control.test_restore_acceptance import add_relation_with_approval

    with psycopg.connect(world["live"], autocommit=True) as conn:
        conn.execute("INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256,"
                     " transport, auth_type, registered_by) VALUES (gen_random_uuid(), %s, 's1',"
                     " 'awaiting_approval', repeat('a', 64), 'http', 'none', 'x')", (INSTANCE,))
        conn.execute("UPDATE mint.servers SET status = 'approved'")
        relation, _ = add_relation_with_approval(conn, "ops")
        allowlist = _allowlist(conn)
        conn.execute("UPDATE mint.usage_relations SET status = 'terminating'")
        conn.execute("UPDATE mint.allowlists SET status = 'lifted'")
        conn.execute("UPDATE mint.orgs SET status = 'closed' WHERE org_id = 'acme'")
        exports.write_export(conn, INSTANCE, world["settings"], "negative_state")
        exports.write_export(conn, INSTANCE, world["settings"], "checkpoint")
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
        conn.execute("UPDATE mint.usage_relations SET status = 'terminated'")  # 부정 상태 안의 이동
        assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK
        conn.execute("SET session_replication_role = replica")
        for table, column, key in (("usage_relations", "id", relation),
                                   ("allowlists", "id", allowlist),
                                   ("orgs", "org_id", "acme")):
            conn.execute(f"UPDATE mint.{table} SET status = 'active', state_version ="
                         f" state_version + 5 WHERE {column}::text = %s", (str(key),))
            first, second = _verdicts(world["live"], world["settings"])
            assert first.state == judge.HOLD and second.blocked, table
            conn.execute(f"UPDATE mint.{table} SET status = %s WHERE {column}::text = %s",
                         ({"usage_relations": "terminated", "allowlists": "lifted",
                           "orgs": "closed"}[table], str(key)))
            assert _verdicts(world["live"], world["settings"], 1)[0].state == judge.OK, table


def test_an_old_request_cannot_resume_over_a_newer_unfinished_publication(world, monkeypatch):
    """A 보관 뒤 중단 -> B가 새 latest.json을 쓰고 .done 전에 중단 -> DB가 A 대기 시점으로
    되돌아가도 A는 B의 최신 파일을 덮지 못한다."""
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)  # A
    settings = world["settings"]
    real_write = exports.write_export

    def dying(*args, **kwargs):
        raise OSError("killed")

    monkeypatch.setattr(exports, "write_export", dying)
    run_worker(world)  # A: 보관만 끝났다
    monkeypatch.setattr(exports, "write_export", real_write)
    add_admins(world["restored"])
    with psycopg.connect(world["restored"]) as conn:
        restore.accept_stale(make_ctx(conn), settings, "B 복원", Operator("second", "admin", "u2"))
        conn.commit()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        a_id, b_id = [str(r["id"]) for r in fetchall(
            conn, "SELECT id FROM mint.restore_requests ORDER BY created_at")]
        conn.execute("UPDATE mint.jobs SET run_after = now() + interval '1 hour'"
                     " WHERE target_ref = %s", (a_id,))  # A는 아직 기다린다

    real_latest = exports.write_latest_file

    def latest_then_dies(*args, **kwargs):
        real_latest(*args, **kwargs)
        raise OSError("killed after latest.json")

    monkeypatch.setattr(exports, "write_latest_file", latest_then_dies)
    run_worker(world)  # B: latest.json까지 쓰고 .done 전에 중단
    monkeypatch.setattr(exports, "write_latest_file", real_latest)
    restored = settings.export_dir / INSTANCE / "restored"
    latest = files.latest_path(settings.export_dir, INSTANCE)
    assert latest.exists() and (restored / b_id / ".publishing").exists()
    assert not (restored / b_id / ".done").exists()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")  # DB가 B 이전으로 돌아간다
        conn.execute("DELETE FROM mint.jobs WHERE target_ref = %s", (b_id,))
        conn.execute("DELETE FROM mint.restore_requests WHERE id::text = %s", (b_id,))
        conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'"
                     " WHERE target_ref = %s", (a_id,))
    run_worker(world)
    assert not (restored / a_id / ".done").exists()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "rejected"
        assert fetchone(conn, "SELECT count(*) AS n FROM mint.alerts"
                        " WHERE kind = 'restore_request_rejected'")["n"] == 1


def test_a_request_resumes_when_latest_is_absent_or_equal_to_its_binding(world, monkeypatch):
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    monkeypatch.setattr(exports, "write_export", lambda *a, **k: (_ for _ in ()).throw(
        OSError("killed")))
    run_worker(world)  # 보관만 끝났다: 원래 위치에 파일이 없다
    monkeypatch.undo()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'")
    assert run_worker(world).state == judge.OK


def test_a_request_that_died_right_after_writing_its_own_latest_finishes_on_rerun(
    world, monkeypatch
):
    """자기 latest.json을 쓴 직후 죽음 -> 재실행: 결속값과 달라도 표지의 해시와 같으면 자기 파일로
    보고 파일을 다시 쓰지 않고 검증·확정만 마친다."""
    from mint_litellm.control import restore_publish

    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    settings = world["settings"]
    real_latest = exports.write_latest_file

    def latest_then_dies(*args, **kwargs):
        real_latest(*args, **kwargs)
        raise OSError("killed right after latest.json")

    monkeypatch.setattr(exports, "write_latest_file", latest_then_dies)
    run_worker(world)
    monkeypatch.setattr(exports, "write_latest_file", real_latest)
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        request = fetchone(conn, "SELECT id, status, bound_latest FROM mint.restore_requests")
        assert request["status"] == "pending"
        conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'"
                     " WHERE kind = 'restore_publish'")
    dest = settings.export_dir / INSTANCE / "restored" / str(request["id"])
    latest = files.latest_path(settings.export_dir, INSTANCE)
    own = (dest / ".publishing").read_text(encoding="utf-8").splitlines()[1]
    assert files.file_sha256(latest) == own != request["bound_latest"]
    assert not (dest / ".done").exists()

    class NoWrites:
        def __getattr__(self, name):
            return getattr(exports, name)

        @staticmethod
        def write_export(*args, **kwargs):
            raise AssertionError("이미 게시한 요청은 파일을 다시 쓰지 않는다")

        write_latest_file = write_export

    monkeypatch.setattr(restore_publish, "exports", NoWrites())
    run_worker(world)
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "published"
    assert (dest / ".done").exists()


@pytest.mark.parametrize("broken", ["", "2026-11-0", "2026-11-08T01:02:03+00:00\nabc"])
def test_a_request_with_an_empty_or_truncated_own_marker_publishes_again_from_scratch(
    world, monkeypatch, broken
):
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    settings = world["settings"]

    def dying(*args, **kwargs):
        raise OSError("killed")

    monkeypatch.setattr(exports, "write_export", dying)
    run_worker(world)  # 보관과 표지까지 끝났다
    monkeypatch.undo()
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        rid = str(fetchone(conn, "SELECT id FROM mint.restore_requests")["id"])
        conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second'")
    marker = settings.export_dir / INSTANCE / "restored" / rid / ".publishing"
    assert marker.exists()
    marker.write_text(broken, encoding="utf-8")  # 비우다 중단된 표지
    assert run_worker(world).state == judge.OK
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "published"
    assert (marker.parent / ".done").exists()


@pytest.mark.parametrize("name", [".publishing", ".done"])
@pytest.mark.parametrize("broken", ["", "2026-11-0"])
def test_a_malformed_marker_of_another_request_rejects_with_an_alert(world, name, broken):
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    settings = world["settings"]
    other = settings.export_dir / INSTANCE / "restored" / "other-request"
    other.mkdir(parents=True)
    (other / name).write_text(broken, encoding="utf-8")
    run_worker(world)
    with psycopg.connect(world["restored"], autocommit=True) as conn:
        assert fetchone(conn, "SELECT status FROM mint.restore_requests")["status"] == "rejected"
        alert = fetchone(conn, "SELECT subject FROM mint.alerts"
                         " WHERE kind = 'restore_request_rejected'")
        assert alert["subject"]["reason"] == "foreign_marker_malformed"


def test_markers_are_written_through_a_temporary_file_and_a_rename(world, monkeypatch):
    from mint_litellm.control import restore_publish

    seen = []
    real = files.atomic_write_bytes
    monkeypatch.setattr(files, "atomic_write_bytes",
                        lambda path, data: (seen.append(path.name), real(path, data))[1])
    file_epoch = revoke_and_export(world)
    overtake_epoch(world["restored"], file_epoch)
    attest_restored(world)
    assert run_worker(world).state == judge.OK
    assert {".archived", ".moved", ".publishing", ".done"} <= set(seen)
    assert restore_publish._read_marker(
        next(world["settings"].export_dir.glob("*/restored/*/.done"))) is not None
