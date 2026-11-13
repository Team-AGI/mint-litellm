"""작업 실행기: 임대·연장·회수, 수렴 작업 규칙, 우선순위, 재시도, 일정, 되돌림 보호,
종료 신호. 실 Postgres와 ``mint_worker_app`` 로그인으로 돌린다(MINT_TEST_DATABASE_URL이 없으면
건너뜀). 시간 의존은 짧은 임대 값과 이벤트로 줄이고, 재시도·일정의 시각은 행의 시각 열을 직접
당겨 지나간 것으로 만든다.
"""

import re
import signal
import subprocess
import sys
import tempfile
import threading
from datetime import timedelta

import pytest
from ctl_fixtures import INSTANCE, LOGIN_PASSWORDS, make_ctx

psycopg = pytest.importorskip("psycopg")

from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402

from mint_litellm import cli  # noqa: E402
from mint_litellm.control import jobs, orgs, relations, servers  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.db.roles import LOGIN_ROLES  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.services import base  # noqa: E402
from mint_litellm.control.settings_store import ensure  # noqa: E402
from mint_litellm.control.stage2_config import Stage2Settings  # noqa: E402
from mint_litellm.control.worker import Worker, install_signals  # noqa: E402

HEX = "ab" * 32
KEY = "A" * 43  # base64url, 디코딩하면 32바이트
# 작업 실행기가 내보내기 파일을 실제로 쓰므로 시험마다 비어 있는 임시 디렉터리를 쓴다.
ENV = {"MINT_EXPORT_DIR": tempfile.mkdtemp(prefix="mint-export-"), "MINT_EXPORT_HMAC_KEY": KEY}
SETTINGS = Stage2Settings.from_env(ENV)


@pytest.fixture
def url(fresh_db, login_roles):
    return fresh_db


def login_url(url: str, key: str = "mint_worker") -> str:
    params = conninfo_to_dict(url)
    params.update(user=LOGIN_ROLES[key], password=LOGIN_PASSWORDS[key])
    return make_conninfo(**params)


@pytest.fixture
def admin(url):
    """시험이 상태를 보고 바꾸는 슈퍼유저 연결(자동 커밋)."""
    with psycopg.connect(url, autocommit=True) as conn:
        yield conn


@pytest.fixture
def make_worker(url, admin):
    made: list[Worker] = []

    def make(schedules=False, **kwargs) -> Worker:
        worker = Worker(login_url(url), INSTANCE, kwargs.pop("settings", SETTINGS), **kwargs)
        worker.open()
        if not schedules:  # 일정이 만드는 작업이 시험의 작업과 섞이지 않게 한다
            admin.execute("DELETE FROM mint.schedules")
        elif schedules != "all":  # 일정 시험은 만료 점검 하나만 본다
            admin.execute("DELETE FROM mint.schedules WHERE kind <> 'approval_expiry_scan'")
        made.append(worker)
        return worker

    yield make
    for worker in made:
        worker.close()


@pytest.fixture
def all_handlers(monkeypatch):
    """모든 종류에 빈 처리기를 둔다(우선순위·직렬화·재시도처럼 종류별 동작과 무관한 시험용)."""
    ran: list[tuple[str, str]] = []
    for kind in jobs.KINDS:
        monkeypatch.setitem(
            jobs.HANDLERS, kind, lambda job, kind=kind: ran.append((kind, job.job["target_ref"]))
        )
    return ran


def put(conn, kind, target, key=None, lease=None, **columns) -> str:
    """작업 행을 넣는다. ``lease=(소유자, 만료 시각 SQL 식)``이면 실행 중으로 바꾼다."""
    names = ["id", "instance_id", "kind", "target_ref", "idempotency_key", *columns]
    marks = ["gen_random_uuid()"] + ["%s"] * (len(names) - 1)
    row = fetchone(
        conn,
        f"INSERT INTO mint.jobs ({', '.join(names)}) VALUES ({', '.join(marks)}) RETURNING id",
        (INSTANCE, kind, target, key, *columns.values()),
    )
    if lease is not None:
        conn.execute(
            f"UPDATE mint.jobs SET status = 'running', lease_owner = %s, lease_until = {lease[1]}"
            " WHERE id = %s", (lease[0], row["id"]))
    return str(row["id"])


def job(conn, job_id):
    return fetchone(conn, "SELECT * FROM mint.jobs WHERE id = %s", (job_id,))


def alerts(conn):
    return fetchall(conn, "SELECT * FROM mint.alerts ORDER BY first_at")


def past(conn, job_id):
    """재시도 대기 시각을 지나간 것으로 만든다."""
    conn.execute("UPDATE mint.jobs SET run_after = now() - interval '1 second' WHERE id = %s",
                 (job_id,))


# --- 기동 -------------------------------------------------------------------


def test_the_worker_refuses_to_start_without_required_settings(url, capsys):
    environ = {"MINT_DATABASE_URL": login_url(url), "MINT_INSTANCE_ID": INSTANCE}
    assert cli.main(["worker"], environ) == 1
    assert "MINT_EXPORT_DIR" in capsys.readouterr().err
    environ["MINT_EXPORT_DIR"] = "/tmp/x"
    assert cli.main(["worker"], environ) == 1
    assert "MINT_EXPORT_HMAC_KEY" in capsys.readouterr().err
    assert cli.main(["worker"], {**ENV, "MINT_INSTANCE_ID": INSTANCE}) == 1  # 접속 주소 없음
    assert "MINT_DATABASE_URL" in capsys.readouterr().err


def test_the_worker_needs_the_worker_login(url):
    worker = Worker(login_url(url, "mint_plugin"), INSTANCE, SETTINGS)
    with pytest.raises(ControlError, match="mint_worker_app"):
        worker.open()
    worker.close()


def test_the_worker_login_creates_the_schedules_it_has_handlers_for(make_worker, admin):
    make_worker(schedules="all")
    rows = fetchall(admin, "SELECT kind, interval_seconds FROM mint.schedules")
    expected = {k: f(SETTINGS) for k, f in jobs.SCHEDULES.items() if k in jobs.HANDLERS}
    assert {r["kind"]: r["interval_seconds"] for r in rows} == expected
    assert {"approval_expiry_scan", "seal"} <= set(expected)


# --- 수렴 작업 등록 규칙 ----------------------------------------------------------


def test_job_kinds_follow_the_registration_rules(url, all_handlers):
    assert len(jobs.KINDS) == 22  # 20종 + 해제 경로의 restore_publish
    assert {k for k, v in jobs.KINDS.items() if v.convergent} == {
        "contract_observe", "sync_server", "sync_target", "activation_finalize",
        "relation_finalize", "server_finalize"}
    with psycopg.connect(url) as conn:
        ensure(conn, INSTANCE)
        ctx = make_ctx(conn)
        with pytest.raises(ValueError, match="알 수 없는"):
            base.enqueue_job(ctx, "nothing", "x", "k")
        with pytest.raises(ValueError, match="쓰지 않습니다"):
            base.enqueue_job(ctx, "sync_server", "x", "key")  # 수렴 작업은 멱등 키가 없다
        with pytest.raises(ValueError, match="써야 합니다"):
            base.enqueue_job(ctx, "seal", "x")  # 예약·키 작업은 키가 있다


def test_a_known_kind_without_a_handler_is_registered_but_never_leased(
    make_worker, admin, url, monkeypatch
):
    """처리기가 없는 알려진 종류도 등록은 받고, 실행기는 처리기가 붙기 전까지 임대하지 않는다."""
    monkeypatch.delitem(jobs.HANDLERS, "sync_server", raising=False)
    with psycopg.connect(url) as conn:
        ensure(conn, INSTANCE)
        ctx = make_ctx(conn)
        job_id = base.enqueue_job(ctx, "sync_server", "x")
        assert base.enqueue_job(ctx, "sync_server", "x") == job_id  # 수렴
        conn.commit()
    worker = make_worker()
    assert worker.step() is False
    assert job(admin, job_id)["status"] == "pending"
    monkeypatch.setitem(jobs.HANDLERS, "sync_server", lambda ctx: None)  # 처리기가 붙으면 실행된다
    assert worker.step() is True
    assert job(admin, job_id)["status"] == "done"


def test_an_unknown_kind_is_still_refused(url):
    with psycopg.connect(url) as conn:
        ensure(conn, INSTANCE)
        with pytest.raises(ValueError, match="알 수 없는"):
            base.enqueue_job(make_ctx(conn), "nothing", "x", "k")


def test_a_pending_job_is_not_leased_while_the_same_target_runs(
    make_worker, admin, all_handlers
):
    first, second = make_worker(), make_worker()
    running = put(admin, "sync_server", "srv-a")
    got = jobs.lease(first.conn, INSTANCE, "w1", 60, ["sync_server"])
    assert str(got["id"]) == running
    waiting = put(admin, "sync_server", "srv-a")  # 실행 중 행만 있으므로 새 대기 행
    other = put(admin, "sync_server", "srv-b")
    got2 = jobs.lease(second.conn, INSTANCE, "w2", 60, ["sync_server"])
    assert str(got2["id"]) == other  # 같은 대상의 대기 행은 건너뛰고 다른 대상을 잡는다
    assert jobs.lease(second.conn, INSTANCE, "w2", 60, ["sync_server"]) is None
    assert jobs.complete(first.conn, running, "w1")
    got3 = jobs.lease(second.conn, INSTANCE, "w2", 60, ["sync_server"])
    assert str(got3["id"]) == waiting  # 실행이 끝나자마자 뒤따르는 작업이 잡힌다


def test_two_workers_never_run_the_same_job_twice(make_worker, admin, all_handlers):
    ids = {put(admin, "seal", f"t{i}", f"seal:{i}") for i in range(30)}
    workers = [make_worker(), make_worker()]
    start = threading.Barrier(2)
    errors = []

    def drain(worker):
        try:
            start.wait()
            while worker.step():
                pass
        except Exception as error:  # pragma: no cover
            errors.append(error)

    threads = [threading.Thread(target=drain, args=(w,)) for w in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert not errors
    assert sorted(t for _, t in all_handlers) == sorted(f"t{i}" for i in range(30))  # 중복 없이
    assert {str(r["id"]) for r in fetchall(admin, "SELECT id FROM mint.jobs WHERE status='done'")
            } == ids


def test_a_locked_job_is_skipped_not_waited_for(make_worker, admin, url, all_handlers):
    held = put(admin, "seal", "locked", "seal:a", run_after="2000-01-01T00:00:00Z")
    free = put(admin, "seal", "free", "seal:b")
    worker = make_worker()
    with psycopg.connect(url) as other:  # 다른 실행기가 이 행을 잡고 있는 중
        other.execute("SELECT 1 FROM mint.jobs WHERE id = %s FOR UPDATE", (held,))
        got = jobs.lease(worker.conn, INSTANCE, "w", 60, ["seal"])
        assert str(got["id"]) == free
        other.rollback()


# --- 우선순위 ------------------------------------------------------------------


def test_priority_is_export_then_sync_then_the_rest_and_ties_go_by_run_after(
    make_worker, admin, all_handlers
):
    put(admin, "seal", "late", "seal:1", run_after="2020-01-02T00:00:00Z")
    put(admin, "seal", "early", "seal:2", run_after="2020-01-01T00:00:00Z")
    put(admin, "sync_reconcile", "rec", "sync_reconcile:1", run_after="2020-01-03T00:00:00Z")
    put(admin, "sync_server", "srv", run_after="2020-01-04T00:00:00Z")
    put(admin, "export_negative_state", "epoch", "export_negative:9",
        run_after="2020-01-05T00:00:00Z")
    worker = make_worker()
    while worker.step():
        pass
    assert [t for _, t in all_handlers] == ["epoch", "rec", "srv", "early", "late"]


# --- 재시도·실패·경보 --------------------------------------------------------------


def test_a_failing_job_backs_off_and_fails_after_the_maximum_with_one_grouped_alert(
    make_worker, admin, monkeypatch
):
    class Boom(Exception):
        code = "UPSTREAM_DOWN"

    def explode(ctx):
        raise Boom("비밀이 들어 있을 수 있는 메시지")

    monkeypatch.setitem(jobs.HANDLERS, "seal", explode)
    worker = make_worker()
    first = put(admin, "seal", "t", "seal:1")
    delays = []
    for attempt in range(1, 8):
        assert worker.step()
        row = job(admin, first)
        assert (row["status"], row["attempts"], row["last_error_code"]) == (
            "pending", attempt, "UPSTREAM_DOWN")
        wait = fetchone(admin, "SELECT extract(epoch FROM run_after - now()) AS s FROM mint.jobs"
                        " WHERE id = %s", (first,))["s"]
        delays.append(round(float(wait) / 5) * 5)
        assert float(wait) <= jobs.backoff_seconds(attempt)
        assert not worker.step()  # 아직 대기 시간 안이라 잡히지 않는다
        past(admin, first)
    assert delays == [10, 20, 40, 80, 160, 320, 600]  # 2^attempts x 5초, 상한 10분
    assert not alerts(admin)
    assert worker.step()  # 여덟 번째 실패
    row = job(admin, first)
    assert (row["status"], row["attempts"], row["lease_owner"]) == ("failed", 8, None)
    [alert] = alerts(admin)
    assert (alert["kind"], alert["severity"], alert["status"], alert["count"]) == (
        "job_failed", "high", "open", 1)
    assert alert["dedup_key"] == "job_failed:seal:t"
    assert alert["subject"]["last_error_code"] == "UPSTREAM_DOWN"
    assert "비밀" not in str(row) + str(alert)  # 오류 메시지는 저장하지 않는다
    # 같은 종류·대상이 또 한도에 닿으면 새 경보가 아니라 같은 경보의 횟수만 오른다
    second = put(admin, "seal", "t", "seal:2", max_attempts=1)
    assert worker.step()
    assert job(admin, second)["status"] == "failed"
    [alert] = alerts(admin)
    assert alert["count"] == 2
    put(admin, "seal", "other", "seal:3", max_attempts=1)
    assert worker.step()
    assert len(alerts(admin)) == 2  # 다른 대상은 다른 경보


def _periodic_key(kind):
    return None if jobs.KINDS[kind].convergent else f"{kind}:old"


def test_periodic_retry_waits_are_capped_by_a_quarter_of_the_observe_period():
    short = Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "60"})
    tiny = Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "20"})
    for kind in jobs.PERIODIC_RETRY_KINDS:
        assert [jobs.backoff_seconds(n, kind, short) for n in (1, 2, 3, 8)] == [10, 15, 15, 15]
        assert jobs.backoff_seconds(8, kind, tiny) == 5  # 최소 5초
        assert jobs.backoff_seconds(8, kind, SETTINGS) == 600  # 기본 주기에서는 10분 상한이 먼저
    assert jobs.backoff_seconds(8, "seal", short) == 600  # 주기 작업이 아니면 그대로
    assert jobs.backoff_seconds(8, "contract_observe") == 600


@pytest.mark.parametrize("kind", sorted(jobs.PERIODIC_RETRY_KINDS))
def test_startup_pulls_far_pending_periodic_jobs_inside_the_cap(make_worker, admin, kind):
    """이전 판본이 먼 시각으로 잡아 둔 대기 행은 기동 때 새 상한 안으로 당겨진다."""
    worker = make_worker(settings=Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "60"}))
    far = put(admin, kind, kind, _periodic_key(kind))
    admin.execute("UPDATE mint.jobs SET run_after = now() + interval '600 seconds' WHERE id = %s",
                  (far,))
    near = put(admin, kind, "near", _periodic_key(kind) and f"{kind}:near")
    admin.execute("UPDATE mint.jobs SET run_after = now() + interval '3 seconds' WHERE id = %s",
                  (near,))
    jobs.ensure_schedules(worker.conn, INSTANCE, worker.settings)
    waits = {
        str(r["id"]): float(r["s"])
        for r in fetchall(admin, "SELECT id, extract(epoch FROM run_after - now()) AS s"
                          " FROM mint.jobs")
    }
    assert 0 < waits[far] <= 15
    assert waits[near] <= 3  # 가까운 행은 그대로


def test_a_retry_folding_into_a_far_pending_job_stays_inside_the_cap(
    make_worker, admin, monkeypatch
):
    monkeypatch.setitem(jobs.HANDLERS, "contract_observe", lambda ctx: 1 / 0)
    settings = Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "60"})
    worker = make_worker(settings=settings)
    running = put(admin, "contract_observe", "contract_observe")
    got = jobs.lease(worker.conn, INSTANCE, worker.owner, 60, ["contract_observe"])
    assert str(got["id"]) == running
    waiting = put(admin, "contract_observe", "contract_observe")
    admin.execute("UPDATE mint.jobs SET run_after = now() + interval '600 seconds' WHERE id = %s",
                  (waiting,))
    assert jobs.fail(worker.conn, running, worker.owner, "X", settings) == "done"
    wait = fetchone(admin, "SELECT extract(epoch FROM run_after - now()) AS s FROM mint.jobs"
                    " WHERE id = %s", (waiting,))["s"]
    assert 0 < float(wait) <= 15


@pytest.mark.parametrize("kind", sorted(jobs.PERIODIC_RETRY_KINDS))
def test_a_failing_periodic_job_is_retried_within_the_cap(make_worker, admin, monkeypatch, kind):
    monkeypatch.setitem(jobs.HANDLERS, kind, lambda ctx: 1 / 0)
    worker = make_worker(settings=Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "60"}))
    job_id = put(admin, kind, kind, _periodic_key(kind), attempts=6)
    assert worker.step()
    row = job(admin, job_id)
    assert (row["status"], row["attempts"]) == ("pending", 7)
    wait = fetchone(admin, "SELECT extract(epoch FROM run_after - now()) AS s FROM mint.jobs"
                    " WHERE id = %s", (job_id,))["s"]
    assert 0 < float(wait) <= 15  # 지수 후퇴라면 640초


@pytest.mark.parametrize("kind", sorted(jobs.PERIODIC_RETRY_KINDS))
def test_a_periodic_job_that_ended_failed_is_registered_again_in_the_next_period(
    make_worker, admin, monkeypatch, kind
):
    monkeypatch.setitem(jobs.HANDLERS, kind, lambda ctx: 1 / 0)
    worker = make_worker(schedules="all")
    admin.execute("DELETE FROM mint.schedules WHERE kind <> %s", (kind,))
    admin.execute("UPDATE mint.schedules SET next_run_at = now() + interval '1 hour'")
    failed = put(admin, kind, kind, _periodic_key(kind), max_attempts=1)
    assert worker.step()
    assert job(admin, failed)["status"] == "failed"
    admin.execute("UPDATE mint.schedules SET next_run_at = now() - interval '1 second'")
    assert jobs.register_due_schedules(worker.conn, INSTANCE) == 1
    rows = fetchall(admin, "SELECT status FROM mint.jobs WHERE kind = %s ORDER BY status", (kind,))
    assert [r["status"] for r in rows] == ["failed", "pending"]


def test_an_exception_without_a_code_is_recorded_by_its_class_name(make_worker, admin, monkeypatch):
    monkeypatch.setitem(jobs.HANDLERS, "seal", lambda ctx: 1 / 0)
    make_worker()
    job_id = put(admin, "seal", "t", "seal:1")
    worker = make_worker()
    worker.step()
    assert job(admin, job_id)["last_error_code"] == "ZeroDivisionError"


def test_a_retry_folds_into_the_pending_job_of_the_same_target(make_worker, admin, monkeypatch):
    monkeypatch.setitem(jobs.HANDLERS, "sync_server", lambda ctx: 1 / 0)
    worker = make_worker()
    running = put(admin, "sync_server", "srv")
    got = jobs.lease(worker.conn, INSTANCE, worker.owner, 60, ["sync_server"])
    assert str(got["id"]) == running
    waiting = put(admin, "sync_server", "srv")  # 실행 중 행이 있는 동안 생긴 대기 행
    assert jobs.fail(worker.conn, running, worker.owner, "X") == "done"  # 대기 행에 합쳐진다
    assert job(admin, running)["last_error_code"] == "superseded"
    row = job(admin, waiting)
    assert (row["status"], row["attempts"], row["last_error_code"]) == ("pending", 1, "X")
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.jobs WHERE status = 'pending'")["n"] == 1


# --- 임대 만료 회수 ------------------------------------------------------------------


def test_an_expired_running_job_is_reclaimed_and_a_live_one_is_not(make_worker, admin):
    dead = put(admin, "seal", "dead", "seal:1", lease=("gone", "now() - interval '1 day'"))
    put(admin, "seal", "alive", "seal:2", lease=("here", "now() + interval '1 hour'"))
    worker = make_worker()
    assert jobs.reclaim_expired(worker.conn, INSTANCE) == 1
    row = job(admin, dead)
    assert (row["status"], row["attempts"], row["lease_owner"], row["last_error_code"]) == (
        "pending", 1, None, "lease_expired")
    assert fetchone(admin, "SELECT status FROM mint.jobs WHERE target_ref = 'alive'"
                    )["status"] == "running"
    assert jobs.reclaim_expired(worker.conn, INSTANCE) == 0


def test_reclaiming_counts_as_an_attempt_and_the_last_one_fails_with_an_alert(
    make_worker, admin
):
    job_id = put(admin, "seal", "t", "seal:1", attempts=7,
                 lease=("gone", "now() - interval '1 day'"))
    worker = make_worker()
    assert jobs.reclaim_expired(worker.conn, INSTANCE) == 1
    assert job(admin, job_id)["status"] == "failed"
    assert [a["kind"] for a in alerts(admin)] == ["job_failed"]


# --- 연장과 취소 ------------------------------------------------------------------


def test_the_lease_is_extended_while_running_and_a_lost_lease_cancels_the_job(
    make_worker, admin, monkeypatch
):
    seen = {}
    started, stolen, finished = threading.Event(), threading.Event(), threading.Event()

    def long_job(ctx):
        seen["until"] = job(admin, ctx.job["id"])["lease_until"]
        started.set()
        # 연장이 일어날 때까지 기다린다(임대 0.9초, 0.3초마다 연장)
        while job(admin, ctx.job["id"])["lease_until"] <= seen["until"]:
            ctx.cancel.wait(0.05)
        seen["extended"] = True
        stolen.wait(10)
        assert ctx.cancel.wait(10)  # 임대를 잃으면 취소 신호가 온다
        seen["lost"] = ctx.lost.is_set()
        finished.set()
        ctx.checkpoint()  # 외부 호출 앞의 확인점: Cancelled로 끝난다
        seen["reached_external_call"] = True

    monkeypatch.setitem(jobs.HANDLERS, "seal", long_job)
    worker = make_worker(lease_seconds=0.9)
    job_id = put(admin, "seal", "t", "seal:1")
    thread = threading.Thread(target=worker.step)
    thread.start()
    assert started.wait(10)
    while "extended" not in seen:
        threading.Event().wait(0.02)
    admin.execute("UPDATE mint.jobs SET lease_owner = 'other-worker' WHERE id = %s", (job_id,))
    stolen.set()
    thread.join(15)
    assert finished.is_set() and seen["lost"] is True
    assert "reached_external_call" not in seen
    row = job(admin, job_id)  # 임대를 잃은 실행기는 결과를 기록하지 않는다
    assert (row["status"], row["lease_owner"], row["attempts"]) == ("running", "other-worker", 0)


def test_extending_an_expired_lease_fails(make_worker, admin):
    job_id = put(admin, "seal", "t", "seal:1", lease=("w", "now() - interval '1 day'"))
    worker = make_worker()
    assert not jobs.extend(worker.conn, job_id, "w", 60)
    assert not jobs.extend(worker.conn, job_id, "someone-else", 60)


# --- 일정 -----------------------------------------------------------------------


def test_a_schedule_registers_one_job_per_period_even_with_two_workers(make_worker, admin):
    first, second = make_worker(schedules=True), make_worker(schedules=True)
    admin.execute("DELETE FROM mint.schedules WHERE kind <> 'approval_expiry_scan'")
    admin.execute("UPDATE mint.schedules SET next_run_at = date_trunc('second', now())"
                  " - interval '1 second'")
    start = threading.Barrier(2)
    counts = []

    def register(worker):
        start.wait()
        counts.append(jobs.register_due_schedules(worker.conn, INSTANCE))

    threads = [threading.Thread(target=register, args=(w,)) for w in (first, second)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(15)
    assert sorted(counts) == [0, 1]
    [row] = fetchall(admin, "SELECT * FROM mint.jobs")
    assert row["kind"] == "approval_expiry_scan" and row["status"] == "pending"
    assert re.fullmatch(r"approval_expiry_scan:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                        row["idempotency_key"])
    assert jobs.register_due_schedules(first.conn, INSTANCE) == 0  # 같은 주기에는 더 없다
    nxt = fetchone(admin, "SELECT next_run_at > now() AS future FROM mint.schedules")
    assert nxt["future"] is True


def test_missed_periods_are_skipped_to_the_current_one_on_the_original_grid(make_worker, admin):
    worker = make_worker(schedules=True)
    admin.execute("DELETE FROM mint.schedules WHERE kind <> 'approval_expiry_scan'")
    admin.execute("UPDATE mint.schedules SET next_run_at = now() - interval '605 seconds'")
    before = fetchone(admin, "SELECT next_run_at FROM mint.schedules")["next_run_at"]
    assert jobs.register_due_schedules(worker.conn, INSTANCE) == 1  # 열 번 밀렸어도 한 건
    after = fetchone(admin, "SELECT next_run_at FROM mint.schedules")["next_run_at"]
    assert (after - before) % timedelta(seconds=60) == timedelta(0)  # 주기 격자 위
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.jobs")["n"] == 1


def test_the_period_key_is_utc_seconds_iso_8601():
    from datetime import UTC, datetime, timezone

    kst = timezone(timedelta(hours=9))
    assert jobs.period_key("seal", datetime(2030, 1, 2, 3, 4, 5, 678, tzinfo=kst)) == (
        "seal:2030-01-01T18:04:05Z")
    assert jobs.period_key("seal", datetime(2030, 1, 1, 18, 4, tzinfo=UTC)) == (
        "seal:2030-01-01T18:04:00Z")


def test_a_disabled_schedule_registers_nothing(make_worker, admin):
    worker = make_worker(schedules=True)
    admin.execute("UPDATE mint.schedules SET enabled = false, next_run_at = now() - interval '1 h'")
    assert jobs.register_due_schedules(worker.conn, INSTANCE) == 0


# --- 만료 작업 -----------------------------------------------------------------------


def test_the_worker_runs_the_approval_expiry_scan_from_its_schedule(
    url, make_worker, admin, litellm
):
    with psycopg.connect(url) as conn:
        ensure(conn, INSTANCE)
        ctx = make_ctx(conn)
        orgs.add(ctx, "acme", "ACME")
        servers.register(ctx, litellm, "ctl-everything", "http://upstream.test/mcp")
        relations.add(ctx, "acme", "ctl-everything", "ops", None)
        conn.execute("INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256,"
                     " bundle_sha256) VALUES (%s, 'v1', %s, %s)", (INSTANCE, HEX, HEX))
        for tag, delta in (("past", "-1 minute"), ("future", "+1 hour")):
            conn.execute(
                "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type,"
                " principal_id, server_id, tool, args_fp, fp_key_version, policy_version_id,"
                " status, requested_by, expires_at) VALUES (gen_random_uuid(), %s, 'acme',"
                " 'user', %s, 'ctl-everything', 't', %s, 1, 'v1', 'pending', 'r',"
                " now() + %s::interval)", (INSTANCE, tag, HEX, delta))
        conn.commit()
    worker = make_worker(schedules=True)
    admin.execute("DELETE FROM mint.schedules WHERE kind <> 'approval_expiry_scan'")
    assert worker.step()  # 일정 등록 -> 임대 -> 처리
    states = {r["principal_id"]: r["status"]
              for r in fetchall(admin, "SELECT principal_id, status FROM mint.call_approvals")}
    assert states == {"past": "expired", "future": "pending"}
    [done] = fetchall(admin, "SELECT status, attempts FROM mint.jobs")
    assert (done["status"], done["attempts"]) == ("done", 0)
    assert not worker.step()  # 같은 주기에는 다시 돌지 않는다


# --- 되돌림 보호 -------------------------------------------------------------------


def test_a_restored_database_blocks_external_writes_but_not_the_rest(
    make_worker, admin, all_handlers
):
    calls = []

    def restored(conn, instance_id):
        calls.append(instance_id)
        return True

    worker = make_worker(restore_check=restored)
    blocked = put(admin, "sync_server", "srv")
    export = put(admin, "export_checkpoint", "c", "export_checkpoint:1")
    free = put(admin, "intake_run", "s", "intake_run:1")
    ran = 0
    while worker.step() and ran < 20:
        ran += 1
    assert [k for k, _ in all_handlers] == ["intake_run"]  # 외부 쓰기 작업은 실행되지 않았다
    for job_id in (blocked, export):
        row = job(admin, job_id)
        assert (row["status"], row["attempts"], row["last_error_code"]) == (
            "pending", 0, "restore_blocked")
        assert row["run_after"] > fetchone(admin, "SELECT now() AS n")["n"]
    assert job(admin, free)["status"] == "done"
    assert len(calls) >= 3  # 작업 전마다 판정한다
    # 작업은 실패가 아니라 대기이므로 job_failed 경보는 없고, 차단 자체의 경보 하나만 열린다
    assert [a["kind"] for a in alerts(admin)] == ["enforcement_unverified"]


def test_the_default_check_never_blocks(make_worker, admin, all_handlers):
    worker = make_worker()
    put(admin, "sync_server", "srv")
    assert worker.step()
    assert all_handlers == [("sync_server", "srv")]


# --- 종료 신호 --------------------------------------------------------------------


def test_a_stop_signal_releases_the_running_job_and_ends_the_loop(
    make_worker, admin, monkeypatch
):
    started = threading.Event()

    def waits(ctx):
        started.set()
        assert ctx.cancel.wait(10)
        ctx.checkpoint()

    monkeypatch.setitem(jobs.HANDLERS, "seal", waits)
    worker = make_worker()
    job_id = put(admin, "seal", "t", "seal:1")
    thread = threading.Thread(target=worker.run_forever, kwargs={"poll_seconds": 0.05})
    thread.start()
    assert started.wait(10)
    worker.request_stop()
    thread.join(15)
    assert not thread.is_alive()
    row = job(admin, job_id)
    assert (row["status"], row["attempts"], row["lease_owner"], row["last_error_code"]) == (
        "pending", 0, None, "shutdown")


def test_a_job_that_finishes_on_its_own_after_the_signal_is_done(make_worker, admin, monkeypatch):
    started, go = threading.Event(), threading.Event()

    def finishes(ctx):
        started.set()
        go.wait(10)  # 취소 신호를 무시하고 끝까지 한다

    monkeypatch.setitem(jobs.HANDLERS, "seal", finishes)
    worker = make_worker()
    job_id = put(admin, "seal", "t", "seal:1")
    thread = threading.Thread(target=worker.run_forever, kwargs={"poll_seconds": 0.05})
    thread.start()
    assert started.wait(10)
    worker.request_stop()
    go.set()
    thread.join(15)
    assert job(admin, job_id)["status"] == "done"


def test_an_idle_worker_stops_at_once(make_worker):
    worker = make_worker()
    thread = threading.Thread(target=worker.run_forever, kwargs={"poll_seconds": 30})
    thread.start()
    worker.request_stop()
    thread.join(10)
    assert not thread.is_alive()


def test_signal_handlers_stop_the_worker_and_are_restored(make_worker):
    worker = make_worker()
    names = [n for n in ("SIGTERM", "SIGINT", "SIGBREAK") if hasattr(signal, n)]
    before = {n: signal.getsignal(getattr(signal, n)) for n in names}
    restore = install_signals(worker)
    try:
        signal.raise_signal(signal.SIGTERM)
        assert worker.stop.is_set()
        worker.stop.clear()
        signal.raise_signal(signal.SIGINT)
        assert worker.stop.is_set()
    finally:
        restore()
    assert {n: signal.getsignal(getattr(signal, n)) for n in names} == before


def test_the_worker_process_exits_cleanly_on_a_termination_signal(url, tmp_path):
    env = {
        "PATH": __import__("os").environ.get("PATH", ""),
        "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", ""),
        "PYTHONIOENCODING": "utf-8",
        "MINT_DATABASE_URL": login_url(url),
        "MINT_INSTANCE_ID": INSTANCE,
        **ENV,
    }
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    proc = subprocess.Popen(
        [sys.executable, "-m", "mint_litellm.cli", "worker"],
        env=env, stderr=subprocess.PIPE, text=True, encoding="utf-8", creationflags=flags,
    )
    watchdog = threading.Timer(60, proc.kill)  # 자기가 띄운 프로세스만 정리한다
    watchdog.start()
    try:
        assert "작업 실행기 시작" in proc.stderr.readline()
        proc.send_signal(signal.CTRL_BREAK_EVENT if sys.platform == "win32" else signal.SIGTERM)
        assert proc.wait(30) == 0
        assert "작업 실행기 종료" in proc.stderr.read()
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
        proc.stderr.close()


# --- 되돌림 판정과 외부 쓰기 경계-------------------------------------------


def _restore_settings(tmp_path):
    from mint_litellm.control.stage2_config import Stage2Settings as S

    return S.from_env({"MINT_EXPORT_DIR": str(tmp_path / "ex"), "MINT_EXPORT_HMAC_KEY": KEY})


def _forge_negative_ahead(settings):
    """부정 상태 파일을 DB보다 앞선 값으로 바꿔 DB를 되돌린 것처럼 만든다(서명은 올바르다)."""
    from mint_litellm.control import exports
    from mint_litellm.restore import files

    path = files.newest_negative(settings.export_dir, INSTANCE)
    doc = files.read_verified(path, exports.keys(settings))
    doc["items"][0]["state_version"] = 99
    files.atomic_write(path, files.sign(doc, settings.export_hmac_key))


def _closed_org_and_export(url, worker, settings):
    from mint_litellm.control import exports

    with psycopg.connect(url) as conn:
        ensure(conn, INSTANCE)
        conn.execute("INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, 'a', 'a')",
                     (INSTANCE,))
        conn.execute("UPDATE mint.orgs SET status = 'closed' WHERE org_id = 'a'")
        conn.commit()
    exports.write_export(worker.conn, INSTANCE, settings, "negative_state")


def test_the_startup_checkpoint_writes_the_first_latest(url, make_worker, admin, tmp_path):
    from mint_litellm.control.worker import RestoreCheck
    from mint_litellm.restore import files

    settings = _restore_settings(tmp_path)
    worker = make_worker(settings=settings, restore_check=RestoreCheck(settings, 0))
    worker.enqueue_startup_checkpoint()
    assert worker.step()
    assert files.latest_path(settings.export_dir, INSTANCE).exists()
    assert fetchone(admin, "SELECT status FROM mint.jobs WHERE kind = 'export_checkpoint'")[
        "status"] == "done"


def test_the_startup_checkpoint_does_not_overwrite_a_file_that_fails_verification(
    url, make_worker, admin, tmp_path
):
    """기존 파일을 먼저 검증한다: 되돌린 DB가 기존 증거를 새 정상본으로 덮지 못한다."""
    from mint_litellm.control.worker import RestoreCheck
    from mint_litellm.restore import files

    settings = _restore_settings(tmp_path)
    worker = make_worker(settings=settings, restore_check=RestoreCheck(settings, 0))
    worker.enqueue_startup_checkpoint()
    worker.step()
    path = files.latest_path(settings.export_dir, INSTANCE)
    broken = path.read_text().replace('"state_epoch"', '"state_epochs"')
    path.write_text(broken)
    worker.enqueue_startup_checkpoint()
    assert worker.step()
    assert path.read_text() == broken
    job_row = fetchone(admin, "SELECT * FROM mint.jobs WHERE status = 'pending'"
                       " AND kind = 'export_checkpoint'")
    assert job_row["last_error_code"] == "restore_blocked" and job_row["attempts"] == 0


def test_the_first_mismatch_holds_evidence_jobs_only_and_the_second_blocks_all_writes(
    url, make_worker, admin, tmp_path, all_handlers
):
    from mint_litellm.control.worker import RestoreCheck

    settings = _restore_settings(tmp_path)
    worker = make_worker(settings=settings, restore_check=RestoreCheck(settings, 0))
    _closed_org_and_export(url, worker, settings)
    _forge_negative_ahead(settings)
    admin.execute("DELETE FROM mint.jobs")  # 부정 전이가 등록한 작업은 이 시험의 대상이 아니다
    seal_job = put(admin, "seal", "s", "seal:1")
    export = put(admin, "export_checkpoint", "c", "export_checkpoint:1")
    sync = put(admin, "sync_server", "x")
    assert worker.step()  # 첫 불일치: 보류. 우선순위가 높은 sync는 돈다
    assert worker.verdict.state == "hold" and not worker.verdict.blocked
    assert [k for k, _ in all_handlers] == ["sync_server"]
    assert job(admin, sync)["status"] == "done"
    worker.restore_check.interval = 1e9  # 이후 판정은 직전 값을 쓴다
    while worker.step():
        pass
    for job_id in (seal_job, export):  # 증거 작업은 보류된다(시도 횟수 그대로)
        row = job(admin, job_id)
        assert row["status"] == "pending" and row["last_error_code"] == "restore_blocked"
        assert row["attempts"] == 0
    assert [k for k, _ in all_handlers] == ["sync_server"]
    sync2 = put(admin, "sync_server", "y")
    assert worker.step() and job(admin, sync2)["status"] == "done"  # 보류 중에도 호출 차단은 아니다
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.events"
                    " WHERE kind = 'restore_blocked'")["n"] == 0
    worker.restore_check.interval = 0  # 둘째 불일치: 차단
    sync3 = put(admin, "sync_server", "z")
    while worker.step():
        pass
    assert worker.verdict.blocked and worker.verdict.cause == "restore_pending"
    assert job(admin, sync3)["last_error_code"] == "restore_blocked"
    assert [k for k, _ in all_handlers] == ["sync_server", "sync_server"]
    events = fetchall(admin, "SELECT * FROM mint.events WHERE kind = 'restore_blocked'")
    assert len(events) == 1 and events[0]["source_key"].endswith(":1:restore_blocked")
    raised = {a["kind"]: a for a in alerts(admin)}
    assert raised["enforcement_unverified"]["subject"]["cause"] == "restore_pending"
    assert raised["restore_blocked"]["count"] == 1  # 같은 차단은 한 번만 연다
    worker.step()
    assert fetchone(admin, "SELECT count(*) AS n FROM mint.events"
                    " WHERE kind = 'restore_blocked'")["n"] == 1  # 한 번만 남긴다


def test_a_checkpoint_right_after_a_restore_that_overtook_the_epoch_does_not_cover_the_evidence(
    url, make_worker, admin, tmp_path
):
    from mint_litellm.control import exports
    from mint_litellm.control.worker import RestoreCheck
    from mint_litellm.restore import files

    settings = _restore_settings(tmp_path)
    worker = make_worker(settings=settings, restore_check=RestoreCheck(settings, 0))
    _closed_org_and_export(url, worker, settings)
    _forge_negative_ahead(settings)
    # 복구 뒤의 소비·확인으로 DB 세대가 파일 세대를 추월했다
    for _ in range(3):
        admin.execute("UPDATE mint.settings SET mode = mode WHERE instance_id = %s", (INSTANCE,))
    latest_path = files.latest_path(settings.export_dir, INSTANCE)
    before = latest_path.read_bytes()
    assert fetchone(admin, "SELECT epoch FROM mint.state_epoch")["epoch"] >= 4
    worker.enqueue_startup_checkpoint()
    assert worker.step()
    assert latest_path.read_bytes() == before
    assert worker.verdict.held
    assert files.read_verified(latest_path, exports.keys(settings))


def test_the_external_write_boundary_blocks_at_the_write_even_mid_job(
    url, make_worker, admin, monkeypatch
):
    """공통 경계: 작업이 도는 중에 되돌림이 감지되면 다음 외부 쓰기 직전에 멈춘다."""
    from mint_litellm.restore.judge import BLOCKED, Verdict

    worker = make_worker(restore_check=lambda c, i: False)
    wrote = []

    def handler(ctx):
        ctx.external_write()
        wrote.append("first")
        worker.verdict = Verdict(BLOCKED, "restore_pending")  # 작업 도중 판정이 바뀐다
        ctx.external_write()
        wrote.append("second")

    monkeypatch.setitem(jobs.HANDLERS, "sync_target", handler)
    job_id = put(admin, "sync_target", "t")
    assert worker.step()
    assert wrote == ["first"]
    row = job(admin, job_id)
    assert row["status"] == "pending" and row["last_error_code"] == "restore_blocked"
    assert row["attempts"] == 0


def test_a_shortened_interval_brings_the_next_run_forward(make_worker, admin):
    """주기를 줄여 다시 기동하면 이미 예약된 먼 다음 시각이 아니라 새 주기를 따른다."""
    long_settings = Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "3600"})
    short_settings = Stage2Settings.from_env({**ENV, "MINT_OBSERVE_SECONDS": "60"})
    first = make_worker(schedules="all", settings=long_settings)
    admin.execute("DELETE FROM mint.schedules WHERE kind <> 'contract_observe'")
    assert jobs.register_due_schedules(first.conn, INSTANCE) == 1  # 최초 1회
    later = fetchone(admin, "SELECT next_run_at - now() AS wait FROM mint.schedules")["wait"]
    assert later > timedelta(minutes=59)
    second = make_worker(schedules="all", settings=short_settings)
    admin.execute("DELETE FROM mint.schedules WHERE kind <> 'contract_observe'")
    soon = fetchone(admin, "SELECT next_run_at - now() AS wait FROM mint.schedules")["wait"]
    assert soon <= timedelta(seconds=60)
    admin.execute("UPDATE mint.schedules SET next_run_at = now() - interval '1 second'")
    admin.execute("UPDATE mint.jobs SET status = 'running', lease_owner = 'x',"
                  " lease_until = now() + interval '1 h'")
    admin.execute("UPDATE mint.jobs SET status = 'done', lease_owner = NULL, lease_until = NULL")
    assert jobs.register_due_schedules(second.conn, INSTANCE) == 1


def test_every_scheduled_kind_is_registered_again_in_each_period(make_worker, admin):
    """수렴 작업과 키 작업 모두, 앞 주기의 작업이 끝난 뒤 다음 주기에 다시 등록된다."""
    worker = make_worker(schedules="all")
    kinds = {k for k in jobs.SCHEDULES if k in jobs.HANDLERS}
    for age in (10, 20, 30):  # 멱등 키가 초 단위라 주기마다 시작 시각을 초 단위로 달리한다
        admin.execute("UPDATE mint.schedules SET next_run_at = now() - make_interval(secs => %s)",
                      (age,))
        assert jobs.register_due_schedules(worker.conn, INSTANCE) == len(kinds)
        admin.execute("UPDATE mint.jobs SET status = 'running', lease_owner = 'x',"
                      " lease_until = now() + interval '1 h' WHERE status = 'pending'")
        admin.execute("UPDATE mint.jobs SET status = 'done', lease_owner = NULL,"
                      " lease_until = NULL WHERE status = 'running'")
    registered = {r["kind"] for r in fetchall(admin, "SELECT DISTINCT kind FROM mint.jobs")}
    assert registered == kinds
