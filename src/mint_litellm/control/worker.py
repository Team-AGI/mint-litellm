"""작업 실행기 ``mint-litellm worker``.

작업 실행기는 ``mint_worker_app`` 로그인으로 접속하고, 일정을 작업으로 등록하고, 임대가 만료된
작업을 회수하고, 대기 작업을 하나씩 임대해 처리기를 부른다. 복제본이 여럿이어도 임대와 일정
등록이 ``FOR UPDATE SKIP LOCKED``와 멱등 키로 한 번씩만 일어난다.
"""

import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any

import psycopg
from psycopg.errors import UniqueViolation

from mint_litellm.control import alerts, exports, intake_jobs, jobs, ledger
from mint_litellm.control.config import ControlConfig
from mint_litellm.control.db.connection import connect, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.intake_checks import PolicyDataSource
from mint_litellm.control.litellm_control import LiteLLMControl
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.restore import judge as restore_judge
from mint_litellm.types.events import EventKind

log = logging.getLogger("mint_litellm.worker")

# 처리기가 붙은 작업 종류(이 모듈을 부르는 실행기가 쓰는 처리기를 등록한다)
jobs.HANDLERS.update(intake_jobs.HANDLERS)

POLL_SECONDS = 1.0
# 되돌림 상태에서 외부 쓰기 작업을 다시 시도하기까지의 간격(초)
RESTORE_BLOCKED_RETRY_SECONDS = 10


# 되돌림 판정 주기(초). 플러그인과 같다.
RESTORE_INTERVAL_SECONDS = 60.0


class RestoreCheck:
    """내보내기 파일과 DB의 내용 대조(``restore.judge``). 주기 안에서는 직전 판정을 돌려준다."""

    def __init__(self, settings: Stage2Settings, interval: float = RESTORE_INTERVAL_SECONDS):
        self.settings = settings
        self.interval = interval
        self.judge = restore_judge.Judge()
        self._at = -1e18
        self._last = restore_judge.Verdict(restore_judge.SKIP)

    def __call__(self, conn: psycopg.Connection, instance_id: str) -> restore_judge.Verdict:
        if time.monotonic() - self._at >= self.interval:
            self._last = self.judge.evaluate(
                conn, self.settings.export_dir, instance_id, exports.keys(self.settings)
            )
            self._at = time.monotonic()
        return self._last


def no_restore_detected(conn: psycopg.Connection, instance_id: str) -> restore_judge.Verdict:
    """판정을 하지 않는 검사기(시험용)."""
    return restore_judge.Verdict(restore_judge.OK)


class Worker:
    def __init__(
        self,
        database_url: str,
        instance_id: str,
        settings: Stage2Settings,
        *,
        lease_seconds: float | None = None,
        restore_check: Callable[[psycopg.Connection, str], restore_judge.Verdict | bool]
        | None = None,
        owner: str | None = None,
        litellm: Any = None,
        policy_data: Any = None,
    ) -> None:
        self.litellm = litellm
        self.policy_data = policy_data
        self.database_url = database_url
        self.instance_id = instance_id
        self.settings = settings
        self.lease_seconds = lease_seconds or settings.worker_lease_seconds
        self.restore_check = restore_check or RestoreCheck(settings)
        self.litellm = litellm
        self.verdict = restore_judge.Verdict(restore_judge.SKIP)
        self._reported_blocks: set[int] = set()
        self._alerted: set[tuple] = set()
        self.litellm = litellm
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.stop = threading.Event()
        self.current: jobs.JobContext | None = None
        self.conn: psycopg.Connection | None = None
        self._beat_conn: psycopg.Connection | None = None

    # --- 수명 ---------------------------------------------------------------

    def open(self) -> None:
        self.conn = connect(self.database_url)
        self.conn.autocommit = True
        self._beat_conn = connect(self.database_url)
        self._beat_conn.autocommit = True
        if fetchone(self.conn, "SELECT to_regclass('mint.jobs') IS NOT NULL AS ok")["ok"] is False:
            raise ControlError("2단계 스키마가 적용되어 있지 않습니다. init을 실행하십시오.")
        member = fetchone(
            self.conn, "SELECT pg_has_role(current_user, 'mint_worker', 'USAGE') AS ok"
        )
        if not member["ok"]:
            raise ControlError(
                "작업 실행기는 mint_worker_app 로그인(mint_worker 그룹)으로 접속해야 합니다."
            )
        jobs.ensure_schedules(self.conn, self.instance_id, self.settings)

    def enqueue_startup_checkpoint(self) -> None:
        """기동 직후 체크포인트 한 번(첫 ``latest.json``). 기존 파일 검증은 판정이 먼저 한다."""
        assert self.conn is not None
        self.conn.execute(
            "INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key)"
            " VALUES (gen_random_uuid(), %s, 'export_checkpoint', 'startup', %s)"
            " ON CONFLICT (instance_id, idempotency_key) DO NOTHING",
            (self.instance_id, f"export_checkpoint:start:{uuid.uuid4().hex}"),
        )

    def close(self) -> None:
        for conn in (self.conn, self._beat_conn):
            if conn is not None:
                conn.close()
        self.conn = self._beat_conn = None

    def request_stop(self) -> None:
        """종료 신호: 현재 작업에 취소를 알리고(처리기가 끝내거나 임대를 놓는다) 반복을 끝낸다."""
        self.stop.set()
        if self.current is not None:
            self.current.cancel.set()

    # --- 한 번의 반복 ---------------------------------------------------------

    def step(self) -> bool:
        """일정 등록, 만료 회수, 작업 하나 처리. 작업을 처리했으면 참이다."""
        assert self.conn is not None
        self.verdict = self._judge()
        jobs.register_due_schedules(self.conn, self.instance_id)
        jobs.reclaim_expired(self.conn, self.instance_id)
        if self.settings.webhook_urls:
            alerts.enqueue_deliveries(self.conn, self.instance_id, self.settings.webhook_urls)
        job = jobs.lease(
            self.conn, self.instance_id, self.owner, self.lease_seconds, sorted(jobs.HANDLERS)
        )
        if job is None:
            return False
        self._run(job)
        return True

    def _judge(self) -> restore_judge.Verdict:
        assert self.conn is not None
        result = self.restore_check(self.conn, self.instance_id)
        if isinstance(result, bool):  # 시험용 훅: 참이면 되돌림
            result = restore_judge.Verdict(restore_judge.BLOCKED if result else restore_judge.OK)
        if (
            result.blocked
            and result.cause == restore_judge.RESTORE_PENDING
            and result.file_epoch not in self._reported_blocks
        ):
            self._reported_blocks.add(result.file_epoch)
            try:  # 같은 파일 세대에 한 건(다른 실행기가 먼저 남겼으면 건너뛴다)
                with self.conn.transaction():
                    ledger.record(
                        self.conn, self.instance_id, EventKind.RESTORE_BLOCKED,
                        entity_id=str(result.file_epoch), state_version=1, actor="worker",
                        payload={"cause": result.cause, **result.detail},
                    )
            except UniqueViolation:
                pass
        if result.blocked:
            self._alert_blocked(result)
        return result

    def _alert_blocked(self, result: restore_judge.Verdict) -> None:
        """차단 상태가 시작될 때 경보를 연다(같은 원인·파일 세대는 한 번만 부른다)."""
        assert self.conn is not None
        key = (result.cause, result.file_epoch)
        if key in self._alerted:
            return
        self._alerted.add(key)
        subject = {"cause": result.cause, "file_epoch": result.file_epoch, **result.detail}
        with self.conn.transaction():
            alerts.raise_alert(
                self.conn, self.instance_id, kind="enforcement_unverified", severity="critical",
                dedup_key=f"enforcement_unverified:restore:{result.cause}", subject=subject,
            )
            if result.cause == restore_judge.RESTORE_PENDING:
                alerts.raise_alert(
                    self.conn, self.instance_id, kind="restore_blocked", severity="critical",
                    dedup_key=f"restore_blocked:{result.file_epoch}", subject=subject,
                )

    def run_forever(self, poll_seconds: float = POLL_SECONDS) -> None:
        while not self.stop.is_set():
            if not self.step():
                self.stop.wait(poll_seconds)

    # --- 작업 하나 ------------------------------------------------------------

    def _beat(self, ctx: jobs.JobContext, finished: threading.Event) -> None:
        """임대 1/3마다 연장한다. 연장이 실패하면 임대를 잃은 것이므로 작업에 취소를 알린다."""
        assert self._beat_conn is not None
        while not finished.wait(self.lease_seconds / 3):
            try:
                alive = jobs.extend(self._beat_conn, ctx.job["id"], self.owner, self.lease_seconds)
            except psycopg.Error:
                alive = False  # 연장 결과를 알 수 없으면 외부 호출을 멈추는 쪽이 안전하다
            if not alive:
                ctx.lost.set()
                ctx.cancel.set()
                return

    def _restore_in_flight(self) -> bool:
        """게시를 기다리는 복원 요청이 있는가. 있으면 증거 파일을 쓰지 않는다.

        복원 요청은 만들 때의 ``latest.json``에 결속하므로 그 사이에 정상 체크포인트가 파일을
        바꾸면 요청이 거절된다. 작업이 이미 실패로 끝난 요청은 세지 않는다(영구 보류 방지).
        """
        assert self.conn is not None
        row = fetchone(
            self.conn,
            "SELECT EXISTS (SELECT 1 FROM mint.restore_requests r JOIN mint.jobs j"
            " ON j.instance_id = r.instance_id AND j.kind = 'restore_publish'"
            " AND j.target_ref = r.id::text AND j.status IN ('pending', 'running')"
            " WHERE r.instance_id = %s AND r.status = 'pending') AS busy",
            (self.instance_id,),
        )
        return bool(row and row["busy"])

    def _run(self, job: dict) -> None:
        assert self.conn is not None
        conn, job_id = self.conn, job["id"]
        verdict, kind = self.verdict, job["kind"]
        if (
            (verdict.blocked and jobs.KINDS[kind].external_write)
            or (verdict.held and kind in jobs.EVIDENCE_KINDS)
            or (kind in jobs.EVIDENCE_KINDS and self._restore_in_flight())
        ):
            jobs.release(conn, job_id, self.owner, "restore_blocked", RESTORE_BLOCKED_RETRY_SECONDS)
            return
        ctx = jobs.JobContext(
            conn, self.instance_id, job, self.settings, litellm=self.litellm,
            policy_data=self.policy_data, verdict=lambda: self.verdict,
        )
        self.current = ctx
        if self.stop.is_set():
            ctx.cancel.set()
        finished = threading.Event()
        beat = threading.Thread(target=self._beat, args=(ctx, finished), daemon=True)
        beat.start()
        outcome: str | tuple = "ok"
        try:
            jobs.HANDLERS[job["kind"]](ctx)
        except jobs.PermanentFailure as error:
            outcome = ("permanent", error.code)
        except jobs.Cancelled:
            outcome = "cancelled"
        except jobs.RestoreBlocked:
            outcome = "restore_blocked"
        except jobs.WaitForOperator as error:
            outcome = ("wait", error.code, error.delay)
        except Exception as error:  # 어떤 실패도 작업 실패로 센다(메시지는 저장하지 않는다)
            code = str(getattr(error, "code", None) or type(error).__name__)[:100]
            log.warning("작업 %s(%s) 실패: %s", job["kind"], job_id, code)
            outcome = ("error", code)
        finally:
            finished.set()
            beat.join()
            self.current = None
        if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            conn.rollback()
        if ctx.lost.is_set():
            log.warning("작업 %s(%s)의 임대를 잃어 결과를 기록하지 않습니다.", job["kind"], job_id)
        elif outcome == "ok":
            jobs.complete(conn, job_id, self.owner)
        elif outcome == "cancelled":
            jobs.release(conn, job_id, self.owner, "shutdown")
        elif outcome == "restore_blocked":
            jobs.release(conn, job_id, self.owner, "restore_blocked", RESTORE_BLOCKED_RETRY_SECONDS)
        elif outcome[0] == "wait":
            jobs.release(conn, job_id, self.owner, outcome[1], outcome[2])
        elif outcome[0] == "permanent":
            jobs.fail_permanently(conn, job_id, self.owner, outcome[1])
        else:
            jobs.fail(conn, job_id, self.owner, outcome[1])


def install_signals(worker: Worker) -> Callable[[], None]:
    """SIGTERM·SIGINT(Windows는 SIGBREAK도)로 종료한다. 이전 처리기를 되돌리는 함수를 돌려준다."""
    names = [n for n in ("SIGTERM", "SIGINT", "SIGBREAK") if hasattr(signal, n)]
    previous = {
        n: signal.signal(getattr(signal, n), lambda *_: worker.request_stop()) for n in names
    }

    def restore() -> None:
        for name, handler in previous.items():
            signal.signal(getattr(signal, name), handler)

    return restore


def main(environ: Mapping[str, str] | None = None) -> int:
    """``mint-litellm worker``. 필수 설정이 없으면 기동하지 않는다."""
    environ = dict(os.environ) if environ is None else dict(environ)
    config = ControlConfig.from_env(environ)
    settings = Stage2Settings.from_env(environ)
    litellm = None
    if config.litellm_url and config.litellm_key:
        litellm = LiteLLMControl(config.litellm_url, config.litellm_key)
    worker = Worker(
        config.require_database(), config.instance_id, settings, litellm=litellm,
        policy_data=PolicyDataSource(environ.get("MINT_OPA_URL")),
    )
    worker.open()
    worker.enqueue_startup_checkpoint()
    restore = install_signals(worker)
    print(f"작업 실행기 시작: {worker.owner}", file=sys.stderr, flush=True)
    try:
        worker.run_forever()
    finally:
        restore()
        worker.close()
    print("작업 실행기 종료", file=sys.stderr, flush=True)
    return 0
