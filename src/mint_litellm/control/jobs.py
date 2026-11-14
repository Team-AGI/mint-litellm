"""작업 표: 작업 종류, 임대, 연장, 회수, 재시도, 일정.

작업 실행기(``worker.py``)와 서비스 계층의 작업 등록(``services/base.py``)이 같은 표를 쓴다.
모든 상태 전이는 한 문장 또는 한 트랜잭션이며, 같은 대상의 수렴 작업이 실행 중이면 그 대상의
대기 작업을 임대하지 않는다. 연결은 자동 커밋이어야 한다(문장마다 확정).
"""

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import psycopg
from psycopg.errors import UniqueViolation

from mint_litellm.control import alerts, links, seal, webhook
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.services import expiry
from mint_litellm.types.ids import new_uuid7

MAX_BACKOFF_SECONDS = 600


@dataclass(frozen=True)
class JobKind:
    # 멱등 키 없이 대상당 대기 행 1개로 수렴하는 작업(실행 시점의 DB 상태를 읽는다)
    convergent: bool = False
    # 되돌림 상태에서 실행하지 않는 외부 쓰기 작업(되돌림 보호)
    external_write: bool = False


KINDS: dict[str, JobKind] = {
    "submission_poll": JobKind(),
    "intake_run": JobKind(),
    "contract_observe": JobKind(convergent=True),
    "sync_server": JobKind(convergent=True, external_write=True),
    "sync_target": JobKind(convergent=True, external_write=True),
    "sync_reconcile": JobKind(external_write=True),
    "relation_finalize": JobKind(convergent=True),
    "server_finalize": JobKind(convergent=True, external_write=True),
    "activation_finalize": JobKind(convergent=True, external_write=True),
    # 되돌림 상태에서는 봉인도 하지 않는다(되돌린 DB 위에 새 연쇄를 잇지 않는다).
    "seal": JobKind(external_write=True),
    "export_negative_state": JobKind(external_write=True),
    "export_checkpoint": JobKind(external_write=True),
    "alert_deliver": JobKind(external_write=True),
    "approval_expiry_scan": JobKind(),
    "endpoint_result_scan": JobKind(),
    "evidence_expiry_scan": JobKind(),
    "session_verify": JobKind(),
    "call_spike_scan": JobKind(),
    "bulk_extraction_scan": JobKind(),
    "content_finding_scan": JobKind(),
    "server_address_scan": JobKind(),
    "result_unenforced_scan": JobKind(),
    "token_audience_scan": JobKind(),
    "package_vuln_scan": JobKind(),
    "config_secret_scan": JobKind(),
    "key_block_scan": JobKind(),
    "key_block_apply": JobKind(external_write=True),
    # 사건 분할을 미리 만들고 닫힌 달을 내보낸다 / 보관 기간이 지난 달을 지운다.
    "event_partition_maintain": JobKind(external_write=True),
    "event_retention": JobKind(external_write=True),
    "approval_dormant_scan": JobKind(),
    "metric_rollup": JobKind(),
    "siem_forward": JobKind(),
    "org_suggest_scan": JobKind(),
    # 해제 경로: 되돌림 차단 상태에서도 실행한다(외부 쓰기 목록에 넣지 않는다).
    "restore_publish": JobKind(),
}

# 우선순위: export_negative_state > sync_* > 나머지(같으면 run_after 순).
PRIORITY_SQL = (
    "CASE WHEN j.kind = 'export_negative_state' THEN 0"
    " WHEN j.kind LIKE 'sync\\_%%' THEN 1 ELSE 2 END"
)


class Cancelled(Exception):
    """작업 코드가 취소 신호를 보고 외부 호출을 멈추고 끝낼 때 낸다."""


class PermanentFailure(Exception):
    """재시도해도 소용없는 실패. 작업을 바로 ``failed``로 끝낸다(경보는 낸 쪽이 이미 열었다)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class WaitForOperator(Exception):
    """운영자 조치(설정 저장 등)를 기다린다. 시도 횟수를 세지 않고 ``delay``초 뒤 다시 대기한다."""

    code = "wait_for_operator"
    delay = 300


class RestoreBlocked(Exception):
    """되돌림 상태라 외부 쓰기를 하지 않는다. 작업은 실패가 아니라 대기로 돌아간다."""

    def __init__(self, cause: str | None = None) -> None:
        super().__init__(cause or "restore_blocked")
        self.cause = cause


# 처음 어긋난 순간부터 보류하는 증거 작업(봉인·내보내기). 나머지 외부 쓰기는 차단 때만 멈춘다.
EVIDENCE_KINDS = frozenset({"seal", "export_negative_state", "export_checkpoint"})


@dataclass
class JobContext:
    """처리기에 건네는 맥락. 처리기는 외부 호출 전에 ``checkpoint()``로 취소를 확인한다."""

    conn: psycopg.Connection
    instance_id: str
    job: dict
    settings: Any = None
    litellm: Any = None
    cancel: threading.Event = field(default_factory=threading.Event)
    lost: threading.Event = field(default_factory=threading.Event)
    # 관리 API 클라이언트(쓰기 가능). 설정이 없으면 None이다.
    litellm: Any = None
    # 활성 번들 데이터 조회(``PolicyDataSource``). 없으면 번들 데이터가 필요한 검사는 판별 불가
    policy_data: Any = None
    # 되돌림 판정의 현재 값(작업 실행기가 채운다). 외부 쓰기 경계가 읽는다.
    verdict: Callable[[], Any] = lambda: None

    def checkpoint(self) -> None:
        if self.cancel.is_set():
            raise Cancelled

    def external_write(self) -> None:
        """외부 쓰기(LiteLLM 쓰기·파일 쓰기) 직전마다 부르는 공통 경계.

        임대를 잃었거나 종료 신호가 왔으면 ``Cancelled``, 되돌림 상태이면 ``RestoreBlocked``이다.
        봉인·내보내기는 처음 어긋난 순간(``hold``)부터 멈춘다.
        """
        self.checkpoint()
        verdict = self.verdict()
        if verdict is None:
            return
        if verdict.blocked or (verdict.held and self.job["kind"] in EVIDENCE_KINDS):
            raise RestoreBlocked(verdict.cause)


def guard_external_write(ctx: "JobContext") -> None:
    """LiteLLM 쓰기 직전에 부르는 경계. 임대를 잃었거나 종료 중이거나 되돌림 상태면 쓰지 않는다.

    임시 구현이다. 공용 경계(임대 유효성과 되돌림 상태 확인)는 되돌림 보호 단계가 만들고
    그때 이 함수를 대신한다. LiteLLM 쓰기는 클라이언트의 쓰기 메서드 한 곳만 이 함수를 부른다.
    """
    ctx.checkpoint()
    if ctx.lost.is_set():
        raise Cancelled
    if ctx.restore_check is not None and ctx.restore_check(ctx.conn, ctx.instance_id):
        raise RestoreBlocked


def _approval_expiry_scan(job: JobContext) -> None:
    from mint_litellm.control.services import recert  # 서비스 틀이 jobs를 불러오므로 늦게 가져온다

    expiry.expire_due(job.conn, job.instance_id)
    expiry.warn_expiring(job.conn, job.instance_id)
    expiry.announce_requests(job.conn, job.instance_id)
    expiry.close_settled_requests(job.conn, job.instance_id)
    settings = job.settings
    recert.scan(
        job.conn,
        job.instance_id,
        timedelta(days=getattr(settings, "recert_days", 90)),
        timedelta(days=getattr(settings, "recert_grace_days", 14)),
    )


def _endpoint_result_scan(job: JobContext) -> None:
    from mint_litellm.control import endpoint_posture, endpoint_results

    with job.conn.transaction():
        endpoint_results.scan(job.conn, job.instance_id)
        endpoint_posture.scan(
            job.conn,
            job.instance_id,
            timedelta(hours=getattr(job.settings, "endpoint_silent_hours", 24)),
        )


def _alert_deliver(job: JobContext) -> None:
    """경보 전송 한 건(주소 하나). 응답 본문은 읽어 버리고 상태와 보낸 횟수만 남긴다."""
    row = fetchone(
        job.conn,
        "SELECT d.id, d.status, d.channel, d.alert_count AS count, a.kind, a.severity,"
        " a.subject,"
        " a.first_at, a.last_at FROM mint.alert_deliveries d JOIN mint.alerts a"
        " ON a.instance_id = d.instance_id AND a.id = d.alert_id"
        " WHERE d.instance_id = %s AND d.delivery_id = %s::uuid",
        (job.instance_id, job.job["target_ref"]),
    )
    if row is None or row["status"] != "pending":
        return
    settings = job.settings
    url = next((u for u in settings.webhook_urls if alerts.channel_for(u) == row["channel"]), None)
    sent, attempts = False, 0
    if url is not None:
        hosts = [urlsplit(u).hostname for u in settings.webhook_urls]
        webhook.check_url(url, hosts)
        with webhook.client() as http:
            sent, attempts = webhook.post(
                http,
                url,
                settings.webhook_hmac_key,
                job.job["target_ref"],
                webhook.build_body(
                    row,
                    settings.console_url,
                    settings.webhook_format(url),
                    links.for_alert(
                        row, settings.console_url, settings.webhook_hmac_key,
                        settings.link_ttl_seconds,
                    ),
                    buttons=bool(settings.slack_signing_secret),
                ),
            )
    job.conn.execute(
        "UPDATE mint.alert_deliveries SET status = %s, attempts = %s,"
        " sent_at = CASE WHEN %s THEN now() END WHERE id = %s",
        ("sent" if sent else "failed", attempts, sent, row["id"]),
    )


def _call_spike_scan(job: JobContext) -> None:
    from mint_litellm.control import call_spike

    call_spike.run(job)


def _bulk_extraction_scan(job: JobContext) -> None:
    from mint_litellm.control import bulk_extraction

    bulk_extraction.run(job)
def _content_finding_scan(job: JobContext) -> None:
    from mint_litellm.control import content_finding

    content_finding.run(job)
def _result_unenforced_scan(job: JobContext) -> None:
    from mint_litellm.control import result_unenforced

    result_unenforced.run(job)


def _key_block_scan(job: JobContext) -> None:
    from mint_litellm.control import key_block

    key_block.run(job)


def _key_block_apply(job: JobContext) -> None:
    from mint_litellm.control import key_block

    key_block.apply(job)


def _server_address_scan(job: JobContext) -> None:
    from mint_litellm.control import server_address

    server_address.run(job)


def _token_audience_scan(job: JobContext) -> None:
    from mint_litellm.control import token_audience

    token_audience.run(job)


def _approval_dormant_scan(job: JobContext) -> None:
    from mint_litellm.control import dormant

    dormant.run(job)


def _metric_rollup(job: JobContext) -> None:
    from mint_litellm.control import metric_rollup

    metric_rollup.run(job)
def _siem_forward(job: JobContext) -> None:
    from mint_litellm.control import siem

    siem.run(job)


def _org_suggest_scan(job: JobContext) -> None:
    from mint_litellm.control import org_suggest

    org_suggest.run(job)


def _config_secret_scan(job: JobContext) -> None:
    from mint_litellm.control import config_secrets

    config_secrets.run(job)


def _package_vuln_scan(job: JobContext) -> None:
    from mint_litellm.control import vuln

    vuln.run(job)


def _event_partition_maintain(job: JobContext) -> None:
    from mint_litellm.control import event_partitions

    event_partitions.maintain(job)


def _event_retention(job: JobContext) -> None:
    from mint_litellm.control import event_partitions

    event_partitions.retain(job)


def _contract_observe(job: JobContext) -> None:
    from mint_litellm.control.contract_observe import handle

    handle(job)


def _sync(name: str) -> Callable[[JobContext], None]:
    """권한 동기화 처리기(``sync_jobs``)를 부를 때 불러온다(모듈 순환을 피한다)."""

    def run(job: JobContext) -> None:
        from mint_litellm.control import sync_jobs

        getattr(sync_jobs, name)(job)

    return run


def _seal(job: JobContext) -> None:
    job.external_write()
    seal.seal_once(job.conn, job.instance_id, getattr(job.settings, "export_hmac_key", None))


def _export_negative_state(job: JobContext) -> None:
    from mint_litellm.control import exports

    exports.export_negative_state(job)


def _restore_publish(job: JobContext) -> None:
    from mint_litellm.control import restore_publish

    restore_publish.publish(job)


def _export_checkpoint(job: JobContext) -> None:
    from mint_litellm.control import exports

    exports.export_checkpoint(job)


def _session_verify(job: JobContext) -> None:
    from mint_litellm.control import session_verify

    session_verify.run(job)


# 이 단계에서 처리기가 붙은 작업. 나머지는 해당 단계에서 붙이며, 처리기 없는 작업은 등록할 수 없다.
HANDLERS: dict[str, Callable[[JobContext], None]] = {
    "approval_expiry_scan": _approval_expiry_scan,
    "endpoint_result_scan": _endpoint_result_scan,
    "contract_observe": _contract_observe,
    "sync_server": _sync("sync_server"),
    "sync_target": _sync("sync_target"),
    "sync_reconcile": _sync("sync_reconcile"),
    "activation_finalize": _sync("activation_finalize"),
    "relation_finalize": _sync("relation_finalize"),
    "server_finalize": _sync("server_finalize"),
    "seal": _seal,
    "export_negative_state": _export_negative_state,
    "export_checkpoint": _export_checkpoint,
    "restore_publish": _restore_publish,
    "alert_deliver": _alert_deliver,
    "session_verify": _session_verify,
    "call_spike_scan": _call_spike_scan,
    "bulk_extraction_scan": _bulk_extraction_scan,
    "content_finding_scan": _content_finding_scan,
    "server_address_scan": _server_address_scan,
    "result_unenforced_scan": _result_unenforced_scan,
    "token_audience_scan": _token_audience_scan,
    "package_vuln_scan": _package_vuln_scan,
    "config_secret_scan": _config_secret_scan,
    "key_block_scan": _key_block_scan,
    "key_block_apply": _key_block_apply,
    "event_partition_maintain": _event_partition_maintain,
    "event_retention": _event_retention,
    "approval_dormant_scan": _approval_dormant_scan,
    "metric_rollup": _metric_rollup,
    "siem_forward": _siem_forward,
    "org_suggest_scan": _org_suggest_scan,
}

# 일정(주기 작업): 종류 -> 설정에서 주기(초)를 얻는 함수. 처리기가 있는 종류만 일정을 만든다.
SCHEDULES: dict[str, Callable[[Any], int]] = {
    "approval_expiry_scan": lambda s: 60,
    "endpoint_result_scan": lambda s: 60,
    "contract_observe": lambda s: s.observe_seconds,
    "seal": lambda s: 60,
    "submission_poll": lambda s: s.submission_poll_seconds,
    "sync_reconcile": lambda s: s.reconcile_seconds,
    "export_checkpoint": lambda s: s.checkpoint_seconds,
    "session_verify": lambda s: s.session_verify_seconds,
    "evidence_expiry_scan": lambda s: 3600,  # 1시간(고정)
    "call_spike_scan": lambda s: 60,
    "bulk_extraction_scan": lambda s: 60,
    "content_finding_scan": lambda s: 60,
    "server_address_scan": lambda s: 60,
    "result_unenforced_scan": lambda s: 60,
    "token_audience_scan": lambda s: 60,
    "package_vuln_scan": lambda s: s.vuln_scan_seconds,
    "config_secret_scan": lambda s: 3600,  # 1시간(고정)
    "key_block_scan": lambda s: 60,
    "event_partition_maintain": lambda s: 3600,  # 1시간(고정)
    "event_retention": lambda s: 3600,  # 1시간(고정). 보관 일수가 없으면 아무것도 하지 않는다.
    "approval_dormant_scan": lambda s: 3600,  # 1시간(고정)
    "metric_rollup": lambda s: 60,
    "siem_forward": lambda s: 15,
    "org_suggest_scan": lambda s: s.org_suggest_seconds,
}


# 관측을 이어 주는 주기 작업. 미관측 차단은 관측 주기의 2배에 닿으면 걸리므로, 일시 실패 뒤의
# 재시도 간격은 관측 주기의 4분의 1(최소 5초)을 넘지 않는다.
PERIODIC_RETRY_KINDS = frozenset({"contract_observe", "sync_reconcile", "submission_poll"})


def retry_cap(kind: str | None, settings: Any) -> int | None:
    """주기 작업의 재시도 간격 상한(초). 주기 작업이 아니거나 설정이 없으면 None."""
    if settings is None or kind not in PERIODIC_RETRY_KINDS:
        return None
    return min(MAX_BACKOFF_SECONDS, max(5, settings.observe_seconds // 4))


def backoff_seconds(attempts: int, kind: str | None = None, settings: Any = None) -> int:
    return min(2**attempts * 5, retry_cap(kind, settings) or MAX_BACKOFF_SECONDS)


def period_key(kind: str, period_start: datetime) -> str:
    """예약 작업의 멱등 키 ``<kind>:<주기 시작 시각>``. 시각은 UTC 초 단위 ISO 8601이다."""
    return f"{kind}:{period_start.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}"


# --- 임대 --------------------------------------------------------------------


def lease(
    conn: psycopg.Connection, instance_id: str, owner: str, lease_seconds: float, kinds: list[str]
) -> dict | None:
    """실행할 대기 작업 하나를 잡는다. 같은 대상에 실행 중인 수렴 작업이 있으면 건너뛴다."""
    with conn.transaction():
        return fetchone(
            conn,
            "WITH picked AS ("
            " SELECT j.id FROM mint.jobs j"
            " WHERE j.instance_id = %(inst)s AND j.status = 'pending' AND j.run_after <= now()"
            "  AND j.kind = ANY(%(kinds)s)"
            "  AND NOT (j.idempotency_key IS NULL AND EXISTS ("
            "   SELECT 1 FROM mint.jobs r WHERE r.instance_id = j.instance_id AND r.kind = j.kind"
            "   AND r.target_ref = j.target_ref AND r.status = 'running'))"
            f" ORDER BY {PRIORITY_SQL}, j.run_after LIMIT 1 FOR UPDATE SKIP LOCKED)"
            " UPDATE mint.jobs SET status = 'running', lease_owner = %(owner)s,"
            " lease_until = now() + make_interval(secs => %(secs)s), updated_at = now()"
            " FROM picked WHERE jobs.id = picked.id RETURNING jobs.*",
            {"inst": instance_id, "kinds": kinds, "owner": owner, "secs": lease_seconds},
        )


def extend(conn: psycopg.Connection, job_id: Any, owner: str, lease_seconds: float) -> bool:
    """임대를 연장한다. 이미 만료됐거나 다른 소유자가 가졌으면 거짓이다(임대를 잃음)."""
    return (
        conn.execute(
            "UPDATE mint.jobs SET lease_until = now() + make_interval(secs => %s),"
            " updated_at = now() WHERE id = %s AND status = 'running' AND lease_owner = %s"
            " AND lease_until > now()",
            (lease_seconds, job_id, owner),
        ).rowcount
        == 1
    )


def complete(conn: psycopg.Connection, job_id: Any, owner: str) -> bool:
    """작업을 끝낸다. 같은 종류·대상의 「작업 실패」 경보는 이 성공으로 해결된다."""
    row = fetchone(
        conn,
        "UPDATE mint.jobs SET status = 'done', lease_owner = NULL, lease_until = NULL,"
        " last_error_code = NULL, updated_at = now()"
        " WHERE id = %s AND status = 'running' AND lease_owner = %s"
        " RETURNING instance_id, kind, target_ref",
        (job_id, owner),
    )
    if row is None:
        return False
    alerts.resolve(
        conn, row["instance_id"], alerts.job_failed_key(row["kind"], row["target_ref"])
    )
    return True


# --- 재시도·실패·회수 -----------------------------------------------------------


def _alert_failed(conn: psycopg.Connection, row: dict, error_code: str) -> None:
    """같은 종류·대상의 미해결 경보가 있으면 횟수만 올린다(경보 함수가 묶는다)."""
    alerts.raise_alert(
        conn,
        row["instance_id"],
        kind="job_failed",
        severity="high",
        dedup_key=alerts.job_failed_key(row["kind"], row["target_ref"]),
        subject={
            "job_kind": row["kind"],
            "target_ref": row["target_ref"],
            "job_id": str(row["id"]),
            "attempts": row["attempts"],
            "last_error_code": error_code,
        },
    )


def _requeue(
    conn: psycopg.Connection,
    job_id: Any,
    guard: str,
    params: tuple,
    code: str | None,
    *,
    count: bool,
    delay: float | None = None,
    settings: Any = None,
) -> str | None:
    """실행 중 작업을 ``pending`` 또는 ``failed``로 돌린다. ``guard``를 만족하는 행이 없으면 None.

    ``count``이면 시도 횟수를 올리고 한도에 닿으면 ``failed``와 경보 ``job_failed``이다.
    ``delay``가 None이면 재시도 간격 공식을 쓴다(``settings``가 있으면 주기 작업의 상한을 건다).
    """
    with conn.transaction():
        row = fetchone(
            conn,
            "SELECT * FROM mint.jobs WHERE id = %s AND status = 'running' AND "
            + guard
            + " FOR UPDATE",
            (job_id, *params),
        )
        if row is None:
            return None
        attempts = row["attempts"] + (1 if count else 0)
        if count and attempts >= row["max_attempts"]:
            conn.execute(
                "UPDATE mint.jobs SET status = 'failed', attempts = %s, last_error_code = %s,"
                " lease_owner = NULL, lease_until = NULL, updated_at = now() WHERE id = %s",
                (attempts, code, job_id),
            )
            _alert_failed(conn, {**row, "attempts": attempts}, code or "")
            return "failed"
        wait = backoff_seconds(attempts, row["kind"], settings) if delay is None else delay
        try:
            with conn.transaction():  # 세이브포인트: 같은 대상의 대기 행이 따로 있으면 실패한다
                conn.execute(
                    "UPDATE mint.jobs SET status = 'pending', attempts = %s, last_error_code = %s,"
                    " run_after = now() + make_interval(secs => %s), lease_owner = NULL,"
                    " lease_until = NULL, updated_at = now() WHERE id = %s",
                    (attempts, code, wait, job_id),
                )
        except UniqueViolation:
            # 대기 행이 실행 시점 상태를 읽으므로(수렴) 그 행에 합치고 이 행은 끝낸다.
            cap = retry_cap(row["kind"], settings)
            later = "GREATEST(run_after, now() + make_interval(secs => %s))"
            if cap is not None:  # 이미 먼 시각으로 잡힌 대기 행도 상한 안으로 당긴다
                later = f"LEAST({later}, now() + make_interval(secs => {int(cap)}))"
            conn.execute(
                "UPDATE mint.jobs SET attempts = GREATEST(attempts, %s),"
                f" run_after = {later},"
                " last_error_code = %s, updated_at = now()"
                " WHERE instance_id = %s AND kind = %s AND target_ref = %s"
                " AND status = 'pending' AND idempotency_key IS NULL",
                (attempts, wait, code, row["instance_id"], row["kind"], row["target_ref"]),
            )
            conn.execute(
                "UPDATE mint.jobs SET status = 'done', last_error_code = 'superseded',"
                " lease_owner = NULL, lease_until = NULL, updated_at = now() WHERE id = %s",
                (job_id,),
            )
            return "done"
        return "pending"


def fail(
    conn: psycopg.Connection, job_id: Any, owner: str, code: str, settings: Any = None
) -> str | None:
    """처리기가 실패했다. ``pending``(재시도), ``failed``, 임대를 잃었으면 None을 돌려준다."""
    return _requeue(
        conn, job_id, "lease_owner = %s", (owner,), code, count=True, settings=settings
    )


def fail_permanently(conn: psycopg.Connection, job_id: Any, owner: str, code: str) -> bool:
    """재시도 없이 ``failed``로 끝낸다. 임대를 잃었으면 거짓이다."""
    return (
        conn.execute(
            "UPDATE mint.jobs SET status = 'failed', last_error_code = %s, lease_owner = NULL,"
            " lease_until = NULL, updated_at = now()"
            " WHERE id = %s AND status = 'running' AND lease_owner = %s",
            (code, job_id, owner),
        ).rowcount
        == 1
    )


def release(
    conn: psycopg.Connection, job_id: Any, owner: str, code: str | None, delay: float = 0
) -> str | None:
    """시도 횟수를 올리지 않고 임대를 놓는다(종료 신호, 되돌림 차단)."""
    return _requeue(conn, job_id, "lease_owner = %s", (owner,), code, count=False, delay=delay)


def reclaim_expired(conn: psycopg.Connection, instance_id: str, settings: Any = None) -> int:
    """임대가 만료된 ``running`` 작업을 되돌린다(작업 실행기가 죽은 경우). 시도 한 번으로 센다."""
    ids = fetchall(
        conn,
        "SELECT id FROM mint.jobs WHERE instance_id = %s AND status = 'running'"
        " AND lease_until <= now()",
        (instance_id,),
    )
    reclaimed = 0
    for row in ids:
        # 그 사이 연장·완료됐거나 다른 실행기가 먼저 회수했으면 건너뛴다
        if _requeue(
            conn, row["id"], "lease_until <= now()", (), "lease_expired", count=True,
            settings=settings,
        ):
            reclaimed += 1
    return reclaimed


# --- 일정 --------------------------------------------------------------------


def ensure_schedules(conn: psycopg.Connection, instance_id: str, settings: Any) -> None:
    """처리기가 있는 주기 작업의 일정 행을 만든다. 주기가 설정과 다르면 맞춘다.

    주기를 줄이면 이미 잡혀 있던 먼 다음 시각도 새 주기 안으로 당긴다. 그대로 두면 옛 주기가
    끝날 때까지 새 주기의 작업이 등록되지 않는다. 주기를 늘릴 때는 다음 시각을 그대로 둔다.
    """
    with conn.transaction():
        for kind, interval in SCHEDULES.items():
            if kind not in HANDLERS:
                continue
            conn.execute(
                "INSERT INTO mint.schedules (instance_id, kind, interval_seconds, next_run_at)"
                " VALUES (%s, %s, %s, date_trunc('second', now()))"
                " ON CONFLICT (instance_id, kind) DO UPDATE"
                " SET interval_seconds = EXCLUDED.interval_seconds,"
                " next_run_at = LEAST(mint.schedules.next_run_at,"
                "  date_trunc('second', now()) + make_interval(secs => EXCLUDED.interval_seconds))"
                " WHERE mint.schedules.interval_seconds <> EXCLUDED.interval_seconds",
                (instance_id, kind, interval(settings)),
            )
        # 이전 판본이 먼 시각으로 잡아 둔 주기 작업의 대기 행을 새 재시도 상한 안으로 당긴다.
        for kind in PERIODIC_RETRY_KINDS:
            conn.execute(
                "UPDATE mint.jobs SET run_after = now() + make_interval(secs => %s),"
                " updated_at = now() WHERE instance_id = %s AND kind = %s AND status = 'pending'"
                " AND run_after > now() + make_interval(secs => %s)",
                (retry_cap(kind, settings), instance_id, kind, retry_cap(kind, settings)),
            )


def register_due_schedules(conn: psycopg.Connection, instance_id: str) -> int:
    """주기가 된 일정마다 작업을 한 번 등록한다.

    일정 행을 ``FOR UPDATE SKIP LOCKED``로 잡고 멱등 키 ``<kind>:<주기 시작 시각>``으로 넣으므로
    실행기가 여럿이어도 한 주기에 한 번이다. 실행기가 멈춰 있던 동안 놓친 주기는 건너뛰고
    현재 주기 하나만 등록한다.
    """
    with conn.transaction():
        due = fetchall(
            conn,
            "WITH due AS ("
            " SELECT kind, interval_seconds, next_run_at + make_interval(secs => interval_seconds"
            "  * floor(extract(epoch FROM now() - next_run_at) / interval_seconds)) AS period_start"
            " FROM mint.schedules WHERE instance_id = %s AND enabled AND next_run_at <= now()"
            " FOR UPDATE SKIP LOCKED)"
            " UPDATE mint.schedules s SET next_run_at ="
            " due.period_start + make_interval(secs => s.interval_seconds)"
            " FROM due WHERE s.instance_id = %s AND s.kind = due.kind"
            " RETURNING due.kind, due.period_start",
            (instance_id, instance_id),
        )
        registered = 0
        for row in due:
            if KINDS[row["kind"]].convergent:
                registered += conn.execute(
                    "INSERT INTO mint.jobs (id,instance_id,kind,target_ref) VALUES (%s,%s,%s,%s)"
                    " ON CONFLICT (instance_id,kind,target_ref)"
                    " WHERE status='pending' AND idempotency_key IS NULL DO NOTHING",
                    (new_uuid7(), instance_id, row["kind"], row["kind"]),
                ).rowcount
                continue
            registered += conn.execute(
                "INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key)"
                " VALUES (%s, %s, %s, %s, %s)"
                " ON CONFLICT (instance_id, idempotency_key) DO NOTHING",
                (
                    new_uuid7(),
                    instance_id,
                    row["kind"],
                    row["kind"],
                    period_key(row["kind"], row["period_start"]),
                ),
            ).rowcount
        return registered
