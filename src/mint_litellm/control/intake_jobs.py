"""수용검증 작업 처리기: ``submission_poll``, ``intake_run``, ``evidence_expiry_scan``.

LiteLLM 읽기·쓰기는 모두 제어 평면 클라이언트(``JobContext.litellm``)를 통한다. 쓰기(제출
승인·거절)는 클라이언트의 쓰기 메서드 한 곳을 지나며, 그 직전에 공통 경계
``JobContext.external_write``가 불린다.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from mint_litellm.control import alerts
from mint_litellm.control import intake_checks as checks
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.jobs import JobContext
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.services import intakes
from mint_litellm.control.services.base import enqueue_job
from mint_litellm.types.jobs import intake_run_job_key

POLL_LIMIT = 500
EXPIRY_WARNING = timedelta(days=7)


class LiteLLMNotConfigured(ControlError):
    code = "litellm_not_configured"


def _client(job: JobContext) -> Any:
    if job.litellm is None:
        raise LiteLLMNotConfigured("MINT_LITELLM_URL과 MINT_LITELLM_KEY가 필요합니다.")
    return job.litellm.with_guard(job.external_write)


def _context(job: JobContext) -> Context:
    return Context(job.conn, job.instance_id, Operator(intakes.SYSTEM_ACTOR, "admin", None))


# --- submission_poll ---------------------------------------------------------------------


def submission_poll(job: JobContext) -> None:
    """LiteLLM 제출(``pending_review``)을 읽어 신청(``received``)을 만든다. 한 번에 500건까지."""
    client = _client(job)
    job.checkpoint()
    pending = [i for i in client.list_submissions() if i.get("approval_status") == "pending_review"]
    ctx = _context(job)
    for item in pending[:POLL_LIMIT]:
        job.checkpoint()
        intakes.receive_submission(ctx, item)
        # 접수 직후 중단돼도 다음 조회가 이어받도록, 이미 있는 received 제출도 매번 본다
        intakes.reject_forbidden_address(ctx, item.get("server_id"), lambda contract, org_id: (
            _url_guard(job, contract, _allowlists(job, org_id))))


def _url_guard(job: JobContext, contract: dict | None, allowlists: list[dict]) -> checks.Outcome:
    ports = tuple(getattr(job.settings, "intake_allowed_ports", checks.DEFAULT_PORTS))
    return checks.url_guard(contract and contract["url"], contract and contract["transport"],
                            allowlists, ports)


# --- intake_run ---------------------------------------------------------------------------


def _allowlists(job: JobContext, org_id: str) -> list[dict]:
    return fetchall(
        job.conn,
        "SELECT id, kind, value FROM mint.allowlists WHERE instance_id = %s AND status = 'active'"
        " AND valid_from <= now() AND valid_until > now() AND (org_id IS NULL OR org_id = %s)",
        (job.instance_id, org_id),
    )


def _stored_definitions(job: JobContext, server_id: str) -> list[dict] | None:
    rows = fetchall(
        job.conn,
        "SELECT canonical_text FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status = 'candidate' AND source = 'intake' ORDER BY tool",
        (job.instance_id, server_id),
    )
    return [json.loads(r["canonical_text"]) for r in rows] or None


class AllKeysNotClosed(Exception):
    """승인한 제출 서버의 ``allow_all_keys``를 끄지 못했다. 신청은 더 진행하지 않는다."""


def _alert_divergence(job: JobContext, server_id: str, item: str, **subject: Any) -> None:
    with job.conn.transaction():
        alerts.raise_alert(
            job.conn, job.instance_id, kind="sync_divergence", severity="high",
            dedup_key=f"sync_divergence:{item}:{server_id}",
            subject={"server_id": server_id, "item": item, **subject},
        )


def _close_all_keys(job: JobContext, client: Any, server_id: str) -> None:
    """``allow_all_keys``를 끄고 다시 읽어 확인한다. 못 끄면 경보를 내고 ``AllKeysNotClosed``."""
    try:
        closed = client.close_all_keys(server_id)
    except LiteLLMError:
        closed = False
    if not closed:
        _alert_divergence(job, server_id, "allow_all_keys", expected=False)
        raise AllKeysNotClosed


def _isolate_submission(job: JobContext, client: Any, server_id: str) -> None:
    """승인 뒤에도 ``allow_all_keys``를 끄지 못한 서버는 제출 ``reject``로 격리한다(보상 절차).

    열린 채 레지스트리에 남는 것보다 거절 상태가 안전하다. 거절도 못 하면 경보로 남는다.
    """
    try:
        done = client.reject_submission(server_id, "allow_all_keys를 끄지 못해 격리")
    except LiteLLMError:
        done = "failed"
    if done not in ("done", "already"):
        _alert_divergence(job, server_id, "submission_isolation_failed", result=done)


def _status_after_lost_approval(client: Any, server_id: str) -> str | None:
    """승인 응답이 유실된 뒤 서버의 ``approval_status``. 다시 읽지 못하면 None(불확실)."""
    try:
        item = next((i for i in client.list_submissions() if i.get("server_id") == server_id),
                    None) or client.get_server(server_id)
    except LiteLLMError:
        return None
    return (item or {}).get("approval_status")


def _gate(job: JobContext, client: Any, server_id: str, mode: str) -> str | None:
    """연결 검사 직전에 LiteLLM 서버 상태를 맞춘다. 사유 코드가 돌아오면 검사를 하지 않는다.

    ``registry``: 승인 전에 대기 중인 서버에 쓸 수 있으면 ``allow_all_keys``를 먼저 끈다(두 외부
    쓰기 사이의 노출을 줄인다). 제출을 레지스트리에 올린(승인) 뒤에는 **값과 상관없이** 같은
    작업에서 다시 끄고 읽어 확인하며, 그래도 못 끄면 제출을 ``reject``로 격리한다. 그 밖의 방식:
    이미 레지스트리에 있는 서버가
    열려 있으면(``allow_all_keys=true``) 다시 끈다. 끄지 못하면 ``AllKeysNotClosed``이다.
    """
    if mode == "registry":
        submissions = client.list_submissions()
        item = next((i for i in submissions if i.get("server_id") == server_id), None)
        if item is None:
            return "SUBMISSION_GONE"
        if item.get("approval_status") == "pending_review":
            try:  # 대기 중인 서버에 쓸 수 없으면(오류·읽기 불일치) 승인 뒤 절차로 넘어간다
                client.close_all_keys(server_id)
            except LiteLLMError:
                pass
            lost: LiteLLMError | None = None
            try:
                approved = client.approve_submission(server_id)
            except LiteLLMError as error:  # 응답이 유실됐어도 승인은 반영됐을 수 있다
                approved, lost = "unknown", error
            if approved == "refused":
                return "APPROVE_REFUSED"
            if lost is not None and _status_after_lost_approval(client, server_id) not in (
                "active", None
            ):
                raise lost  # 반영되지 않았다: 재시도한다(닫기는 이미 시도했다)
        try:
            _close_all_keys(job, client, server_id)
        except AllKeysNotClosed:
            _isolate_submission(job, client, server_id)
            raise
        return None
    entry = client.get_server(server_id)
    if (
        entry is not None
        and entry.get("approval_status") in (None, "active")  # 대기·거절 제출은 건드리지 않는다
        and entry.get("allow_all_keys") is True
    ):
        _close_all_keys(job, client, server_id)
    return None


def _oauth2_flow_read(
    client: Any, server_id: str, statuses: frozenset[str]
) -> tuple[str | None, bool]:
    """(``oauth2_flow``, 읽었는가). 현재 서버 설정을 먼저, 없으면 ``statuses``의 제출을 본다."""
    try:
        entry = client.get_server(server_id) or next(
            (i for i in client.list_submissions()
             if i.get("server_id") == server_id and i.get("approval_status") in statuses), None)
    except LiteLLMError:
        return None, False
    flow = (entry or {}).get("oauth2_flow")
    return (flow if isinstance(flow, str) else None), True


def _oauth2_flow(client: Any, server_id: str) -> str | None:
    """신청 검사용: LiteLLM에 저장된 서버 설정의 ``oauth2_flow``. 읽지 못하거나 없으면 None."""
    return _oauth2_flow_read(client, server_id, frozenset({"approved", "pending_review"}))[0]


def _run_checks(
    job: JobContext, ctx: Context, row: dict, attempt: int, mode: str, persist: bool
) -> bool:
    """검사를 순서대로 실행·기록한다. 앞 단계가 실패하면 멈춘다. 자격 필요 여부를 돌려준다."""
    client = _client(job)
    server_id = row["server_id"]
    contract = intakes.deployment_candidate(job.conn, job.instance_id, server_id)
    if contract is None and mode == "evidence":  # 승인된 신청은 승인된 배포 계약으로 검사한다
        contract = intakes.approved_deployment(job.conn, job.instance_id, server_id)
    allowlists = _allowlists(job, row["org_id"])
    data = job.policy_data.get(job.conn, job.instance_id) if job.policy_data else None
    defs: list[dict] | None = None
    needs_credentials = False
    halt = False
    spec = None
    if contract is not None:
        spec = {"url": contract["url"], "transport": contract["transport"],
                "auth_type": contract["auth_type"]}
    pending: list[tuple[str, Any]] = []

    def flush() -> None:
        if not pending:
            return
        bound = intakes.contract_binding(job.conn, job.instance_id, server_id)
        for pending_name, pending_out in pending:
            intakes.record_check(ctx, row, attempt, pending_name, pending_out, bound)
        pending.clear()

    for name in checks.CHECKS:
        job.checkpoint()
        done = intakes.existing_check(job.conn, job.instance_id, row["id"], name, attempt)
        if done is not None:  # 재시도: 이 시도에서 이미 기록한 검사는 건너뛴다
            if name == "connection":
                needs_credentials = done["reason_code"] == "CREDENTIALS_REQUIRED"
                if done["reason_code"] == "ALL_KEYS_NOT_CLOSED":
                    return needs_credentials  # 끄지 못한 신청은 더 진행하지 않는다
            if name == "definitions" and done["result"] == "pass":
                defs = _stored_definitions(job, server_id)
            if done["result"] == "fail":
                return needs_credentials
            continue
        if name == "url_guard":
            out = _url_guard(job, contract, allowlists)
        elif name == "oauth_issuer_allowlist":
            auth = contract and contract["auth_type"]
            out = checks.oauth_issuer_allowlist(
                auth, contract and contract["issuer"], allowlists,
                _oauth2_flow(client, server_id) if auth == "oauth2" else None)
        elif name in ("connection", "definitions"):
            probe = dict(spec or {})
            blocked = None
            if name == "connection":
                try:
                    blocked = _gate(job, client, server_id, mode)
                except AllKeysNotClosed:
                    blocked, halt = "ALL_KEYS_NOT_CLOSED", True
            if mode == "registry":
                probe["server_id"] = server_id
            if blocked:
                out = checks.Outcome("indeterminate", blocked, "litellm:registry_first")
            elif name == "connection":
                out = checks.connection(client, probe)
            else:
                out = checks.definitions(client, probe)
                defs = out.extra.get("definitions")
                if persist and defs is not None:
                    # 재승인 계획이 진행 중이면 후보도 등급도 바꾸지 않는다
                    persist = intakes.store_candidates(ctx, server_id, defs)
            if name == "connection":
                needs_credentials = out.reason == "CREDENTIALS_REQUIRED"
        elif name == "description_scan":
            out = checks.description_scan(defs, data)
        elif name == "risk_grade":
            out = checks.risk_grade(defs, row["data_grade"], data)
            graded = out.extra.get("graded")
            if persist and graded:
                intakes.store_grades(ctx, server_id, graded)
        elif name == "termination_readiness":
            out = checks.termination_readiness(row["readiness"])
        else:
            out = checks.supply_chain(contract and contract["image_digest"],
                                      contract and contract["source_commit"])
        pending.append((name, out))
        if name == "definitions" or out.result == "fail" or halt:
            flush()  # 후보 계약이 정해진 뒤에야 증거를 계약에 결속할 수 있다
        if out.result == "fail" or halt:
            break
    flush()
    return needs_credentials


def _reject_at_litellm(job: JobContext, row: dict) -> None:
    """결정된 거절을 LiteLLM 제출에 한 번 전달한다(이미 거절됐으면 그대로 끝)."""
    if row["source"] != "submission" or row["decision"] != "rejected":
        return
    reason = (row["decision_reason"] or "rejected")[:200]
    result = _client(job).reject_submission(row["server_id"], reason)
    if result == "refused":
        # LiteLLM이 거절을 받지 않는다(이미 다른 상태로 결정된 제출). 재시도해도 같으므로 반복하지
        # 않고 경보로 남긴다. 운영자가 LiteLLM에서 그 서버를 정리한다.
        _alert_divergence(job, row["server_id"], "submission_reject_refused",
                          intake_id=str(row["id"]))


def _evidence_run(job: JobContext, ctx: Context, row: dict, attempt: int) -> None:
    """승인된 신청의 검사를 다시 한다. 서버에 드리프트가 있으면 후보 계약과 결속 증거를 저장한다.

    신청 상태는 ``decided``로 둔다. 드리프트가 없으면 증거만 새로 쌓고 후보는 만들지 않는다
    (증거 만료 재검사). 배포 드리프트면 레지스트리의 현재 값으로 배포 후보를 먼저 만든다.
    """
    persist = intakes.drift_pending(job.conn, job.instance_id, row["server_id"])
    if persist:
        server = fetchone(
            job.conn,
            "SELECT deployment_drift, deployment_drift_fields FROM mint.servers"
            " WHERE instance_id = %s AND server_id = %s",
            (job.instance_id, row["server_id"]),
        )
        approved = intakes.approved_deployment(job.conn, job.instance_id, row["server_id"])
        if server["deployment_drift"] and approved is not None:
            job.checkpoint()
            entry = _client(job).get_server(row["server_id"]) or {}
            # 운영자가 준 후보는 레지스트리 값으로 덮지 않는다(only_if_none)
            made = intakes.store_deployment_candidate(
                ctx, row["server_id"], approved, entry, only_if_none=True)
            if not made and "oauth2_flow" in (server["deployment_drift_fields"] or ()):
                # 서버 자격 흐름 드리프트: 승인된 값 그대로 후보를 두고 OAuth 검사를 다시 한다
                intakes.store_deployment_candidate(
                    ctx, row["server_id"], approved,
                    {k: approved[k] for k in ("url", "transport", "auth_type", "issuer")},
                    keep_same=True, only_if_none=True)
    _run_checks(job, ctx, row, attempt, "evidence", persist=persist)


def intake_run(job: JobContext) -> None:
    target, _, mode = job.job["target_ref"].partition("/")
    ctx = _context(job)
    row = intakes.get(ctx, target)
    if mode == "reject":
        _reject_at_litellm(job, row)
        return
    attempt = int(job.job["idempotency_key"].rsplit(":", 1)[1])
    if mode == "evidence":
        _evidence_run(job, ctx, row, attempt)
        return
    if row["status"] == "decided":
        if row["decision"] == "rejected":  # 거절 전달은 신청마다 하나의 작업으로 수렴한다
            intakes.enqueue_reject(ctx, row)
        return
    started = intakes.begin_checking(ctx, target)
    if started is None:
        return  # 필수 입력이 없으면 검사로 가지 않는다
    needs = _run_checks(job, ctx, started, attempt, mode, persist=True)
    verdict = intakes.conclude(ctx, target, needs_registry_credentials=needs)
    if verdict == "failed":
        _reject_at_litellm(job, intakes.get(ctx, target))


# --- evidence_expiry_scan -------------------------------------------------------------------


def evidence_expiry_scan(job: JobContext) -> None:
    """승인된 신청의 증거가 7일 안에 만료되면 경보 ``evidence_expiring``과 재검사를 등록한다."""
    ctx = _context(job)
    rows = fetchall(
        job.conn,
        "SELECT DISTINCT ON (i.server_id) i.id, i.server_id FROM mint.intakes i"
        " JOIN mint.servers s ON s.instance_id = i.instance_id AND s.server_id = i.server_id"
        " WHERE i.instance_id = %s AND i.status = 'decided'"
        " AND i.decision IN ('approved', 'exception') AND s.contract_status = 'managed'"
        " AND s.status NOT IN ('rejected', 'terminating', 'terminated')"
        " ORDER BY i.server_id, i.decided_at DESC",
        (job.instance_id,),
    )
    horizon = datetime.now(UTC) + EXPIRY_WARNING
    for row in rows:
        job.checkpoint()
        expiring = [
            c for c in intakes.latest_checks(job.conn, job.instance_id, row["id"])
            if c["evidence_valid_until"] is not None and c["evidence_valid_until"] <= horizon
        ]
        if not expiring:
            continue
        for c in expiring:
            with job.conn.transaction():
                alerts.raise_alert(
                    job.conn, job.instance_id, kind="evidence_expiring", severity="medium",
                    dedup_key=f"evidence_expiring:{row['id']}:{c['check']}"[:512],
                    subject={"intake_id": str(row["id"]), "server_id": row["server_id"],
                             "check": c["check"],
                             "valid_until": c["evidence_valid_until"].isoformat()})
        attempt = intakes.next_attempt(job.conn, job.instance_id, row["id"])
        enqueue_job(ctx, "intake_run", f"{row['id']}/evidence",
                    intake_run_job_key(row["id"], attempt))


HANDLERS = {
    "submission_poll": submission_poll,
    "intake_run": intake_run,
    "evidence_expiry_scan": evidence_expiry_scan,
}
