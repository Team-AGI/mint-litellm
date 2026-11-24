"""수용검증 작업 처리기: ``submission_poll``, ``intake_run``, ``evidence_expiry_scan``.

LiteLLM 읽기·쓰기는 모두 제어 평면 클라이언트(``JobContext.litellm``)를 통한다. 쓰기(제출
승인·거절)는 클라이언트의 쓰기 메서드 한 곳을 지나며, 그 직전에 공통 경계
``JobContext.external_write``가 불린다.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg.types.json import Jsonb

from mint_litellm.control import alerts, inspection, packs, source_scan
from mint_litellm.control import allowlists as allowlist_domain
from mint_litellm.control import intake_checks as checks
from mint_litellm.control import servers as server_domain
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.jobs import JobContext
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.services import evidence, intakes
from mint_litellm.control.services import intake_inspections as inspections
from mint_litellm.control.services.base import enqueue_job, transact
from mint_litellm.types.exec_contract import ExecContract
from mint_litellm.types.ids import new_uuid7
from mint_litellm.types.jobs import intake_run_job_key

POLL_LIMIT = 500
PACK_PYTHON = "3.12"
# 시간이 지나면 풀릴 수 있는 묶음 실패(기본 저장소 미등록, 네트워크·의존 판본 해석 실패)
RETRYABLE_PACK_REASONS = ("PACK_INDEX_NOT_ALLOWED", "PACK_RESOLVE_FAILED")
PACK_RETRIES = intakes.RETRY_LIMIT  # 5분 간격으로 약 1시간
START_FAILED_REASONS = intakes.START_FAILED_REASONS
DEFAULT_LOCAL_PYTHON = "/usr/bin/python3"
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


def _oauth_config_read(
    client: Any, server_id: str, statuses: frozenset[str]
) -> tuple[str | None, list[str], bool]:
    """(``oauth2_flow``, OAuth 범위, 읽었는가).

    현재 서버 설정을 먼저, 없으면 ``statuses``의 제출을 본다.
    """
    try:
        entry = client.get_server(server_id) or next(
            (i for i in client.list_submissions()
             if i.get("server_id") == server_id and i.get("approval_status") in statuses), None)
    except LiteLLMError:
        return None, [], False
    flow = (entry or {}).get("oauth2_flow")
    return (flow if isinstance(flow, str) else None), checks.oauth_scopes_of(entry), True


def _oauth2_flow_read(
    client: Any, server_id: str, statuses: frozenset[str]
) -> tuple[str | None, bool]:
    """(``oauth2_flow``, 읽었는가)."""
    flow, _, readable = _oauth_config_read(client, server_id, statuses)
    return flow, readable


def _oauth2_flow(client: Any, server_id: str) -> str | None:
    """신청 검사용: LiteLLM에 저장된 서버 설정의 ``oauth2_flow``. 읽지 못하거나 없으면 None."""
    return _oauth2_flow_read(client, server_id, frozenset({"approved", "pending_review"}))[0]


class StaffRegistryConflict(ControlError):
    """다른 등록이나 열린 등록을 도입 검증 대상으로 재사용하지 않는다."""


def _staff_registry(client: Any, row: dict, contract: dict | None) -> None:
    """직원 신청의 재시도는 이 신청이 만든 비공개 서버만 재사용한다."""
    if contract is None:
        raise ControlError("직원 신청의 배포 계약이 없습니다.")
    expected = {"mint_intake_id": str(row["id"]), "mint_url_sha256": contract["url_sha256"]}
    entry = client.get_server(row["server_id"])
    if entry is None:
        client.provision_staff_server(row["server_id"], contract["url"], contract["transport"],
                                      str(row["id"]), contract["url_sha256"])
        entry = client.get_server(row["server_id"])
    if (entry is None or not isinstance(entry.get("mcp_info"), dict)
            or any(entry["mcp_info"].get(k) != v for k, v in expected.items())
            or entry.get("allow_all_keys") is not False):
        raise StaffRegistryConflict("도입 신청과 다른 서버 등록이 있거나 "
                                    "비공개 상태를 확인하지 못했습니다.")


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
            if mode == "staff" and out.result == "fail" and out.reason == "PROVIDER_NOT_ALLOWED":
                # 직원은 제공자 허용 목록을 알 수 없다. 자동 거절하지 않고 관리자 판단으로 넘기되,
                # 허용되지 않은 곳에 접속하지 않도록 검사는 여기서 멈춘다.
                out = replace(out, result="indeterminate")
                halt = True
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
                    if mode == "staff" and row.get("staff_registry_required"):
                        _staff_registry(client, row, contract)
                    blocked = _gate(job, client, server_id, mode)
                except AllKeysNotClosed:
                    blocked, halt = "ALL_KEYS_NOT_CLOSED", True
                except StaffRegistryConflict:
                    blocked, halt = "REGISTRY_ID_CONFLICT", True
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


def _record_pack(job: JobContext, ctx: Context, contract: dict, spec: dict,
                 digest: str, manifest: dict) -> None:
    """같은 배포 계약 행에 묶음 해시·manifest·실행 계약(판 2)을 적는다. 다시 써도 같다."""
    python = getattr(job.settings, "local_python", None) or DEFAULT_LOCAL_PYTHON
    legacy = fetchone(job.conn, "SELECT network_legacy FROM mint.intakes WHERE id = %s",
                      (contract["id"],))
    with transact(ctx):
        ctx.conn.execute(
            "UPDATE mint.deployment_contracts SET pack_sha256 = %s, pack_manifest = %s::jsonb,"
            " exec_contract = %s::jsonb WHERE instance_id = %s AND id = %s",
            (digest, json.dumps(manifest), json.dumps(
                checks.local_exec_contract(
                    spec, digest, manifest, python, bool(legacy and legacy["network_legacy"]))),
             job.instance_id, contract["id"]),
        )
        # 묶음·계약이 바뀌면 열린 검사용 승인은 쓸 수 없다
        inspections.invalidate_changed(ctx.conn, job.instance_id, contract["id"])


def _run_local_checks(job: JobContext, ctx: Context, row: dict, attempt: int) -> None:
    """단말 출처 신청의 검사. 이름·인자 수 위반만 거절이고 나머지 실패는 판별 불가이다."""
    server_id = row["server_id"]
    with transact(ctx):
        allowlist_domain.ensure_defaults(ctx)
    contract = intakes.deployment_candidate(job.conn, job.instance_id, server_id)
    spec = contract and contract.get("pack_spec")
    data = job.policy_data.get(job.conn, job.instance_id) if job.policy_data else None
    allowlists = _allowlists(job, row["org_id"])
    pack: tuple[str, dict] | None = None
    defs: list[dict] | None = None
    pending: list[tuple[str, Any]] = []

    def flush() -> None:
        bound = intakes.contract_binding(job.conn, job.instance_id, server_id)
        for pending_name, pending_out in pending:
            intakes.record_check(ctx, row, attempt, pending_name, pending_out, bound)
        pending.clear()

    for name in checks.LOCAL_CHECKS:
        job.checkpoint()
        done = intakes.existing_check(job.conn, job.instance_id, row["id"], name, attempt)
        if done is not None:  # 재시도: 이 시도에서 이미 기록한 검사는 건너뛴다
            if name == "pack_build" and done["result"] == "pass" and contract:
                pack = (contract["pack_sha256"], contract["pack_manifest"])
            if name == "inspection" and done["result"] == "pass":
                defs = _stored_definitions(job, server_id)
            if done["result"] == "fail":
                return
            continue
        if name == "exec_shape":
            out = checks.exec_shape(spec)
        elif name == "pack_build":
            try:
                pack = packs.build_pack(spec, allowlists, python=PACK_PYTHON)
                _record_pack(job, ctx, contract, spec, *pack)
                out = checks.pack_build_outcome(*pack)
            except packs.PackError as error:
                out = checks.pack_build_failed(error.code)
        elif name == "inspection":
            if pack is None:
                out = checks.Outcome("indeterminate", "PACK_UNAVAILABLE", "inspector:tools_list")
            else:
                out = checks.inspection_outcome(
                    inspection.inspect_pack(pack[0], pack[1]["entry"], spec.get("argv", [])))
                defs = out.extra.get("definitions")
                if defs is not None:
                    intakes.store_candidates(ctx, server_id, defs)
        elif name == "description_scan":
            out = checks.description_scan(defs, data)
        elif name == "risk_grade":
            out = checks.risk_grade(defs, row["data_grade"], data)
            if out.extra.get("graded"):
                intakes.store_grades(ctx, server_id, out.extra["graded"])
        elif name == "sbom":
            out = source_scan.sbom_outcome(pack and pack[1])
        elif name == "code_scan":
            request = source_scan.scan_request(spec, pack)
            out = source_scan.code_outcome(
                source_scan.request_scan(request, wait=job.checkpoint) if request else None)
        elif name == "dependency_vulns":
            feed = getattr(job.settings, "vuln_feed_url", None) or "https://api.osv.dev"
            out = source_scan.dependency_outcome(pack and pack[1], feed)
        else:
            out = checks.termination_readiness(row["readiness"])
        pending.append((name, out))
        if name == "inspection" or out.result == "fail":
            flush()  # 후보 계약이 정해진 뒤에야 증거를 계약에 결속할 수 있다
        if out.result == "fail":
            return
    flush()


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
                    {k: approved[k] for k in ("url", "transport", "auth_type", "issuer",
                                              "oauth_scopes")},
                    keep_same=True, only_if_none=True)
    _run_checks(job, ctx, row, attempt, "evidence", persist=persist)


def _repack_run(job: JobContext, ctx: Context, row: dict, attempt: int) -> None:
    """승인된 뒤 서버가 시작되지 않는 단말 신청: 승인된 묶음 명세로 판본 맞춤 묶음을 다시 만든다.

    승인된 계약은 묶음 열이 고정이라, 새 묶음이 다르면 같은 명세·같은 권한으로 계약을 갈아 끼운다
    (이전 계약은 대체됨). 권한은 넓어지지 않고 승인·이용 범위·신청 상태는 그대로이다.
    """
    approved = intakes.approved_deployment(job.conn, job.instance_id, row["server_id"])
    spec = approved and approved.get("pack_spec")
    if not spec or not isinstance(approved.get("exec_contract"), dict):
        return
    try:
        digest, manifest = packs.build_pack(spec, _allowlists(job, row["org_id"]),
                                            python=PACK_PYTHON)
    except packs.PackError as error:
        intakes.record_check(ctx, row, attempt, "pack_build", checks.pack_build_failed(error.code))
        return
    if digest != approved["pack_sha256"]:
        _swap_pack(job, ctx, approved, digest, manifest)
    out = checks.inspection_outcome(
        inspection.inspect_pack(digest, manifest["entry"], spec.get("argv", [])))
    intakes.record_check(ctx, row, attempt, "inspection", out)
    defs = out.extra.get("definitions")
    if defs is not None:
        data = job.policy_data.get(job.conn, job.instance_id) if job.policy_data else None
        intakes.record_check(ctx, row, attempt, "description_scan",
                             checks.description_scan(defs, data))
        intakes.record_check(ctx, row, attempt, "risk_grade",
                             checks.risk_grade(defs, row["data_grade"], data))


def _swap_pack(job: JobContext, ctx: Context, approved: dict, digest: str,
               manifest: dict) -> None:
    """승인된 배포 계약을 묶음만 다른 새 계약으로 대체하고 서버의 계약 값을 맞춘다."""
    document = {k: v for k, v in approved["exec_contract"].items() if k != "identity_kind"}
    document["pack"] = {**document["pack"], "sha256": digest,
                        "python": manifest["platform"]["python"], "entry": manifest["entry"]}
    contract = ExecContract.model_validate(document)
    keep = {k: v for k, v in approved.items() if k not in (
        "id", "status", "version", "pack_sha256", "pack_manifest", "exec_contract",
        "exec_contract_sha256", "exec_contract_version")}
    if keep.get("pack_spec") is not None:
        keep["pack_spec"] = Jsonb(keep["pack_spec"])
    columns = ", ".join(["id", *keep])
    new_id = new_uuid7()
    with transact(ctx):
        ctx.conn.execute("UPDATE mint.deployment_contracts SET status = 'superseded'"
                         " WHERE id = %s", (approved["id"],))
        ctx.conn.execute(
            f"INSERT INTO mint.deployment_contracts ({columns}) VALUES"
            f" ({', '.join(['%s'] * (len(keep) + 1))})", (new_id, *keep.values()))
        ctx.conn.execute(
            "UPDATE mint.deployment_contracts SET pack_sha256 = %s, pack_manifest = %s::jsonb,"
            " exec_contract_sha256 = %s, exec_contract_version = %s, exec_contract = %s::jsonb,"
            " status = 'approved' WHERE id = %s",
            (digest, json.dumps(manifest), contract.sha256(), contract.schema_version,
             json.dumps(contract.document()), new_id))
        server_domain.register_local(ctx, approved["server_id"], contract)
        inspections.invalidate_changed(ctx.conn, job.instance_id, new_id)
        enqueue_job(ctx, "kit_key_sync", "all")  # 단말이 새 묶음을 받도록


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
    if mode == "repack":
        _repack_run(job, ctx, row, attempt)
        return
    if row["status"] == "decided":
        if row["decision"] == "rejected":  # 거절 전달은 신청마다 하나의 작업으로 수렴한다
            intakes.enqueue_reject(ctx, row)
        return
    started = intakes.begin_checking(ctx, target)
    if started is None:
        return  # 필수 입력이 없으면 검사로 가지 않는다
    if started["source"] == "staff" and intakes.server_approved(
            job.conn, job.instance_id, started["server_id"]):
        intakes.skip_checks(ctx, target)  # 이미 승인된 서버: 이용 범위만 더한다
        return
    if started["source"] == "endpoint":
        _run_local_checks(job, ctx, started, attempt)
        needs = False
    else:
        needs = _run_checks(job, ctx, started, attempt, mode, persist=True)
    intakes.conclude(ctx, target, needs_registry_credentials=needs)
    _finish_deferred(job, ctx, target)


def _finish_deferred(job: JobContext, ctx: Context, intake_id: str) -> None:
    """보류된 승인이 있으면 묶음이 준비된 때 적용한다. 끝내 안 되면 경보 한 줄을 남긴다."""
    result = intakes.apply_deferred_approval(
        ctx, intake_id, (lambda: _client(job)) if job.litellm is not None else None)
    row = intakes.get(ctx, intake_id)
    if result is None and row["approve_when_ready"] is None:
        return
    if result is not None and not result.startswith("failed"):
        return
    reason = result or "묶음을 만들지 못했습니다."
    tries = intakes.next_attempt(job.conn, job.instance_id, row["id"])
    if result is None and tries <= PACK_RETRIES:
        return  # 자동 재시도가 이어진다
    with job.conn.transaction():
        alerts.raise_alert(
            job.conn, job.instance_id, kind="job_failed", severity="high",
            dedup_key=f"job_failed:pack:{row['id']}",
            subject={"target_ref": row["server_id"], "reason": reason[:200]})


# 묶음은 있는데 가장 최근 시도의 검사에서 서버가 시작되지 못한 신청(인자: 사유 목록)
_START_FAILED = (
    "EXISTS (SELECT 1 FROM mint.intake_checks c WHERE c.instance_id = i.instance_id"
    " AND c.intake_id = i.id AND c.\"check\" = 'inspection' AND c.result = 'indeterminate'"
    " AND {reason} AND c.attempt = ("
    " SELECT max(m.attempt) FROM mint.intake_checks m WHERE m.instance_id = i.instance_id"
    " AND m.intake_id = i.id AND m.\"check\" = 'inspection'))"
)
_UNAPPROVED_FAILED = _START_FAILED.format(reason="c.reason_code <> 'ENDPOINT_INSPECTED'")
_APPROVED_FAILED = _START_FAILED.format(
    reason="(c.reason_code = ANY(%s) OR (c.reason_code = 'INSPECTION_FAILED'"
    " AND coalesce(c.inputs #>> '{detail,stage}', c.inputs ->> 'stage') = 'start'))")


def local_pack_retry(job: JobContext) -> None:
    """기본 저장소를 넣고, 묶음이 없어 막히거나 서버가 시작되지 못한 단말 신청을 다시 만든다.

    승인 전 신청은 다시 검사하고, 승인된 신청은 승인된 명세로 묶음을 다시 만든다(횟수 상한까지).
    """
    ctx = _context(job)
    with transact(ctx):
        allowlist_domain.ensure_defaults(ctx)
    rows = fetchall(
        job.conn,
        "SELECT i.id, (i.status = 'decided') AS approved FROM mint.intakes i"
        " WHERE i.instance_id = %s AND i.source = 'endpoint'"
        " AND ((i.status IN ('indeterminate', 'failed', 'passed') AND ((NOT EXISTS ("
        " SELECT 1 FROM mint.deployment_contracts d WHERE d.instance_id = i.instance_id"
        " AND d.server_id = i.server_id AND d.status = 'candidate' AND d.pack_sha256 IS NOT NULL)"
        " AND (i.approve_when_ready IS NOT NULL OR EXISTS ("
        " SELECT 1 FROM mint.intake_checks c WHERE c.instance_id = i.instance_id"
        " AND c.intake_id = i.id AND c.\"check\" = 'pack_build'"
        " AND c.reason_code = ANY(%s)))) OR " + _UNAPPROVED_FAILED + "))"
        " OR (i.status = 'decided' AND i.decision IN ('approved', 'exception')"
        " AND EXISTS (SELECT 1 FROM mint.servers s WHERE s.instance_id = i.instance_id"
        " AND s.server_id = i.server_id AND s.status = 'approved') AND " + _APPROVED_FAILED + "))",
        (job.instance_id, list(RETRYABLE_PACK_REASONS), list(START_FAILED_REASONS)),
    )
    for row in rows:
        job.checkpoint()
        attempt = intakes.next_attempt(job.conn, job.instance_id, row["id"])
        if attempt > PACK_RETRIES:
            if not row["approved"]:
                _finish_deferred(job, ctx, str(row["id"]))
        elif row["approved"]:
            enqueue_job(ctx, "intake_run", f"{row['id']}/repack",
                        intake_run_job_key(row["id"], attempt))
        else:
            intakes.enqueue_run(ctx, intakes.get(ctx, str(row["id"])))


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
    evidence.scan_alerts(job.conn, job.instance_id)  # 사람이 확인하는 증빙의 없음·만료 경보
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
    "local_pack_retry": local_pack_retry,
}
