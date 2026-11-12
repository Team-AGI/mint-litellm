"""수용검증 신청 서비스: 신청 생성·신청자 지정·재검사·결정, 그리고 작업 처리기가 쓰는 상태 전이.

모든 상태 변경은 한 트랜잭션(상태 + 사건 + 작업 등록)이다. LiteLLM은 이 안에서 부르지 않는다.
"""

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from mint_litellm.control import intake_checks
from mint_litellm.control.approvals import _derive_org
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import (
    ControlError,
    conflict,
    not_found,
    separation_of_duties,
    stale_evidence,
)
from mint_litellm.control.services import evidence
from mint_litellm.control.services.base import (
    Prefetched,
    enqueue_job,
    require_role,
    transact,
)
from mint_litellm.types.canonical import canonical_text, pin_sha256, sha256
from mint_litellm.types.cli_commands import APPROVER_UP
from mint_litellm.types.decision import normalize_auth_type, url_sha256
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7
from mint_litellm.types.jobs import intake_reject_job_key, intake_run_job_key

DATA_GRADES = ("public", "internal", "confidential", "restricted")
READINESS_KEYS = ("credential_notice", "revocation_record", "audit_access_days")
EVIDENCE_MAX_AGE = timedelta(hours=24)
EXCEPTION_MAX_DAYS = 90
DEFAULT_DAYS = 90
DEFAULT_SHORT_DAYS = 30
SYSTEM_ACTOR = "intake_run"
_REQUIRED = (
    "purpose", "data_grade", "allowed_resources", "provider", "owner_user_id", "readiness",
    "data_return_terms", "requested_by",
)
# 서버 행이 새 신청으로 이어질 수 있는 상태(재검사 전이가 있는 상태)
_SERVER_REENTRY = ("pending", "awaiting_approval", "rejected")


# --- 읽기 보조 ---------------------------------------------------------------------


def get(ctx: Context, intake_id: str, *, lock: bool = False) -> dict:
    row = fetchone(
        ctx.conn,
        "SELECT * FROM mint.intakes WHERE instance_id = %s AND id = %s"
        + (" FOR UPDATE" if lock else ""),
        (ctx.instance_id, intake_id),
    )
    if row is None:
        raise not_found(f"신청 {intake_id}이(가) 없습니다.")
    return row


def is_complete(row: dict) -> bool:
    return all(row[name] is not None for name in _REQUIRED)


def next_attempt(conn: Any, instance_id: str, intake_id: Any) -> int:
    row = fetchone(
        conn,
        "SELECT coalesce(max(attempt), 0) + 1 AS n FROM mint.intake_checks"
        " WHERE instance_id = %s AND intake_id = %s",
        (instance_id, intake_id),
    )
    return row["n"]


def latest_checks(conn: Any, instance_id: str, intake_id: Any) -> list[dict]:
    """각 검사의 가장 최근 시도 행(검사 순서)."""
    rows = fetchall(
        conn,
        "SELECT DISTINCT ON (\"check\") * FROM mint.intake_checks"
        " WHERE instance_id = %s AND intake_id = %s ORDER BY \"check\", attempt DESC",
        (instance_id, intake_id),
    )
    order = {name: i for i, name in enumerate(intake_checks.CHECKS)}
    return sorted(rows, key=lambda r: order[r["check"]])


def list_intakes(ctx: Context, status: str | None = None) -> list[dict]:
    require_role(ctx, "intake list")
    return fetchall(
        ctx.conn,
        "SELECT id, server_id, source, status, decision, requested_by, owner_user_id, created_at,"
        " decided_at, state_version FROM mint.intakes WHERE instance_id = %s"
        " AND (%s::text IS NULL OR status = %s) ORDER BY created_at DESC, id",
        (ctx.instance_id, status, status),
    )


def show(ctx: Context, intake_id: str) -> dict:
    require_role(ctx, "intake show")
    row = get(ctx, intake_id)
    checks = latest_checks(ctx.conn, ctx.instance_id, row["id"])
    contracts = fetchall(
        ctx.conn,
        "SELECT tool, risk_grade, action_type, status FROM mint.tool_contracts"
        " WHERE instance_id = %s AND server_id = %s AND status IN ('candidate', 'approved')"
        " ORDER BY tool",
        (ctx.instance_id, row["server_id"]),
    )
    return {"intake": row, "checks": checks, "tool_contracts": contracts}


# --- 서버 행과 배포 계약 후보 ----------------------------------------------------------


def _ensure_server(
    ctx: Context, server_id: str, url: str | None, transport: str, auth_type: str,
    issuer: str | None, registered_by: str,
) -> None:
    digest = url_sha256(url or "")
    server = fetchone(
        ctx.conn,
        "SELECT id, status FROM mint.servers WHERE instance_id = %s AND server_id = %s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    if server is None:
        ctx.conn.execute(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport,"
            " auth_type, registered_by, issuer) VALUES (%s, %s, %s, 'pending', %s, %s, %s, %s, %s)",
            (new_uuid7(), ctx.instance_id, server_id, digest, transport, auth_type, registered_by,
             issuer),
        )
        return
    if server["status"] not in _SERVER_REENTRY:
        raise ControlError(
            f"서버 {server_id}는 {server['status']} 상태라 새 수용검증을 시작할 수 없습니다."
        )
    ctx.conn.execute(
        "UPDATE mint.servers SET url_sha256 = %s, transport = %s, auth_type = %s WHERE id = %s",
        (digest, transport, auth_type, server["id"]),
    )


def _deployment_candidate(
    ctx: Context, server_id: str, url: str, transport: str, auth_type: str, issuer: str | None,
    allowed_tools: list[str] | None, image_digest: str | None, source_commit: str | None,
    proposed_by: str | None = None,
) -> None:
    """배포 계약 후보를 새로 만든다. 이전 후보는 대체된다."""
    ctx.conn.execute(
        "UPDATE mint.deployment_contracts SET status = 'superseded' WHERE instance_id = %s"
        " AND server_id = %s AND status = 'candidate'",
        (ctx.instance_id, server_id),
    )
    values = {
        "url": url, "transport": transport, "auth_type": auth_type, "issuer": issuer,
        "oauth_scopes": [], "allowed_tools": allowed_tools, "image_digest": image_digest,
        "source_commit": source_commit,
    }
    text = canonical_text(values)
    ctx.conn.execute(
        "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text, sha256,"
        " url, url_sha256, transport, auth_type, issuer, oauth_scopes, allowed_tools, image_digest,"
        " source_commit, proposed_by)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (new_uuid7(), ctx.instance_id, server_id, text, intake_checks.sha256_hex(text), url,
         url_sha256(url), transport, auth_type, issuer, [], allowed_tools, image_digest,
         source_commit, proposed_by),
    )


def deployment_candidate(conn: Any, instance_id: str, server_id: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT * FROM mint.deployment_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status = 'candidate' ORDER BY id DESC LIMIT 1",
        (instance_id, server_id),
    )


def _enqueue_run(ctx: Context, row: dict, mode: str = "") -> str:
    """수용검증 작업을 등록한다. 시도 번호가 같으면 한 작업이다."""
    target = f"{row['id']}/{mode}" if mode else str(row["id"])
    if mode == "reject":  # 같은 신청의 LiteLLM 거절 전달은 어느 경로에서든 한 작업이다
        return enqueue_job(ctx, "intake_run", target, intake_reject_job_key(row["id"]))
    attempt = next_attempt(ctx.conn, ctx.instance_id, row["id"])
    return enqueue_job(ctx, "intake_run", target, intake_run_job_key(row["id"], attempt))


# --- 신청 생성 ---------------------------------------------------------------------------


def _validated_inputs(
    purpose: str, data_grade: str, allowed_resources: Any, provider: str, owner_user_id: str,
    readiness: dict, data_return_terms: str,
) -> dict:
    if not 1 <= len(purpose.strip()) <= 256:
        raise ControlError("목적은 1자 이상 256자 이하여야 합니다.")
    if data_grade not in DATA_GRADES:
        raise ControlError(f"자료 등급은 {', '.join(DATA_GRADES)} 중 하나여야 합니다.")
    if not isinstance(allowed_resources, (list, dict)):
        raise ControlError("허용 자원은 JSON 배열이나 객체여야 합니다.")
    if not provider.strip() or not owner_user_id.strip() or not data_return_terms.strip():
        raise ControlError("제공자, 책임자, 자료 삭제·반환 조건은 비어 있을 수 없습니다.")
    if not isinstance(readiness, dict) or set(readiness) != set(READINESS_KEYS):
        raise ControlError(
            "종료 준비도는 " + ", ".join(READINESS_KEYS) + " 세 항목을 모두 가져야 합니다."
        )
    return {
        "purpose": purpose.strip(), "data_grade": data_grade,
        "allowed_resources": allowed_resources, "provider": provider.strip(),
        "owner_user_id": owner_user_id.strip(), "readiness": readiness,
        "data_return_terms": data_return_terms.strip(),
    }


def create(
    ctx: Context,
    litellm: Any,
    server_id: str,
    *,
    url: str | None = None,
    org_id: str | None = None,
    purpose: str,
    data_grade: str,
    allowed_resources: Any,
    provider: str,
    owner_user_id: str,
    readiness: dict,
    data_return_terms: str,
    image_digest: str | None = None,
    source_commit: str | None = None,
    expected_version: int | None = None,
) -> str:
    """신청을 만든다. 같은 서버에 제출에서 온 ``received`` 신청이 있으면 그 신청의 입력을 채운다."""
    require_role(ctx, "intake create")
    inputs = _validated_inputs(
        purpose, data_grade, allowed_resources, provider, owner_user_id, readiness,
        data_return_terms,
    )
    existing = fetchone(
        ctx.conn,
        "SELECT id FROM mint.intakes WHERE instance_id = %s AND server_id = %s"
        " AND status <> 'decided'",
        (ctx.instance_id, server_id),
    )
    facts = Prefetched(litellm)
    if existing is None:
        facts.prefetch("get_server", server_id)
    with transact(ctx):
        existing = fetchone(
            ctx.conn,
            "SELECT * FROM mint.intakes WHERE instance_id = %s AND server_id = %s"
            " AND status <> 'decided' FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        if existing is not None:
            return _fill(ctx, existing, inputs, image_digest, source_commit, expected_version)
        entry = facts.get_server(server_id)
        if entry is None:
            raise ControlError(f"LiteLLM에 서버 {server_id}이(가) 없습니다.")
        if ctx.operator.user_id is None:
            raise ControlError("신청자는 LiteLLM 사용자에 결속된 운영자여야 합니다.")
        org = org_id or _derive_org(ctx, None, ctx.operator.user_id)
        if org is None:
            raise ControlError(
                "조직을 정할 수 없습니다. --org를 지정하거나 기본 조직을 설정하십시오."
            )
        resolved = url or entry.get("url")
        transport = "openapi" if entry.get("spec_path") else entry.get("transport") or ""
        if not transport:
            raise ControlError(f"서버 {server_id}의 전송 방식을 읽을 수 없습니다.")
        if not resolved and transport not in ("stdio", "openapi"):
            raise ControlError(
                "제어 평면 키에는 서버 URL이 응답되지 않습니다. "
                "--url로 계약 값에 쓸 URL을 지정하십시오."
            )
        auth_type = normalize_auth_type(entry.get("auth_type"))
        issuer = entry.get("issuer")
        _ensure_server(ctx, server_id, resolved, transport, auth_type, issuer, ctx.operator.name)
        if resolved:
            _deployment_candidate(ctx, server_id, resolved, transport, auth_type, issuer, None,
                                  image_digest, source_commit)
        intake_id = new_uuid7()
        row = fetchone(
            ctx.conn,
            "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, purpose,"
            " data_grade, allowed_resources, provider, owner_user_id, readiness, data_return_terms,"
            " requested_by) VALUES (%s, %s, %s, %s, 'operator', %s, %s, %s::jsonb, %s, %s,"
            " %s::jsonb, %s, %s) RETURNING *",
            (intake_id, ctx.instance_id, org, server_id, inputs["purpose"], inputs["data_grade"],
             json.dumps(inputs["allowed_resources"]), inputs["provider"], inputs["owner_user_id"],
             json.dumps(inputs["readiness"]), inputs["data_return_terms"], ctx.operator.user_id),
        )
        ctx.emit(EventKind.INTAKE_RECEIVED, intake_id, row["state_version"],
                 {"intake_id": str(intake_id), "server_id": server_id, "source": "operator",
                  "requested_by": ctx.operator.user_id})
        _enqueue_run(ctx, row)
        return str(intake_id)


def _fill(
    ctx: Context, existing: dict, inputs: dict, image_digest: str | None,
    source_commit: str | None, expected_version: int | None,
) -> str:
    if existing["status"] != "received":
        raise conflict(f"서버 {existing['server_id']}에 결정되지 않은 신청이 이미 있습니다"
                       f"({existing['status']}).")
    if expected_version is not None and existing["state_version"] != expected_version:
        raise conflict(f"신청의 상태 버전이 요청({expected_version})과 다릅니다"
                       f"(현재 {existing['state_version']}).")
    row = fetchone(
        ctx.conn,
        "UPDATE mint.intakes SET purpose = %s, data_grade = %s, allowed_resources = %s::jsonb,"
        " provider = %s, owner_user_id = %s, readiness = %s::jsonb, data_return_terms = %s"
        " WHERE id = %s RETURNING *",
        (inputs["purpose"], inputs["data_grade"], json.dumps(inputs["allowed_resources"]),
         inputs["provider"], existing["owner_user_id"] or inputs["owner_user_id"],
         json.dumps(inputs["readiness"]), inputs["data_return_terms"], existing["id"]),
    )
    if image_digest or source_commit:
        cand = deployment_candidate(ctx.conn, ctx.instance_id, existing["server_id"])
        if cand is not None:
            _deployment_candidate(ctx, existing["server_id"], cand["url"], cand["transport"],
                                  cand["auth_type"], cand["issuer"], cand["allowed_tools"],
                                  image_digest, source_commit)
    if row["requested_by"] is not None:
        _enqueue_run(ctx, row)
    return str(row["id"])


# --- 제출 수신(작업 처리기) ----------------------------------------------------------------


def receive_submission(ctx: Context, item: dict) -> str | None:
    """LiteLLM 제출 한 건을 신청(``received``)으로 만든다. 이미 신청이 있으면 None."""
    server_id = item.get("server_id")
    if not isinstance(server_id, str) or not server_id:
        return None
    submitted_by = (item.get("submitted_by") or "").strip() or None
    with transact(ctx):
        open_one = fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.intakes WHERE instance_id = %s AND server_id = %s"
            " AND (status <> 'decided' OR decided_at >= %s::timestamptz)",
            (ctx.instance_id, server_id,
             item.get("submitted_at") or datetime.min.replace(tzinfo=UTC)),
        )
        if open_one:
            return None
        org = _derive_org(ctx, None, submitted_by)
        if org is None:
            return None  # 조직을 정할 수 없으면 다음 조회에서 다시 본다
        url = item.get("url") or None
        transport = "openapi" if item.get("spec_path") else item.get("transport") or "http"
        auth_type = normalize_auth_type(item.get("auth_type"))
        issuer = item.get("issuer") or None
        server = fetchone(
            ctx.conn,
            "SELECT status FROM mint.servers WHERE instance_id = %s AND server_id = %s",
            (ctx.instance_id, server_id),
        )
        if server is not None and server["status"] not in _SERVER_REENTRY:
            return None
        _ensure_server(ctx, server_id, url, transport, auth_type, issuer, SYSTEM_ACTOR)
        if url:
            allowed = [t for t in (item.get("allowed_tools") or []) if isinstance(t, str)]
            _deployment_candidate(ctx, server_id, url, transport, auth_type, issuer,
                                  allowed or None, None, None)
        intake_id = new_uuid7()
        row = fetchone(
            ctx.conn,
            "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, requested_by,"
            " owner_user_id) VALUES (%s, %s, %s, %s, 'submission', %s, %s) RETURNING state_version",
            (intake_id, ctx.instance_id, org, server_id, submitted_by, submitted_by),
        )
        ctx.emit(EventKind.INTAKE_RECEIVED, intake_id, row["state_version"],
                 {"intake_id": str(intake_id), "server_id": server_id, "source": "submission",
                  "requested_by": submitted_by})
        return str(intake_id)


# --- 신청자 지정·재검사 -----------------------------------------------------------------------


def assign_requester(
    ctx: Context, litellm: Any, intake_id: str, user_id: str, *, expected_version: int | None = None
) -> None:
    require_role(ctx, "intake assign")
    facts = Prefetched(litellm).prefetch("get_user", user_id)
    with transact(ctx):
        row = get(ctx, intake_id, lock=True)
        if expected_version is not None and row["state_version"] != expected_version:
            raise conflict(f"신청의 상태 버전이 요청({expected_version})과 다릅니다"
                           f"(현재 {row['state_version']}).")
        if row["status"] != "received" or row["requested_by"] is not None:
            raise conflict("신청자를 지정할 수 있는 것은 신청자가 비어 있는 received 신청뿐입니다.")
        user = facts.get_user(user_id)
        if user is None or user.get("user_role") == "service_account":
            raise ControlError(f"LiteLLM에서 사람 사용자 {user_id}을(를) 찾을 수 없습니다.")
        if user_id == ctx.operator.user_id:
            raise separation_of_duties("운영자 본인을 신청자로 지정할 수 없습니다.")
        updated = fetchone(
            ctx.conn,
            "UPDATE mint.intakes SET requested_by = %s,"
            " owner_user_id = coalesce(owner_user_id, %s) WHERE id = %s RETURNING *",
            (user_id, user_id, row["id"]),
        )
        ctx.emit(EventKind.INTAKE_REQUESTER_ASSIGNED, row["id"], updated["state_version"],
                 {"intake_id": str(row["id"]), "server_id": row["server_id"],
                  "requested_by": user_id, "assigned_by": ctx.operator.name})
        if is_complete(updated):
            _enqueue_run(ctx, updated)


def recheck(
    ctx: Context, intake_id: str, *, registry_first: bool = False,
    expected_version: int | None = None, url: str | None = None, transport: str | None = None,
) -> str:
    """재검사 작업을 등록한다. ``registry_first``는 제출 서버를 레지스트리에 올린 뒤 검사한다.

    승인된 신청(``decided``, 승인·예외)은 ``evidence`` 모드로 받는다. 이 재검사는 서버에
    드리프트가 있으면 후보 계약과 결속된 증거를 저장하고, 신청 상태는 ``decided``로 둔다.
    ``url``(과 ``transport``)은 LiteLLM이 서버 URL을 돌려주지 않을 때 운영자가 주는 새 배포 주소로,
    관측된 배포 URL 해시와 같을 때만 받아 배포 후보로 저장한다.
    """
    require_role(ctx, "intake recheck")
    with transact(ctx):
        # 잠금 순서는 서버 행 → 신청 행이다(재승인 계획 등록과 같다). 승인된 신청만 서버 행을 먼저
        # 잠근다: 결정 전 신청의 결정·검사 경로는 신청 행 → 서버 행 순서를 쓴다.
        peek = get(ctx, intake_id)
        if peek["status"] == "decided":
            fetchone(
                ctx.conn,
                "SELECT 1 AS x FROM mint.servers WHERE instance_id = %s AND server_id = %s"
                " FOR UPDATE",
                (ctx.instance_id, peek["server_id"]),
            )
        row = get(ctx, intake_id, lock=True)
        if expected_version is not None and row["state_version"] != expected_version:
            raise conflict(f"신청의 상태 버전이 요청({expected_version})과 다릅니다"
                           f"(현재 {row['state_version']}).")
        approved = row["status"] == "decided" and row["decision"] in ("approved", "exception")
        if row["status"] not in ("received", "passed", "indeterminate") and not approved:
            raise conflict(f"{row['status']} 상태의 신청은 재검사할 수 없습니다.")
        if approved:
            server = fetchone(
                ctx.conn,
                "SELECT contract_status, status FROM mint.servers"
                " WHERE instance_id = %s AND server_id = %s",
                (ctx.instance_id, row["server_id"]),
            )
            if (server is None or server["contract_status"] != "managed"
                    or server["status"] in ("rejected", "terminating", "terminated")):
                raise conflict("관리 중인 승인 서버의 신청만 재검사할 수 있습니다.")
        if not is_complete(row):
            raise ControlError("필수 입력이 모두 채워져야 검사할 수 있습니다(intake create).")
        if (url is not None or transport is not None) and not approved:
            raise ControlError("--url은 승인된 신청의 재검사에만 쓸 수 있습니다.")
        if approved and (url is not None or transport is not None):
            _operator_deployment_candidate(ctx, row["server_id"], url, transport)
        if registry_first and (approved or not (row["source"] == "submission"
                                                and row["needs_registry_credentials"])):
            raise ControlError(
                "레지스트리 등록 후 검사는 자격이 필요한 제출 신청"
                "(CREDENTIALS_REQUIRED)에만 쓸 수 있습니다."
            )
        return _enqueue_run(ctx, row, "evidence" if approved else "registry" if registry_first
                            else "")


def enqueue_drift_recheck(ctx: Context, server_id: str) -> str | None:
    """서버를 승인한 가장 최근 신청의 재검사(``evidence``)를 등록한다. 작업 실행기가 부른다.

    같은 시도 번호는 한 작업이라 처리 전에 드리프트가 여러 번 기록돼도 작업은 하나다. 승인한
    신청이 없거나 입력이 비어 있으면 아무것도 하지 않는다(None).
    """
    row = fetchone(
        ctx.conn,
        "SELECT * FROM mint.intakes WHERE instance_id = %s AND server_id = %s"
        " AND status = 'decided' AND decision IN ('approved', 'exception')"
        " ORDER BY decided_at DESC, id DESC LIMIT 1",
        (ctx.instance_id, server_id),
    )
    if row is None or not is_complete(row):
        return None
    return _enqueue_run(ctx, row, "evidence")


def drift_pending(conn: Any, instance_id: str, server_id: str) -> bool:
    """서버에 재승인을 기다리는 드리프트(배포·도구 변경·추가)가 있는가."""
    row = fetchone(
        conn,
        "SELECT ((s.deployment_drift"
        " OR EXISTS (SELECT 1 FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "   AND t.server_id = s.server_id AND t.status = 'approved' AND t.drift <> 'none')"
        " OR EXISTS (SELECT 1 FROM mint.contract_observations o WHERE o.instance_id = s.instance_id"
        "   AND o.server_id = s.server_id AND o.kind = 'tool' AND o.change_seq > 0"
        "   AND NOT EXISTS (SELECT 1 FROM mint.tool_contracts t"
        "     WHERE t.instance_id = o.instance_id AND t.id = o.entity_id)))"
        # 재승인 계획이 진행 중이면 후보를 바꾸지 않는다(확정 중 후보 교체 방지)
        " AND NOT EXISTS (SELECT 1 FROM mint.contract_reapproval_plans p"
        "   WHERE p.instance_id = s.instance_id AND p.server_id = s.server_id"
        "   AND p.status = 'pending')) AS pending"
        " FROM mint.servers s WHERE s.instance_id = %s AND s.server_id = %s",
        (instance_id, server_id),
    )
    return bool(row and row["pending"])


def approved_deployment(conn: Any, instance_id: str, server_id: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT * FROM mint.deployment_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status = 'approved' ORDER BY version DESC LIMIT 1",
        (instance_id, server_id),
    )


def store_deployment_candidate(
    ctx: Context, server_id: str, approved: dict, entry: dict, *, keep_same: bool = False,
    only_if_none: bool = False, proposed_by: str | None = None,
) -> bool:
    """서버 값(``entry``)이 승인된 배포 계약과 다르면 배포 후보를 만든다.

    ``entry``는 url·transport·auth_type·issuer를 가진 사전이다.

    허용 도구·이미지 지문·소스 커밋은 승인본을 그대로 잇는다. URL이 없으면 만들지 않는다. 값이
    같을 때는 ``keep_same``이어야 같은 값의 후보를 만든다(OAuth 흐름 재검사: 값은 그대로 두고
    검사만 다시 해 재승인한다). ``only_if_none``이면 이미 배포 후보가 있을 때 만들지 않는다.
    재승인 계획이 진행 중이면 만들지 않는다(확인과 교체는 한 트랜잭션, 서버 행 잠금 아래).
    만들었으면 참.
    """
    url = entry.get("url")
    if not url:
        return False
    transport = "openapi" if entry.get("spec_path") else entry.get("transport") or approved[
        "transport"]
    auth_type = normalize_auth_type(entry.get("auth_type"))
    issuer = entry.get("issuer") or None
    if not keep_same and (url, transport, auth_type, issuer) == (
        approved["url"], approved["transport"], approved["auth_type"], approved["issuer"]
    ):
        return False
    with transact(ctx):
        if not server_free_of_plan(ctx, server_id):
            return False
        if only_if_none and deployment_candidate(ctx.conn, ctx.instance_id, server_id):
            return False
        _deployment_candidate(ctx, server_id, url, transport, auth_type, issuer,
                              approved["allowed_tools"], approved["image_digest"],
                              approved["source_commit"], proposed_by)
    return True


def _operator_deployment_candidate(
    ctx: Context, server_id: str, url: str | None, transport: str | None
) -> None:
    """운영자가 준 새 주소·전송 방식을 관측값과 대조해 배포 후보로 저장한다(제시자를 기록)."""
    if not url:
        raise ControlError("--transport는 --url과 함께 줘야 합니다.")
    if not server_free_of_plan(ctx, server_id):
        raise conflict("재승인 계획이 진행 중이라 새 주소를 받을 수 없습니다.")
    approved = approved_deployment(ctx.conn, ctx.instance_id, server_id)
    observed = fetchone(
        ctx.conn,
        "SELECT canonical_text FROM mint.contract_observations WHERE instance_id = %s"
        " AND server_id = %s AND kind = 'deployment' AND scope = 'server' AND name = 'identity'",
        (ctx.instance_id, server_id),
    )
    hashes = json.loads(observed["canonical_text"]) if observed else {}
    if approved is None or hashes.get("url_sha256") is None:
        raise ControlError("관측된 배포 URL 해시가 없어 주소를 받을 수 없습니다.")
    # 플러그인은 레지스트리 값(이미 URL 해시)의 정규 해시를 기록한다(전송 방식과 같은 규칙)
    if sha256(url_sha256(url)) != hashes["url_sha256"]:
        raise ControlError("입력한 주소가 관측된 배포 URL과 다릅니다(해시 불일치).")
    transport = transport or approved["transport"]
    # 전송 방식이 관측됐으면 그 해시와, 아니면 승인된 전송 방식과 같아야 한다
    if "transport" in hashes:
        matches = sha256(transport) == hashes["transport"]
    else:
        matches = transport == approved["transport"]
    if not matches:
        raise ControlError("입력한 전송 방식이 관측값(또는 승인된 값)과 다릅니다.")
    store_deployment_candidate(
        ctx, server_id, approved,
        {"url": url, "transport": transport,
         "auth_type": approved["auth_type"], "issuer": approved["issuer"]},
        keep_same=True, proposed_by=ctx.operator.user_id,
    )


# --- 작업 처리기가 쓰는 전이 --------------------------------------------------------------------


def _server_to(ctx: Context, server_id: str, target: str, sources: tuple[str, ...]) -> None:
    ctx.conn.execute(
        "UPDATE mint.servers SET status = %s WHERE instance_id = %s AND server_id = %s"
        " AND status = ANY(%s)",
        (target, ctx.instance_id, server_id, list(sources)),
    )


def begin_checking(ctx: Context, intake_id: str) -> dict | None:
    """``received|passed|indeterminate`` → ``checking``. 필수 입력이 없으면 None(그대로 둔다)."""
    with transact(ctx):
        row = get(ctx, intake_id, lock=True)
        if row["status"] == "checking":
            return row
        if row["status"] not in ("received", "passed", "indeterminate") or not is_complete(row):
            return None
        updated = fetchone(ctx.conn,
                           "UPDATE mint.intakes SET status = 'checking' WHERE id = %s RETURNING *",
                           (row["id"],))
        _server_to(ctx, row["server_id"], "validating", _SERVER_REENTRY)
        return updated


def contract_binding(conn: Any, instance_id: str, server_id: str) -> str:
    """현재 후보 계약 전체의 증거 해시. 재승인이 요구하는 ``contract_sha256``과 같은 식이다."""
    tools = fetchall(
        conn,
        "SELECT tool, sha256 FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status = 'candidate' AND source = 'intake'",
        (instance_id, server_id),
    )
    deployment = deployment_candidate(conn, instance_id, server_id)
    return sha256({"tools": {t["tool"]: t["sha256"] for t in tools},
                   "deployment": deployment["sha256"] if deployment else None})


def record_check(
    ctx: Context, intake: dict, attempt: int, check: str, outcome: intake_checks.Outcome,
    bound: str | None = None,
) -> dict:
    """검사 한 행과 사건을 한 트랜잭션에 쓴다. 같은 시도의 같은 검사는 한 번만 기록된다.

    ``bound``는 후보 계약에 결속하는 해시다. 통과한 검사에 증거 해시가 없으면 입력 해시로 채운다.
    """
    days = intake_checks.EVIDENCE_DAYS.get(check, intake_checks.DEFAULT_EVIDENCE_DAYS)
    inputs = dict(outcome.inputs)
    if bound:
        inputs["contract_sha256"] = bound
    evidence = outcome.evidence_sha256
    if evidence is None and outcome.result == "pass":
        evidence = intake_checks.sha256_hex(intake_checks.jcs(inputs))
    row_id = new_uuid7()
    with transact(ctx):
        ctx.conn.execute(
            "INSERT INTO mint.intake_checks (id, instance_id, intake_id, \"check\", attempt,"
            " result, reason_code, method, inputs, evidence_ref, evidence_sha256,"
            " evidence_valid_until)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s,"
            " now() + make_interval(days => %s))",
            (row_id, ctx.instance_id, intake["id"], check, attempt, outcome.result, outcome.reason,
             outcome.method, json.dumps(inputs), outcome.evidence_ref,
             evidence, days),
        )
        ctx.emit(EventKind.INTAKE_CHECKED, row_id, attempt,
                 {"intake_id": str(intake["id"]), "check": check, "attempt": attempt,
                  "result": outcome.result, "reason_code": outcome.reason})
    return {"id": row_id}


def existing_check(
    conn: Any, instance_id: str, intake_id: Any, check: str, attempt: int
) -> dict | None:
    return fetchone(
        conn,
        "SELECT * FROM mint.intake_checks WHERE instance_id = %s AND intake_id = %s"
        " AND \"check\" = %s AND attempt = %s",
        (instance_id, intake_id, check, attempt),
    )


def server_free_of_plan(ctx: Context, server_id: str) -> bool:
    """서버 행을 잠그고(재승인 계획 등록과 같은 잠금) 진행 중인 재승인 계획이 없는가.

    후보를 바꾸는 쪽은 이 확인과 교체를 같은 트랜잭션에서 한다. 계획이 진행 중이면 후보를
    바꾸지 않는다(확정 중 후보 교체 방지).
    """
    fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.servers WHERE instance_id = %s AND server_id = %s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    return fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.contract_reapproval_plans WHERE instance_id = %s"
        " AND server_id = %s AND status = 'pending'",
        (ctx.instance_id, server_id),
    ) is None


def store_candidates(ctx: Context, server_id: str, defs: list[dict]) -> bool:
    """수집한 도구 정의를 후보 계약으로 둔다. 이전 후보는 대체된다.

    재승인 계획이 진행 중이면 아무것도 바꾸지 않고 거짓을 돌려준다.
    """
    with transact(ctx):
        if not server_free_of_plan(ctx, server_id):
            return False
        ctx.conn.execute(
            "UPDATE mint.tool_contracts SET status = 'superseded' WHERE instance_id = %s"
            " AND server_id = %s AND status = 'candidate' AND source = 'intake'",
            (ctx.instance_id, server_id),
        )
        for d in defs:
            text = canonical_text(d)
            ctx.conn.execute(
                "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope,"
                " tool, canonical_text, sha256, pin_sha256, source) VALUES"
                " (%s, %s, %s, 'server', %s, %s, %s, %s, 'intake')",
                (new_uuid7(), ctx.instance_id, server_id, d["name"], text,
                 intake_checks.sha256_hex(text), pin_sha256(d)),
            )
    return True


def store_grades(ctx: Context, server_id: str, graded: dict[str, tuple[str, str]]) -> None:
    with transact(ctx):
        for tool, (action, grade) in graded.items():
            ctx.conn.execute(
                "UPDATE mint.tool_contracts SET action_type = %s, risk_grade = %s"
                " WHERE instance_id = %s AND server_id = %s AND tool = %s AND status = 'candidate'"
                " AND source = 'intake'",
                (action, grade, ctx.instance_id, server_id, tool),
            )


def _supersede_candidates(ctx: Context, server_id: str) -> None:
    ctx.conn.execute(
        "UPDATE mint.tool_contracts SET status = 'superseded' WHERE instance_id = %s"
        " AND server_id = %s AND status = 'candidate'", (ctx.instance_id, server_id))
    ctx.conn.execute(
        "UPDATE mint.deployment_contracts SET status = 'superseded' WHERE instance_id = %s"
        " AND server_id = %s AND status = 'candidate'", (ctx.instance_id, server_id))


def _decided(ctx: Context, row: dict, decision: str, reason: str, extra: dict) -> dict:
    updated = fetchone(
        ctx.conn,
        "UPDATE mint.intakes SET status = 'decided', decision = %s, decided_by = %s,"
        " decision_reason = %s, decided_at = now() WHERE id = %s RETURNING *",
        (decision, ctx.operator.name, reason, row["id"]),
    )
    ctx.emit(EventKind.INTAKE_DECIDED, row["id"], updated["state_version"],
             {"intake_id": str(row["id"]), "server_id": row["server_id"], "decision": decision,
              "reason": reason, "decided_by": ctx.operator.name, **extra})
    return updated


def conclude(ctx: Context, intake_id: str, *, needs_registry_credentials: bool) -> str:
    """최근 검사 행으로 판정한다. 실패면 같은 트랜잭션에서 자동 거절한다. 판정을 돌려준다."""
    with transact(ctx):
        row = get(ctx, intake_id, lock=True)
        checks = latest_checks(ctx.conn, ctx.instance_id, row["id"])
        failed = [c for c in checks if c["result"] == "fail"]
        verdict = ("failed" if failed else
                   "indeterminate" if any(c["result"] == "indeterminate" for c in checks)
                   or len(checks) < len(intake_checks.CHECKS) else "passed")
        if row["status"] != "checking":
            raise conflict(f"checking이 아닌 신청({row['status']})은 판정할 수 없습니다.")
        ctx.conn.execute(
            "UPDATE mint.intakes SET status = %s, needs_registry_credentials = %s WHERE id = %s",
            (verdict, needs_registry_credentials, row["id"]),
        )
        if verdict == "failed":
            row = get(ctx, intake_id)
            reason = f"check_failed:{failed[0]['check']}:{failed[0]['reason_code']}"
            _decided(ctx, row, "rejected", reason, {"automatic": True})
            _server_to(ctx, row["server_id"], "rejected", ("validating",))
            _supersede_candidates(ctx, row["server_id"])
        else:
            _server_to(ctx, row["server_id"], "awaiting_approval", ("validating",))
        return verdict


def enqueue_reject(ctx: Context, row: dict) -> str:
    """결정된 거절의 LiteLLM 전달 작업을 등록한다. 신청마다 하나로 수렴한다."""
    return _enqueue_run(ctx, row, "reject")


def reject_forbidden_address(
    ctx: Context, server_id: str, check: Callable[[dict | None, str], intake_checks.Outcome]
) -> bool:
    """제출 신청(``received``)의 주소가 거부 대상 IP이면 운영자 입력 없이 바로 거절한다.

    신청 행을 먼저 잠근 뒤(``begin_checking``·``create``와 같은 순서, 서버 행은 뒤따르는 갱신이
    잠근다) 그 시점의 배포 후보로 ``check(후보, 조직)``을 판정하므로 운영자 입력·후보 교체·검사
    시작과 겹치지 않는다. 검사 한 행과 거절을 남기고 서버를 닫는다.
    제출이므로 LiteLLM 거절은 작업이 한다. 거절했으면 참.
    """
    with transact(ctx):
        row = fetchone(
            ctx.conn,
            "SELECT * FROM mint.intakes WHERE instance_id = %s AND server_id = %s"
            " AND source = 'submission' AND status = 'received' FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        if row is None:
            return False
        outcome = check(deployment_candidate(ctx.conn, ctx.instance_id, server_id), row["org_id"])
        if outcome.reason != "IP_FORBIDDEN":
            return False
        record_check(ctx, row, next_attempt(ctx.conn, ctx.instance_id, row["id"]), "url_guard",
                     outcome, contract_binding(ctx.conn, ctx.instance_id, server_id))
        updated = _decided(ctx, row, "rejected", f"check_failed:url_guard:{outcome.reason}",
                           {"automatic": True})
        _server_to(ctx, server_id, "validating", _SERVER_REENTRY)
        _server_to(ctx, server_id, "rejected", ("validating",))
        _supersede_candidates(ctx, server_id)
        _enqueue_run(ctx, updated, "reject")
        return True


# --- 결정 ---------------------------------------------------------------------------------


def _assigner_user_id(ctx: Context, intake_id: Any) -> str | None:
    """「신청자 지정」을 한 운영자의 사용자 식별자. 지정한 운영자는 그 신청을 승인할 수 없다."""
    row = fetchone(
        ctx.conn,
        "SELECT o.user_id FROM mint.events e JOIN mint.operators o"
        " ON o.instance_id = e.instance_id AND o.name = e.actor"
        " WHERE e.instance_id = %s AND e.kind = 'intake_requester_assigned'"
        " AND e.payload->>'intake_id' = %s ORDER BY e.inserted_at DESC LIMIT 1",
        (ctx.instance_id, str(intake_id)),
    )
    return row["user_id"] if row else None


def _require_separation(
    ctx: Context, row: dict, second: Operator | None, exception: bool
) -> dict | None:
    user = ctx.operator.user_id
    if user is None or user == row["requested_by"]:
        raise separation_of_duties("신청자와 같은 사용자는 그 신청을 결정할 수 없습니다.")
    if user == _assigner_user_id(ctx, row["id"]):
        raise separation_of_duties("신청자를 지정한 운영자는 그 신청을 결정할 수 없습니다.")
    if not exception:
        return None
    if second is None:
        raise separation_of_duties("예외 승인은 다른 사용자의 두 번째 승인자가 필요합니다.")
    if (second.role not in {r.value for r in APPROVER_UP}
            or second.user_id in (None, user, row["requested_by"],
                                  _assigner_user_id(ctx, row["id"]))):
        raise separation_of_duties(
            "두 번째 승인자는 결정자·신청자·신청자 지정자와 다른 사용자에 결속된 "
            "approver 이상이어야 합니다."
        )
    return {"name": second.name, "user_id": second.user_id}


def _require_fresh_evidence(ctx: Context, row: dict) -> None:
    for c in latest_checks(ctx.conn, ctx.instance_id, row["id"]):
        if c["check"] in ("connection", "definitions") and (
            datetime.now(UTC) - c["ran_at"] > EVIDENCE_MAX_AGE
        ):
            raise stale_evidence(
                f"{c['check']} 증거가 24시간을 넘었습니다. 재검사한 뒤 결정하십시오."
            )


def decide(
    ctx: Context,
    intake_id: str,
    decision: str,
    *,
    reason: str | None = None,
    valid_until: datetime | None = None,
    scope_type: str | None = None,
    scope_id: str | None = None,
    team_id: str | None = None,
    second: Operator | None = None,
    expected_version: int | None = None,
) -> dict:
    """``approve``(통과), ``except``(판별 불가, 사유 필수·2인·유효 기간 90일 이내), ``reject``."""
    require_role(ctx, f"intake {decision}")
    if decision not in ("approve", "except", "reject"):
        raise ValueError(decision)
    reason = (reason or "").strip() or None
    if decision in ("except", "reject") and reason is None:
        raise ControlError("사유가 필요합니다(--reason).")
    with transact(ctx):
        row = get(ctx, intake_id, lock=True)
        if expected_version is not None and row["state_version"] != expected_version:
            raise conflict(f"신청의 상태 버전이 요청({expected_version})과 다릅니다"
                           f"(현재 {row['state_version']}).")
        required = {"approve": ("passed",), "except": ("indeterminate",),
                    "reject": ("passed", "indeterminate")}[decision]
        if row["status"] not in required:
            raise conflict(f"{row['status']} 상태의 신청은 {decision}할 수 없습니다.")
        second_info = _require_separation(ctx, row, second, decision == "except")
        checks = latest_checks(ctx.conn, ctx.instance_id, row["id"])
        if decision == "reject":
            return _reject(ctx, row)
        if decision != "reject" and any(c["reason_code"] == "ALL_KEYS_NOT_CLOSED" for c in checks):
            raise conflict(
                "승인한 제출 서버의 allow_all_keys를 끄지 못해 진행할 수 없습니다. "
                "LiteLLM에서 서버를 정리하거나 재검사하십시오."
            )
        if any(c["result"] == "fail" for c in checks) or (
            decision == "approve" and any(c["result"] != "pass" for c in checks)
        ):
            raise conflict("모든 검사가 통과해야 승인할 수 있습니다.")
        _require_fresh_evidence(ctx, row)
        if decision == "approve":  # 사람이 확인하는 증빙이 없으면 일반 승인을 하지 않는다
            evidence.require(ctx, "approve", "intake", str(row["id"]))
        now = datetime.now(UTC)
        if valid_until is not None:
            if valid_until <= now:
                raise ControlError("valid-until이 이미 지났습니다.")
            if decision == "except" and valid_until > now + timedelta(days=EXCEPTION_MAX_DAYS):
                raise ControlError(
                    f"예외 승인의 유효 기간은 {EXCEPTION_MAX_DAYS}일을 넘을 수 없습니다."
                )
        return _approve(ctx, row, decision, reason, valid_until, scope_type, scope_id, team_id,
                        second_info, checks)


def _reject(ctx: Context, row: dict) -> dict:
    updated = _decided(ctx, row, "rejected", "operator_rejected", {"automatic": False})
    _server_to(ctx, row["server_id"], "rejected", ("awaiting_approval",))
    _supersede_candidates(ctx, row["server_id"])
    if row["source"] == "submission":
        # LiteLLM 거절은 외부 쓰기라 작업이 한다(되돌림 보호)
        _enqueue_run(ctx, updated, "reject")
    return updated


def _approve(
    ctx: Context, row: dict, decision: str, reason: str | None, valid_until: datetime,
    scope_type: str | None, scope_id: str | None, team_id: str | None, second_info: dict | None,
    checks: list[dict],
) -> dict:
    server_id = row["server_id"]
    scope_type = scope_type or "user"
    scope_id = scope_id or row["owner_user_id"]
    if scope_type not in ("key", "user", "team"):
        raise ControlError("승인 범위는 key, user, team 중 하나여야 합니다.")
    tools = fetchall(
        ctx.conn,
        "SELECT id, tool, risk_grade, action_type FROM mint.tool_contracts WHERE instance_id = %s"
        " AND server_id = %s AND status = 'candidate' AND source = 'intake' ORDER BY tool",
        (ctx.instance_id, server_id),
    )
    if any(c["check"] == "definitions" and c["reason_code"] == "LIMIT_EXCEEDED" for c in checks):
        # 이전 검사의 후보가 남아 있어도 최신 정의 수집이 상한을 넘었으면 승인하지 않는다
        raise ControlError("정의 상한 초과: 서버의 도구 수·크기를 줄여 다시 신청하십시오.")
    if not tools:
        raise ControlError("승인할 도구 계약 후보가 없습니다. 정의 수집이 끝나야 합니다.")
    if any(t["risk_grade"] is None or t["action_type"] is None for t in tools):
        raise ControlError("위험 등급이 산정되지 않은 도구가 있어 승인할 수 없습니다.")
    if valid_until is None:  # 기본: 일반 90일, high·critical 도구가 있으면 30일, 예외 30일
        short = decision == "except" or any(t["risk_grade"] in ("high", "critical") for t in tools)
        valid_until = datetime.now(UTC) + timedelta(days=DEFAULT_SHORT_DAYS if short else
                                                    DEFAULT_DAYS)
    deployment = deployment_candidate(ctx.conn, ctx.instance_id, server_id)
    if deployment is None:
        raise ControlError("승인할 배포 계약 후보가 없습니다.")
    allowlist_ids = sorted(
        {a for c in checks for a in (c["inputs"] or {}).get("allowlist_ids", [])}
    )
    updated = _decided(
        ctx, row, "exception" if decision == "except" else "approved",
        reason or "수용검증 통과",
        {"second_approver": None if second_info is None else second_info["name"]},
    )
    # 후보 계약 승인
    for tool in tools:
        version = fetchone(ctx.conn,
                           "UPDATE mint.tool_contracts SET status = 'approved' WHERE id = %s"
                           " RETURNING version", (tool["id"],))["version"]
        ctx.emit(EventKind.CONTRACT_APPROVED, tool["id"], version,
                 {"server_id": server_id, "tool": tool["tool"], "risk_grade": tool["risk_grade"],
                  "action_type": tool["action_type"], "intake_id": str(row["id"])})
    version = fetchone(ctx.conn,
                       "UPDATE mint.deployment_contracts SET status = 'approved' WHERE id = %s"
                       " RETURNING version", (deployment["id"],))["version"]
    ctx.emit(EventKind.DEPLOYMENT_CONTRACT_APPROVED, deployment["id"], version,
             {"server_id": server_id, "sha256": deployment["sha256"],
              "intake_id": str(row["id"])})
    # 서버 행에 계약 값을 복사한다(정본은 servers 열)
    ctx.conn.execute(
        "UPDATE mint.servers SET url_sha256 = %s, transport = %s, auth_type = %s, issuer = %s,"
        " contract_status = 'managed', basis_allowlist_ids = %s::uuid[]"
        " WHERE instance_id = %s AND server_id = %s",
        (deployment["url_sha256"], deployment["transport"], deployment["auth_type"],
         deployment["issuer"], allowlist_ids, ctx.instance_id, server_id),
    )
    # 이용 관계와 승인(pending)
    relation = fetchone(
        ctx.conn,
        "SELECT id FROM mint.usage_relations WHERE instance_id = %s AND org_id = %s"
        " AND server_id = %s AND purpose = %s AND team_id IS NOT DISTINCT FROM %s FOR UPDATE",
        (ctx.instance_id, row["org_id"], server_id, row["purpose"], team_id),
    )
    if relation is None:
        relation_id = new_uuid7()
        rel = fetchone(
            ctx.conn,
            "INSERT INTO mint.usage_relations (id, instance_id, org_id, team_id, purpose,"
            " server_id) VALUES (%s, %s, %s, %s, %s, %s) RETURNING state_version",
            (relation_id, ctx.instance_id, row["org_id"], team_id, row["purpose"], server_id),
        )
        ctx.emit(EventKind.RELATION_CREATED, relation_id, rel["state_version"],
                 {"relation_id": str(relation_id), "org_id": row["org_id"], "team_id": team_id,
                  "purpose": row["purpose"], "server_id": server_id})
    else:
        relation_id = relation["id"]
    high = sorted(t["tool"] for t in tools if t["risk_grade"] in ("high", "critical"))
    conditions = {"high_risk_tools": high} if high else {}
    basis = {"text": reason or "수용검증 통과", "intake_id": str(row["id"]),
             "allowlist_ids": allowlist_ids}
    if second_info:
        basis["second_approver"] = second_info["name"]
    approval_id = new_uuid7()
    ctx.conn.execute(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id, tools,"
        " scope_type, scope_id, valid_from, valid_until, conditions, basis, granted_by,"
        " requested_by, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), %s, %s::jsonb,"
        " %s::jsonb, %s, %s, 'pending')",
        (approval_id, ctx.instance_id, row["org_id"], relation_id,
         "exception" if decision == "except" else "standard", server_id,
         [t["tool"] for t in tools], scope_type, scope_id, valid_until, json.dumps(conditions),
         json.dumps(basis, ensure_ascii=False), ctx.operator.name, row["requested_by"]),
    )
    enqueue_job(ctx, "sync_server", server_id)
    if scope_type in ("key", "team"):
        enqueue_job(ctx, "sync_target", f"{scope_type}:{scope_id}")
    return {**updated, "approval_id": str(approval_id), "relation_id": str(relation_id)}
