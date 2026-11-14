"""계약 비교와 증거·직무 분리를 확인한 재승인 계획 등록."""

import json
from datetime import timedelta
from uuid import UUID

from psycopg.types.json import Jsonb

from mint_litellm.control import change_summary
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import (
    conflict,
    not_found,
    separation_of_duties,
    stale_evidence,
)
from mint_litellm.control.services import evidence
from mint_litellm.control.services.base import enqueue_job, require_role, service, transact
from mint_litellm.types.canonical import (
    canonical_text,
    credential_scope,
    pin_sha256,
    sha256,
)
from mint_litellm.types.contracts import ActionType, DataGrade, RiskGrade, risk_grade
from mint_litellm.types.decision import url_sha256
from mint_litellm.types.events import EventKind, control_source_key
from mint_litellm.types.ids import new_uuid7


@service("contract show")
def show(ctx: Context, server_id: str) -> dict:
    server = fetchone(
        ctx.conn,
        "SELECT server_id,contract_status,state_version,last_observed_at,"
        " deployment_drift,deployment_drift_fields FROM mint.servers"
        " WHERE instance_id=%s AND server_id=%s",
        (ctx.instance_id, server_id),
    )
    if server is None:
        raise not_found("서버가 없습니다.")
    return {
        "server": server,
        "tools": fetchall(
            ctx.conn,
            "SELECT * FROM mint.tool_contracts WHERE instance_id=%s AND server_id=%s"
            " ORDER BY credential_scope,tool,version",
            (ctx.instance_id, server_id),
        ),
        "deployments": fetchall(
            ctx.conn,
            "SELECT * FROM mint.deployment_contracts WHERE instance_id=%s AND server_id=%s"
            " ORDER BY version",
            (ctx.instance_id, server_id),
        ),
    }


def approve_provisional(
    ctx: Context, server_id: str, *, expected_version: int | None = None
) -> dict:
    """로컬(stdio) 서버의 임시 계약을 승인된 도구 계약으로 바꾼다.

    관측한 정의(이름·설명·입력 정의)가 계약 정본이 되고, 이미 승인된 같은 도구의 계약은 대체된다.
    실행(``exec``) 유형은 도구 계약의 행위 분류에 없어 옮기지 않고 임시 계약으로 남긴다. 신청·수용
    검증을 거치는 원격 서버의 재승인과 달리 운영자가 관측 목록을 보고 직접 승인한다.
    """
    require_role(ctx, "contract reapprove")
    with transact(ctx):
        server = fetchone(
            ctx.conn,
            "SELECT * FROM mint.servers WHERE instance_id=%s AND server_id=%s FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        if server is None:
            raise not_found("서버가 없습니다.")
        if (
            server["identity_kind"] != "stdio"
            or server["status"] != "approved"
            or server["contract_status"] == "managed"
        ):
            raise conflict("승인된 로컬 서버의 임시 계약만 승인할 수 있습니다.")
        if expected_version is not None and server["state_version"] != expected_version:
            raise conflict("서버 상태 버전이 다릅니다.")
        rows = fetchall(
            ctx.conn,
            "SELECT * FROM mint.provisional_contracts WHERE instance_id=%s AND server_id=%s"
            " AND action_type <> 'exec' ORDER BY tool FOR UPDATE",
            (ctx.instance_id, server_id),
        )
        if not rows:
            raise conflict("승인할 임시 계약이 없습니다.")
        approved = []
        for row in rows:
            value = {
                "name": row["tool"],
                "description": row["description"],
                "input_schema": row["input_schema"],
            }
            ctx.conn.execute(
                "UPDATE mint.tool_contracts SET status='superseded' WHERE instance_id=%s"
                " AND server_id=%s AND credential_scope='server' AND tool=%s"
                " AND status IN ('approved', 'candidate')",
                (ctx.instance_id, server_id, row["tool"]),
            )
            contract_id = new_uuid7()
            text = canonical_text(value)
            ctx.conn.execute(
                "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope,"
                " tool, canonical_text, sha256, pin_sha256, source)"
                " VALUES (%s, %s, %s, 'server', %s, %s, %s, %s, 'observed')",
                (contract_id, ctx.instance_id, server_id, row["tool"], text, sha256(value),
                 pin_sha256(value)),
            )
            ctx.conn.execute(
                "UPDATE mint.tool_contracts SET action_type=%s, risk_grade=%s WHERE id=%s",
                (row["action_type"], row["risk_grade"], contract_id),
            )
            version = fetchone(
                ctx.conn,
                "UPDATE mint.tool_contracts SET status='approved' WHERE id=%s RETURNING version",
                (contract_id,),
            )["version"]
            ctx.emit(
                EventKind.CONTRACT_APPROVED, contract_id, version,
                {"server_id": server_id, "tool": row["tool"], "risk_grade": row["risk_grade"],
                 "action_type": row["action_type"], "source": "provisional"},
            )
            approved.append(row["tool"])
        ctx.conn.execute(
            "DELETE FROM mint.provisional_contracts WHERE instance_id=%s AND server_id=%s"
            " AND tool = ANY(%s)",
            (ctx.instance_id, server_id, approved),
        )
        return {"server_id": server_id, "approved": approved}


@service("contract diff")
def diff(ctx: Context, server_id: str) -> dict:
    current = show(ctx, server_id)
    current["observations"] = fetchall(
        ctx.conn,
        "SELECT kind,scope,name,observed_sha256,canonical_text,change_seq,observed_at,"
        "change_summary"
        " FROM mint.contract_observations WHERE instance_id=%s AND server_id=%s"
        " ORDER BY kind,scope,name",
        (ctx.instance_id, server_id),
    )
    return current


def request_deployment(
    ctx: Context, server_id: str, candidate_id: str, *, expected_version: int | None = None
) -> None:
    """수용검증이 만든 배포 후보를 재승인 대기 상태로 기록한다.

    관측 기록은 작업 실행기 역할만 쓰므로 운영자 명령이 아니라 작업 실행기의 같은 트랜잭션에서
    부른다(역할 확인 없음, 호출한 작업이 이미 신청 경로를 거쳤다).
    """
    from mint_litellm.control.contract_observe import _alert, _observe

    server = fetchone(
        ctx.conn,
        "SELECT * FROM mint.servers WHERE instance_id=%s AND server_id=%s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    if server is None:
        raise not_found("서버가 없습니다.")
    if server["contract_status"] != "managed":
        raise conflict("관리 서버의 배포 후보만 갱신할 수 있습니다.")
    if expected_version is not None and server["state_version"] != expected_version:
        raise conflict("서버 상태 버전이 다릅니다.")
    contracts = fetchall(
        ctx.conn,
        "SELECT * FROM mint.deployment_contracts WHERE instance_id=%s AND server_id=%s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    old = next((c for c in contracts if c["status"] == "approved"), None)
    candidate = next(
        (c for c in contracts if str(c["id"]) == candidate_id and c["status"] == "candidate"), None
    )
    if old is None or candidate is None:
        raise conflict("승인본과 새 배포 후보가 필요합니다.")
    fields = [
        key
        for key in (
            "url_sha256",
            "transport",
            "auth_type",
            "issuer",
            "oauth_scopes",
            "allowed_tools",
            "image_digest",
            "source_commit",
        )
        if old[key] != candidate[key]
    ]
    if not fields:
        return
    observation, changed = _observe(
        ctx,
        server_id,
        "deployment",
        "server",
        "identity",
        old["id"],
        {"candidate_sha256": candidate["sha256"]},
        summary=change_summary.deployment_summary(fields, old, candidate),
    )
    merged = sorted(set(server["deployment_drift_fields"] or ()) | set(fields))
    if not server["deployment_drift"] or merged != server["deployment_drift_fields"]:
        ctx.conn.execute(
            "UPDATE mint.servers SET deployment_drift=true,deployment_drift_fields=%s"
            " WHERE instance_id=%s AND server_id=%s",
            (merged, ctx.instance_id, server_id),
        )
    if changed:
        payload = {
            "server_id": server_id,
            "fields": fields,
            "version": old["version"],
            "candidate_id": candidate_id,
            "kind": "deployment",
        }
        ctx.emit(EventKind.DEPLOYMENT_DRIFT_DETECTED, old["id"], observation["change_seq"], payload)
        ctx.emit(EventKind.REAPPROVAL_REQUESTED, old["id"], observation["change_seq"], payload)
        _alert(ctx, old["id"], observation["observed_sha256"], "high", payload)


def current_operator(conn, instance_id: str, name: str, user_id: str | None) -> Operator | None:
    """지금 유효한 운영자(삭제·만료 아님, 사용자 결속 일치)의 현재 역할(``FOR SHARE``)."""
    row = fetchone(
        conn,
        "SELECT role FROM mint.operators WHERE instance_id=%s AND name=%s AND user_id=%s"
        " AND (expires_at IS NULL OR expires_at > now()) FOR SHARE",
        (instance_id, name, user_id),
    )
    return Operator(name, row["role"], user_id) if row else None


def _exception_gate(
    ctx: Context, server_id: str, intake: dict, proposed_by: str | None,
    first: Operator, second: Operator | None,
) -> bool:
    """서버의 현재 승인 근거가 예외이면 서로 다른 admin 2인과 아직 유효한 예외를 요구한다.

    고른 신청이 아니라 서버의 현재 승인 근거(가장 최근에 승인·예외로 결정된 신청)로 판단한다.
    새 유효 기한을 따로 두지 않으므로 기한은 원래 예외의 기한을 넘지 않는다. 확정 단계에서도
    다시 불러 현재의 자격으로 확인한다. 요구했으면 참.
    """
    basis = fetchone(
        ctx.conn,
        "SELECT * FROM mint.intakes WHERE instance_id=%s AND server_id=%s AND status='decided'"
        " AND decision IN ('approved','exception') ORDER BY decided_at DESC, id DESC LIMIT 1",
        (ctx.instance_id, server_id),
    )
    involved = [i for i in (intake, basis) if i is not None and i["decision"] == "exception"]
    if not involved:
        return False
    barred = {i["requested_by"] for i in (intake, basis) if i is not None}
    barred |= {first.user_id, proposed_by}
    if (
        first.role != "admin"
        or first.user_id in {i["requested_by"] for i in (intake, basis) if i is not None}
        or second is None
        or second.role != "admin"
        or second.user_id is None
        or second.user_id in barred
    ):
        raise separation_of_duties(
            "예외 승인 서버의 재승인에는 신청자·후보 제시자와 다른 admin 두 명이 필요합니다."
        )
    now = fetchone(ctx.conn, "SELECT now() AS t")["t"]
    for item in involved:
        original = fetchone(
            ctx.conn,
            "SELECT max(valid_until) AS valid_until FROM mint.approvals WHERE instance_id=%s"
            " AND class='exception' AND basis->>'intake_id'=%s",
            (ctx.instance_id, str(item["id"])),
        )
        if original is None or original["valid_until"] is None or original["valid_until"] <= now:
            raise stale_evidence(
                "원래 예외 승인의 유효 기한이 지났습니다. 새 예외 승인이 필요합니다.")
    return True


def _plan(
    ctx: Context,
    server_id: str,
    intake_id: str,
    candidate_ids: list[str],
    deployment_id: str | None,
    expected_version: int | None,
    second: Operator | None = None,
    first: Operator | None = None,
) -> dict:
    first = first or ctx.operator
    try:
        for value in [intake_id, *candidate_ids, *([deployment_id] if deployment_id else [])]:
            UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise conflict("신청과 후보 계약 식별자는 UUID여야 합니다.") from None
    server = fetchone(
        ctx.conn,
        "SELECT *,now() AS checked_at FROM mint.servers"
        " WHERE instance_id=%s AND server_id=%s FOR UPDATE",
        (ctx.instance_id, server_id),
    )
    if server is None:
        raise not_found("서버가 없습니다.")
    if server["contract_status"] != "managed" or server["status"] != "approved":
        raise conflict("승인된 관리 서버만 재승인할 수 있습니다.")
    if expected_version is not None and server["state_version"] != expected_version:
        raise conflict("서버 상태 버전이 다릅니다.")
    intake = fetchone(
        ctx.conn,
        "SELECT * FROM mint.intakes WHERE instance_id=%s AND id=%s AND server_id=%s FOR UPDATE",
        (ctx.instance_id, intake_id, server_id),
    )
    if intake is None or intake["status"] not in {"passed", "decided"}:
        raise stale_evidence("통과한 재검사 신청이 필요합니다.")
    if intake["status"] == "decided" and intake["decision"] not in ("approved", "exception"):
        raise stale_evidence("승인되지 않은 신청의 증거입니다.")
    if not ctx.operator.user_id or not intake["requested_by"]:
        raise separation_of_duties("신청자와 승인자의 사용자 결속이 필요합니다.")
    if ctx.operator.user_id == intake["requested_by"]:
        raise separation_of_duties("신청자는 같은 계약을 재승인할 수 없습니다.")
    if not candidate_ids and deployment_id is None:
        raise conflict("새 후보 계약을 지정하십시오.")
    if len(set(candidate_ids)) != len(candidate_ids):
        raise conflict("중복된 후보 계약입니다.")
    candidates = (
        fetchall(
            ctx.conn,
            "SELECT * FROM mint.tool_contracts WHERE instance_id=%s"
            " AND server_id=%s AND id=ANY(%s::uuid[]) FOR UPDATE",
            (ctx.instance_id, server_id, candidate_ids),
        )
        if candidate_ids
        else []
    )
    if len(candidates) != len(candidate_ids) or any(c["status"] != "candidate" for c in candidates):
        raise conflict("후보 도구 계약이 없거나 이미 처리되었습니다.")
    deployment = (
        fetchone(
            ctx.conn,
            "SELECT * FROM mint.deployment_contracts"
            " WHERE instance_id=%s AND server_id=%s AND id=%s AND status='candidate' FOR UPDATE",
            (ctx.instance_id, server_id, deployment_id),
        )
        if deployment_id
        else None
    )
    if deployment_id and deployment is None:
        raise conflict("후보 배포 계약이 없습니다.")
    if deployment and deployment["proposed_by"] == ctx.operator.user_id:
        raise separation_of_duties("배포 후보를 제시한 운영자는 그 후보를 재승인할 수 없습니다.")
    exception_required = _exception_gate(
        ctx, server_id, intake, deployment["proposed_by"] if deployment else None, first, second)
    auth = deployment["auth_type"] if deployment else server["auth_type"]
    scope = credential_scope(auth)
    if any(c["credential_scope"] != scope for c in candidates):
        raise conflict("배포 계약의 자격 범위와 후보 도구 계약이 다릅니다.")
    if len({c["tool"] for c in candidates}) != len(candidates):
        raise conflict("한 도구에 여러 후보를 지정할 수 없습니다.")
    approved = fetchall(
        ctx.conn,
        "SELECT * FROM mint.tool_contracts WHERE instance_id=%s"
        " AND server_id=%s AND credential_scope=%s AND status='approved' FOR UPDATE",
        (ctx.instance_id, server_id, scope),
    )
    desired = {c["tool"]: json.loads(c["canonical_text"]) for c in approved}
    for candidate in candidates:
        value = json.loads(candidate["canonical_text"])
        if (
            canonical_text(value) != candidate["canonical_text"]
            or sha256(value) != candidate["sha256"]
            or pin_sha256(value) != candidate["pin_sha256"]
        ):
            raise conflict("후보 계약의 해시가 일치하지 않습니다.")
        try:
            grade = risk_grade(
                DataGrade(intake["data_grade"]),
                ActionType(candidate["action_type"]),
            )
            declared = RiskGrade(candidate["risk_grade"])
        except (ValueError, TypeError):
            raise stale_evidence("후보 도구의 위험 등급 재검사가 필요합니다.") from None
        # 비가역성의 상향 평가는 후보에 결속된 수용검증 증거가 담당한다.
        if tuple(RiskGrade).index(declared) < tuple(RiskGrade).index(grade):
            raise stale_evidence("후보 도구의 위험 등급이 재산정 하한보다 낮습니다.")
        desired[candidate["tool"]] = value
    if deployment and sha256(json.loads(deployment["canonical_text"])) != deployment["sha256"]:
        raise conflict("배포 계약의 해시가 일치하지 않습니다.")
    if deployment:
        definition = json.loads(deployment["canonical_text"])
        if url_sha256(deployment["url"]) != deployment["url_sha256"] or any(
            definition.get(key) != deployment[key]
            for key in (
                "url",
                "transport",
                "auth_type",
                "issuer",
                "oauth_scopes",
                "allowed_tools",
                "image_digest",
                "source_commit",
            )
        ):
            raise conflict("배포 계약 전문과 배포 값이 다릅니다.")
    evidence_hash = sha256(
        {
            "tools": {c["tool"]: c["sha256"] for c in candidates},
            "deployment": deployment["sha256"] if deployment else None,
        }
    )
    from mint_litellm.control.services.intakes import deployment_candidate

    # 재검사 증거는 배포 후보까지 결속된다. 배포 후보가 있으면 함께 재승인해야 증거와 맞는다.
    pending = deployment_candidate(ctx.conn, ctx.instance_id, server_id)
    if pending and not deployment:
        raise conflict("배포 값 후보가 있어 도구와 함께 재승인해야 합니다.")
    checks = fetchall(
        ctx.conn,
        'SELECT DISTINCT ON ("check") * FROM mint.intake_checks'
        ' WHERE instance_id=%s AND intake_id=%s ORDER BY "check",attempt DESC',
        (ctx.instance_id, intake_id),
    )
    by_name = {row["check"]: row for row in checks}
    required = {"connection", "definitions", "description_scan", "risk_grade"}
    if deployment:
        required |= {"url_guard", "connection", "oauth_issuer_allowlist"}
    for name in required:
        row = by_name.get(name)
        if (
            row is None
            or row["result"] != "pass"
            or not server["checked_at"] - timedelta(hours=24)
            <= row["ran_at"]
            <= server["checked_at"]
            or row["inputs"].get("contract_sha256") != evidence_hash
            or not row["evidence_sha256"]
            or row["evidence_valid_until"] is None
            or row["evidence_valid_until"] <= server["checked_at"]
        ):
            raise stale_evidence("후보에 결속된 24시간 이내 재검사 증거가 필요합니다.")
    return {
        "server": server,
        "candidates": candidates,
        "deployment": deployment,
        "approved": approved,
        "desired": desired,
        "scope": scope,
        "evidence_hash": evidence_hash,
        "exception_required": exception_required,
    }


def freeze_plan(plan: dict) -> dict:
    """관측·응답 대기 중 바뀔 수 있는 계약의 id와 판본을 계획에 고정한다."""

    def refs(rows):
        return sorted(
            ({"id": str(c["id"]), "version": c["version"], "sha256": c["sha256"]} for c in rows),
            key=lambda c: c["id"],
        )

    return {
        "server_version": plan["server"]["state_version"],
        "candidates": refs(plan["candidates"]),
        "deployment": refs([plan["deployment"]])[0] if plan["deployment"] else None,
        "approved": refs(plan["approved"]),
        "desired": plan["desired"],
        "scope": plan["scope"],
        "evidence_hash": plan["evidence_hash"],
        "drift_fields": sorted(plan["server"]["deployment_drift_fields"] or ()),
    }


def _saved_plan(plan: dict, second: Operator | None) -> dict:
    """저장하는 계획. 예외 서버면 두 번째 승인자를 함께 고정해 확정 때 다시 확인한다."""
    saved = freeze_plan(plan)
    if plan.get("exception_required") and second is not None:
        saved["second"] = {"name": second.name, "user_id": second.user_id}
    return saved


@service("contract reapprove")
def reapprove(
    ctx: Context,
    server_id: str,
    intake_id: str,
    candidate_ids: list[str],
    *,
    deployment_id: str | None = None,
    expected_version: int | None = None,
    second: Operator | None = None,
) -> dict:
    """계획·차단·사건과 sync_server만 커밋한다. LiteLLM에는 쓰지 않는다.

    예외 승인 신청이면 ``second``(다른 admin)가 필요하다.
    """
    plan = _plan(ctx, server_id, intake_id, candidate_ids, deployment_id, expected_version,
                 second)
    if plan["deployment"]:  # 배포 계약(판본·실행 위치)이 바뀌는 재승인은 판본 확인 증빙이 먼저다
        evidence.require(ctx, "reapprove", "server", server_id)
    fields = set(plan["server"]["deployment_drift_fields"] or ())
    if plan["server"]["deployment_drift"] and not fields:
        fields.add("unknown")
    fields.add("pin_reapproval")
    marker = fetchone(
        ctx.conn,
        "UPDATE mint.servers SET deployment_drift=true,deployment_drift_fields=%s"
        " WHERE instance_id=%s AND server_id=%s RETURNING state_version",
        (sorted(fields), ctx.instance_id, server_id),
    )["state_version"]
    plan["server"].update(state_version=marker, deployment_drift_fields=sorted(fields))
    plan_id = new_uuid7()
    ctx.conn.execute(
        "INSERT INTO mint.contract_reapproval_plans"
        " (id,instance_id,server_id,intake_id,requested_by,requested_user_id,plan)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s)"
        " ON CONFLICT (instance_id,server_id) DO UPDATE SET id=EXCLUDED.id,"
        " intake_id=EXCLUDED.intake_id,requested_by=EXCLUDED.requested_by,"
        " requested_user_id=EXCLUDED.requested_user_id,plan=EXCLUDED.plan,"
        " status='pending',result=NULL",
        (
            plan_id,
            ctx.instance_id,
            server_id,
            intake_id,
            ctx.operator.name,
            ctx.operator.user_id,
            Jsonb(_saved_plan(plan, second)),
        ),
    )
    requested = [(c, "tool") for c in plan["candidates"]]
    if plan["deployment"]:
        requested.append((plan["deployment"], "deployment"))
    for candidate, kind in requested:
        key = control_source_key(
            EventKind.REAPPROVAL_REQUESTED, str(candidate["id"]), candidate["version"]
        )
        if (
            fetchone(
                ctx.conn,
                "SELECT 1 FROM mint.events WHERE instance_id=%s AND source_key=%s",
                (ctx.instance_id, key),
            )
            is None
        ):
            ctx.emit(
                EventKind.REAPPROVAL_REQUESTED,
                candidate["id"],
                candidate["version"],
                {
                    "server_id": server_id,
                    "version": candidate["version"],
                    "kind": kind,
                    "candidate_sha256": candidate["sha256"],
                    **({"second_approver": second.name}
                       if second is not None and plan.get("exception_required") else {}),
                },
            )
    job_id = enqueue_job(ctx, "sync_server", server_id)
    return {"server_id": server_id, "plan_id": str(plan_id), "job_id": job_id}
