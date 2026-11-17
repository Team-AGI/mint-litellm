"""단말 검사 결과 처리 작업(``endpoint_inspection``).

단말이 검사용 승인으로 올린 도구 목록을 후보 계약으로 저장하고 설명 검사·위험 등급을 돌린다.
단말의 주장이므로 신청 상태는 판별 불가로 둔다(검사 기록 ``inspection``은 판별 불가, 사유
``ENDPOINT_INSPECTED``). 예외 승인(두 번째 승인자)으로만 승인할 수 있다. annotations는 등급을
낮추는 근거가 아니다(등급 산정은 기존 표를 그대로 쓴다).
"""

from typing import Any

from mint_litellm.control import intake_checks as checks
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.jobs import JobContext
from mint_litellm.control.services import intakes
from mint_litellm.control.services.base import transact

METHOD = "endpoint:tools_list"
INSPECTED = "ENDPOINT_INSPECTED"
INCOMPLETE = "ENDPOINT_INCOMPLETE"


def _finish(ctx: Context, row: dict, status: str, outcome: str) -> None:
    ctx.conn.execute(
        "UPDATE mint.endpoint_inspections SET status = %s, outcome = %s,"
        " verified_at = CASE WHEN %s::text = 'verified' THEN now() END WHERE id = %s",
        (status, outcome, status, row["id"]),
    )


def _inspection_outcome(row: dict) -> checks.Outcome:
    """올린 결과의 검사 기록. 부분 목록·형식 위반은 판별 불가이고 후보를 만들지 않는다."""
    result = row["result"]
    trace = {"inspection_id": str(row["id"]), "result_sha256": row["result_sha256"]}
    if result.get("complete") is not True:
        failure = checks._failure_detail(result)
        return checks.Outcome("indeterminate", INCOMPLETE, METHOD, {**failure, **trace})
    parsed = checks.inspection_outcome(
        {"status": "ok", "complete": True, "tools": result.get("tools")})
    if parsed.result != "pass":
        return checks.Outcome("indeterminate", parsed.reason, METHOD, {**parsed.inputs, **trace})
    return checks.Outcome("indeterminate", INSPECTED, METHOD, {**parsed.inputs, **trace},
                          "endpoint:tools_list", parsed.evidence_sha256, parsed.extra)


def run(job: JobContext) -> None:
    ctx = Context(job.conn, job.instance_id, Operator(intakes.SYSTEM_ACTOR, "admin", None))
    row = fetchone(
        job.conn,
        "SELECT *, encode(sha256(convert_to((SELECT d.exec_contract::text FROM"
        " mint.deployment_contracts d WHERE d.instance_id = i.instance_id"
        " AND d.server_id = i.server_id AND d.status = 'candidate' ORDER BY d.id DESC LIMIT 1),"
        " 'UTF8')), 'hex') AS current_contract FROM mint.endpoint_inspections i"
        " WHERE i.instance_id = %s AND i.id = %s",
        (job.instance_id, job.job["target_ref"]),
    )
    if row is None or row["status"] != "submitted":
        return  # 철회·무효로 끝난 권한이나 이미 처리한 권한은 건드리지 않는다
    with transact(ctx):
        intake = intakes.get(ctx, str(row["intake_id"]), lock=True)
        deployment = intakes.deployment_candidate(ctx.conn, ctx.instance_id, row["server_id"])
        if (intake["status"] != "indeterminate" or deployment is None
                or deployment["pack_sha256"] != row["pack_sha256"]
                or row["current_contract"] != row["contract_sha256"]):
            _finish(ctx, row, "invalid", "superseded")
            return
        outcome = _inspection_outcome(row)
        defs: list[dict[str, Any]] | None = outcome.extra.get("definitions")
        stored = defs is not None and intakes.store_candidates(ctx, row["server_id"], defs)
        if defs is not None and not stored:
            outcome = checks.Outcome("indeterminate", "REAPPROVAL_PENDING", METHOD)
            defs = None
        attempt = intakes.next_attempt(ctx.conn, ctx.instance_id, intake["id"])
        recorded: list[tuple[str, checks.Outcome]] = [("inspection", outcome)]
        if defs is not None:  # 부분 목록은 기록만 하고 후보도 설명 검사도 만들지 않는다
            data = job.policy_data.get(job.conn, job.instance_id) if job.policy_data else None
            # 단말의 annotations는 등급을 낮추는 근거가 아니다(없는 것으로 산정한다)
            plain = [{**d, "annotations": {}} for d in defs]
            grade = checks.risk_grade(plain, intake["data_grade"], data)
            if grade.extra.get("graded"):
                intakes.store_grades(ctx, row["server_id"], grade.extra["graded"])
            recorded += [("description_scan", checks.description_scan(defs, data)),
                         ("risk_grade", grade)]
        bound = intakes.contract_binding(ctx.conn, ctx.instance_id, row["server_id"])
        for name, out in recorded:
            intakes.record_check(ctx, intake, attempt, name, out, bound)
        _finish(ctx, row, "verified", "stored" if defs is not None else outcome.reason or "none")


HANDLERS = {"endpoint_inspection": run}
