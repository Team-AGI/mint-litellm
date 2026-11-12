"""콘솔 화면과 HTTP API의 조회. 상태를 바꾸지 않고 한 배치(``instance_id``)만 읽는다."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone

PAGE_SIZE = 50
EXPORT_LIMIT = 100_000
LEDGER_DEFAULT_DAYS = 7


def jsonable(value: Any) -> Any:
    """JSON으로 보낼 수 있는 값으로 바꾼다(UUID·시각 → 문자열)."""
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (bytes, memoryview)):
        return bytes(value).hex()
    return value


def _page(page: int) -> tuple[int, int]:
    page = max(page, 1)
    return PAGE_SIZE, (page - 1) * PAGE_SIZE


def servers(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT s.server_id, s.status, s.transport, s.auth_type, s.registered_by, s.state_version,"
        " s.contract_status, s.deployment_drift,"
        " (SELECT count(*) FROM mint.usage_relations r WHERE r.instance_id = s.instance_id"
        "  AND r.server_id = s.server_id AND r.status = 'active') AS relations,"
        " (SELECT count(*) FROM mint.approvals a WHERE a.instance_id = s.instance_id"
        "  AND a.server_id = s.server_id AND a.status = 'active' AND a.valid_until > now())"
        "  AS approvals,"
        " (SELECT count(*) FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "  AND t.server_id = s.server_id AND t.status = 'approved') AS tools,"
        " (SELECT count(*) FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "  AND t.server_id = s.server_id AND t.status = 'approved' AND t.drift <> 'none')"
        "  AS drifted"
        " FROM mint.servers s WHERE s.instance_id = %s ORDER BY s.server_id",
        (instance,),
    )


def server(conn: psycopg.Connection, instance: str, server_id: str) -> dict | None:
    row = fetchone(
        conn,
        "SELECT server_id, status, url_sha256, transport, auth_type, registered_by, state_version,"
        " identity_kind, exec_contract_sha256, contract_status, deployment_drift,"
        " deployment_drift_fields, last_observed_at"
        " FROM mint.servers WHERE instance_id = %s AND server_id = %s",
        (instance, server_id),
    )
    if row is None:
        return None
    row["relations"] = relations(conn, instance, server_id)
    row["approvals"] = approvals(conn, instance, server_id=server_id)
    row["denials"] = [d for d in denials(conn, instance) if d["server_id"] == server_id]
    row["tools"] = fetchall(
        conn,
        "SELECT tool, credential_scope, risk_grade, action_type, status, drift"
        " FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status = 'approved' ORDER BY tool",
        (instance, server_id),
    )
    return row


def relations(conn: psycopg.Connection, instance: str, server_id: str | None = None) -> list[dict]:
    return fetchall(
        conn,
        "SELECT r.id, r.org_id, o.name AS org_name, r.team_id, r.purpose, r.server_id, r.status,"
        " r.state_version FROM mint.usage_relations r JOIN mint.orgs o"
        " ON o.instance_id = r.instance_id AND o.org_id = r.org_id"
        " WHERE r.instance_id = %s AND (%s::text IS NULL OR r.server_id = %s)"
        " ORDER BY r.server_id, r.org_id, r.purpose",
        (instance, server_id, server_id),
    )


def queue(conn: psycopg.Connection, instance: str) -> list[dict]:
    """승인 대기열: 첫 승인을 기다리는 서버의 활성 이용 관계. 오래된 것(등록 순서) 먼저."""
    return fetchall(
        conn,
        "SELECT s.server_id, s.registered_by, s.transport, s.auth_type, s.state_version AS"
        " server_version, r.id AS relation_id, r.org_id, o.name AS org_name, r.team_id, r.purpose,"
        " r.state_version AS relation_version FROM mint.servers s"
        " LEFT JOIN mint.usage_relations r ON r.instance_id = s.instance_id"
        " AND r.server_id = s.server_id AND r.status = 'active'"
        " LEFT JOIN mint.orgs o ON o.instance_id = r.instance_id AND o.org_id = r.org_id"
        " WHERE s.instance_id = %s AND s.status = 'awaiting_approval'"
        " ORDER BY s.id, r.id",
        (instance,),
    )


def relation(conn: psycopg.Connection, instance: str, relation_id: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT r.id, r.org_id, o.name AS org_name, r.team_id, r.purpose, r.server_id, r.status,"
        " r.state_version, s.status AS server_status, s.state_version AS server_version"
        " FROM mint.usage_relations r JOIN mint.orgs o ON o.instance_id = r.instance_id"
        " AND o.org_id = r.org_id JOIN mint.servers s ON s.instance_id = r.instance_id"
        " AND s.server_id = r.server_id WHERE r.instance_id = %s AND r.id = %s",
        (instance, relation_id),
    )


def high_risk_tools(conn: psycopg.Connection, instance: str, server_id: str) -> list[str]:
    return [
        r["tool"]
        for r in fetchall(
            conn,
            "SELECT tool FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
            " AND status = 'approved' AND risk_grade IN ('high', 'critical')",
            (instance, server_id),
        )
    ]


def approvals(
    conn: psycopg.Connection,
    instance: str,
    *,
    server_id: str | None = None,
    status: str | None = None,
    page: int = 1,
) -> list[dict]:
    limit, offset = _page(page)
    return fetchall(
        conn,
        "SELECT id, org_id, relation_id, class, server_id, tools, scope_type, scope_id, valid_from,"
        " valid_until, conditions, basis, granted_by, requested_by, status, revoked_at,"
        " revoke_reason, state_version FROM mint.approvals WHERE instance_id = %s"
        " AND (%s::text IS NULL OR server_id = %s) AND (%s::text IS NULL OR status = %s)"
        " ORDER BY valid_until DESC, id DESC LIMIT %s OFFSET %s",
        (instance, server_id, server_id, status, status, limit, offset),
    )


def approval(conn: psycopg.Connection, instance: str, approval_id: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT id, org_id, relation_id, class, server_id, tools, scope_type, scope_id, valid_from,"
        " valid_until, conditions, basis, granted_by, requested_by, status, revoked_at,"
        " revoke_reason, state_version FROM mint.approvals WHERE instance_id = %s AND id = %s",
        (instance, approval_id),
    )


def denials(conn: psycopg.Connection, instance: str, *, active_only: bool = False) -> list[dict]:
    return fetchall(
        conn,
        "SELECT id, org_id, scope_type, scope_id, server_id, tools, reason, created_by, lifted_at,"
        " lifted_by, state_version FROM mint.denials WHERE instance_id = %s"
        " AND (NOT %s OR lifted_at IS NULL) ORDER BY (lifted_at IS NOT NULL), id DESC",
        (instance, active_only),
    )


def call_approvals(
    conn: psycopg.Connection, instance: str, *, status: str | None = None, page: int = 1
) -> list[dict]:
    limit, offset = _page(page)
    return fetchall(
        conn,
        "SELECT id, org_id, principal_type, principal_id, server_id, tool, status, requested_by,"
        " approved_by, expires_at, state_version FROM mint.call_approvals WHERE instance_id = %s"
        " AND (%s::text IS NULL OR status = %s)"
        " ORDER BY (status = 'pending') DESC, expires_at ASC, id LIMIT %s OFFSET %s",
        (instance, status, status, limit, offset),
    )


def orgs(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT o.org_id, o.name, o.status, o.state_version,"
        " (SELECT count(*) FROM mint.org_bindings b WHERE b.instance_id = o.instance_id"
        "  AND b.org_id = o.org_id) AS bindings,"
        " (SELECT count(*) FROM mint.usage_relations r WHERE r.instance_id = o.instance_id"
        "  AND r.org_id = o.org_id AND r.status = 'active') AS relations"
        " FROM mint.orgs o WHERE o.instance_id = %s ORDER BY o.org_id",
        (instance,),
    )


def bindings(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT id, org_id, subject_type, subject_id, created_by FROM mint.org_bindings"
        " WHERE instance_id = %s ORDER BY org_id, subject_type, subject_id",
        (instance,),
    )


def operators(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT name, role, user_id, expires_at, state_version FROM mint.operators"
        " WHERE instance_id = %s AND (expires_at IS NULL OR expires_at > now()) ORDER BY name",
        (instance,),
    )


def allowlists(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT id, org_id, kind, value, note, valid_from, valid_until, created_by,"
        " CASE WHEN status = 'active' AND valid_until <= now() THEN 'expired' ELSE status END"
        " AS status, state_version FROM mint.allowlists WHERE instance_id = %s"
        " ORDER BY valid_until DESC, id DESC",
        (instance,),
    )


def policy_versions(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT id, status, activated_at, activated_by, state_version FROM mint.policy_versions"
        " WHERE instance_id = %s ORDER BY activated_at DESC NULLS LAST, id DESC",
        (instance,),
    )


def settings(conn: psycopg.Connection, instance: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT mode, observable_reasons, observable_policy_ids, default_org_id, settings_version"
        " FROM mint.settings WHERE instance_id = %s",
        (instance,),
    )


# --- 원장 -----------------------------------------------------------------------------------


def _ledger_where(
    instance: str,
    *,
    since: datetime | None,
    until: datetime | None,
    kind: str | None,
    actor: str | None,
    server_id: str | None,
    result: str | None,
) -> tuple[str, list[Any]]:
    since = since or datetime.now(UTC) - timedelta(days=LEDGER_DEFAULT_DAYS)
    clauses = ["instance_id = %s", "inserted_at >= %s"]
    params: list[Any] = [instance, since]
    for clause, value in (
        ("inserted_at < %s", until),
        ("kind = %s", kind),
        ("actor = %s", actor),
        ("(payload->>'resolved_server_id' = %s OR payload->>'server_id' = %s)", server_id),
    ):
        if value is not None:
            clauses.append(clause)
            params.extend([value, value] if clause.count("%s") == 2 else [value])
    if result is not None:  # 차단은 deny와 stop 두 값으로 기록된다
        clauses.append("payload->>'enforced_action' = ANY(%s)")
        params.append(["deny", "stop"] if result == "deny" else [result])
    return " AND ".join(clauses), params


def ledger(
    conn: psycopg.Connection,
    instance: str,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    kind: str | None = None,
    actor: str | None = None,
    server_id: str | None = None,
    result: str | None = None,
    page: int = 1,
    limit: int | None = None,
) -> list[dict]:
    where, params = _ledger_where(
        instance, since=since, until=until, kind=kind, actor=actor, server_id=server_id,
        result=result,
    )
    size, offset = (limit, 0) if limit is not None else _page(page)
    return fetchall(
        conn,
        "SELECT event_id, inserted_at, kind, source_key, actor,"
        " COALESCE(payload->>'resolved_server_id', payload->>'server_id') AS server_id,"
        " payload->>'enforced_action' AS result, payload"
        f" FROM mint.events WHERE {where} ORDER BY inserted_at DESC, event_id DESC"
        " LIMIT %s OFFSET %s",
        (*params, size, offset),
    )


def ledger_filters(conn: psycopg.Connection, instance: str) -> dict[str, list[str]]:
    kinds = fetchall(
        conn, "SELECT DISTINCT kind FROM mint.events WHERE instance_id = %s ORDER BY kind",
        (instance,),
    )
    actors = fetchall(
        conn,
        "SELECT DISTINCT actor FROM mint.events WHERE instance_id = %s AND actor IS NOT NULL"
        " ORDER BY actor",
        (instance,),
    )
    return {"kinds": [r["kind"] for r in kinds], "actors": [r["actor"] for r in actors]}


# --- 개요 -----------------------------------------------------------------------------------


def overview(
    conn: psycopg.Connection, instance: str, handled: list[str] | None = None,
    time_zone: str = "UTC",
) -> dict[str, Any]:
    def one(sql: str, *params: Any) -> Any:
        row = fetchone(conn, sql, (instance, *params))
        return next(iter(row.values())) if row else None

    jobs = {
        r["status"]: r["n"]
        for r in fetchall(
            conn,
            "SELECT status, count(*) AS n FROM mint.jobs WHERE instance_id = %s"
            " AND status IN ('pending', 'failed') GROUP BY status",
            (instance,),
        )
    }
    alerts = {
        r["severity"]: r["n"]
        for r in fetchall(
            conn,
            "SELECT severity, count(*) AS n FROM mint.alerts WHERE instance_id = %s"
            " AND status <> 'resolved' GROUP BY severity",
            (instance,),
        )
    }
    days = fetchall(
        conn,
        "SELECT to_char(date_trunc('day', inserted_at AT TIME ZONE %s::text), 'MM-DD') AS day,"
        " count(*) FILTER (WHERE payload->>'enforced_action' = 'allow') AS allowed,"
        " count(*) FILTER (WHERE payload->>'enforced_action' <> 'allow') AS blocked"
        " FROM mint.events WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= (date_trunc('day', now() AT TIME ZONE %s::text)"
        " - interval '6 days') AT TIME ZONE %s::text"
        " GROUP BY 1 ORDER BY 1",
        (time_zone, instance, time_zone, time_zone),
    )
    unhandled = fetchone(
        conn,
        "SELECT count(*) AS n, max(EXTRACT(EPOCH FROM now() - created_at)) AS oldest"
        " FROM mint.jobs WHERE instance_id = %s AND status = 'pending'"
        " AND NOT (kind = ANY(%s))",
        (instance, handled or []),
    )
    return {
        "unhandled_jobs": unhandled["n"],
        "unhandled_oldest_seconds": unhandled["oldest"],
        "pending_servers": one(
            "SELECT count(*) FROM mint.servers WHERE instance_id = %s"
            " AND status = 'awaiting_approval'"
        ),
        "pending_calls": one(
            "SELECT count(*) FROM mint.call_approvals WHERE instance_id = %s"
            " AND status = 'pending' AND expires_at > now()"
        ),
        "reapproval": one(
            "SELECT count(*) FROM mint.servers WHERE instance_id = %s AND deployment_drift"
        ),
        "alerts": alerts,
        "jobs_pending": jobs.get("pending", 0),
        "jobs_failed": jobs.get("failed", 0),
        "last_export": one(
            "SELECT max(written_at) FROM mint.exports WHERE instance_id = %s AND status = 'written'"
        ),
        "last_seal": one("SELECT max(sealed_at) FROM mint.seal_batches WHERE instance_id = %s"),
        "held_grants": one(
            "SELECT count(*) FROM mint.litellm_grants WHERE instance_id = %s AND held"
        ),
        "decisions_by_day": days,
    }


# --- 계약 변경과 신청 -------------------------------------------------------------------------


def drifted_servers(conn: psycopg.Connection, instance: str) -> list[dict]:
    """계약이 관리되는 서버 가운데 변경이 있거나 재승인 계획이 있는 서버."""
    return fetchall(
        conn,
        "SELECT s.server_id, s.deployment_drift, s.last_observed_at, s.state_version,"
        " (SELECT count(*) FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "  AND t.server_id = s.server_id AND t.status = 'approved' AND t.drift <> 'none')"
        "  AS drifted_tools,"
        " (SELECT count(*) FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "  AND t.server_id = s.server_id AND t.status = 'candidate') AS candidates,"
        " p.status AS plan_status"
        " FROM mint.servers s LEFT JOIN mint.contract_reapproval_plans p"
        " ON p.instance_id = s.instance_id AND p.server_id = s.server_id"
        " WHERE s.instance_id = %s AND s.contract_status = 'managed'"
        " AND (s.deployment_drift OR p.status = 'pending' OR EXISTS ("
        "  SELECT 1 FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "  AND t.server_id = s.server_id AND t.status = 'approved' AND t.drift <> 'none')"
        "  OR EXISTS (SELECT 1 FROM mint.tool_contracts t WHERE t.instance_id = s.instance_id"
        "  AND t.server_id = s.server_id AND t.status = 'candidate'))"
        " ORDER BY s.server_id",
        (instance,),
    )


def reapproval_plan(conn: psycopg.Connection, instance: str, server_id: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT status, requested_by, intake_id, result FROM mint.contract_reapproval_plans"
        " WHERE instance_id = %s AND server_id = %s",
        (instance, server_id),
    )


def candidates(conn: psycopg.Connection, instance: str, server_id: str) -> dict[str, Any]:
    return {
        "tools": fetchall(
            conn,
            "SELECT id, tool, credential_scope, risk_grade, action_type FROM mint.tool_contracts"
            " WHERE instance_id = %s AND server_id = %s AND status = 'candidate' ORDER BY tool",
            (instance, server_id),
        ),
        "deployments": fetchall(
            conn,
            "SELECT id, version FROM mint.deployment_contracts WHERE instance_id = %s"
            " AND server_id = %s AND status = 'candidate' ORDER BY version",
            (instance, server_id),
        ),
        "intakes": fetchall(
            conn,
            "SELECT id, status, created_at FROM mint.intakes WHERE instance_id = %s"
            " AND server_id = %s AND (status = 'passed' OR (status = 'decided'"
            " AND decision = 'approved')) ORDER BY created_at DESC",
            (instance, server_id),
        ),
    }
