"""콘솔 화면과 HTTP API의 조회. 상태를 바꾸지 않고 한 배치(``instance_id``)만 읽는다."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg

from mint_litellm.control.approvals import CALL_EXTEND_WITHIN_MINUTES
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
        " deployment_drift_fields, last_observed_at, vuln_blocked_at, instance_mismatch_at"
        " FROM mint.servers WHERE instance_id = %s AND server_id = %s",
        (instance, server_id),
    )
    if row is None:
        return None
    row["exec_drift"] = fetchone(
        conn,
        "SELECT subject -> 'axes' AS axes, subject -> 'widened' AS widened FROM mint.alerts"
        " WHERE instance_id = %s AND kind = 'contract_drift' AND status <> 'resolved'"
        " AND subject ->> 'kind' = 'exec' AND subject ->> 'server_id' = %s"
        " ORDER BY last_at DESC LIMIT 1",
        (instance, server_id),
    )
    declared = None if row["identity_kind"] != "stdio" else fetchone(
        conn,
        "SELECT payload -> 'exec_contract' -> 'file_access' AS access,"
        " payload -> 'exec_contract' ->> 'network' AS network,"
        " payload -> 'exec_contract' -> 'allowed_hosts' AS hosts FROM mint.events"
        " WHERE instance_id = %s AND kind = 'server_registered'"
        " AND payload ->> 'server_id' = %s AND payload ->> 'exec_contract_sha256' = %s"
        " ORDER BY inserted_at DESC LIMIT 1",
        (instance, server_id, row["exec_contract_sha256"]),
    )
    row["file_access"] = (declared or {}).get("access") or []
    row["network"] = (declared or {}).get("network") or "any"
    row["allowed_hosts"] = (declared or {}).get("hosts") or []
    row["packages"] = fetchall(
        conn,
        "SELECT p.ecosystem, p.name, p.version, p.pinned, p.registry FROM mint.servers s"
        " JOIN mint.server_packages p ON p.instance_id = s.instance_id"
        " AND p.server_id = s.server_id AND p.exec_contract_sha256 = s.exec_contract_sha256"
        " WHERE s.instance_id = %s AND s.server_id = %s ORDER BY p.ecosystem, p.name",
        (instance, server_id),
    )
    row["vulns"] = fetchall(
        conn,
        "SELECT v.ecosystem, v.name, v.version, v.vuln_id, v.severity, v.cvss, v.exploited,"
        " v.first_seen_at, v.first_seen_at + interval '48 hours' AS deadline_at, NULL::text AS path"
        " FROM mint.servers s JOIN mint.server_packages p"
        " ON p.instance_id = s.instance_id AND p.server_id = s.server_id"
        " AND p.exec_contract_sha256 = s.exec_contract_sha256 JOIN mint.package_vulns v"
        " ON v.instance_id = p.instance_id AND v.ecosystem = p.ecosystem AND v.name = p.name"
        " AND v.version = p.version AND v.cleared_at IS NULL"
        " WHERE s.instance_id = %s AND s.server_id = %s"
        " UNION ALL SELECT v.ecosystem, v.name, v.version, v.vuln_id, v.severity, v.cvss,"
        " v.exploited, v.first_seen_at, v.first_seen_at + interval '48 hours', d.path"
        " FROM mint.servers s JOIN mint.server_packages p"
        " ON p.instance_id = s.instance_id AND p.server_id = s.server_id"
        " AND p.exec_contract_sha256 = s.exec_contract_sha256 JOIN mint.package_deps t"
        " ON t.instance_id = p.instance_id AND t.ecosystem = p.ecosystem AND t.name = p.name"
        " AND t.version = p.version AND t.dep_name = t.name AND t.dep_version = t.version"
        " JOIN mint.package_deps d ON d.instance_id = t.instance_id AND d.ecosystem = t.ecosystem"
        " AND d.name = t.name AND d.version = t.version AND d.resolved_at = t.resolved_at"
        " AND NOT (d.dep_name = d.name AND d.dep_version = d.version)"
        " JOIN mint.package_vulns v ON v.instance_id = d.instance_id"
        " AND v.ecosystem = d.ecosystem AND v.name = d.dep_name AND v.version = d.dep_version"
        " AND v.cleared_at IS NULL WHERE s.instance_id = %s AND s.server_id = %s"
        " ORDER BY first_seen_at",
        (instance, server_id, instance, server_id),
    )
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
    only_id: str | None = None,
) -> list[dict]:
    limit, offset = _page(page)
    return fetchall(
        conn,
        "SELECT id, org_id, relation_id, class, server_id, tools, scope_type, scope_id, valid_from,"
        " valid_until, conditions, basis, granted_by, requested_by, status, revoked_at,"
        " revoke_reason, state_version, recert_confirmed_at, recert_confirmed_by,"
        " recert_requested_at, recert_held_at FROM mint.approvals WHERE instance_id = %s"
        " AND (%s::text IS NULL OR server_id = %s) AND (%s::text IS NULL OR status = %s)"
        " AND (%s::uuid IS NULL OR id = %s::uuid)"
        " ORDER BY valid_until DESC, id DESC LIMIT %s OFFSET %s",
        (instance, server_id, server_id, status, status, only_id, only_id, limit, offset),
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
    conn: psycopg.Connection,
    instance: str,
    *,
    status: str | None = None,
    page: int = 1,
    only_id: str | None = None,
) -> list[dict]:
    limit, offset = _page(page)
    return fetchall(
        conn,
        "SELECT id, org_id, principal_type, principal_id, server_id, tool, status, requested_by,"
        " approved_by, expires_at, window_minutes, valid_until, state_version,"
        " target, action, display, requested_at, decided_at, decision_reason,"
        " CASE WHEN c.valid_until IS NOT NULL AND c.status = 'approved'"
        "  THEN greatest(extract(epoch FROM c.valid_until - now()), 0)::int END"
        "  AS remaining_seconds,"
        " greatest(extract(epoch FROM now() - c.requested_at), 0)::int AS age_seconds,"
        " extended_by, extended_at,"
        " (c.status = 'approved' AND c.window_minutes IS NOT NULL AND c.extended_at IS NULL"
        "  AND c.valid_until > now() AND c.valid_until <= now() + make_interval(mins => %s))"
        "  AS can_extend,"
        " (SELECT t.action_type FROM mint.tool_contracts t"
        "  WHERE t.instance_id = c.instance_id AND t.id = c.contract_id) AS action_type,"
        " (SELECT count(*) FROM mint.call_approval_uses u WHERE u.call_approval_id = c.id) AS uses"
        " FROM mint.call_approvals c WHERE c.instance_id = %s"
        " AND (%s::text IS NULL OR c.status = %s)"
        " AND (%s::uuid IS NULL OR c.id = %s::uuid)"
        " ORDER BY (c.status = 'pending') DESC, coalesce(c.valid_until, c.expires_at) ASC, c.id"
        " LIMIT %s OFFSET %s",
        (CALL_EXTEND_WITHIN_MINUTES, instance, status, status, only_id, only_id, limit, offset),
    )


def call_approval_rules(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT id, org_id, scope_type, principal_type, scope_id, server_id, action_class,"
        " tool_pattern, window_minutes, valid_until, created_by, created_at,"
        " CASE WHEN status = 'active' AND valid_until <= now() THEN 'expired' ELSE status END"
        " AS status, state_version,"
        " (SELECT count(*) FROM mint.call_approvals c WHERE c.instance_id = r.instance_id"
        "  AND c.approved_by = 'rule:' || r.id::text) AS opened"
        " FROM mint.call_approval_rules r WHERE r.instance_id = %s"
        " ORDER BY (r.status = 'active') DESC, r.created_at DESC, r.id",
        (instance,),
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


PERMITTING_RESULTS = frozenset({"Allow", "Alert"})


def flip_kind(active: str, shadow: str) -> str:
    """판정이 달라진 방향. 허용·경고는 통과, 승인 요구·차단은 막힘으로 본다."""
    if (active in PERMITTING_RESULTS) and (shadow not in PERMITTING_RESULTS):
        return "allow_to_deny"
    if (active not in PERMITTING_RESULTS) and (shadow in PERMITTING_RESULTS):
        return "deny_to_allow"
    return "other"


def policy_shadow(conn: psycopg.Connection, instance: str) -> dict | None:
    """시험 중인 판본과 판정이 달라진 호출 집계. 시험 판본이 없으면 None이다."""
    current = fetchone(
        conn,
        "SELECT version_id, bundle_sha256, set_by, set_at FROM mint.policy_shadow"
        " WHERE instance_id = %s AND version_id IS NOT NULL",
        (instance,),
    )
    if current is None:
        return None
    stats = fetchone(
        conn,
        "SELECT evaluated, same, errors, skipped, updated_at FROM mint.policy_shadow_stats"
        " WHERE instance_id = %s AND version_id = %s",
        (instance, current["version_id"]),
    ) or {"evaluated": 0, "same": 0, "errors": 0, "skipped": 0, "updated_at": None}
    flips = fetchall(
        conn,
        "SELECT server_id, tool, active_result, shadow_result, active_reason, shadow_reason,"
        " calls, last_seen_at, samples FROM mint.policy_shadow_results"
        " WHERE instance_id = %s AND version_id = %s ORDER BY calls DESC, server_id, tool",
        (instance, current["version_id"]),
    )
    totals = {"allow_to_deny": 0, "deny_to_allow": 0, "other": 0}
    for row in flips:
        row["flip"] = flip_kind(row["active_result"], row["shadow_result"])
        totals[row["flip"]] += row["calls"]
    return {**current, "stats": stats, "flips": flips, "totals": totals}


def settings(conn: psycopg.Connection, instance: str) -> dict | None:
    return fetchone(
        conn,
        "SELECT mode, observable_reasons, observable_policy_ids, default_org_id, settings_version"
        " FROM mint.settings WHERE instance_id = %s",
        (instance,),
    )


# --- 원장 -----------------------------------------------------------------------------------


def parse_ref(text: str) -> tuple[UUID, int | None]:
    """차단 응답의 판정 참조(``<호출 식별자>`` 또는 ``<호출 식별자>:<시도 번호>``)를 푼다."""
    head, _, tail = text.strip().partition(":")
    attempt = int(tail) if tail else None
    if attempt is not None and attempt < 1:
        raise ValueError("attempt")
    return UUID(head), attempt


def _ledger_where(
    instance: str,
    *,
    since: datetime | None,
    until: datetime | None,
    kind: str | None,
    actor: str | None,
    server_id: str | None,
    result: str | None,
    ref: str | None = None,
    invocation_id: str | None = None,
) -> tuple[str, list[Any]]:
    clauses = ["instance_id = %s"]
    params: list[Any] = [instance]
    # 판정 참조로 찾을 때는 기본 조회 기간을 두지 않는다.
    if since is not None or ref is None:
        clauses.append("inserted_at >= %s")
        params.append(since or datetime.now(UTC) - timedelta(days=LEDGER_DEFAULT_DAYS))
    if ref is not None:
        invocation, attempt = parse_ref(ref)
        clauses.append("invocation_id = %s")
        params.append(invocation)
        if attempt is not None:
            clauses.append("attempt_id = %s")
            params.append(attempt)
    for clause, value in (
        ("inserted_at < %s", until),
        ("kind = %s", kind),
        ("actor = %s", actor),
        ("(payload->>'resolved_server_id' = %s OR payload->>'server_id' = %s)", server_id),
        ("invocation_id = %s", invocation_id),
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
    ref: str | None = None,
    page: int = 1,
    limit: int | None = None,
    invocation_id: str | None = None,
) -> list[dict]:
    where, params = _ledger_where(
        instance, since=since, until=until, kind=kind, actor=actor, server_id=server_id,
        result=result, ref=ref, invocation_id=invocation_id,
    )
    size, offset = (limit, 0) if limit is not None else _page(page)
    return fetchall(
        conn,
        "SELECT event_id, inserted_at, kind, source_key, actor,"
        " COALESCE(payload->>'resolved_server_id', payload->>'server_id') AS server_id,"
        " payload->>'enforced_action' AS result, payload->>'outcome' AS outcome, payload"
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


# --- 경보 ----------------------------------------------------------------------------------

ALERT_COLUMNS = (
    "id, kind, severity, status, subject, first_at, last_at, count, acknowledged_by, resolved_at,"
    " subject->>'server_id' AS server_id"
)


def alerts(
    conn: psycopg.Connection,
    instance: str,
    *,
    status: str | None = None,
    severity: str | None = None,
    kind: str | None = None,
    server_id: str | None = None,
    page: int = 1,
) -> list[dict]:
    """해결되지 않은 경보를 먼저, 심각한 순서로, 그다음 최근 순서로 낸다."""
    where, params = ["instance_id = %s"], [instance]
    for column, value in (("status", status), ("severity", severity), ("kind", kind),
                          ("subject->>'server_id'", server_id)):
        if value:
            where.append(f"{column} = %s")
            params.append(value)
    size, offset = _page(page)
    return fetchall(
        conn,
        f"SELECT {ALERT_COLUMNS} FROM mint.alerts WHERE {' AND '.join(where)}"
        " ORDER BY (status = 'resolved'),"
        " array_position(ARRAY['critical', 'high', 'medium', 'low'], severity),"
        " last_at DESC, id LIMIT %s OFFSET %s",
        (*params, size, offset),
    )


def alert(conn: psycopg.Connection, instance: str, alert_id: str) -> dict | None:
    return fetchone(
        conn,
        f"SELECT {ALERT_COLUMNS} FROM mint.alerts WHERE instance_id = %s AND id = %s",
        (instance, alert_id),
    )


def alert_filters(conn: psycopg.Connection, instance: str) -> dict[str, list[str]]:
    kinds = fetchall(
        conn, "SELECT DISTINCT kind FROM mint.alerts WHERE instance_id = %s ORDER BY kind",
        (instance,),
    )
    servers = fetchall(
        conn,
        "SELECT DISTINCT subject->>'server_id' AS server_id FROM mint.alerts"
        " WHERE instance_id = %s AND subject->>'server_id' IS NOT NULL ORDER BY 1",
        (instance,),
    )
    return {"kinds": [r["kind"] for r in kinds], "servers": [r["server_id"] for r in servers]}


def urgent_alert_count(conn: psycopg.Connection, instance: str) -> int:
    """아직 확인하지 않은 높음·심각 경보의 수(메뉴 표지)."""
    row = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.alerts WHERE instance_id = %s AND status = 'open'"
        " AND severity IN ('high', 'critical')",
        (instance,),
    )
    return row["n"] if row else 0


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
        "pending_intakes": one(
            "SELECT count(*) FROM mint.intakes WHERE instance_id = %s AND status = 'passed'"
        ),
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
