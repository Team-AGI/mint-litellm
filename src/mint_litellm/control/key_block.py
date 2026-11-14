"""LiteLLM 가상 키 차단 제안: 탐지한 강한 증거를 사람이 승인한 뒤에만 LiteLLM의 차단으로 옮긴다.

탐지(``key_block_scan``)는 최근 구간의 사건에서 한 키로 확정되는 증거만 제안으로 만든다.

- ``secret_exposure``: 인자나 결과에서 비밀·자격이 걸렸다.
- ``repeated_denials``: 같은 키가 정책 거부를 되풀이했다.
- ``bulk_extraction``: 대량 추출 경보의 호출 주체가 쓴 키가 하나로 확정된다.
- ``endpoint_compromise``: 단말 경보(실행기 밖 미승인 패키지, 허용 밖 접속 거절)의 설치 키.

키는 판정 사건의 주체(``principal.key_id``)로만 확정한다. 키 없는 주체(JWT 등)나 한 호출 주체의
증거가 여러 키에 걸리면 제안하지 않는다. 증거에는 탐지 종류·건수·사건 식별자만 둔다.

승인은 승인 시점에 LiteLLM의 현재 상태를 다시 읽고, 차단 호출과 결과 확인(``blocked`` 다시 읽기)은
작업 실행기(``key_block_apply``)가 한다. 해제는 자동으로 하지 않는다. LiteLLM은 차단 여부를 불리언
하나로만 보관하므로 MINT가 차단한 표지와 그때의 키 갱신 시각을 따로 남기고, 해제 때 비교해
그 사이 바뀐 것으로 보이면 경고한다.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from mint_litellm.control import alerts, ledger
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import (
    ControlError,
    conflict,
    forbidden,
    not_found,
    separation_of_duties,
    stale_evidence,
)
from mint_litellm.control.jobs import JobContext
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.litellm_write import (
    LiteLLMForbidden,
    LiteLLMHttpError,
    LiteLLMUnreachable,
)
from mint_litellm.control.services.base import enqueue_job
from mint_litellm.plugin.policy.sensitive_scan import SECRET_KINDS
from mint_litellm.types.events import AlertKind, EventKind
from mint_litellm.types.ids import new_uuid7

log = logging.getLogger(__name__)

ALERT = AlertKind.KEY_BLOCK_PROPOSED.value
ACTOR = "key-block-scan"
JOB_KIND = "key_block_apply"
WINDOW_SECONDS = 900
EXPIRES_AFTER = timedelta(hours=24)
# 같은 키에 대한 제안은 이 시간 안에 다시 만들지 않는다(거절·만료·해제 뒤에도 같다).
COOLDOWN = timedelta(hours=24)
DENIAL_THRESHOLD = 10
PRINCIPALS = ("user", "team_key", "service_account")
ENDPOINT_ALERTS = (
    AlertKind.ENDPOINT_OUTSIDE_UNAPPROVED.value,
    AlertKind.ENDPOINT_EGRESS_REFUSED.value,
)
INPUT_SECRET = "input_secret"
APPROVERS = ("admin", "approver")
OPEN = ("proposed", "approved", "unblocking")


def alert_key(proposal_id: Any) -> str:
    return f"{ALERT}:{proposal_id}"


# --- 탐지 ------------------------------------------------------------------------------------

_DECISION = (
    " JOIN mint.events d ON d.instance_id = r.instance_id AND d.invocation_id = r.invocation_id"
    " AND d.attempt_id = r.attempt_id AND d.kind = 'decision_evaluated'"
)
_KEY = "d.payload->'principal'->>'key_id'"
_TYPE = "d.payload->'principal'->>'principal_type'"


def _secret_rows(conn: psycopg.Connection, instance: str) -> list[dict]:
    """결과에서 걸린 비밀 종류, 계약 관리 전 서버가 관측만 한 인자 비밀, 막힌 인자 비밀."""
    found = fetchall(
        conn,
        f"SELECT {_KEY} AS key_id, {_TYPE} AS ptype, count(*) AS n,"
        " (array_agg(r.event_id ORDER BY r.inserted_at DESC))[1:10] AS ids,"
        " array_agg(DISTINCT lbl) AS labels FROM mint.events r" + _DECISION
        + " CROSS JOIN LATERAL jsonb_object_keys(COALESCE(CASE WHEN"
        " jsonb_typeof(r.payload->'sensitive_findings') = 'object'"
        " THEN r.payload->'sensitive_findings' END, '{}'::jsonb)) AS lbl"
        " WHERE r.instance_id = %s AND r.kind = 'call_response_received'"
        " AND r.inserted_at >= now() - make_interval(secs => %s) AND lbl = ANY(%s)"
        " GROUP BY 1, 2",
        (instance, WINDOW_SECONDS, sorted(SECRET_KINDS)),
    )
    observed = fetchall(
        conn,
        f"SELECT {_KEY} AS key_id, {_TYPE} AS ptype, count(*) AS n,"
        " (array_agg(r.event_id ORDER BY r.inserted_at DESC))[1:10] AS ids,"
        f" ARRAY['{INPUT_SECRET}'] AS labels FROM mint.events r" + _DECISION
        + " WHERE r.instance_id = %s"
        " AND r.kind IN ('call_response_received', 'call_outcome_unknown')"
        " AND r.inserted_at >= now() - make_interval(secs => %s)"
        " AND jsonb_typeof(r.payload->'unmanaged_findings') = 'array'"
        " AND r.payload->'unmanaged_findings' ? 'POL-E-05' GROUP BY 1, 2",
        (instance, WINDOW_SECONDS),
    )
    blocked = fetchall(
        conn,
        "SELECT e.payload->'principal'->>'key_id' AS key_id,"
        " e.payload->'principal'->>'principal_type' AS ptype, count(*) AS n,"
        " (array_agg(e.event_id ORDER BY e.inserted_at DESC))[1:10] AS ids,"
        f" ARRAY['{INPUT_SECRET}'] AS labels FROM mint.events e"
        " WHERE e.instance_id = %s AND e.kind = 'decision_evaluated'"
        " AND e.inserted_at >= now() - make_interval(secs => %s)"
        " AND e.payload @? '$.findings[*] ? (@.detail like_regex \"^input \")' GROUP BY 1, 2",
        (instance, WINDOW_SECONDS),
    )
    return [*found, *observed, *blocked]


def _denial_rows(conn: psycopg.Connection, instance: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT payload->'principal'->>'key_id' AS key_id,"
        " payload->'principal'->>'principal_type' AS ptype, count(*) AS n,"
        " (array_agg(event_id ORDER BY inserted_at DESC))[1:10] AS ids FROM mint.events"
        " WHERE instance_id = %s AND kind = 'decision_evaluated'"
        " AND inserted_at >= now() - make_interval(secs => %s)"
        " AND payload->>'enforced_action' = 'block' AND payload->>'operation' = 'tool_call'"
        " AND jsonb_array_length(CASE WHEN jsonb_typeof(payload->'policy_ids') = 'array'"
        " THEN payload->'policy_ids' ELSE '[]'::jsonb END) > 0"
        " GROUP BY 1, 2 HAVING count(*) >= %s",
        (instance, WINDOW_SECONDS, DENIAL_THRESHOLD),
    )


def _bulk_candidates(conn: psycopg.Connection, instance: str) -> list[dict]:
    out = []
    for alert in fetchall(
        conn,
        "SELECT id, subject FROM mint.alerts WHERE instance_id = %s AND kind = %s"
        " AND status <> 'resolved'",
        (instance, AlertKind.BULK_EXTRACTION.value),
    ):
        subject = alert["subject"]
        if not subject.get("principal_id") or not subject.get("server_id"):
            continue
        keys = fetchall(
            conn,
            f"SELECT {_KEY} AS key_id, count(*) AS n,"
            " (array_agg(r.event_id ORDER BY r.inserted_at DESC))[1:10] AS ids"
            " FROM mint.events r" + _DECISION
            + " WHERE r.instance_id = %s AND r.kind = 'call_response_received'"
            " AND r.subject->>'principal_id' = %s AND r.payload->>'server_id' = %s"
            " AND r.inserted_at >= now() - make_interval(secs => %s) GROUP BY 1",
            (instance, subject["principal_id"], subject["server_id"],
             int(subject.get("window_seconds") or WINDOW_SECONDS)),
        )
        if len(keys) == 1 and keys[0]["key_id"]:
            out.append({
                "key_token": keys[0]["key_id"], "signal": "bulk_extraction",
                "evidence": {
                    "calls": keys[0]["n"], "event_ids": [str(i) for i in keys[0]["ids"]],
                    "server_id": subject["server_id"], "alert_id": str(alert["id"]),
                    "bytes": subject.get("bytes"), "items": subject.get("items"),
                },
            })
    return out


def _endpoint_candidates(conn: psycopg.Connection, instance: str) -> list[dict]:
    rows = fetchall(
        conn,
        "SELECT a.id, a.kind, a.subject, i.key_token FROM mint.alerts a"
        " JOIN mint.endpoint_installs i ON i.instance_id = a.instance_id"
        " AND i.key_alias = a.subject->>'key_alias' AND i.revoked_at IS NULL"
        " WHERE a.instance_id = %s AND a.kind = ANY(%s) AND a.status <> 'resolved'",
        (instance, list(ENDPOINT_ALERTS)),
    )
    return [
        {
            "key_token": r["key_token"], "signal": "endpoint_compromise",
            "evidence": {
                "alert_id": str(r["id"]), "alert_kind": r["kind"],
                "server_id": r["subject"].get("server_id"), "package": r["subject"].get("package"),
                "count": r["subject"].get("count"), "event_ids": [],
            },
        }
        for r in rows
    ]


def candidates(conn: psycopg.Connection, instance: str) -> dict[str, dict]:
    """키 하나당 제안 후보 하나(먼저 찾은 근거가 이긴다). 키로 확정되지 않은 증거는 버린다."""
    out: dict[str, dict] = {}

    def add(key: str | None, ptype: str | None, signal: str, evidence: dict) -> None:
        if key and ptype in PRINCIPALS and key not in out:
            out[key] = {"key_token": key, "signal": signal, "evidence": evidence}

    for r in _secret_rows(conn, instance):
        add(r["key_id"], r["ptype"], "secret_exposure", {
            "labels": sorted(r["labels"]), "calls": r["n"],
            "event_ids": [str(i) for i in r["ids"]],
        })
    for r in _denial_rows(conn, instance):
        add(r["key_id"], r["ptype"], "repeated_denials", {
            "denials": r["n"], "event_ids": [str(i) for i in r["ids"]],
        })
    for c in (*_bulk_candidates(conn, instance), *_endpoint_candidates(conn, instance)):
        out.setdefault(c["key_token"], c)
    return out


def _team_impact(litellm: Any, team_id: str | None, cache: dict) -> tuple[int | None, int | None]:
    """팀 전체 차단을 고를 때 보여 줄 영향: (키 수, 구성원 수). 읽지 못하면 None."""
    if not team_id:
        return None, None
    try:
        team = litellm.get_team(team_id) or {}
        if "keys" not in cache:
            cache["keys"] = litellm.list_keys()
    except LiteLLMError:
        return None, None
    keys = sum(1 for k in cache["keys"] if k.get("team_id") == team_id)
    return keys, len(team.get("members_with_roles") or [])


def _propose(job: JobContext, found: dict, cache: dict) -> bool:
    conn, instance, client = job.conn, job.instance_id, job.litellm
    token = found["key_token"]
    if token == client.key_token:
        return False  # 제어 평면 키는 제안하지 않는다
    if fetchone(
        conn,
        "SELECT 1 AS x FROM mint.key_block_proposals WHERE instance_id = %s AND key_token = %s"
        " AND created_at > now() - %s",
        (instance, token, COOLDOWN),
    ):
        return False
    try:
        info = client.get_key(token)
        if info is None or info.get("blocked") is True:
            return False  # 없거나 이미 막혀 있으면 제안할 것이 없다
        keys, members = _team_impact(client, info.get("team_id"), cache)
    except LiteLLMError:
        return False
    proposal_id = new_uuid7()
    expires = datetime.now(UTC) + EXPIRES_AFTER
    with conn.transaction():
        made = conn.execute(
            "INSERT INTO mint.key_block_proposals (id, instance_id, signal, key_token, key_alias,"
            " user_id, team_id, team_key_count, team_member_count, evidence, expires_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (proposal_id, instance, found["signal"], token, info.get("key_alias"),
             info.get("user_id"), info.get("team_id"), keys, members,
             Jsonb({**found["evidence"], "window_seconds": WINDOW_SECONDS,
                    "principal_binding": "decision_principal_key"}), expires),
        ).rowcount
        if not made:
            return False
        alerts.raise_alert(
            conn, instance, kind=ALERT, severity="high", dedup_key=alert_key(proposal_id),
            subject={
                "proposal_id": str(proposal_id), "key_alias": info.get("key_alias"),
                "signal": found["signal"], "expires_at": expires.isoformat(),
            },
        )
        ledger.record(
            conn, instance, EventKind.KEY_BLOCK_PROPOSED, entity_id=str(proposal_id),
            state_version=1, actor=ACTOR,
            payload={"signal": found["signal"], "key_alias": info.get("key_alias"),
                     "expires_at": expires.isoformat()},
        )
    return True


def _expire(conn: psycopg.Connection, instance: str) -> None:
    with conn.transaction():
        for row in fetchall(
            conn,
            "UPDATE mint.key_block_proposals SET status = 'expired' WHERE instance_id = %s"
            " AND status = 'proposed' AND expires_at <= now() RETURNING id, state_version",
            (instance,),
        ):
            alerts.resolve(conn, instance, alert_key(row["id"]))
            ledger.record(
                conn, instance, EventKind.KEY_BLOCK_EXPIRED, entity_id=str(row["id"]),
                state_version=row["state_version"], actor=ACTOR, payload={},
            )


def run(job: JobContext) -> None:
    _expire(job.conn, job.instance_id)
    if job.litellm is None:
        return  # 키가 LiteLLM에 있는지 확인할 수 없으면 제안하지 않는다
    cache: dict = {}
    for found in candidates(job.conn, job.instance_id).values():
        _propose(job, found, cache)


# --- 승인·거절·해제 ---------------------------------------------------------------------------


def _require(ctx: Context, roles: tuple[str, ...]) -> None:
    if ctx.operator.role not in roles:
        raise forbidden(f"{ctx.operator.role} 역할은 이 작업을 할 수 없습니다.", exit_code=4)


def _row(ctx: Context, proposal_id: str) -> dict:
    row = fetchone(
        ctx.conn,
        "SELECT * FROM mint.key_block_proposals WHERE instance_id = %s AND id = %s",
        (ctx.instance_id, proposal_id),
    )
    if row is None:
        raise not_found(f"차단 제안 {proposal_id}이(가) 없습니다.")
    return row


def _check_version(row: dict, expected: int | None) -> None:
    if expected is not None and row["state_version"] != expected:
        raise conflict(
            f"제안의 상태 버전이 요청({expected})과 다릅니다(현재 {row['state_version']}). "
            "다시 읽은 뒤 시도하십시오."
        )


def _decide(ctx: Context, row: dict, status: str, kind: EventKind, reason: str, **cols: Any):
    """``proposed`` 행만 한 번 바꾼다. 같은 트랜잭션에 사건을 남기고 경보를 닫는다."""
    sets = ", ".join(f"{c} = %s" for c in cols)
    done = fetchone(
        ctx.conn,
        f"UPDATE mint.key_block_proposals SET status = %s, decided_by = %s,"
        f" decided_at = clock_timestamp(), decision_reason = %s{', ' + sets if sets else ''}"
        " WHERE instance_id = %s AND id = %s AND status = 'proposed' RETURNING state_version",
        (status, ctx.operator.name, reason[:500], *cols.values(), ctx.instance_id, row["id"]),
    )
    if done is None:
        raise conflict("다른 곳에서 이미 처리한 제안입니다. 다시 읽은 뒤 시도하십시오.")
    alerts.resolve(ctx.conn, ctx.instance_id, alert_key(row["id"]))
    ctx.emit(kind, row["id"], done["state_version"],
             {"signal": row["signal"], "key_alias": row["key_alias"], "reason": reason[:500],
              "scope": cols.get("scope", row["scope"])})


def _state_of(litellm: Any, scope: str, row: dict) -> dict | None:
    return litellm.get_key(row["key_token"]) if scope == "key" else litellm.get_team(row["team_id"])


def approve(
    ctx: Context, litellm: Any, proposal_id: str, *, scope: str = "key", reason: str = "",
    expected_version: int | None = None,
) -> dict:
    """제안을 승인한다. 현재 LiteLLM 상태를 다시 읽고, 차단은 작업 실행기가 한다.

    같은 제안을 다시 승인해도 작업을 또 만들지 않고 현재 상태를 돌려준다.
    """
    _require(ctx, APPROVERS)
    if scope not in ("key", "team"):
        raise ControlError("scope는 key 또는 team이어야 합니다.")
    row = _row(ctx, proposal_id)
    if row["status"] in ("approved", "applied"):
        return {"id": str(row["id"]), "status": row["status"], "repeated": True}
    if row["status"] != "proposed":
        raise conflict(f"이미 {row['status']} 상태인 제안은 승인할 수 없습니다.")
    _check_version(row, expected_version)
    if row["expires_at"] <= datetime.now(UTC):
        raise stale_evidence("제안이 만료되었습니다. 증거를 다시 확인하십시오.")
    if scope == "team" and not row["team_id"]:
        raise ControlError("이 키는 팀에 속하지 않아 팀 차단을 고를 수 없습니다.")
    if not ctx.operator.user_id:
        raise separation_of_duties("승인자의 사용자 결속이 필요합니다.")
    key = litellm.get_key(row["key_token"])
    if key is None:
        raise stale_evidence("LiteLLM에서 이 키를 찾을 수 없습니다. 제안을 거절하십시오.")
    if key.get("user_id") == ctx.operator.user_id:
        raise separation_of_duties("자기 키의 차단 제안은 승인할 수 없습니다.")
    target = _state_of(litellm, scope, row)
    if target is None:
        raise stale_evidence("LiteLLM에서 차단 대상을 찾을 수 없습니다.")
    if scope == "team" and ctx.operator.user_id in {
        m.get("user_id") for m in target.get("members_with_roles") or []
    }:
        raise separation_of_duties("자기가 속한 팀의 차단은 승인할 수 없습니다.")
    with ctx.conn.transaction():
        if target.get("blocked") is True:
            # 승인 사이에 누군가 이미 막았다. MINT가 막은 것이 아니므로 표지를 남기지 않는다.
            _decide(ctx, row, "applied", EventKind.KEY_BLOCK_APPROVED, reason, scope=scope,
                    applied_at=datetime.now(UTC), last_error="already_blocked")
            return {"id": str(row["id"]), "status": "applied", "already_blocked": True}
        _decide(ctx, row, "approved", EventKind.KEY_BLOCK_APPROVED, reason, scope=scope)
        enqueue_job(ctx, JOB_KIND, f"{row['id']}:block", f"{JOB_KIND}:{row['id']}:block")
    return {"id": str(row["id"]), "status": "approved"}


def reject(
    ctx: Context, proposal_id: str, *, reason: str = "", expected_version: int | None = None
) -> dict:
    _require(ctx, APPROVERS)
    row = _row(ctx, proposal_id)
    if row["status"] == "rejected":
        return {"id": str(row["id"]), "status": "rejected", "repeated": True}
    if row["status"] != "proposed":
        raise conflict(f"이미 {row['status']} 상태인 제안은 거절할 수 없습니다.")
    _check_version(row, expected_version)
    with ctx.conn.transaction():
        _decide(ctx, row, "rejected", EventKind.KEY_BLOCK_REJECTED, reason)
    return {"id": str(row["id"]), "status": "rejected"}


def changed_since_block(row: dict, current: dict) -> bool:
    """차단을 확인한 뒤 LiteLLM 객체가 바뀐 것으로 보이는가. 표지가 없으면 바뀐 것으로 본다."""
    marker = row["marker_updated_at"]
    return marker is None or str(current.get("updated_at")) != marker


def request_unblock(
    ctx: Context, litellm: Any, proposal_id: str, *, reason: str, acknowledge: bool = False,
    expected_version: int | None = None,
) -> dict:
    """MINT가 제안해 막은 대상을 푼다(관리자만, 자동 해제 없음). 바뀐 것 같으면 확인을 요구한다."""
    _require(ctx, ("admin",))
    if not reason.strip():
        raise ControlError("해제 사유가 필요합니다.")
    row = _row(ctx, proposal_id)
    if row["status"] == "unblocking":
        return {"id": str(row["id"]), "status": "unblocking", "repeated": True}
    if row["status"] != "applied" or not row["mint_blocked"]:
        raise conflict("MINT가 제안해 차단한 대상만 여기서 해제할 수 있습니다.")
    _check_version(row, expected_version)
    current = _state_of(litellm, row["scope"], row)
    if current is None:
        raise stale_evidence("LiteLLM에서 차단 대상을 찾을 수 없습니다.")
    if current.get("blocked") is not True:
        with ctx.conn.transaction():
            _unblocked(ctx, row, "already_unblocked", reason)
        return {"id": str(row["id"]), "status": "unblocked", "already_unblocked": True}
    if changed_since_block(row, current) and not acknowledge:
        raise conflict(
            "MINT가 차단한 뒤 LiteLLM에서 이 대상이 바뀐 것으로 보입니다. 다른 관리자가 차단했거나 "
            "설정을 바꿨을 수 있으니 확인한 뒤 확인 표시와 함께 다시 해제하십시오."
        )
    with ctx.conn.transaction():
        done = fetchone(
            ctx.conn,
            "UPDATE mint.key_block_proposals SET status = 'unblocking', unblocked_by = %s,"
            " unblock_reason = %s, unblock_acknowledged = %s WHERE instance_id = %s AND id = %s"
            " AND status = 'applied' RETURNING state_version",
            (ctx.operator.name, reason[:500], acknowledge, ctx.instance_id, row["id"]),
        )
        if done is None:
            raise conflict("다른 곳에서 이미 처리한 제안입니다. 다시 읽은 뒤 시도하십시오.")
        ctx.emit(EventKind.KEY_BLOCK_UNBLOCK_REQUESTED, row["id"], done["state_version"],
                 {"signal": row["signal"], "key_alias": row["key_alias"], "scope": row["scope"],
                  "reason": reason[:500], "acknowledged": acknowledge})
        enqueue_job(ctx, JOB_KIND, f"{row['id']}:unblock", f"{JOB_KIND}:{row['id']}:unblock")
    return {"id": str(row["id"]), "status": "unblocking"}


def _unblocked(ctx: Context, row: dict, result: str, reason: str) -> None:
    done = fetchone(
        ctx.conn,
        "UPDATE mint.key_block_proposals SET status = 'unblocked', unblocked_by = %s,"
        " unblock_reason = %s, unblocked_at = clock_timestamp() WHERE instance_id = %s AND id = %s"
        " RETURNING state_version",
        (ctx.operator.name, reason[:500], ctx.instance_id, row["id"]),
    )
    ctx.emit(EventKind.KEY_BLOCK_UNBLOCKED, row["id"], done["state_version"],
             {"signal": row["signal"], "key_alias": row["key_alias"], "scope": row["scope"],
              "result": result})


# --- 작업 실행기: 차단·해제 호출과 결과 확인 ------------------------------------------------


def apply(job: JobContext) -> None:
    """``<제안>:block|unblock`` 작업. 같은 작업이 다시 돌아도 이미 끝난 제안은 건드리지 않는다."""
    proposal_id, _, action = job.job["target_ref"].partition(":")
    conn, instance = job.conn, job.instance_id
    row = fetchone(
        conn, "SELECT * FROM mint.key_block_proposals WHERE instance_id = %s AND id = %s",
        (instance, proposal_id),
    )
    blocking = action == "block"
    if row is None or row["status"] != ("approved" if blocking else "unblocking"):
        return
    if job.litellm is None:
        raise ControlError("MINT_LITELLM_URL과 MINT_LITELLM_KEY가 없어 차단할 수 없습니다.")
    client = job.litellm.with_hook(job.external_write)
    scope = row["scope"]
    target = row["key_token"] if scope == "key" else row["team_id"]
    error = None
    marker = None
    try:
        before = _state_of(client, scope, row)
        if before is None:
            error = "target_missing"
        elif (before.get("blocked") is True) == blocking:
            marker = before.get("updated_at")  # 이미 원하는 상태: 호출하지 않는다
        else:
            client.set_blocked(scope, target, blocking)
            after = _state_of(client, scope, row)
            if after is None or (after.get("blocked") is True) != blocking:
                error = "not_confirmed"
            marker = (after or {}).get("updated_at")
        already = before is not None and (before.get("blocked") is True) == blocking
    except LiteLLMUnreachable:
        raise
    except LiteLLMForbidden:
        error, already = "route_forbidden", False
    except LiteLLMHttpError as failure:
        error, already = f"http_{failure.status}", False
    ctx = Context(conn, instance, Operator(ACTOR, "system", None))
    with conn.transaction():
        if blocking:
            _finish_block(ctx, row, error, already, marker)
        elif error:
            conn.execute(
                "UPDATE mint.key_block_proposals SET status = 'applied', last_error = %s"
                " WHERE instance_id = %s AND id = %s", (error, instance, row["id"]),
            )
        else:
            _unblocked_done(ctx, row, already)


def _finish_block(ctx: Context, row: dict, error: str | None, already: bool, marker: Any) -> None:
    status = "failed" if error else "applied"
    done = fetchone(
        ctx.conn,
        "UPDATE mint.key_block_proposals SET status = %s, last_error = %s, applied_at = %s,"
        " mint_blocked = %s, marker_updated_at = %s WHERE instance_id = %s AND id = %s"
        " RETURNING state_version",
        (status, error or ("already_blocked" if already else None),
         None if error else datetime.now(UTC), not error and not already,
         None if marker is None else str(marker), ctx.instance_id, row["id"]),
    )
    ctx.emit(
        EventKind.KEY_BLOCK_FAILED if error else EventKind.KEY_BLOCK_APPLIED, row["id"],
        done["state_version"],
        {"signal": row["signal"], "key_alias": row["key_alias"], "scope": row["scope"],
         "result": error or ("already_blocked" if already else "blocked_confirmed")},
    )


def _unblocked_done(ctx: Context, row: dict, already: bool) -> None:
    done = fetchone(
        ctx.conn,
        "UPDATE mint.key_block_proposals SET status = 'unblocked', unblocked_at = clock_timestamp()"
        " WHERE instance_id = %s AND id = %s RETURNING state_version",
        (ctx.instance_id, row["id"]),
    )
    ctx.emit(EventKind.KEY_BLOCK_UNBLOCKED, row["id"], done["state_version"],
             {"signal": row["signal"], "key_alias": row["key_alias"], "scope": row["scope"],
              "result": "already_unblocked" if already else "unblocked_confirmed"})


# --- 조회 --------------------------------------------------------------------------------------


def listing(conn: psycopg.Connection, instance: str, status: str | None = None) -> list[dict]:
    return fetchall(
        conn,
        "SELECT * FROM mint.key_block_proposals WHERE instance_id = %s"
        " AND (%s::text IS NULL OR status = %s) ORDER BY created_at DESC LIMIT 200",
        (instance, status, status),
    )


def show(conn: psycopg.Connection, instance: str, proposal_id: str) -> dict:
    row = fetchone(
        conn, "SELECT * FROM mint.key_block_proposals WHERE instance_id = %s AND id = %s",
        (instance, proposal_id),
    )
    if row is None:
        raise not_found(f"차단 제안 {proposal_id}이(가) 없습니다.")
    return row


def count_waiting(conn: psycopg.Connection, instance: str) -> int:
    row = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.key_block_proposals WHERE instance_id = %s"
        " AND status = 'proposed' AND expires_at > now()",
        (instance,),
    )
    return row["n"]
