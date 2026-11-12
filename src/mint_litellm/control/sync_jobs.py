"""권한 동기화 작업 처리기: ``sync_target``, ``sync_server``, ``sync_reconcile``,
``activation_finalize``.

모든 처리기는 실행 시점의 DB 상태를 읽어 결과를 계산하는 수렴형이다. 같은 작업이 두 번 돌거나
순서가 바뀌어도 결과가 같다. 외부 호출(LiteLLM 읽기·쓰기)은 트랜잭션 밖에서 하고, 그 결과를 DB에
적는 일만 한 트랜잭션으로 묶는다.
"""

import functools
import json
from collections.abc import Callable
from typing import Any

import psycopg

from mint_litellm.control import ledger
from mint_litellm.control.alerts import raise_alert
from mint_litellm.control.alerts import resolve as resolve_alert
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminError, ControlError
from mint_litellm.control.jobs import JobContext, PermanentFailure, WaitForOperator
from mint_litellm.control.litellm_write import (
    LiteLLMForbidden,
    LiteLLMHttpError,
    LiteLLMSync,
    LiteLLMUnreachable,
)
from mint_litellm.control.services.base import enqueue_job
from mint_litellm.control.sync_state import (
    ACTOR,
    SYNC_SCOPES,
    Item,
    Plan,
    desired_for_target,
    expected_pin,
    load_rows,
    make_plan,
    mark_observed,
    permission_of,
    pin_satisfied,
    present,
    server_scope,
    split_ref,
    target_ref,
    upsert_grant,
    withdraw_grant,
)
from mint_litellm.types.canonical import canonical_text, pin_sha256, sha256
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

# MINT가 소유하지 않는 키·팀 필드. 쓰기 응답에서 읽기 전 값과 다르면 다른 관리자의 동시 수정이다.
FOREIGN_FIELDS = ("blocked", "models", "max_budget", "user_id", "team_id", "allowed_routes",
                  "metadata")
UNREACHABLE_ALERT_AFTER = 3
# 관리 API 연속 실패 횟수(작업 실행기 프로세스 안, 실행기 복제본마다 따로 센다).
_failures: dict[str, int] = {}


class NotConfigured(ControlError):
    code = "litellm_not_configured"


def _actor_context(ctx: JobContext) -> Context:
    return Context(ctx.conn, ctx.instance_id, Operator(ACTOR, "system", None))


def _client(ctx: JobContext) -> LiteLLMSync:
    if ctx.litellm is None:
        raise NotConfigured("MINT_LITELLM_URL과 MINT_LITELLM_KEY가 없어 동기화할 수 없습니다.")
    return ctx.litellm.with_hook(ctx.external_write)


def _reachable(handler: Callable[[JobContext], None]) -> Callable[[JobContext], None]:
    """관리 API 연속 실패를 세어 3회째에 경보 ``litellm_unreachable``을 연다. 성공하면 닫는다."""

    @functools.wraps(handler)
    def run(ctx: JobContext) -> None:
        try:
            handler(ctx)
        except LiteLLMUnreachable:
            _failures[ctx.instance_id] = _failures.get(ctx.instance_id, 0) + 1
            if _failures[ctx.instance_id] >= UNREACHABLE_ALERT_AFTER:
                raise_alert(
                    ctx.conn, ctx.instance_id, kind="litellm_unreachable", severity="high",
                    dedup_key="litellm_unreachable",
                    subject={"consecutive_failures": _failures[ctx.instance_id]},
                )
            raise
        _failures[ctx.instance_id] = 0
        resolve_alert(ctx.conn, ctx.instance_id, "litellm_unreachable")

    return run


def _read(client: LiteLLMSync, kind: str, target_id: str) -> dict | None:
    return client.get_key(target_id) if kind == "key" else client.get_team(target_id)


def _event(
    conn: psycopg.Connection, instance_id: str, kind: EventKind, grant: dict, payload: dict
) -> None:
    ledger.record(
        conn, instance_id, kind, entity_id=str(grant["id"]),
        state_version=grant["state_version"], actor=ACTOR, payload=payload,
    )


def _pending_approvals(conn: psycopg.Connection, instance_id: str, ids: tuple[str, ...]) -> list:
    if not ids:
        return []
    rows = fetchall(
        conn,
        "SELECT id FROM mint.approvals WHERE instance_id = %s AND status = 'pending'"
        " AND id = ANY(%s::uuid[])",
        (instance_id, list(ids)),
    )
    return [str(r["id"]) for r in rows]


def _request_finalize(ctx: JobContext, approval_ids: list[str]) -> None:
    for approval_id in approval_ids:
        enqueue_job(_actor_context(ctx), "activation_finalize", approval_id)


# --- sync_target -------------------------------------------------------------------


def _foreign_changes(before: dict, after: dict | None) -> list[str]:
    """쓰기 전에 읽은 값과 쓰기 응답에서 MINT 소유가 아닌 필드가 달라진 것."""
    after = after or {}
    return [f for f in FOREIGN_FIELDS if f in before and f in after and before[f] != after[f]]


def _write(client: LiteLLMSync, kind: str, target_id: str, plan: Plan) -> dict:
    if kind == "key":
        return client.update_key_permission(target_id, plan.servers, plan.tools)
    return client.update_team_permission(target_id, plan.servers, plan.tools)


def _record(
    ctx: JobContext, kind: str, target_id: str, plan: Plan,
    before: tuple[list[str], dict], after: tuple[list[str], dict], written: bool,
) -> list[dict]:
    """읽어 확인한 결과를 ``litellm_grants``에 적고 사건을 남긴다. 확인되지 않은 항목을 돌려준다."""
    conn, inst = ctx.conn, ctx.instance_id
    unconfirmed: list[dict] = []
    with conn.transaction():
        # 쓰는 사이 다른 작업이 바꿨을 수 있으므로 갱신 직전에 행을 잠그고 다시 읽는다
        old = {
            (r["item"], r["server_id"]): r
            for r in load_rows(conn, inst, kind, target_id, lock=True)
            if r["observed"] is not None
        }
        for it in plan.items:
            confirmed = present(it, *after)
            tools = it.tools if it.item == "tool_permission" else None
            if it.want:
                applied = confirmed and written and not present(it, *before)
                grant = upsert_grant(
                    conn, inst, kind, target_id, it.item, it.server_id, tools=tools,
                    preexisting=it.preexisting, observed=confirmed, applied=applied,
                )
                if applied:
                    _event(conn, inst, EventKind.SYNC_APPLIED, grant, _payload(kind, target_id, it,
                                                                               "grant"))
                if not confirmed:
                    unconfirmed.append(_payload(kind, target_id, it, "grant"))
                continue
            # 거두는 항목: 원래 있던 것은 그대로 두고 관리만 끝낸다
            if (it.item, it.server_id) not in old:
                continue  # 그 사이 다른 작업이 이미 거뒀다
            if it.preexisting or confirmed:
                grant = withdraw_grant(conn, old[(it.item, it.server_id)]["id"])
                if not it.preexisting and written:
                    _event(conn, inst, EventKind.SYNC_APPLIED, grant,
                           _payload(kind, target_id, it, "withdraw"))
            else:
                unconfirmed.append(_payload(kind, target_id, it, "withdraw"))
    return unconfirmed


def _payload(kind: str, target_id: str, it: Item, action: str) -> dict:
    return {"target_type": kind, "target_id": target_id, "item": it.item,
            "server_id": it.server_id, "tools": it.tools, "preexisting": it.preexisting,
            "action": action}


def _pre_record(
    ctx: JobContext, kind: str, target_id: str, plan: Plan, before: tuple[list[str], dict]
) -> None:
    """쓰기 전에 더할 항목의 행을 ``observed=false``로 먼저 적는다.

    쓰고 나서 기록하기 전에 죽어도 다음 실행이 MINT가 넣은 항목을 원래 있던 것
    (``preexisting``)으로 잘못 보지 않는다.
    """
    with ctx.conn.transaction():
        for it in plan.items:
            if it.want and not present(it, *before):
                upsert_grant(
                    ctx.conn, ctx.instance_id, kind, target_id, it.item, it.server_id,
                    tools=it.tools if it.item == "tool_permission" else None,
                    preexisting=it.preexisting, observed=False,
                )


@_reachable
def sync_target(ctx: JobContext) -> None:
    """키·팀 하나를 원하는 상태로 맞춘다. MINT 소유 항목만 바꾼 전체 목록·맵을 쓴다."""
    kind, target_id = split_ref(ctx.job["target_ref"])
    ref, conn, inst = target_ref(kind, target_id), ctx.conn, ctx.instance_id
    client = _client(ctx)
    ctx.checkpoint()
    current = _read(client, kind, target_id)
    gone_key = f"sync_divergence:target:{ref}"
    if current is None:
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=gone_key,
                    subject={"target": ref, "reason": "target_missing"})
        return
    resolve_alert(conn, inst, gone_key)
    desired = desired_for_target(conn, inst, kind, target_id)
    rows = load_rows(conn, inst, kind, target_id)
    before = permission_of(current)
    plan = make_plan(*before, desired, rows)
    response = None
    if plan.changed:
        _pre_record(ctx, kind, target_id, plan, before)
        try:
            response = _write(client, kind, target_id, plan)
        except LiteLLMForbidden:
            team = current.get("team_id") if kind == "key" else None
            if team:  # 팀을 먼저 맞춰 두면 다음 재조회가 이 키를 다시 맞춘다
                enqueue_job(_actor_context(ctx), "sync_target", target_ref("team", team))
            raise_alert(conn, inst, kind="sync_divergence", severity="high",
                        dedup_key=f"sync_divergence:forbidden:{ref}",
                        subject={"target": ref, "reason": "forbidden", "team_id": team})
            raise PermanentFailure("litellm_forbidden") from None
        resolve_alert(conn, inst, f"sync_divergence:forbidden:{ref}")
        changed_fields = _foreign_changes(
            current, response if kind == "key" else (response or {}).get("data")
        )
        key = f"sync_foreign_change:{ref}"
        if changed_fields:
            raise_alert(conn, inst, kind="sync_foreign_change", severity="medium", dedup_key=key,
                        subject={"target": ref, "fields": changed_fields})
        else:
            resolve_alert(conn, inst, key)
    reread = _read(client, kind, target_id)
    after = permission_of(reread)
    unconfirmed = _record(ctx, kind, target_id, plan, before, after, response is not None)
    key = f"sync_divergence:readback:{ref}"
    if unconfirmed:
        raise_alert(conn, inst, kind="sync_divergence", severity="medium", dedup_key=key,
                    subject={"target": ref, "reason": "readback_mismatch", "items": unconfirmed})
    else:
        resolve_alert(conn, inst, key)
    _request_finalize(ctx, _pending_approvals(conn, inst, desired.approvals))


# --- relation_finalize ----------------------------------------------------------------


def _unwithdrawn(
    ctx: JobContext, client: LiteLLMSync, kind: str, target_id: str, server_id: str
) -> tuple[list[str], list[str]]:
    """종료한 관계의 서버에 대해 대상(키·팀)에 남은 것: (거두지 못한 MINT 항목, 원래 있던 권한).

    다른 승인이 아직 그 서버를 원하면 둘 다 비어 있다. 대상이 LiteLLM에서 사라졌으면 권한도
    없는 것이다.
    """
    current = _read(client, kind, target_id)
    if current is None:
        return [], []
    if server_id in desired_for_target(ctx.conn, ctx.instance_id, kind, target_id).servers:
        return [], []
    managed = [
        r["item"]
        for r in load_rows(ctx.conn, ctx.instance_id, kind, target_id)
        if r["server_id"] == server_id and r["observed"] is not None
    ]
    servers, tools = permission_of(current)
    # MINT가 넣지 않은 권한은 MINT가 거두지 않는다. 남아 있다는 사실만 결과에 적는다.
    retained = [] if managed or (server_id not in servers and server_id not in tools) else [
        "mcp_server" if server_id in servers else "tool_permission"
    ]
    return managed, retained


@_reachable
def relation_finalize(ctx: JobContext) -> None:
    """종료 중인 이용 관계의 권한 회수를 확인하고 결과를 남긴다.

    관계의 철회·만료된 승인이 가리키던 키·팀마다 LiteLLM 값을 읽어, MINT가 넣은 서버 권한이 모두
    거두어졌을 때만 관계를 ``terminated``로 바꾸고 결과(대상과 남은 권한)를 사건으로 적는다.
    거두지 못한 항목이 있는데 그 대상의 동기화가 진행 중이 아니면 동기화를 다시 요청하고 경보
    ``termination_unconfirmed``를 연다. 주기 조정(``sync_reconcile``)이 종료 중인 관계마다 이
    작업을 다시 등록하므로 확인은 조정 주기 안에 끝난다.
    """
    relation_id, conn, inst = ctx.job["target_ref"], ctx.conn, ctx.instance_id
    relation = fetchone(
        conn,
        "SELECT org_id, server_id, status FROM mint.usage_relations"
        " WHERE instance_id = %s AND id = %s",
        (inst, relation_id),
    )
    if relation is None or relation["status"] != "terminating":
        return
    targets = fetchall(
        conn,
        "SELECT DISTINCT scope_type AS kind, scope_id AS id FROM mint.approvals"
        " WHERE instance_id = %s AND relation_id = %s AND scope_type IN ('key', 'team')"
        " AND status IN ('revoked', 'expired') ORDER BY 1, 2",
        (inst, relation_id),
    )
    client = _client(ctx) if targets else None
    pending: list[dict] = []
    retained: list[dict] = []
    for target in targets:
        ctx.checkpoint()
        left, kept = _unwithdrawn(ctx, client, target["kind"], target["id"], relation["server_id"])
        ref = target_ref(target["kind"], target["id"])
        pending += [{"target": ref, "item": item} for item in left]
        retained += [{"target": ref, "item": item} for item in kept]
    key = f"termination_unconfirmed:{relation_id}"
    if pending:
        refs = sorted({p["target"] for p in pending})
        if fetchone(
            conn,
            "SELECT 1 AS x FROM mint.jobs WHERE instance_id = %s AND kind = 'sync_target'"
            " AND target_ref = ANY(%s) AND status IN ('pending', 'running')",
            (inst, refs),
        ):
            return  # 거두는 동기화가 진행 중이다. 끝난 뒤 주기 조정이 다시 확인한다.
        for ref in refs:
            enqueue_job(_actor_context(ctx), "sync_target", ref)
        raise_alert(conn, inst, kind="termination_unconfirmed", severity="high", dedup_key=key,
                    subject={"relation_id": relation_id, "server_id": relation["server_id"],
                             "pending": pending})
        return
    with conn.transaction():
        row = fetchone(
            conn,
            "UPDATE mint.usage_relations SET status = 'terminated' WHERE instance_id = %s"
            " AND id = %s AND status = 'terminating' RETURNING state_version",
            (inst, relation_id),
        )
        if row is None:
            return  # 그 사이 다른 작업이 마무리했다
        ledger.record(
            conn, inst, EventKind.RELATION_TERMINATING, entity_id=relation_id,
            state_version=row["state_version"], actor=ACTOR,
            payload={"relation_id": relation_id, "org_id": relation["org_id"],
                     "server_id": relation["server_id"], "phase": "revocation_confirmed",
                     "targets": [target_ref(t["kind"], t["id"]) for t in targets],
                     "retained": retained},
        )
        resolve_alert(conn, inst, key)


def _finalize_terminating(ctx: JobContext) -> None:
    """종료 중인 이용 관계마다 마무리 확인을 다시 요청한다."""
    for row in fetchall(
        ctx.conn,
        "SELECT id::text AS ref FROM mint.usage_relations WHERE instance_id = %s"
        " AND status = 'terminating'",
        (ctx.instance_id,),
    ):
        enqueue_job(_actor_context(ctx), "relation_finalize", row["ref"])


# --- sync_server ---------------------------------------------------------------------


@_reachable
def sync_server(ctx: JobContext) -> None:
    """LiteLLM 서버가 있는지 확인하고, 제출 서버면 승인한 뒤 고정(pin)을 맞춘다.

    재승인 계획이 있으면 그 확정(재pin과 승인본 교체)이 먼저다. 결과를 적고 활성화 완결과
    대기 승인 대상의 동기화를 요청한다.
    """
    server_id, conn, inst = ctx.job["target_ref"], ctx.conn, ctx.instance_id
    if not fetchone(
        conn, "SELECT 1 AS x FROM mint.servers WHERE instance_id = %s AND server_id = %s",
        (inst, server_id),
    ):
        return
    client = None
    if _unpin_pending(conn, inst, server_id):
        # 승인이 모두 사라졌어도 풀지 못한 고정은 풀어야 한다
        client = _client(ctx)
        _unpin(ctx, client, server_id)
    if _has_pending_plan(conn, inst, server_id):
        client = client or _client(ctx)
        _finalize_plan(ctx, client, server_id)
    wanted = fetchall(
        conn,
        "SELECT id, status, scope_type, scope_id FROM mint.approvals WHERE instance_id = %s"
        " AND server_id = %s AND ((status = 'active' AND valid_from <= now()"
        " AND valid_until > now()) OR (status = 'pending' AND valid_until > now()))",
        (inst, server_id),
    )
    if not wanted:
        return  # 서버 승인 상태는 명시 중지로만 바뀐다. LiteLLM 고정은 그대로 둔다.
    client = client or _client(ctx)
    ctx.checkpoint()
    key = f"sync_divergence:server:{server_id}"
    server = client.get_server(server_id)
    if server is None:
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=key,
                    subject={"server_id": server_id, "reason": "registry_missing"})
        _record_server(ctx, server_id, observed=False, approved_now=False, first_seen_active=False)
        return
    status = server.get("approval_status")
    approved_now = False
    if status == "pending_review":
        try:
            client.approve_server(server_id)
            approved_now = True
        except LiteLLMHttpError as error:
            if error.status != 400:  # 400은 그 사이 다른 쪽이 승인한 경우다
                raise
        status = (client.get_server(server_id) or {}).get("approval_status")
    active = status == "active"
    _record_server(ctx, server_id, observed=active, approved_now=approved_now,
                   first_seen_active=active and not approved_now)
    pinned = False
    if active:
        resolve_alert(conn, inst, key)
        pinned = _pin_step(ctx, client, server_id)
    else:
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=key,
                    subject={"server_id": server_id, "reason": "not_active", "status": status})
    pending = [r for r in wanted if r["status"] == "pending"]
    if pinned:
        # 고정이 맞기 전에는 대기 승인의 키·팀 권한이 나가지 않았다. 이제 그 대상을 맞춘다.
        for ref in sorted({target_ref(r["scope_type"], r["scope_id"]) for r in pending
                           if r["scope_type"] in SYNC_SCOPES}):
            enqueue_job(_actor_context(ctx), "sync_target", ref)
    _request_finalize(ctx, [str(r["id"]) for r in pending])


def _has_pending_plan(conn: psycopg.Connection, instance_id: str, server_id: str) -> bool:
    return fetchone(
        conn,
        "SELECT 1 AS x FROM mint.contract_reapproval_plans WHERE instance_id = %s"
        " AND server_id = %s AND status = 'pending'",
        (instance_id, server_id),
    ) is not None


def _finalize_plan(ctx: JobContext, client: LiteLLMSync, server_id: str) -> None:
    """재승인 확정: 재pin 응답이 후보와 같을 때만 승인본을 바꾼다(작업 실행기 로그인 하나로)."""
    from mint_litellm.control.contract_pin import finalize_reapproval

    key = f"sync_divergence:reapproval:{server_id}"
    ctx.checkpoint()
    try:
        finalize_reapproval(
            ctx.conn, ctx.instance_id, server_id, client, guard=ctx.external_write)
    except AdminError as error:
        if "진행 중" in error.message:
            raise  # 다른 실행기가 같은 서버를 확정하는 중이다. 재시도로 푼다.
        # 확정할 수 없는 계획은 취소한다. 차단 표지는 그대로 두고 운영자가 재승인을 다시 요청한다.
        ctx.conn.execute(
            "UPDATE mint.contract_reapproval_plans SET status = 'cancelled'"
            " WHERE instance_id = %s AND server_id = %s AND status = 'pending'",
            (ctx.instance_id, server_id),
        )
        raise_alert(ctx.conn, ctx.instance_id, kind="sync_divergence", severity="high",
                    dedup_key=key,
                    subject={"server_id": server_id, "reason": "reapproval_conflict",
                             "message": error.message, "plan": "cancelled"})
        raise PermanentFailure("reapproval_conflict") from None
    resolve_alert(ctx.conn, ctx.instance_id, key)


def _pin_mismatch(expected: dict[str, str], response: dict) -> list[str]:
    """고정 응답이 승인 계약과 다른 도구(집합 차이와 해시 차이)."""
    different = sorted(set(expected) ^ set(response))
    for tool in sorted(set(expected) & set(response)):
        try:
            if pin_sha256(response[tool]) != expected[tool]:
                different.append(tool)
        except (KeyError, TypeError, ValueError, AttributeError):
            different.append(tool)
    return different


def _unpin(ctx: JobContext, client: LiteLLMSync, server_id: str) -> None:
    """맞지 않는 고정을 푼다. 실패하면 경보를 내고 오류를 올려 작업을 재시도하게 한다."""
    key = f"sync_divergence:unpin:{server_id}"
    try:
        client.unpin(server_id)
    except LiteLLMHttpError as error:
        raise_alert(ctx.conn, ctx.instance_id, kind="sync_divergence", severity="high",
                    dedup_key=key,
                    subject={"server_id": server_id, "reason": "unpin_failed",
                             "status": error.status})
        raise
    resolve_alert(ctx.conn, ctx.instance_id, key)


def _unpin_pending(conn: psycopg.Connection, instance_id: str, server_id: str) -> bool:
    """이전 실행에서 풀지 못한 고정이 있는가(열린 경보 ``unpin_failed``)."""
    return fetchone(
        conn,
        "SELECT 1 AS x FROM mint.alerts WHERE instance_id = %s AND dedup_key = %s"
        " AND status <> 'resolved'",
        (instance_id, f"sync_divergence:unpin:{server_id}"),
    ) is not None


def _drift_kind(approved: dict, observed: Any) -> str:
    if observed is None:
        return "removed"
    if not isinstance(observed, dict):
        return "input_schema"  # 정의가 아닌 값은 입력 정의가 바뀐 것과 같이 막는다
    if approved.get("input_schema") != observed.get("input_schema"):
        return "input_schema"
    return "description"


def _record_pin_mismatch(
    ctx: JobContext, server_id: str, expected: dict[str, str], response: dict,
    different: list[str],
) -> None:
    """맞지 않은 고정: 서버를 드리프트 표지로 막고, 다른 도구는 후보 계약(``source=pin``)과
    ``reapproval_requested``로 남긴다(재승인 흐름이 이어받는다). 고정 행은 맞다고 적지 않는다."""
    conn, inst = ctx.conn, ctx.instance_id
    scope = server_scope(conn, inst, server_id)
    with conn.transaction():
        upsert_grant(conn, inst, "server", server_id, "pin", server_id, tools=None,
                     preexisting=False, observed=False)
        conn.execute(
            "UPDATE mint.servers SET deployment_drift = true, deployment_drift_fields ="
            " (SELECT array_agg(DISTINCT f ORDER BY f) FROM unnest("
            "  COALESCE(deployment_drift_fields, '{}') || ARRAY['pin_reapproval']) f)"
            " WHERE instance_id = %s AND server_id = %s",
            (inst, server_id),
        )
        for tool in different:
            value = response.get(tool)
            approved = fetchone(
                conn,
                "SELECT id, canonical_text FROM mint.tool_contracts WHERE instance_id = %s"
                " AND server_id = %s AND credential_scope = %s AND tool = %s"
                " AND status = 'approved'",
                (inst, server_id, scope, tool),
            )
            if approved is not None:
                kind = _drift_kind(json.loads(approved["canonical_text"]), value)
                row = fetchone(
                    conn,
                    "UPDATE mint.tool_contracts SET drift = %s WHERE id = %s RETURNING version",
                    (kind, approved["id"]),
                )
                ledger.record(
                    conn, inst, EventKind.CONTRACT_DRIFT_DETECTED,
                    entity_id=str(approved["id"]), state_version=row["version"], actor=ACTOR,
                    payload={"server_id": server_id, "tool": tool, "credential_scope": scope,
                             "drift": kind, "version": row["version"], "source": "pin"},
                )
            if not isinstance(value, dict) or "input_schema" not in value:
                continue  # 사라진 도구는 후보가 없다
            definition = {"description": value.get("description"),
                          "input_schema": value["input_schema"]}
            digest = sha256(definition)
            exists = fetchone(
                conn,
                "SELECT 1 AS x FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
                " AND credential_scope = %s AND tool = %s AND sha256 = %s"
                " AND status = 'candidate'",
                (inst, server_id, scope, tool, digest),
            )
            if exists is not None:
                continue
            candidate = new_uuid7()
            conn.execute(
                "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope,"
                " tool, canonical_text, sha256, pin_sha256, source) VALUES"
                " (%s, %s, %s, %s, %s, %s, %s, %s, 'pin')",
                (candidate, inst, server_id, scope, tool, canonical_text(definition), digest,
                 pin_sha256(definition)),
            )
            ledger.record(
                conn, inst, EventKind.REAPPROVAL_REQUESTED, entity_id=str(candidate),
                state_version=1, actor=ACTOR,
                payload={"server_id": server_id, "version": 1, "kind": "tool", "tool": tool,
                         "candidate_sha256": digest, "source": "pin"},
            )


class ControlKeyNotSet(WaitForOperator):
    """제어 평면 키가 면제 키로 저장되지 않아 도구를 고정할 수 없다(저장하면 재시도로 풀린다).

    시도 횟수를 세지 않으므로 키 저장이 늦어도 작업이 ``failed``로 끝나지 않는다.
    """

    code = "control_key_not_set"


def _pin_step(ctx: JobContext, client: LiteLLMSync, server_id: str) -> bool:
    """계약을 관리하는 서버의 도구를 LiteLLM에 고정한다. 새로 맞췄으면 참.

    응답의 도구 집합과 모든 해시가 승인 계약과 같을 때만 ``item=pin`` 행에 해시를 적는다. 다르면
    고정을 풀고 적지 않고 경보를 낸다. 이미 맞게 고정한 서버(MINT 기록)와 드리프트 중인 서버는
    다시 고정하지 않는다(업스트림의 현재 값으로 승인본을 덮지 않는다).
    """
    conn, inst = ctx.conn, ctx.instance_id
    expected = expected_pin(conn, inst, server_id)
    if not expected:  # 관리 서버가 아니거나 승인 계약이 없다(없으면 조건이 거짓이다)
        return False
    drift = fetchone(
        conn,
        "SELECT (s.deployment_drift OR EXISTS (SELECT 1 FROM mint.tool_contracts t"
        " WHERE t.instance_id = s.instance_id AND t.server_id = s.server_id"
        " AND t.status = 'approved' AND t.drift <> 'none')) AS drift"
        " FROM mint.servers s WHERE s.instance_id = %s AND s.server_id = %s",
        (inst, server_id),
    )
    if drift["drift"]:
        return False
    digest = sha256(expected)
    row = fetchone(
        conn,
        "SELECT observed, applied_sha256 FROM mint.litellm_grants WHERE instance_id = %s"
        " AND target_type = 'server' AND target_id = %s AND item = 'pin' AND server_id = %s",
        (inst, server_id, server_id),
    )
    if row and row["observed"] is True and row["applied_sha256"] == digest:
        return False
    key = f"sync_divergence:pin:{server_id}"
    if not fetchone(
        conn, "SELECT 1 AS x FROM mint.settings WHERE instance_id = %s"
        " AND control_key_token IS NOT NULL", (inst,)
    ):
        # 면제 키가 없으면 LiteLLM이 숨겨진 도구를 빼고 고정할 것이 없다며 400으로 거절한다.
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=key,
                    subject={"server_id": server_id, "reason": "control_key_not_set",
                             "action": "settings control-key"})
        raise ControlKeyNotSet
    response = client.pin(server_id)
    different = _pin_mismatch(expected, response)
    if not different:
        with conn.transaction():
            grant = upsert_grant(conn, inst, "server", server_id, "pin", server_id, tools=None,
                                 preexisting=False, observed=True, applied=True,
                                 applied_sha256=digest)
            _event(conn, inst, EventKind.SYNC_APPLIED, grant,
                   {"target_type": "server", "target_id": server_id, "item": "pin",
                    "server_id": server_id, "tools": sorted(expected), "preexisting": False,
                    "action": "grant", "applied_sha256": digest})
    if different:
        _record_pin_mismatch(ctx, server_id, expected, response, different)
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=key,
                    subject={"server_id": server_id, "reason": "pin_mismatch",
                             "tools": different})
        _unpin(ctx, client, server_id)
        return False
    resolve_alert(conn, inst, key)
    return True


def _record_server(
    ctx: JobContext, server_id: str, *, observed: bool, approved_now: bool, first_seen_active: bool
) -> None:
    conn, inst = ctx.conn, ctx.instance_id
    with conn.transaction():
        row = fetchone(
            conn,
            "SELECT preexisting FROM mint.litellm_grants WHERE instance_id = %s"
            " AND target_type = 'server' AND target_id = %s AND item = 'server_approval'"
            " AND server_id = %s AND observed IS NOT NULL",
            (inst, server_id, server_id),
        )
        grant = upsert_grant(
            conn, inst, "server", server_id, "server_approval", server_id, tools=None,
            preexisting=row["preexisting"] if row else first_seen_active, observed=observed,
            applied=approved_now,
        )
        if approved_now:
            _event(conn, inst, EventKind.SYNC_APPLIED, grant,
                   {"target_type": "server", "target_id": server_id, "item": "server_approval",
                    "server_id": server_id, "tools": None, "preexisting": False,
                    "action": "grant"})


# --- activation_finalize -------------------------------------------------------------


def _target_ready(client: LiteLLMSync, approval: dict) -> bool:
    """대상 권한에 이 승인의 서버와 도구가 지금 있는가(읽어서 확인)."""
    current = _read(client, approval["scope_type"], approval["scope_id"])
    if current is None:
        return False
    servers, tools = permission_of(current)
    entry = tools.get(approval["server_id"])
    return approval["server_id"] in servers and entry is not None and set(approval["tools"]) <= set(
        entry
    )


@_reachable
def activation_finalize(ctx: JobContext) -> None:
    """대기 승인을 활성으로 바꾼다. 조건이 안 되면 아무것도 하지 않는다.

    조건: 서버의 LiteLLM 승인 상태가 확인되었고, 키·팀 범위면 대상의 서버와 도구가 LiteLLM에
    있다. 고정(pin)이 승인 계약과 맞아야 하며, 활성화 트랜잭션 안에서 행을 잠그고 한 번 더 확인한다.
    """
    conn, inst = ctx.conn, ctx.instance_id
    approval = fetchone(
        conn,
        "SELECT * FROM mint.approvals WHERE instance_id = %s AND id = %s",
        (inst, ctx.job["target_ref"]),
    )
    if approval is None or approval["status"] != "pending":
        return
    server_id = approval["server_id"]
    server_row = fetchone(
        conn,
        "SELECT observed FROM mint.litellm_grants WHERE instance_id = %s AND target_type ="
        " 'server' AND target_id = %s AND item = 'server_approval' AND server_id = %s",
        (inst, server_id, server_id),
    )
    if not server_row or server_row["observed"] is not True:
        return
    if not pin_satisfied(conn, inst, server_id):
        return
    ctx.checkpoint()
    if approval["scope_type"] in SYNC_SCOPES:
        rows = {
            (r["item"], r["server_id"]): r
            for r in load_rows(conn, inst, approval["scope_type"], approval["scope_id"])
        }
        for item in ("mcp_server", "tool_permission"):
            row = rows.get((item, server_id))
            if row is None or row["observed"] is not True:
                return
    client = _client(ctx)
    server = client.get_server(server_id)
    if server is None or server.get("approval_status") != "active":
        return
    if approval["scope_type"] in SYNC_SCOPES and not _target_ready(client, approval):
        return
    with conn.transaction():
        # 고정이 바뀌었을 수 있으므로 활성화 트랜잭션 안에서 행을 잠그고 다시 확인한다
        if not pin_satisfied(conn, inst, server_id, lock=True):
            return
        activated = fetchone(
            conn,
            "UPDATE mint.approvals SET status = 'active',"
            " granted_by = COALESCE(granted_by, %s) WHERE id = %s AND status = 'pending'"
            " RETURNING id",
            (ACTOR, approval["id"]),
        )
        if activated is None:
            return
        first = fetchone(
            conn,
            "SELECT id, status FROM mint.servers WHERE instance_id = %s AND server_id = %s"
            " FOR UPDATE",
            (inst, server_id),
        )
        if first and first["status"] == "awaiting_approval":
            allowlists = (approval["basis"] or {}).get("allowlist_ids") or []
            updated = fetchone(
                conn,
                "UPDATE mint.servers SET status = 'approved', basis_allowlist_ids = %s::uuid[]"
                " WHERE id = %s RETURNING state_version",
                (allowlists, first["id"]),
            )
            ledger.record(
                conn, inst, EventKind.SERVER_APPROVED, entity_id=str(first["id"]),
                state_version=updated["state_version"], actor=ACTOR,
                payload={"server_id": server_id, "first_approval_id": str(approval["id"]),
                         "basis_allowlist_ids": allowlists},
            )
        conn.execute(
            "UPDATE mint.servers SET last_observed_at = now() WHERE instance_id = %s"
            " AND server_id = %s",
            (inst, server_id),
        )


# --- sync_reconcile ------------------------------------------------------------------

_COUNT_MISSING = (
    "WITH expired AS (SELECT (missing_window_start IS NULL OR missing_window_start <="
    " now() - make_interval(secs => %s)) AS fresh FROM mint.litellm_grants WHERE id = %s"
    " FOR UPDATE) "
    "UPDATE mint.litellm_grants g SET observed = false,"
    " missing_count = CASE WHEN e.fresh THEN 1 ELSE g.missing_count + 1 END,"
    " missing_window_start = CASE WHEN e.fresh THEN now() ELSE g.missing_window_start END,"
    " held = NOT e.fresh, held_at = CASE WHEN e.fresh THEN g.held_at ELSE now() END"
    " FROM expired e WHERE g.id = %s RETURNING g.id, g.state_version, g.held, g.missing_count"
)


def _missing(row: dict, desired: Any, servers: list[str], tools: dict) -> bool:
    """MINT가 반영한 항목이 원하는데 LiteLLM에 없는가."""
    if row["item"] == "mcp_server":
        return row["server_id"] in desired.servers and row["server_id"] not in servers
    want = desired.tools.get(row["server_id"])
    return bool(want) and not want <= set(tools.get(row["server_id"], ()))


def _wanted(row: dict, desired: Any) -> bool:
    if row["item"] == "mcp_server":
        return row["server_id"] in desired.servers
    return bool(desired.tools.get(row["server_id"]))


def _count_missing(
    ctx: JobContext, kind: str, target_id: str, row: dict, window_seconds: int
) -> bool:
    """외부 삭제 한 번을 센다. 한 시간 창 안의 두 번째면 보류하고 참을 돌려준다."""
    conn, inst = ctx.conn, ctx.instance_id
    with conn.transaction():
        updated = fetchone(conn, _COUNT_MISSING, (window_seconds, row["id"], row["id"]))
        if not updated["held"]:
            return False
        payload = {"target_type": kind, "target_id": target_id, "item": row["item"],
                   "server_id": row["server_id"], "missing_count": updated["missing_count"],
                   "window_seconds": window_seconds}
        _event(conn, inst, EventKind.SYNC_HELD, updated, payload)
        raise_alert(conn, inst, kind="sync_divergence", severity="high",
                    dedup_key=f"sync_divergence:held:{row['id']}",
                    subject={**payload, "reason": "held"})
    return True


def _reconcile_target(
    ctx: JobContext, client: LiteLLMSync, kind: str, target_id: str, window_seconds: int
) -> None:
    conn, inst = ctx.conn, ctx.instance_id
    ref = target_ref(kind, target_id)
    gone_key = f"sync_divergence:target:{ref}"
    current = _read(client, kind, target_id)
    if current is None:
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=gone_key,
                    subject={"target": ref, "reason": "target_missing"})
        return
    resolve_alert(conn, inst, gone_key)
    desired = desired_for_target(conn, inst, kind, target_id)
    rows = load_rows(conn, inst, kind, target_id)
    servers, tools = permission_of(current)
    regrant = False
    for row in rows:
        # 반영되어 있던 항목이 없어진 순간만 외부 삭제 한 번으로 센다(이미 없다고 본 것은 다시 세지
        # 않는다. 복구 작업이 다시 보면 반영됨으로 돌아온다).
        if row["observed"] is not True or row["held"] or not _missing(row, desired, servers, tools):
            continue
        if not _count_missing(ctx, kind, target_id, row, window_seconds):
            regrant = True
    # 반영 직후 확인이 늦어 ``observed=false``로 남은 행: 항목이 이미 LiteLLM에 있으면 바로잡는다
    fixed = False
    for row in rows:
        if (
            row["observed"] is False
            and not row["held"]
            and _wanted(row, desired)
            and not _missing(row, desired, servers, tools)
        ):
            with conn.transaction():
                grant = mark_observed(conn, row["id"])
                _event(conn, inst, EventKind.SYNC_APPLIED, grant,
                       {"target_type": kind, "target_id": target_id, "item": row["item"],
                        "server_id": row["server_id"], "tools": row["tools"],
                        "preexisting": row["preexisting"], "action": "grant",
                        "late_confirmation": True})
            fixed = True
    after = load_rows(conn, inst, kind, target_id)
    plan = make_plan(servers, tools, desired, after)
    if fixed:
        _request_finalize(ctx, _pending_approvals(conn, inst, desired.approvals))
    if plan.changed or regrant:
        enqueue_job(_actor_context(ctx), "sync_target", ref)


def _close_allow_all_keys(
    ctx: JobContext, client: LiteLLMSync, server_id: str, server: dict
) -> None:
    """통제하는 서버가 모든 키에 열려 있으면 외부 변경으로 보고 닫은 뒤 다시 읽어 확인한다."""
    conn, inst = ctx.conn, ctx.instance_id
    changed_key = f"sync_foreign_change:server:{server_id}"
    failed_key = f"sync_divergence:allow_all_keys:{server_id}"
    if server.get("allow_all_keys") is not True:
        resolve_alert(conn, inst, failed_key)
        resolve_alert(conn, inst, changed_key)
        return
    reason = None
    try:
        client.disable_allow_all_keys(server_id)
        reread = client.get_server(server_id) or {}
        if reread.get("allow_all_keys") is True:
            reason = "still_enabled"
    except LiteLLMHttpError:  # 거부(403)도 같은 계열이다
        reason = "write_failed"
    raise_alert(conn, inst, kind="sync_foreign_change", severity="high", dedup_key=changed_key,
                subject={"server_id": server_id, "fields": ["allow_all_keys"]})
    if reason is None:
        resolve_alert(conn, inst, failed_key)
    else:
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=failed_key,
                    subject={"server_id": server_id, "reason": f"allow_all_keys_{reason}"})


def _reconcile_server(ctx: JobContext, client: LiteLLMSync, server_id: str) -> None:
    conn, inst = ctx.conn, ctx.instance_id
    key = f"sync_divergence:server:{server_id}"
    server = client.get_server(server_id)
    if server is None:
        raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=key,
                    subject={"server_id": server_id, "reason": "registry_missing"})
        return
    _close_allow_all_keys(ctx, client, server_id, server)
    status = server.get("approval_status")
    grant = fetchone(
        conn,
        "SELECT observed FROM mint.litellm_grants WHERE instance_id = %s AND target_type ="
        " 'server' AND target_id = %s AND item = 'server_approval' AND server_id = %s",
        (inst, server_id, server_id),
    )
    if status == "active":
        resolve_alert(conn, inst, key)
        if grant is None or grant["observed"] is not True:
            enqueue_job(_actor_context(ctx), "sync_server", server_id)
        return
    raise_alert(conn, inst, kind="sync_divergence", severity="high", dedup_key=key,
                subject={"server_id": server_id, "reason": "not_active", "status": status})
    if status == "pending_review":
        enqueue_job(_actor_context(ctx), "sync_server", server_id)


def _overdue_activations(ctx: JobContext) -> None:
    """한 시간 안에 완결되지 않은 대기 승인에 경보 ``job_failed``를 올리고 완결을 다시 요청한다."""
    conn, inst = ctx.conn, ctx.instance_id
    for row in fetchall(
        conn,
        "SELECT a.id::text AS ref, (SELECT min(j.created_at) FROM mint.jobs j WHERE"
        " j.instance_id = a.instance_id AND j.kind = 'activation_finalize'"
        " AND j.target_ref = a.id::text) < now() - interval '1 hour' AS overdue"
        " FROM mint.approvals a WHERE a.instance_id = %s AND a.status = 'pending'"
        " AND a.valid_until > now()",
        (inst,),
    ):
        enqueue_job(_actor_context(ctx), "activation_finalize", row["ref"])
        if row["overdue"]:
            raise_alert(conn, inst, kind="job_failed", severity="high",
                        dedup_key=f"job_failed:activation_finalize:{row['ref']}",
                        subject={"job_kind": "activation_finalize", "target_ref": row["ref"],
                                 "reason": "not_completed_within_one_hour"})


@_reachable
def sync_reconcile(ctx: JobContext) -> None:
    """대상마다 LiteLLM 값과 원하는 상태를 비교해 차이가 있으면 그 대상의 동기화를 등록한다."""
    conn, inst = ctx.conn, ctx.instance_id
    client = _client(ctx)
    window = ctx.settings.sync_hold_window_seconds
    targets = fetchall(
        conn,
        "SELECT scope_type AS kind, scope_id AS id FROM mint.approvals WHERE instance_id = %s"
        " AND scope_type IN ('key', 'team') AND status IN ('active', 'pending')"
        " UNION SELECT target_type, target_id FROM mint.litellm_grants WHERE instance_id = %s"
        " AND target_type IN ('key', 'team') AND observed IS NOT NULL ORDER BY 1, 2",
        (inst, inst),
    )
    for target in targets:
        ctx.checkpoint()
        _reconcile_target(ctx, client, target["kind"], target["id"], window)
    servers = fetchall(
        conn,
        "SELECT DISTINCT server_id FROM mint.approvals WHERE instance_id = %s"
        " AND status IN ('active', 'pending') ORDER BY 1",
        (inst,),
    )
    for server in servers:
        ctx.checkpoint()
        _reconcile_server(ctx, client, server["server_id"])
    _overdue_activations(ctx)
    _finalize_terminating(ctx)
