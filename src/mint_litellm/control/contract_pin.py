"""계약 재승인의 pin 쓰기 접점. 시험 목록·제출 클라이언트와 분리한다."""

import contextlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from psycopg.pq import TransactionStatus
from psycopg.types.json import Jsonb

from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, conflict
from mint_litellm.control.services.base import transact
from mint_litellm.control.services.contracts import _plan, freeze_plan
from mint_litellm.types.canonical import pin_set_sha256, pin_sha256
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7


class ContractPinClient:
    def __init__(self, base_url: str, api_key: str, *, before_write=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.before_write = before_write

    def _send(self, server_id: str, method: str) -> dict:
        if self.before_write is not None:
            self.before_write()
        path = urllib.parse.quote(server_id, safe="")
        request = urllib.request.Request(
            f"{self.base_url}/v1/mcp/server/{path}/pin",
            method=method,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ControlError("pin 응답이 상한을 넘었습니다.")
                body = json.loads(raw)
        except (urllib.error.URLError, OSError, ValueError):
            raise ControlError("계약 pin 요청에 실패했습니다.") from None
        if not isinstance(body, dict):
            raise ControlError("pin 응답 형식이 올바르지 않습니다.")
        return body

    def pin(self, server_id: str) -> dict:
        return self._send(server_id, "POST")

    def unpin(self, server_id: str) -> None:
        self._send(server_id, "DELETE")


def verify_pin(desired: dict, response: dict) -> str:
    if not response or set(response) != set(desired):
        raise conflict("재pin 도구 집합이 후보 계약과 다릅니다.")
    try:
        if any(pin_sha256(response[name]) != pin_sha256(value) for name, value in desired.items()):
            raise conflict("재pin 해시가 후보 계약과 다릅니다.")
        return pin_set_sha256(response)
    except (ValueError, TypeError, KeyError):
        raise conflict("재pin 응답의 정의 형식이 올바르지 않습니다.") from None


def _requester_valid(conn, instance_id: str, saved: dict) -> bool:
    """재승인을 요청한 운영자가 지금도 유효한 승인자인가(삭제·만료·역할 변경·사용자 결속 변경).

    운영자 행을 ``FOR SHARE``로 잠가 읽는다: 호출한 트랜잭션이 끝날 때까지 그 승인자의 권한을
    철회하는 변경이 기다린다(확인 뒤 철회된 승인자의 승인본 교체가 커밋되지 않는다)."""
    return fetchone(
        conn,
        "SELECT 1 AS ok FROM mint.operators WHERE instance_id=%s AND name=%s AND user_id=%s"
        " AND role IN ('admin','approver') AND (expires_at IS NULL OR expires_at > now())"
        " FOR SHARE",
        (instance_id, saved["requested_by"], saved["requested_user_id"]),
    ) is not None


def _pending(ctx: Context, saved: dict) -> dict:
    plan = saved["plan"]
    if not _requester_valid(ctx.conn, ctx.instance_id, saved):
        raise conflict("재승인을 요청한 승인자가 더 이상 유효하지 않습니다.")
    fresh = _plan(
        ctx,
        saved["server_id"],
        str(saved["intake_id"]),
        [c["id"] for c in plan["candidates"]],
        plan["deployment"]["id"] if plan["deployment"] else None,
        plan["server_version"],
        replan=True,
    )
    if freeze_plan(fresh) != plan:
        raise conflict("재pin 중 후보 또는 증거가 변경되었습니다.")
    if not fresh["server"]["deployment_drift"] or "pin_reapproval" not in plan["drift_fields"]:
        raise conflict("재승인 차단 표지가 없습니다.")
    return fresh


def _replace(ctx: Context, saved: dict, fresh: dict, digest: str) -> dict:
    server_id = saved["server_id"]
    for candidate in fresh["candidates"]:
        old = next((c for c in fresh["approved"] if c["tool"] == candidate["tool"]), None)
        if old:
            row = fetchone(
                ctx.conn,
                "UPDATE mint.tool_contracts SET status='superseded'"
                " WHERE instance_id=%s AND id=%s RETURNING version",
                (ctx.instance_id, old["id"]),
            )
            ctx.emit(
                EventKind.CONTRACT_SUPERSEDED,
                old["id"],
                row["version"],
                {"server_id": server_id, "replacement": str(candidate["id"])},
            )
        row = fetchone(
            ctx.conn,
            "UPDATE mint.tool_contracts SET status='approved',drift='none',"
            " observed_sha256=sha256,observed_at=now() WHERE instance_id=%s AND id=%s"
            " RETURNING version",
            (ctx.instance_id, candidate["id"]),
        )
        ctx.emit(
            EventKind.CONTRACT_APPROVED,
            candidate["id"],
            row["version"],
            {"server_id": server_id, "pin_sha256": candidate["pin_sha256"]},
        )
    deployment = fresh["deployment"]
    if deployment:
        old = fetchone(
            ctx.conn,
            "UPDATE mint.deployment_contracts SET status='superseded'"
            " WHERE instance_id=%s AND server_id=%s AND status='approved' RETURNING id,version",
            (ctx.instance_id, server_id),
        )
        if old:
            ctx.emit(
                EventKind.DEPLOYMENT_CONTRACT_SUPERSEDED,
                old["id"],
                old["version"],
                {"server_id": server_id},
            )
        row = fetchone(
            ctx.conn,
            "UPDATE mint.deployment_contracts SET status='approved'"
            " WHERE instance_id=%s AND id=%s RETURNING version",
            (ctx.instance_id, deployment["id"]),
        )
        ctx.emit(
            EventKind.DEPLOYMENT_CONTRACT_APPROVED,
            deployment["id"],
            row["version"],
            {"server_id": server_id},
        )
        ctx.conn.execute(
            "UPDATE mint.servers SET url_sha256=%s,transport=%s,auth_type=%s,issuer=%s"
            " WHERE instance_id=%s AND server_id=%s",
            (
                deployment["url_sha256"],
                deployment["transport"],
                deployment["auth_type"],
                deployment["issuer"],
                ctx.instance_id,
                server_id,
            ),
        )
    # 배포 재검사 없는 도구 재승인으로 기존 배포 드리프트를 지우지 않는다.
    clear = deployment is not None or set(saved["plan"]["drift_fields"]) == {"pin_reapproval"}
    ctx.conn.execute(
        "UPDATE mint.servers SET last_observed_at=now(),deployment_drift=%s,"
        " deployment_drift_fields=CASE WHEN %s THEN NULL ELSE deployment_drift_fields END"
        " WHERE instance_id=%s AND server_id=%s",
        (not clear, clear, ctx.instance_id, server_id),
    )
    ctx.conn.execute(
        "INSERT INTO mint.litellm_grants"
        " (id,instance_id,target_type,target_id,item,server_id,preexisting,applied_sha256,"
        " observed,observed_at,last_applied_at)"
        " VALUES (%s,%s,'server',%s,'pin',%s,false,%s,true,now(),now())"
        " ON CONFLICT (instance_id,target_type,target_id,item,server_id) DO UPDATE"
        " SET applied_sha256=EXCLUDED.applied_sha256,observed=true,observed_at=now(),"
        " last_applied_at=now()",
        (new_uuid7(), ctx.instance_id, server_id, server_id, digest),
    )
    result = {
        "server_id": server_id,
        "pin_sha256": digest,
        "contracts": [str(c["id"]) for c in fresh["candidates"]],
    }
    ctx.conn.execute(
        "UPDATE mint.contract_reapproval_plans SET status='completed',result=%s"
        " WHERE instance_id=%s AND server_id=%s AND id=%s",
        (Jsonb(result), ctx.instance_id, server_id, saved["id"]),
    )
    return result


def finalize_reapproval(
    conn, instance_id: str, server_id: str, pin_client, guard: Callable[[], None] | None = None
) -> dict:
    """G4b의 sync_server pin 단계용. 외부 응답 뒤 계획·후보 판본을 다시 잠가 확정한다.

    pin은 DB와 원자적으로 커밋할 수 없으므로 먼저 커밋한 차단 표지를 실패 시 유지한다.
    승인본·사건·pin 원장·계획 완료는 마지막 트랜잭션 하나에서 함께 확정한다. 응답을 받은 뒤
    ``guard``(임대·종료 신호·되돌림 차단 확인)와 계획·후보·서버 상태·요청자 유효성을 다시 확인하고,
    하나라도 확인하지 못하면 고정을 풀고 차단 표지를 유지한 채 끝낸다(다음 실행이 다시 수렴한다).
    """
    if conn.info.transaction_status != TransactionStatus.IDLE:
        raise conflict("재승인 확정은 유휴 연결에서 실행해야 합니다.")
    key = f"contract-pin:{instance_id}:{server_id}"
    with conn.transaction():
        locked = fetchone(
            conn, "SELECT pg_try_advisory_lock(hashtextextended(%s,0)) AS ok", (key,)
        )["ok"]
    if not locked:
        raise conflict("이 서버의 재승인이 진행 중입니다.")
    try:
        with conn.transaction():
            saved = fetchone(
                conn,
                "SELECT * FROM mint.contract_reapproval_plans"
                " WHERE instance_id=%s AND server_id=%s FOR UPDATE",
                (instance_id, server_id),
            )
            if saved is None:
                raise conflict("재승인 계획이 없습니다.")
            if saved["status"] == "completed":
                return saved["result"]
            if saved["status"] == "cancelled":
                raise conflict("재승인 계획이 취소되었습니다. 재승인을 다시 요청하십시오.")
            ctx = Context(
                conn,
                instance_id,
                Operator(saved["requested_by"], "approver", saved["requested_user_id"]),
            )
            _pending(ctx, saved)
        try:
            response = pin_client.pin(server_id)
            digest = verify_pin(saved["plan"]["desired"], response)
            if guard is not None:
                guard()
            with transact(ctx):
                current = fetchone(
                    conn,
                    "SELECT * FROM mint.contract_reapproval_plans"
                    " WHERE instance_id=%s AND server_id=%s FOR UPDATE",
                    (instance_id, server_id),
                )
                if current is None or current["id"] != saved["id"] or current != saved:
                    raise conflict("재pin 중 재승인 계획이 교체되었습니다.")
                fresh = _pending(ctx, current)
                result = _replace(ctx, current, fresh, digest)
            return result
        except Exception:
            # unpin 실패도 이미 커밋된 차단을 해제하지 않으며 원래 실패를 보존한다.
            with contextlib.suppress(Exception):
                pin_client.unpin(server_id)
            with contextlib.suppress(Exception), conn.transaction():
                conn.execute(
                    "UPDATE mint.litellm_grants SET observed=false"
                    " WHERE instance_id=%s AND target_type='server' AND target_id=%s"
                    " AND item='pin' AND server_id=%s",
                    (instance_id, server_id, server_id),
                )
            raise
    finally:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s,0))", (key,))
