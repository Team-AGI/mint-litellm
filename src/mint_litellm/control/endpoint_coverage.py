"""단말이 보고한 AI 도구 보장 현황의 읽기와, 관리 AI 연결 중지·연결 복구·서버 제외·신청 요청 쓰기.

보고 값은 단말의 주장이다(평문 키는 종류와 위치만 있고 값은 받지 않는다). 중지는 설치 키 하나에
걸리고 결정 경로가 그 키의 호출을 거절한다. 재개는 중지만 풀며 도구별 차단은 건드리지 않는다.
"""

from collections import Counter
from typing import Any

import psycopg

from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import ControlError, forbidden, not_found
from mint_litellm.control.services.base import transact
from mint_litellm.types.events import EventKind

CONNECTED = ("pre_call", "local_only")


def pause(ctx: Context, key_alias: str) -> None:
    """설치 키의 호출을 모두 거절하게 한다. 세대가 하나 늘고 사건이 남는다."""
    _admin(ctx)
    with transact(ctx):
        row = ctx.conn.execute(
            "UPDATE mint.endpoint_installs SET paused_at = clock_timestamp(), paused_by = %s,"
            " pause_gen = pause_gen + 1 WHERE instance_id = %s AND key_alias = %s"
            " AND revoked_at IS NULL AND paused_at IS NULL RETURNING user_id, pause_gen",
            (ctx.operator.name, ctx.instance_id, key_alias),
        ).fetchone()
        if row is None:
            raise ControlError("중지할 단말이 없거나 이미 중지되어 있습니다.")
        ctx.emit(
            EventKind.ENDPOINT_PAUSED,
            key_alias,
            row[1],
            {"user_id": row[0]},
            subject={"user_id": row[0], "key_alias": key_alias},
        )


def resume(ctx: Context, key_alias: str) -> None:
    """중지만 푼다. 도구별 차단과 승인은 그대로이다."""
    _admin(ctx)
    with transact(ctx):
        row = ctx.conn.execute(
            "UPDATE mint.endpoint_installs SET paused_at = NULL, paused_by = NULL"
            " WHERE instance_id = %s AND key_alias = %s AND revoked_at IS NULL"
            " AND paused_at IS NOT NULL RETURNING user_id, pause_gen",
            (ctx.instance_id, key_alias),
        ).fetchone()
        if row is None:
            raise ControlError("재개할 단말이 없거나 중지 상태가 아닙니다.")
        ctx.emit(
            EventKind.ENDPOINT_RESUMED,
            key_alias,
            row[1],
            {"user_id": row[0]},
            subject={"user_id": row[0], "key_alias": key_alias},
        )


def request_reconnect(
    conn: psycopg.Connection, instance_id: str, key_alias: str, user_id: str | None = None
) -> None:
    """다음 보고 응답에 연결 복구 지시를 한 번 싣게 한다. ``user_id``가 있으면 본인 단말만."""
    done = conn.execute(
        "UPDATE mint.endpoint_installs SET reconnect_requested = true WHERE instance_id = %s"
        " AND key_alias = %s AND revoked_at IS NULL AND (%s::text IS NULL OR user_id = %s)",
        (instance_id, key_alias, user_id, user_id),
    ).rowcount
    if done != 1:
        raise not_found("연결할 단말이 없습니다.")


def ignore_server(conn: psycopg.Connection, instance_id: str, user_id: str, name: str) -> None:
    """본인이 이 PC에서 쓰던 서버 하나를 알림에서 제외한다(같은 이름은 한 번만)."""
    known = conn.execute(
        "SELECT 1 FROM mint.endpoint_installs i, LATERAL jsonb_array_elements("
        "coalesce(i.local_mcp, '[]'::jsonb)) x(item) WHERE i.instance_id = %s AND i.user_id = %s"
        " AND i.revoked_at IS NULL AND x.item ->> 'name' = %s LIMIT 1",
        (instance_id, user_id, name),
    ).fetchone()
    if known is None:
        raise not_found("이 PC에서 발견된 서버가 아닙니다.")
    conn.execute(
        "INSERT INTO mint.endpoint_ignored_servers (instance_id, user_id, server_name)"
        " VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
        (instance_id, user_id, name),
    )


def request_intake(
    conn: psycopg.Connection, instance_id: str, user_id: str, name: str, purpose: str
) -> None:
    """본인이 동의하고 도입 신청을 요청한다. 같은 서버의 요청은 하나이고 다시 눌러도 재사용한다."""
    purpose = purpose.strip()
    if not 1 <= len(purpose) <= 256:
        raise ControlError("목적을 1자 이상 256자 이하로 입력하십시오.")
    known = conn.execute(
        "SELECT 1 FROM mint.endpoint_installs i, LATERAL jsonb_array_elements("
        "coalesce(i.local_mcp, '[]'::jsonb)) x(item) WHERE i.instance_id = %s AND i.user_id = %s"
        " AND i.revoked_at IS NULL AND x.item ->> 'name' = %s LIMIT 1",
        (instance_id, user_id, name),
    ).fetchone()
    if known is None:
        raise not_found("이 PC에서 발견된 서버가 아닙니다.")
    conn.execute(
        "INSERT INTO mint.endpoint_intake_requests (instance_id, user_id, server_name, purpose)"
        " VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
        (instance_id, user_id, name, purpose),
    )


def _admin(ctx: Context) -> None:
    if ctx.operator.role != "admin":
        raise forbidden("관리자만 할 수 있습니다.", exit_code=4)


def ignored_names(conn: psycopg.Connection, instance_id: str, user_id: str) -> set[str]:
    return {
        r["server_name"]
        for r in fetchall(
            conn,
            "SELECT server_name FROM mint.endpoint_ignored_servers"
            " WHERE instance_id = %s AND user_id = %s",
            (instance_id, user_id),
        )
    }


def intake_requests(
    conn: psycopg.Connection, instance_id: str, user_id: str
) -> dict[str, dict[str, Any]]:
    """본인이 올린 신청 요청(서버 이름별)과 그 서버 이름의 가장 최근 신청 상태."""
    asked = {
        r["server_name"]: {**r, "intake": None}
        for r in fetchall(
            conn,
            "SELECT server_name, purpose, sent_at FROM mint.endpoint_intake_requests"
            " WHERE instance_id = %s AND user_id = %s",
            (instance_id, user_id),
        )
    }
    for r in fetchall(
        conn,
        "SELECT DISTINCT ON (server_id) server_id, status, decision FROM mint.intakes"
        " WHERE instance_id = %s AND requested_by = %s ORDER BY server_id, created_at DESC",
        (instance_id, user_id),
    ):
        asked.setdefault(
            r["server_id"], {"server_name": r["server_id"], "purpose": None, "sent_at": None}
        )["intake"] = r
    return asked


def paused_runner_at(conn: psycopg.Connection, instance_id: str, key_alias: str, since: Any) -> Any:
    """중지 뒤 단말이 실행기를 멈췄다고 보고한(제거 사건) 가장 이른 시각. 없으면 None."""
    rows = fetchall(
        conn,
        "SELECT min(inserted_at) AS at FROM mint.events WHERE instance_id = %s"
        " AND kind = 'endpoint_remediated' AND subject ->> 'key_alias' = %s"
        " AND payload ->> 'kind' = 'process' AND inserted_at >= %s",
        (instance_id, key_alias, since),
    )
    return rows[0]["at"] if rows else None


def coverage_view(rows: list[dict[str, Any]], mcp: list[dict[str, Any]]) -> dict[str, Any]:
    """관리 화면의 AI 도구 현황. ``rows``는 ``installs()`` 결과, ``mcp``는 관리 밖 MCP 목록."""
    live = [r for r in rows if r["state"] in ("managed", "user") and r.get("ai_clients")]
    clients: dict[str, dict[str, Any]] = {}
    for r in live:
        for c in r["ai_clients"]:
            entry = clients.setdefault(
                c["client"],
                {"client": c["client"], "devices": [], "coverage": Counter(), "last": None},
            )
            entry["devices"].append({**c, "install": r})
            entry["coverage"][c["coverage"]] += 1
            if r["reported_at"] and (entry["last"] is None or r["reported_at"] > entry["last"]):
                entry["last"] = r["reported_at"]
    connected = sum(all(c["coverage"] in CONNECTED for c in r["ai_clients"]) for r in live)
    keys = sum(len(r.get("plaintext_keys") or []) for r in live)
    unapproved = sum(1 for m in mcp if not m.get("ignored"))
    return {
        "clients": sorted(clients.values(), key=lambda e: e["client"]),
        "found": len(clients),
        "connected": connected,
        "reporting": len(live),
        "unapproved": unapproved,
        "keys": keys,
    }
