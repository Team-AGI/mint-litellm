"""단말 설치 묶음: 승인된 로컬 서버 계약 읽기, 사용자별 키 발급·해제, 설치 상태 조회.

키는 사용자마다 하나가 활성이다. 새 묶음을 내려받으면 같은 사용자의 이전 키는 지워지고 해제
시각이 남는다. 키 값은 묶음 안에만 있고 이 표에는 키의 해시와 별칭만 남는다.
"""

import hashlib
import secrets
from datetime import datetime
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_write import (
    KIT_ALIAS_PREFIX,
    MCP_ALIAS_PREFIX,
    LiteLLMKitKeys,
)

LIST_LIMIT = 200
INVENTORY_LIMIT = 2000
KEY_DAYS = 90  # 키 유효 기간 기본값(일). 만료 전 14일 안의 보고가 같은 기간만큼 늘린다.


def approved_contracts(conn: psycopg.Connection, instance_id: str) -> dict[str, dict[str, Any]]:
    """승인된 로컬 서버의 현재 실행 계약(서버 이름 -> 계약 문서).

    서버 행의 계약 해시와 같은 값을 등록한 가장 최근 사건에서 읽는다.
    """
    rows = fetchall(
        conn,
        "SELECT DISTINCT ON (s.server_id) s.server_id, e.payload -> 'exec_contract' AS contract"
        " FROM mint.servers s JOIN mint.events e ON e.instance_id = s.instance_id"
        "  AND e.kind = 'server_registered' AND e.payload ->> 'server_id' = s.server_id"
        "  AND e.payload ->> 'exec_contract_sha256' = s.exec_contract_sha256"
        " WHERE s.instance_id = %s AND s.identity_kind = 'stdio' AND s.status = 'approved'"
        " ORDER BY s.server_id, e.inserted_at DESC",
        (instance_id,),
    )
    return {r["server_id"]: r["contract"] for r in rows if isinstance(r["contract"], dict)}


def _active_aliases(conn: psycopg.Connection, instance_id: str, user_id: str) -> list[str]:
    rows = fetchall(
        conn,
        "SELECT key_alias, mcp_key_alias FROM mint.endpoint_installs"
        " WHERE instance_id = %s AND user_id = %s AND revoked_at IS NULL",
        (instance_id, user_id),
    )
    return [a for r in rows for a in (r["key_alias"], r["mcp_key_alias"]) if a]


def _mark_revoked(conn: psycopg.Connection, instance_id: str, user_id: str) -> None:
    conn.execute(
        "UPDATE mint.endpoint_installs SET revoked_at = clock_timestamp()"
        " WHERE instance_id = %s AND user_id = %s AND revoked_at IS NULL",
        (instance_id, user_id),
    )


def issue_key(
    conn: psycopg.Connection,
    issuer: LiteLLMKitKeys,
    instance_id: str,
    *,
    user_id: str,
    team_id: str | None,
    issued_by: str,
    ttl_days: int = KEY_DAYS,
) -> str:
    """사용자의 이전 설치 묶음 키를 지우고 새 키를 발급해 기록한다. 키 값을 돌려준다.

    키는 ``ttl_days`` 뒤에 만료된다(만료 전 보고가 늘려 준다).

    같은 사용자의 발급은 한 번에 하나씩이다(트랜잭션이 끝날 때까지 잠금을 쥔다). 동시에 두 번
    내려받아도 활성 키는 하나만 남는다.
    """
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtext(%s))", (f"endpoint-kit:{instance_id}:{user_id}",)
    )
    old = _active_aliases(conn, instance_id, user_id)
    if old:
        issuer.delete_kit_keys(old)
    alias = KIT_ALIAS_PREFIX + secrets.token_hex(8)
    key = issuer.generate_kit_key(user_id=user_id, team_id=team_id, alias=alias)
    _mark_revoked(conn, instance_id, user_id)
    conn.execute(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, team_id, key_alias,"
        " issued_by, expires_at, ttl_days)"
        " VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp() + make_interval(days => %s), %s)",
        (instance_id, hashlib.sha256(key.encode()).hexdigest(), user_id, team_id, alias, issued_by,
         ttl_days, ttl_days),
    )
    return key


def issue_gateway_key(
    conn: psycopg.Connection,
    issuer: LiteLLMKitKeys,
    instance_id: str,
    *,
    user_id: str,
    team_id: str | None,
    kit_key: str,
) -> str:
    """방금 발급한 설치 묶음 키에 딸린 게이트웨이 MCP 전용 키를 만든다. 키 값을 돌려준다.

    사용자에게 결속되고 MCP 경로만 부를 수 있다. 이 표에는 별칭만 남고, 같은 사용자의 다음 발급이나
    해제 때 설치 묶음 키와 함께 지워진다.
    """
    alias = MCP_ALIAS_PREFIX + secrets.token_hex(8)
    key = issuer.generate_kit_key(user_id=user_id, team_id=team_id, alias=alias)
    conn.execute(
        "UPDATE mint.endpoint_installs SET mcp_key_alias = %s"
        " WHERE instance_id = %s AND key_token = %s",
        (alias, instance_id, hashlib.sha256(kit_key.encode()).hexdigest()),
    )
    return key


def revoke_keys(
    conn: psycopg.Connection, issuer: LiteLLMKitKeys, instance_id: str, user_id: str
) -> int:
    """사용자의 설치 묶음 키를 모두 지운다(이미 설치된 단말은 더 이상 판정을 받지 못한다)."""
    aliases = _active_aliases(conn, instance_id, user_id)
    if not aliases:
        raise ControlError("해제할 단말 연결이 없습니다.")
    issuer.delete_kit_keys(aliases)
    _mark_revoked(conn, instance_id, user_id)
    return len(aliases)


def local_mcp_inventory(conn: psycopg.Connection, instance_id: str) -> list[dict[str, Any]]:
    """단말에서 보고한, MINT가 관리하지 않는 MCP 항목(설치마다 한 줄).

    값은 단말의 주장이다. 이름·하네스·전송 종류·실행 파일 이름이나 호스트·처음과 마지막으로 본
    시각만 있고 인자·환경 변수·토큰은 받지 않는다. 해제된 키와 제거 보고는 제외하고,
    ``endpoints``는 같은 항목(이름·종류·대상·패키지)을 보고한 활성 설치의 수이다.
    """
    rows = fetchall(
        conn,
        "SELECT i.user_id, i.key_alias, i.install_mode, i.reported_at,"
        " x.item ->> 'harness' AS harness, x.item ->> 'name' AS name, x.item ->> 'kind' AS kind,"
        " x.item ->> 'target' AS target, x.item ->> 'package' AS package,"
        " x.item ->> 'first_seen' AS first_seen"
        " FROM mint.endpoint_installs i,"
        " LATERAL jsonb_array_elements(coalesce(i.local_mcp, '[]'::jsonb)) AS x(item)"
        " WHERE i.instance_id = %s AND i.revoked_at IS NULL"
        " AND i.install_mode IN ('managed', 'user')"
        " ORDER BY x.item ->> 'name', i.user_id, i.key_alias LIMIT %s",
        (instance_id, INVENTORY_LIMIT),
    )
    same: dict[tuple, set[str]] = {}
    for row in rows:
        same.setdefault(_same(row), set()).add(row["key_alias"])
    for row in rows:
        row["endpoints"] = len(same[_same(row)])
        row["first_seen"] = datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None
        row["last_seen"] = row.pop("reported_at")
        row["state"] = row.pop("install_mode")
    return rows


def _same(row: dict[str, Any]) -> tuple:
    return (row["name"], row["kind"], row["target"], row["package"])


def installs(
    conn: psycopg.Connection, instance_id: str, user_id: str | None = None
) -> list[dict[str, Any]]:
    """발급·보고 현황(최근 순). ``state``: revoked, pending(보고 전), managed, user, removed."""
    rows = fetchall(
        conn,
        "SELECT user_id, team_id, issued_at, revoked_at, install_mode, kit_version,"
        " claude_version, mcp_servers, processes, outside_processes, reported_at, expires_at"
        " FROM mint.endpoint_installs"
        " WHERE instance_id = %s AND (%s::text IS NULL OR user_id = %s)"
        " ORDER BY issued_at DESC LIMIT %s",
        (instance_id, user_id, user_id, LIST_LIMIT),
    )
    for row in rows:
        row["state"] = (
            "revoked" if row["revoked_at"] else row["install_mode"] or "pending"
        )
    return rows
