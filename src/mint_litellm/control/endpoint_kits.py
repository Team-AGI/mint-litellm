"""단말 설치 묶음: 승인된 로컬 서버 계약 읽기, 사용자별 키 발급·해제, 설치 상태 조회.

키는 사용자마다 하나가 활성이다. 새 묶음을 내려받으면 같은 사용자의 이전 키는 지워지고 해제
시각이 남는다. 키 값은 묶음 안에만 있고 이 표에는 키의 해시와 별칭만 남는다.
"""

import hashlib
import secrets
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_write import KIT_ALIAS_PREFIX, LiteLLMKitKeys

LIST_LIMIT = 200


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
        "SELECT key_alias FROM mint.endpoint_installs"
        " WHERE instance_id = %s AND user_id = %s AND revoked_at IS NULL",
        (instance_id, user_id),
    )
    return [r["key_alias"] for r in rows]


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
) -> str:
    """사용자의 이전 설치 묶음 키를 지우고 새 키를 발급해 기록한다. 키 값을 돌려준다.

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
        " issued_by) VALUES (%s, %s, %s, %s, %s, %s)",
        (instance_id, hashlib.sha256(key.encode()).hexdigest(), user_id, team_id, alias, issued_by),
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


def installs(
    conn: psycopg.Connection, instance_id: str, user_id: str | None = None
) -> list[dict[str, Any]]:
    """발급·보고 현황(최근 순). ``state``: revoked, pending(보고 전), managed, user, removed."""
    rows = fetchall(
        conn,
        "SELECT user_id, team_id, issued_at, revoked_at, install_mode, kit_version,"
        " claude_version, mcp_servers, reported_at FROM mint.endpoint_installs"
        " WHERE instance_id = %s AND (%s::text IS NULL OR user_id = %s)"
        " ORDER BY issued_at DESC LIMIT %s",
        (instance_id, user_id, user_id, LIST_LIMIT),
    )
    for row in rows:
        row["state"] = (
            "revoked" if row["revoked_at"] else row["install_mode"] or "pending"
        )
    return rows
