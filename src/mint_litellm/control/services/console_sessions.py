"""관리자 콘솔 세션 서비스: 로그인 확인 결과로 세션을 만들고, 조회하며, 폐기한다.

세션 식별자는 쿠키에만 있고 DB에는 SHA-256만 둔다. 세션에는 본인 LiteLLM 키의
SHA-256(``key_token``),
사용자 식별자, 운영자 이름과 역할만 남고 평문 키는 어디에도 저장하지 않는다.
"""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

import psycopg

from mint_litellm.control import ledger
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import forbidden
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.types.events import EventKind

# 키 없이 SSO로 연 세션의 key_token 접두사(뒤는 발급자와 주체의 SHA-256)
SSO_PREFIX = "sso:"
_ROLE_RANK = {"viewer": 0, "approver": 1, "admin": 2}


@dataclass(frozen=True)
class SessionInfo:
    id_hash: str
    user_id: str
    operator_name: str
    role: str
    key_token: str


def is_sso_session(key_token: str) -> bool:
    return key_token.startswith(SSO_PREFIX)


def hash_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def csrf_token(session_id: str) -> str:
    """세션 식별자에서 유도한 CSRF 토큰. 식별자는 HttpOnly 쿠키라 다른 출처가 계산할 수 없다."""
    return hmac.new(session_id.encode("utf-8"), b"mint-console-csrf", hashlib.sha256).hexdigest()


def active_operator(conn: psycopg.Connection, instance_id: str, user_id: str) -> dict | None:
    """그 사용자에 결속된 유효한 운영자 행. 여러 행이면 가장 높은 역할."""
    rows = fetchall(
        conn,
        "SELECT name, role FROM mint.operators WHERE instance_id = %s AND user_id = %s"
        " AND (expires_at IS NULL OR expires_at > now())",
        (instance_id, user_id),
    )
    return max(rows, key=lambda r: _ROLE_RANK[r["role"]], default=None)


def create(
    conn: psycopg.Connection,
    instance_id: str,
    settings: Stage2Settings,
    *,
    user_id: str,
    key_token: str,
    via: dict | None = None,
) -> tuple[str, SessionInfo]:
    """활성 운영자 행이 있는 사용자의 세션을 만든다. 세션 식별자(평문)와 정보를 돌려준다.

    ``via``는 로그인 수단의 기록(예: SSO 발급자와 주체)이며 시작 사건에 그대로 싣는다."""
    operator = active_operator(conn, instance_id, user_id)
    if operator is None:
        raise forbidden("운영자로 등록된 사용자가 아닙니다.")
    session_id = secrets.token_urlsafe(32)
    id_hash = hash_id(session_id)
    with conn.transaction():
        conn.execute(
            "INSERT INTO mint.console_sessions (id_hash, instance_id, subject, user_id, key_token,"
            " operator_name, role, idle_expiry, absolute_expiry) VALUES (%s, %s, 'admin', %s, %s,"
            " %s, %s, LEAST(now() + make_interval(secs => %s), now() + make_interval(secs => %s)),"
            " now() + make_interval(secs => %s))",
            (id_hash, instance_id, user_id, key_token, operator["name"], operator["role"],
             settings.session_idle_seconds, settings.session_absolute_seconds,
             settings.session_absolute_seconds),
        )
        ledger.record(
            conn, instance_id, EventKind.CONSOLE_SESSION_STARTED, entity_id=id_hash,
            state_version=1, actor=operator["name"],
            payload={"user_id": user_id, "role": operator["role"], "subject": "admin",
                     **(via or {})},
        )
    return session_id, SessionInfo(id_hash, user_id, operator["name"], operator["role"], key_token)


def lookup(
    conn: psycopg.Connection, instance_id: str, settings: Stage2Settings, session_id: str
) -> SessionInfo | None:
    """유효한 세션이면 유휴 만료를 늘리고(절대 만료까지) 정보를 돌려준다. 아니면 None.

    마지막 성공 확인(``last_verified_at``)이 확인 주기 두 번(기본 10분)을 넘은 세션은 요청마다
    거부한다: 작업 실행기가 멈추거나 큐가 밀려도 만료가 집행된다.
    """
    row = fetchone(
        conn,
        "UPDATE mint.console_sessions SET last_seen_at = now(),"
        " idle_expiry = LEAST(now() + make_interval(secs => %s), absolute_expiry)"
        " WHERE instance_id = %s AND id_hash = %s AND subject = 'admin' AND revoked_at IS NULL"
        " AND idle_expiry > now() AND absolute_expiry > now()"
        " AND last_verified_at > now() - make_interval(secs => %s)"
        " AND EXISTS (SELECT 1 FROM mint.operators o"
        "  WHERE o.instance_id = console_sessions.instance_id"
        "  AND o.user_id = console_sessions.user_id AND o.role = console_sessions.role"
        "  AND (o.expires_at IS NULL OR o.expires_at > now()))"
        " RETURNING id_hash, user_id, operator_name, role, key_token",
        (settings.session_idle_seconds, instance_id, hash_id(session_id),
         settings.session_verify_window_seconds),
    )
    return None if row is None else SessionInfo(**row)


def revoke(
    conn: psycopg.Connection, instance_id: str, id_hash: str, *, actor: str, reason: str
) -> bool:
    """세션을 폐기하고 종료 사건을 남긴다. 이미 폐기됐으면 거짓."""
    with conn.transaction():
        row = fetchone(
            conn,
            "UPDATE mint.console_sessions SET revoked_at = now() WHERE instance_id = %s"
            " AND id_hash = %s AND revoked_at IS NULL RETURNING user_id, subject",
            (instance_id, id_hash),
        )
        if row is None:
            return False
        ledger.record(
            conn, instance_id, EventKind.CONSOLE_SESSION_ENDED, entity_id=id_hash,
            state_version=2, actor=actor,
            payload={"user_id": row["user_id"], "reason": reason, "subject": row["subject"]},
        )
    return True


def revoke_user_sessions(
    conn: psycopg.Connection, instance_id: str, user_id: str, *, actor: str, reason: str
) -> int:
    """그 사용자의 활성 관리자 세션을 모두 폐기한다(운영자 행을 지우거나 역할을 바꿀 때 부른다).

직원 세션은 운영자 행과 무관하므로 건드리지 않는다."""
    rows = fetchall(
        conn,
        "SELECT id_hash FROM mint.console_sessions WHERE instance_id = %s AND user_id = %s"
        " AND subject = 'admin' AND revoked_at IS NULL",
        (instance_id, user_id),
    )
    return sum(revoke(conn, instance_id, r["id_hash"], actor=actor, reason=reason) for r in rows)


def active_sessions(conn: psycopg.Connection, instance_id: str) -> list[dict]:
    return fetchall(
        conn,
        "SELECT id_hash, user_id, key_token, role, subject,"
        " EXTRACT(EPOCH FROM now() - last_verified_at) AS unverified_seconds"
        " FROM mint.console_sessions"
        " WHERE instance_id = %s AND revoked_at IS NULL AND absolute_expiry > now()"
        " AND idle_expiry > now()",
        (instance_id,),
    )


def teams_of(key_info: dict) -> tuple[str, ...]:
    """키 정보의 team_id(문자열일 때만). 화면 입력이나 사용자 정보는 쓰지 않는다."""
    team = key_info.get("team_id")
    return (team,) if isinstance(team, str) and team else ()


def teams_of_user(user_info: dict) -> tuple[str, ...]:
    """사용자 정보의 소속 팀(문자열 또는 ``team_id`` 항목). 토큰 클레임은 쓰지 않는다."""
    teams = user_info.get("teams")
    if not isinstance(teams, list):
        return ()
    ids = (t.get("team_id") if isinstance(t, dict) else t for t in teams)
    return tuple(dict.fromkeys(t for t in ids if isinstance(t, str) and t))


def set_teams(
    conn: psycopg.Connection, instance_id: str, id_hash: str, team_ids: tuple[str, ...]
) -> None:
    """직원 세션의 소속 팀을 본인 키 정보에서 읽은 값으로 맞춘다(로그인 직후와 재확인 때)."""
    conn.execute(
        "UPDATE mint.console_sessions SET team_ids = %s::jsonb WHERE instance_id = %s"
        " AND id_hash = %s AND subject = 'staff' AND team_ids IS DISTINCT FROM %s::jsonb",
        (json.dumps(list(team_ids)), instance_id, id_hash, json.dumps(list(team_ids))),
    )


def mark_verified(conn: psycopg.Connection, instance_id: str, id_hash: str) -> None:
    conn.execute(
        "UPDATE mint.console_sessions SET last_verified_at = now() WHERE instance_id = %s"
        " AND id_hash = %s",
        (instance_id, id_hash),
    )
