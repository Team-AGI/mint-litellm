"""MINT 세션이 끝날 때 그 세션으로 열린 LiteLLM 화면 세션을 지운다(LiteLLM 안의 어댑터에 서명 호출).

지우지 못하면 표시를 남겨 두고 세션 재확인 작업이 다시 시도한다.
"""

import json
import time

import httpx
import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.types import ui_handoff


def _revoke_remote(config_url: str, key: bytes, session_hash: str) -> bool:
    body = json.dumps({"session_hash": session_hash}).encode()
    try:
        reply = httpx.post(
            f"{config_url.rstrip('/')}{ui_handoff.REVOKE_PATH}", content=body, timeout=5.0,
            headers={**ui_handoff.sign(key, ui_handoff.REVOKE_PATH, body),
                     "Content-Type": "application/json"},
        )
    except httpx.HTTPError:
        return False
    return reply.status_code == 200


def end_session(
    conn: psycopg.Connection, instance_id: str, litellm_url: str, key: bytes, session_hash: str
) -> bool:
    """MINT 세션이 끝날 때 안 쓴 코드를 무효로 하고 열린 LiteLLM 화면 세션을 지운다(지웠으면 참)."""
    conn.execute(
        "UPDATE mint.ui_handoffs SET consumed_at = now(), revoked_at = now()"
        " WHERE instance_id = %s AND session_hash = %s AND consumed_at IS NULL",
        (instance_id, session_hash),
    )
    opened = fetchone(
        conn,
        "SELECT 1 AS x FROM mint.ui_handoffs WHERE instance_id = %s AND session_hash = %s"
        " AND consumed_at IS NOT NULL AND revoked_at IS NULL",
        (instance_id, session_hash),
    )
    if opened is None:
        return True
    if not _revoke_remote(litellm_url, key, session_hash):
        return False  # 지우지 못했으면 표시를 남겨 둔다. 다음 세션 재확인 때 다시 시도한다.
    conn.execute(
        "UPDATE mint.ui_handoffs SET revoked_at = now() WHERE instance_id = %s"
        " AND session_hash = %s AND consumed_at IS NOT NULL AND revoked_at IS NULL",
        (instance_id, session_hash),
    )
    return True


def sweep(conn: psycopg.Connection, instance_id: str, litellm_url: str, key: bytes) -> int:
    """끝났거나 만료된 MINT 세션에 남은 LiteLLM 화면 세션을 지운다(로그아웃 때 못 지운 것 포함)."""
    rows = fetchall(
        conn,
        "SELECT DISTINCT h.session_hash FROM mint.ui_handoffs h"
        " LEFT JOIN mint.console_sessions s ON s.id_hash = h.session_hash"
        " WHERE h.instance_id = %s AND h.consumed_at IS NOT NULL AND h.revoked_at IS NULL"
        " AND (s.id_hash IS NULL OR s.revoked_at IS NOT NULL OR s.idle_expiry <= now()"
        "  OR s.absolute_expiry <= now())",
        (instance_id,),
    )
    return sum(
        end_session(conn, instance_id, litellm_url, key, r["session_hash"]) for r in rows
    )


_CHECKED: dict[str, float] = {}
CHECK_SECONDS = 5.0
OPEN_GRACE_SECONDS = 15


def litellm_logged_out(
    conn: psycopg.Connection, instance_id: str, litellm_url: str, key: bytes, session_hash: str
) -> bool:
    """이 MINT 세션이 연 LiteLLM 화면 세션이 모두 사라졌으면 참(화면에서 로그아웃함).

    화면을 연 적 없는 세션, 방금 연 세션, LiteLLM에 닿지 않을 때는 거짓이다(통과).
    """
    now = time.monotonic()
    if now - _CHECKED.get(session_hash, -CHECK_SECONDS) < CHECK_SECONDS:
        return False
    _CHECKED[session_hash] = now
    if len(_CHECKED) > 4096:
        _CHECKED.clear()
    opened = fetchone(
        conn,
        "SELECT 1 AS x FROM mint.ui_handoffs WHERE instance_id = %s AND session_hash = %s"
        " AND consumed_at IS NOT NULL AND revoked_at IS NULL"
        " AND consumed_at < now() - make_interval(secs => %s) LIMIT 1",
        (instance_id, session_hash, OPEN_GRACE_SECONDS),
    )
    if opened is None:
        return False
    body = json.dumps({"session_hash": session_hash}).encode()
    try:
        reply = httpx.post(
            f"{litellm_url.rstrip('/')}{ui_handoff.ALIVE_PATH}", content=body, timeout=3.0,
            headers={**ui_handoff.sign(key, ui_handoff.ALIVE_PATH, body),
                     "Content-Type": "application/json"},
        )
        return reply.status_code == 200 and reply.json().get("open") == 0
    except (httpx.HTTPError, ValueError):
        return False
