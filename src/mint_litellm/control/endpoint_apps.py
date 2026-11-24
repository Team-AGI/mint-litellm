"""직원이 직접 만든 AI 프로그램(앱)의 자격 조회와 회수.

앱 키는 단말에서 ``mint app new``로 만들고(발급은 판정 경로가 한다), 이 모듈은 콘솔의 목록과
회수, 그리고 「연결 해제」 때의 함께 회수를 맡는다. 키 값은 어디에도 남지 않고 해시와 별칭만 있다.
"""

import uuid
from typing import Any

import psycopg

from mint_litellm.control import ledger
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import not_found
from mint_litellm.control.litellm_write import LiteLLMKitKeys
from mint_litellm.types.events import EventKind

LIST_LIMIT = 50

_STATE = (
    "CASE WHEN revoked_at IS NOT NULL THEN 'revoked'"
    " WHEN expires_at <= now() THEN 'expired' ELSE 'active' END"
)


def list_apps(
    conn: psycopg.Connection, instance_id: str, user_id: str | None = None
) -> list[dict[str, Any]]:
    """앱 목록(최근 순). ``state``: active, expired, revoked. 키 값은 없다."""
    return fetchall(
        conn,
        "SELECT id, user_id, name, key_alias, created_at, expires_at, revoked_at,"
        f" {_STATE} AS state"
        " FROM mint.endpoint_apps WHERE instance_id = %s AND (%s::text IS NULL OR user_id = %s)"
        " ORDER BY created_at DESC LIMIT %s",
        (instance_id, user_id, user_id, LIST_LIMIT),
    )


def revoke_app(
    conn: psycopg.Connection, issuer: LiteLLMKitKeys, instance_id: str, app_id: str, *,
    actor: str, user_id: str | None = None,
) -> None:
    """앱 하나의 자격을 지운다. ``user_id``가 있으면 그 사람의 앱만이다(아니면 없는 것으로 본다).

    이미 회수된 앱은 아무것도 하지 않는다.
    """
    try:
        key = str(uuid.UUID(app_id))
    except ValueError:
        raise not_found("앱이 없습니다.") from None
    rows = fetchall(
        conn,
        "SELECT id, user_id, name, key_alias, revoked_at FROM mint.endpoint_apps"
        " WHERE instance_id = %s AND id = %s AND (%s::text IS NULL OR user_id = %s)",
        (instance_id, key, user_id, user_id),
    )
    if not rows:
        raise not_found("앱이 없습니다.")
    if rows[0]["revoked_at"] is None:
        _revoke(conn, issuer, instance_id, rows, actor)


def revoke_user_apps(
    conn: psycopg.Connection, issuer: LiteLLMKitKeys, instance_id: str, user_id: str, actor: str
) -> int:
    """사람의 아직 회수되지 않은 앱을 모두 회수한다. 회수한 수를 돌려준다."""
    rows = fetchall(
        conn,
        "SELECT id, user_id, name, key_alias, revoked_at FROM mint.endpoint_apps"
        " WHERE instance_id = %s AND user_id = %s AND revoked_at IS NULL",
        (instance_id, user_id),
    )
    if rows:
        _revoke(conn, issuer, instance_id, rows, actor)
    return len(rows)


def revoke_install_apps(
    conn: psycopg.Connection, issuer: LiteLLMKitKeys, instance_id: str, install_key_token: str,
    actor: str,
) -> int:
    """이 설치(단말)에 묶인 앱만 회수한다. 회수한 수를 돌려준다."""
    rows = fetchall(
        conn,
        "SELECT id, user_id, name, key_alias, revoked_at FROM mint.endpoint_apps"
        " WHERE instance_id = %s AND install_key_token = %s AND revoked_at IS NULL",
        (instance_id, install_key_token),
    )
    if rows:
        _revoke(conn, issuer, instance_id, rows, actor)
    return len(rows)


def _revoke(
    conn: psycopg.Connection, issuer: LiteLLMKitKeys, instance_id: str, rows: list[dict],
    actor: str,
) -> None:
    issuer.delete_kit_keys([r["key_alias"] for r in rows])
    for row in rows:
        conn.execute(
            "UPDATE mint.endpoint_apps SET revoked_at = clock_timestamp(), revoked_by = %s"
            " WHERE instance_id = %s AND id = %s AND revoked_at IS NULL",
            (actor, instance_id, row["id"]),
        )
        ledger.record(
            conn, instance_id, EventKind.ENDPOINT_APP_REVOKED, entity_id=str(row["id"]),
            state_version=2, actor=actor,
            payload={"app": row["name"], "user_id": row["user_id"]},
            subject={"user_id": row["user_id"], "key_alias": row["key_alias"]},
        )
