"""관리 화면에서 정한 알림(웹훅) 주소.

웹훅 주소에는 비밀이 들어 있으므로 암호문으로만 둔다. 설치 설정(``MINT_WEBHOOK_URLS``)이 있으면
그것이 우선이고, 화면에서는 바꿀 수 없다.
"""

import dataclasses
import hashlib
import json
import os
import secrets

import psycopg

from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.stage2_config import Stage2Settings, _webhook_formats, _webhook_urls

_LABEL = b"mint-webhook-urls\0"


def derive_key(label: bytes) -> bytes:
    # ponytail: 내보내기 서명 키에서 용도를 나눠 만든다. 키를 바꾸면 값을 다시 저장한다.
    secret = os.environ.get("MINT_EXPORT_HMAC_KEY", "")
    if not secret:
        raise ControlError("서버 서명 키가 없어 값을 저장할 수 없습니다.")
    return hashlib.sha256(label + secret.encode()).digest()


def _key() -> bytes:
    return derive_key(_LABEL)


def save(conn: psycopg.Connection, instance: str, url: str, fmt: str, by: str) -> None:
    """주소 하나와 형식을 저장한다. 주소를 비우면 지운다."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not url.strip():
        conn.execute("DELETE FROM mint.webhook_settings WHERE instance_id = %s", (instance,))
        return
    urls = _webhook_urls(url)
    formats = _webhook_formats(fmt, len(urls))
    nonce = secrets.token_bytes(12)
    plain = json.dumps({"urls": list(urls), "formats": list(formats)}).encode()
    sealed = nonce + AESGCM(_key()).encrypt(nonce, plain, instance.encode())
    conn.execute(
        "INSERT INTO mint.webhook_settings (instance_id, sealed, updated_by) VALUES (%s, %s, %s)"
        " ON CONFLICT (instance_id) DO UPDATE SET sealed = excluded.sealed,"
        " updated_by = excluded.updated_by, updated_at = now()",
        (instance, sealed, by),
    )


def stored(conn: psycopg.Connection, instance: str) -> dict | None:
    """저장된 주소({"urls", "formats"}). 없거나 읽을 수 없으면 None."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    row = fetchone(
        conn, "SELECT sealed FROM mint.webhook_settings WHERE instance_id = %s", (instance,)
    )
    if row is None:
        return None
    sealed = bytes(row["sealed"])
    try:
        plain = AESGCM(_key()).decrypt(sealed[:12], sealed[12:], instance.encode())
    except (InvalidTag, ControlError):
        return None
    return json.loads(plain)


def effective(settings: Stage2Settings, conn: psycopg.Connection, instance: str) -> Stage2Settings:
    """설치 설정이 있으면 그대로, 없으면 화면에서 저장한 주소를 넣은 설정."""
    if settings.webhook_urls:
        return settings
    saved = stored(conn, instance)
    if not saved:
        return settings
    return dataclasses.replace(
        settings, webhook_urls=tuple(saved["urls"]), webhook_formats=tuple(saved["formats"])
    )
