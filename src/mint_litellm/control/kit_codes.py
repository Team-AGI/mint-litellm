"""단말 한 줄 설치 명령의 1회용 코드와 설치 스크립트.

코드는 해당 직원에 묶이고 짧게 살며 한 번만 쓰인다(해시만 저장). 코드를 쓰면 그 자리에서 설치
묶음 키가 새로 발급되고, 스크립트는 묶음을 담아 PC에서 풀어 설치한다. 이미 설치된 PC에서는 같은
설치기가 키와 설정만 새 것으로 바꾼다.
"""

import base64
import hashlib
import secrets
from datetime import timedelta
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchone

MINUTES = 15
NAMES = ("install.sh", "install.ps1", "kit.tar.gz", "kit.zip")


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def create(conn: psycopg.Connection, instance_id: str, user_id: str, team_id: str | None) -> str:
    code = secrets.token_urlsafe(24)
    conn.execute(
        "INSERT INTO mint.kit_codes (code_hash, instance_id, user_id, team_id, expires_at)"
        " VALUES (%s, %s, %s, %s, now() + %s)",
        (_hash(code), instance_id, user_id, team_id, timedelta(minutes=MINUTES)),
    )
    return code


def redeem(conn: psycopg.Connection, instance_id: str, code: str) -> dict[str, Any] | None:
    """코드를 한 번 쓴다. 없거나 쓰였거나 만료되었으면 None."""
    return fetchone(
        conn,
        "UPDATE mint.kit_codes SET used_at = now() WHERE code_hash = %s AND instance_id = %s"
        " AND used_at IS NULL AND expires_at > now() RETURNING user_id, team_id",
        (_hash(code), instance_id),
    )


SH = """#!/bin/sh
# MINT 단말 설치: 묶음을 풀어 설치합니다. 이미 설치된 PC는 키만 새 것으로 바뀝니다.
set -e
command -v python3 >/dev/null || { echo "Python 3.9 이상이 필요합니다." >&2; exit 2; }
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
python3 -m base64 -d <<'MINT_KIT' | tar xz -C "$d"
{payload}
MINT_KIT
in=/dev/null; [ -r /dev/tty ] && in=/dev/tty
bash "$d/mint-kit/install.sh" <"$in"
"""

PS1 = """# MINT 단말 설치: 묶음을 풀어 설치합니다. 이미 설치된 PC는 키만 새 것으로 바뀝니다.
$ErrorActionPreference = 'Stop'
$d = Join-Path $env:TEMP ('mint-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $d | Out-Null
try {{
    $zip = Join-Path $d 'kit.zip'
    [IO.File]::WriteAllBytes($zip, [Convert]::FromBase64String('{payload}'))
    Expand-Archive -Path $zip -DestinationPath $d
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $d 'mint-kit/install.ps1')
}} finally {{
    Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
}}
"""


def refusal(name: str, message: str, status: int = 200):
    """설치 스크립트를 못 줄 때의 응답.

    스크립트면 사람이 읽을 한 줄을 출력하고 멈추는 본문을 돌려준다(``curl -f``가 오류 본문을
    숨기기 때문). 묶음 파일이면 상태 코드와 문구를 그대로 낸다.
    """
    from fastapi.responses import PlainTextResponse

    safe = " ".join(message.replace("'", "").replace('"', "").replace("`", "").split())
    held = {"Cache-Control": "no-store"}
    if name == "install.sh":
        return PlainTextResponse(f"echo '{safe}' >&2\nexit 1\n", headers=held)
    if name == "install.ps1":
        return PlainTextResponse(f"Write-Host '{safe}'\n", headers=held)
    return PlainTextResponse(f"{safe}\n", status_code=status)


def script(name: str, kit: bytes) -> str:
    """``name``에 맞는 설치 스크립트(묶음을 base64로 담는다). ``kit.tar.gz``는 묶음 그대로."""
    payload = base64.b64encode(kit).decode()
    if name == "install.ps1":
        return PS1.format(payload=payload)
    if name == "install.sh":
        wrapped = "\n".join(payload[i : i + 76] for i in range(0, len(payload), 76))
        return SH.replace("{payload}", wrapped)
    return payload
