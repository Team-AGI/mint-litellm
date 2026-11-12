"""단말 설치 보고에서 폐기 서버 항목 잔존과 관리되지 않는 설치를 찾아 경보로 남긴다.

설치 보고는 단말의 주장이라 협조적인 단말만 정확하다. 활성 키의 마지막 보고(제거 보고와 해제된
키는 제외)에서 다음을 본다.

- 폐기(종료 중·종료됨)된 로컬 서버가 설치 항목에 남아 있으면 ``endpoint_stale_server``.
- 사용자 수준 설치(관리형이 아님)면 ``endpoint_unmanaged``. 게이트웨이 밖 MCP를 막는 것은 관리형
  설치뿐이라, 사용자 수준 설치는 이 통제가 적용되지 않는다는 표시이다.

조건이 사라지면(재설치·제거·키 해제·서버 되살림) 같은 스캔이 경보를 닫는다.
"""

from collections.abc import Iterable, Mapping
from typing import Any

import psycopg

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall
from mint_litellm.types.events import AlertKind

TERMINATED = ("terminating", "terminated")
KINDS = (AlertKind.ENDPOINT_STALE_SERVER.value, AlertKind.ENDPOINT_UNMANAGED.value)


def findings(
    installs: Iterable[Mapping[str, Any]], statuses: Mapping[str, str]
) -> dict[str, tuple[str, str, dict[str, str]]]:
    """설치 보고 행과 서버 상태에서 열려 있어야 할 경보. 경보 키 -> (종류, 심각도, 대상)."""
    wanted: dict[str, tuple[str, str, dict[str, str]]] = {}
    for row in installs:
        who = {"user_id": row["user_id"], "key_alias": row["key_alias"]}
        if row["install_mode"] == "user":
            kind = AlertKind.ENDPOINT_UNMANAGED.value
            wanted[f"{kind}:{row['key_alias']}"] = (kind, "medium", who)
        for name in row["mcp_servers"] or ():
            if statuses.get(name) in TERMINATED:
                kind = AlertKind.ENDPOINT_STALE_SERVER.value
                wanted[f"{kind}:{row['key_alias']}:{name}"] = (
                    kind, "high", {**who, "server_id": name}
                )
    return wanted


def scan(conn: psycopg.Connection, instance_id: str) -> int:
    """경보를 맞춘다. 새로 연 경보 수를 돌려준다. 이미 열린 경보는 건드리지 않는다."""
    installs = fetchall(
        conn,
        "SELECT user_id, key_alias, install_mode, mcp_servers FROM mint.endpoint_installs"
        " WHERE instance_id = %s AND revoked_at IS NULL AND install_mode IN ('managed', 'user')",
        (instance_id,),
    )
    statuses = {
        r["server_id"]: r["status"]
        for r in fetchall(
            conn,
            "SELECT server_id, status FROM mint.servers"
            " WHERE instance_id = %s AND identity_kind = 'stdio'",
            (instance_id,),
        )
    }
    wanted = findings(installs, statuses)
    open_keys = {
        r["dedup_key"]
        for r in fetchall(
            conn,
            "SELECT dedup_key FROM mint.alerts"
            " WHERE instance_id = %s AND kind = ANY(%s) AND status <> 'resolved'",
            (instance_id, list(KINDS)),
        )
    }
    opened = 0
    for key, (kind, severity, subject) in wanted.items():
        if key not in open_keys:
            opened += alerts.raise_alert(
                conn, instance_id, kind=kind, severity=severity, dedup_key=key, subject=subject
            )
    for key in open_keys - wanted.keys():
        alerts.resolve(conn, instance_id, key)
    return opened
