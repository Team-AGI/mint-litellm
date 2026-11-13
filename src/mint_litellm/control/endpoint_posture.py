"""단말 설치 보고에서 폐기 서버 항목 잔존과 관리되지 않는 설치를 찾아 경보로 남긴다.

설치 보고는 단말의 주장이라 협조적인 단말만 정확하다. 활성 키의 마지막 보고(제거 보고와 해제된
키는 제외)에서 다음을 본다.

- 폐기(종료 중·종료됨)된 로컬 서버가 설치 항목에 남아 있으면 ``endpoint_stale_server``.
- 사용자 수준 설치(관리형이 아님)면 ``endpoint_unmanaged``. 게이트웨이 밖 MCP를 막는 것은 관리형
  설치뿐이라, 사용자 수준 설치는 이 통제가 적용되지 않는다는 표시이다.

- 보고한 실행 중 프로세스나 자동 시작 항목이 가리키는 서버가 승인 상태가 아니거나(폐기·반려·승인
  대기) 레지스트리에 없으면 ``endpoint_stale_process``·``endpoint_stale_autostart``. 제거 보고도
  본다(제거한 뒤에 남은 것을 찾는 점검이다). 서버를 알 수 없는 자동 시작 항목은 비교하지 못한다.

- 마지막 보고가 ``silent_after``(기본 24시간)보다 오래된 관리형·사용자 수준 설치는
  ``endpoint_silent``. 보고하는 묶음은 주기적으로(기본 6시간) 보고하므로 단말이 꺼졌거나 묶음이
  망가졌다는 표시이다. 제거 보고와 보고 전 행은 제외하고, 보고가 다시 오면 닫힌다.
- 키 만료까지 7일 이하인 설치는 ``endpoint_key_expiring``. 보고하는 단말은 만료 14일 전부터 보고가
  키를 늘려 주므로 이 경보는 키가 갱신되지 못하고 있다는 뜻이다. 늘어나거나 키가 해제되면 닫힌다.

- 관리형 설치가 격리 없이(``sandbox`` 값 ``none``) 실행 중인 서버를 보고하면
  ``endpoint_unsandboxed``. Windows(``unsupported``)와 사용자 수준 설치는 격리를 요구하지 않는다.

조건이 사라지면(재설치·제거·키 해제·서버 되살림) 같은 스캔이 경보를 닫는다.
"""

from collections.abc import Iterable, Mapping
from datetime import timedelta
from typing import Any

import psycopg

from mint_litellm.control import alerts
from mint_litellm.control.db.connection import fetchall
from mint_litellm.endpoint.remediation import LIVE
from mint_litellm.types.events import AlertKind

TERMINATED = ("terminating", "terminated")
KINDS = (
    AlertKind.ENDPOINT_STALE_SERVER.value,
    AlertKind.ENDPOINT_UNMANAGED.value,
    AlertKind.ENDPOINT_STALE_PROCESS.value,
    AlertKind.ENDPOINT_STALE_AUTOSTART.value,
    AlertKind.ENDPOINT_UNSANDBOXED.value,
    AlertKind.ENDPOINT_SILENT.value,
    AlertKind.ENDPOINT_KEY_EXPIRING.value,
)
SILENT_AFTER = timedelta(hours=24)
KEY_WARN = timedelta(days=7)


def findings(
    installs: Iterable[Mapping[str, Any]],
    statuses: Mapping[str, str],
    silent_after: timedelta = SILENT_AFTER,
) -> dict[str, tuple[str, str, dict[str, str]]]:
    """설치 보고 행과 서버 상태에서 열려 있어야 할 경보. 경보 키 -> (종류, 심각도, 대상).

    ``now``(데이터베이스 시각)가 없는 행은 시간 점검(침묵·키 만료)을 건너뛴다.
    """
    wanted: dict[str, tuple[str, str, dict[str, str]]] = {}
    for row in installs:
        who = {"user_id": row["user_id"], "key_alias": row["key_alias"]}
        now = row.get("now")
        if now is not None and row["install_mode"] in ("managed", "user"):
            reported = row.get("reported_at")
            if reported is not None and now - reported > silent_after:
                kind = AlertKind.ENDPOINT_SILENT.value
                wanted[f"{kind}:{row['key_alias']}"] = (
                    kind, "medium", {**who, "last_reported_at": reported.isoformat()}
                )
            expires = row.get("expires_at")
            if expires is not None and expires - now <= KEY_WARN:
                kind = AlertKind.ENDPOINT_KEY_EXPIRING.value
                wanted[f"{kind}:{row['key_alias']}"] = (
                    kind, "medium", {**who, "expires_at": expires.isoformat()}
                )
        if row["install_mode"] == "user":
            kind = AlertKind.ENDPOINT_UNMANAGED.value
            wanted[f"{kind}:{row['key_alias']}"] = (kind, "medium", who)
        for name in row["mcp_servers"] or ():
            if statuses.get(name) in TERMINATED:
                kind = AlertKind.ENDPOINT_STALE_SERVER.value
                wanted[f"{kind}:{row['key_alias']}:{name}"] = (
                    kind, "high", {**who, "server_id": name}
                )
        for item in row.get("processes") or ():
            name = item["server"]
            if statuses.get(name) not in LIVE:
                kind = AlertKind.ENDPOINT_STALE_PROCESS.value
                wanted[f"{kind}:{row['key_alias']}:{name}"] = (
                    kind, "high", {**who, "server_id": name, "count": item["count"]}
                )
        if row["install_mode"] == "managed":
            for item in row.get("processes") or ():
                if item.get("sandbox") == "none":
                    kind = AlertKind.ENDPOINT_UNSANDBOXED.value
                    wanted[f"{kind}:{row['key_alias']}:{item['server']}"] = (
                        kind, "high", {**who, "server_id": item["server"]}
                    )
        for item in row.get("autostart") or ():
            name = item.get("server")
            if name is not None and statuses.get(name) not in LIVE:
                kind = AlertKind.ENDPOINT_STALE_AUTOSTART.value
                key = f"{kind}:{row['key_alias']}:{item['kind']}:{item['name']}"
                wanted[key] = (
                    kind, "high",
                    {**who, "server_id": name, "autostart_kind": item["kind"],
                     "autostart_name": item["name"]},
                )  # fmt: skip
    return wanted


def scan(
    conn: psycopg.Connection, instance_id: str, silent_after: timedelta = SILENT_AFTER
) -> int:
    """경보를 맞춘다. 새로 연 경보 수를 돌려준다. 이미 열린 경보는 건드리지 않는다."""
    installs = fetchall(
        conn,
        "SELECT user_id, key_alias, install_mode, mcp_servers, processes, autostart,"
        " reported_at, expires_at, clock_timestamp() AS now"
        " FROM mint.endpoint_installs WHERE instance_id = %s AND revoked_at IS NULL"
        " AND install_mode IN ('managed', 'user', 'removed')",
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
    wanted = findings(installs, statuses, silent_after)
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
