"""``doctor``와 ``status``의 「할 일」: 비어 있거나 기다리는 일과 다음에 실행할 명령."""

from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.types.events import EventKind

SETUP_MISSING = {"what": "데이터베이스가 준비되지 않았습니다", "next": "mint-litellm init"}


def _short(identifier: Any) -> str:
    """운영자가 입력하기 쉽도록 식별자의 끝 8자리를 쓴다(명령이 끝자리만으로도 찾는다)."""
    return str(identifier)[-8:]


def _count(conn: psycopg.Connection, sql: str, instance: str) -> int:
    row = fetchone(conn, sql, (instance,))
    return int(next(iter(row.values()))) if row else 0


def collect(conn: psycopg.Connection, instance: str) -> list[dict[str, str]]:
    """처리할 일을 ``{"what": 상황, "next": 다음 명령}`` 목록으로 돌려준다. 비어 있으면 없다."""
    try:
        return _collect(conn, instance)
    except (psycopg.errors.UndefinedTable, psycopg.errors.InvalidSchemaName):
        conn.rollback()
        return [dict(SETUP_MISSING)]


def _collect(conn: psycopg.Connection, instance: str) -> list[dict[str, str]]:
    todo: list[dict[str, str]] = []

    def add(what: str, command: str) -> None:
        todo.append({"what": what, "next": command})

    if not _count(conn, "SELECT count(*) FROM mint.operators WHERE instance_id = %s", instance):
        add(
            "운영자가 아직 없습니다",
            "mint-litellm operator bootstrap --name <이름> --user-id <LiteLLM 사용자>",
        )
    settings = fetchone(
        conn,
        "SELECT control_key_token FROM mint.settings WHERE instance_id = %s",
        (instance,),
    )
    if settings is None:
        add("배치 설정이 아직 없습니다", "mint-litellm init")
    elif settings["control_key_token"] is None:
        add(
            "제어 평면 키가 저장되지 않아 서버 승인 때 도구를 고정하지 못합니다",
            "MINT_LITELLM_KEY를 설정한 뒤 mint-litellm settings control-key",
        )
    if not _count(
        conn,
        "SELECT count(*) FROM mint.policy_versions WHERE instance_id = %s AND status = 'active'",
        instance,
    ):
        add(
            "적용된 정책 판본이 없어 모든 호출이 차단됩니다", "mint-litellm policy activate initial"
        )
    if not fetchone(
        conn,
        "SELECT 1 AS x FROM mint.events WHERE instance_id = %s AND kind = %s LIMIT 1",
        (instance, EventKind.ENFORCEMENT_VERIFIED.value),
    ):
        add("집행 점검을 통과한 워커가 아직 없습니다", "mint-litellm check")
    if not _count(conn, "SELECT count(*) FROM mint.servers WHERE instance_id = %s", instance):
        add("등록된 서버가 없습니다", "mint-litellm server register <서버 식별자>")

    waiting = _count(
        conn,
        "SELECT count(*) FROM mint.servers WHERE instance_id = %s AND status = 'awaiting_approval'",
        instance,
    )
    if waiting:
        add(f"승인을 기다리는 서버 {waiting}건", "mint-litellm approve --help")
    intake = fetchone(
        conn,
        "SELECT id, (SELECT count(*) FROM mint.intakes WHERE instance_id = %s"
        " AND status = 'passed') AS n FROM mint.intakes WHERE instance_id = %s"
        " AND status = 'passed' ORDER BY created_at LIMIT 1",
        (instance, instance),
    )
    if intake:
        add(
            f"검사를 통과해 결정을 기다리는 신청 {intake['n']}건",
            f"mint-litellm intake show {_short(intake['id'])}",
        )
    call = fetchone(
        conn,
        "SELECT id, (SELECT count(*) FROM mint.call_approvals WHERE instance_id = %s"
        " AND status = 'pending' AND expires_at > now()) AS n FROM mint.call_approvals"
        " WHERE instance_id = %s AND status = 'pending' AND expires_at > now()"
        " ORDER BY expires_at LIMIT 1",
        (instance, instance),
    )
    if call:
        add(
            f"응답을 기다리는 호출별 승인 {call['n']}건",
            f"mint-litellm call-approval approve {_short(call['id'])}",
        )
    for row in fetchall(
        conn,
        "SELECT server_id FROM mint.servers WHERE instance_id = %s AND deployment_drift"
        " ORDER BY server_id LIMIT 3",
        (instance,),
    ):
        server = row["server_id"]
        add(f"재승인이 필요한 서버 {server}", f"mint-litellm contract diff {server}")
    alerts = _count(
        conn,
        "SELECT count(*) FROM mint.alerts WHERE instance_id = %s AND status = 'open'",
        instance,
    )
    if alerts:
        add(f"열린 경보 {alerts}건", "mint-litellm alert list --status open")
    for row in fetchall(
        conn,
        "SELECT kind, last_error_code, count(*) AS n FROM mint.jobs WHERE instance_id = %s"
        " AND status = 'failed' GROUP BY kind, last_error_code ORDER BY n DESC LIMIT 3",
        (instance,),
    ):
        add(
            f"실패한 작업 {row['kind']} {row['n']}건(오류 코드 {row['last_error_code'] or '없음'})",
            "mint-litellm alert list --status open",
        )
    held = _count(
        conn,
        "SELECT count(*) FROM mint.litellm_grants WHERE instance_id = %s AND held",
        instance,
    )
    if held:
        add(f"보류된 권한 동기화 {held}건", "mint-litellm sync status --held")
    return todo


def render(todo: list[dict[str, str]]) -> str:
    if not todo:
        return "할 일: 없음"
    lines = [f"할 일 {len(todo)}건"]
    for number, item in enumerate(todo, start=1):
        lines.append(f"  {number}. {item['what']}")
        lines.append(f"     다음: {item['next']}")
    return "\n".join(lines)
