"""업그레이드 뒤에 사람이 정해야 하는 일. 데이터베이스만 읽으며 승인하거나 바꾸지 않는다."""

from datetime import datetime, timedelta
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.services import evidence
from mint_litellm.types.reuse_policy import FORWARDING_AUTH

_ACCEPTED = frozenset({"valid", "not_applicable", "expiring"})
_LIVE = "('approved', 'awaiting_approval', 'suspended')"
_KIT_SCREEN = "콘솔 직원 화면 「단말 설치」에서 묶음을 다시 내려받아 설치"


def _list(names: list[str]) -> str:
    shown = ", ".join(names[:5])
    return shown + (f" 외 {len(names) - 5}건" if len(names) > 5 else "")


def collect(
    conn: psycopg.Connection,
    instance: str,
    *,
    now: datetime,
    recert_period: timedelta,
    current_kit: str,
) -> list[dict[str, str]]:
    """``{"what": 상황, "next": 해결하는 화면이나 명령}`` 목록. 비어 있으면 남은 일이 없다."""
    items: list[dict[str, str]] = []

    def add(what: str, command: str) -> None:
        items.append({"what": what, "next": command})

    scopes = [r["server_id"] for r in fetchall(
        conn,
        "SELECT s.server_id FROM mint.servers s JOIN mint.deployment_contracts c"
        " ON c.instance_id = s.instance_id AND c.server_id = s.server_id AND c.status = 'approved'"
        " WHERE s.instance_id = %s AND s.deployment_drift AND c.oauth_scopes = '{}'"
        " AND 'oauth_scopes' = ANY(s.deployment_drift_fields) ORDER BY s.server_id",
        (instance,),
    )]
    if scopes:
        add(
            "서버 정의에 OAuth 범위가 있는데 승인된 계약은 범위가 비어 있어 호출이 막힌 서버 "
            f"{_list(scopes)}",
            f"mint-litellm contract diff {scopes[0]}로 확인하고, intake recheck 뒤 "
            "contract reapprove로 한 번 다시 승인",
        )

    forwarding = [r["server_id"] for r in fetchall(
        conn,
        "SELECT DISTINCT a.server_id FROM mint.approvals a JOIN mint.servers s"
        " ON s.instance_id = a.instance_id AND s.server_id = a.server_id"
        " WHERE a.instance_id = %s AND a.status = 'active' AND a.valid_until > %s"
        " AND s.auth_type = ANY(%s) AND s.status IN " + _LIVE
        + " AND COALESCE(a.conditions->>'allow_token_forward', '') <> 'true'"
        " ORDER BY a.server_id",
        (instance, now, sorted(FORWARDING_AUTH)),
    )]
    if forwarding:
        add(
            "호출자 토큰을 업스트림에 전달하는데 승인에 allow_token_forward가 없어 호출이 막힌 "
            f"서버 {_list(forwarding)}",
            "mint-litellm approve ... --allow-token-forward로 승인을 다시 만든다",
        )

    recert = fetchone(
        conn,
        "SELECT count(*) FILTER (WHERE recert_held_at IS NOT NULL) AS held,"
        " count(*) FILTER (WHERE recert_held_at IS NULL"
        "  AND COALESCE(recert_confirmed_at, valid_from) + %s <= %s) AS due"
        " FROM mint.approvals WHERE instance_id = %s AND status = 'active' AND valid_until > %s",
        (recert_period, now, instance, now),
    ) or {}
    if recert.get("held"):
        add(f"재확인이 늦어 보류되어 호출이 막힌 승인 {recert['held']}건",
            "콘솔 승인 내역에서 「재확인」")
    if recert.get("due"):
        add(f"재확인 기한이 된 승인 {recert['due']}건", "콘솔 승인 내역에서 「재확인」")

    loose = []
    for row in fetchall(
        conn,
        "SELECT DISTINCT s.server_id FROM mint.servers s JOIN mint.server_packages p"
        " ON p.instance_id = s.instance_id AND p.server_id = s.server_id"
        " AND p.exec_contract_sha256 = s.exec_contract_sha256"
        " WHERE s.instance_id = %s AND s.status IN " + _LIVE
        + " AND NOT p.pinned AND p.ecosystem <> 'executable' ORDER BY s.server_id",
        (instance,),
    ):
        proof = evidence.current(conn, instance, "server", row["server_id"])
        if evidence.state_of(proof.get("unpinned_acceptance"), now) not in _ACCEPTED:
            loose.append(row["server_id"])
    if loose:
        add(
            "버전이 고정되지 않은 패키지를 쓰는데 사용 승인 증빙이 없는 서버 "
            f"{_list(loose)}",
            f"mint-litellm evidence attach unpinned_acceptance {loose[0]} --summary <사유>",
        )

    kits = fetchone(
        conn,
        "SELECT count(*) FILTER (WHERE reported_at IS NULL) AS silent,"
        " count(*) FILTER (WHERE reported_at IS NOT NULL AND kit_version IS DISTINCT FROM %s)"
        " AS old FROM mint.endpoint_installs WHERE instance_id = %s AND revoked_at IS NULL"
        " AND (expires_at IS NULL OR expires_at > %s)",
        (current_kit, instance, now),
    ) or {}
    if kits.get("silent"):
        add(f"주기 보고를 한 적 없는 단말 설치 묶음 {kits['silent']}건", _KIT_SCREEN)
    if kits.get("old"):
        add(f"이전 판본의 단말 설치 묶음 {kits['old']}건", _KIT_SCREEN)
    return items


def render(items: list[dict[str, Any]]) -> str:
    if not items:
        return "업그레이드 뒤 사람이 정할 일: 없음"
    lines = [f"업그레이드 뒤 사람이 정할 일 {len(items)}건"]
    for number, item in enumerate(items, start=1):
        lines += [f"  {number}. {item['what']}", f"     해결: {item['next']}"]
    return "\n".join(lines)
