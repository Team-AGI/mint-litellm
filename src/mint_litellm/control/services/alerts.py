"""경보 조회·확인·해결 서비스와 웹훅 시험 발송.

경보 생성과 전송 등록은 ``control/alerts.py``와 작업이 한다. 여기서는 운영자가 처리하는 쪽만 다룬다.
"""

import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from mint_litellm.control import alerts, webhook
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import conflict, forbidden, not_found
from mint_litellm.control.services.base import service
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.types.events import EventKind

LIST_COLUMNS = (
    "id, kind, severity, status, dedup_key, subject, first_at, last_at, count,"
    " acknowledged_by, resolved_at"
)


def _alert_id(alert_id: str) -> str:
    try:
        return str(uuid.UUID(alert_id))
    except ValueError:
        raise not_found(f"경보 {alert_id}이(가) 없습니다.") from None


def _locked(ctx: Context, alert_id: str) -> dict[str, Any]:
    row = fetchone(
        ctx.conn,
        "SELECT id, status, kind FROM mint.alerts WHERE instance_id = %s AND id = %s FOR UPDATE",
        (ctx.instance_id, alert_id),
    )
    if row is None:
        raise not_found(f"경보 {alert_id}이(가) 없습니다.")
    return row


def list_alerts(ctx: Context, *, status: str | None = None, limit: int = 100) -> list[dict]:
    clauses, params = ["instance_id = %s"], [ctx.instance_id]
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    params.append(limit)
    return fetchall(
        ctx.conn,
        f"SELECT {LIST_COLUMNS} FROM mint.alerts WHERE {' AND '.join(clauses)}"
        " ORDER BY last_at DESC, id LIMIT %s",
        tuple(params),
    )


@service("alert ack")
def acknowledge(ctx: Context, alert_id: str) -> None:
    alert_id = _alert_id(alert_id)
    row = _locked(ctx, alert_id)
    if row["status"] != "open":
        raise conflict(f"열린 경보만 확인할 수 있습니다(현재 {row['status']}).")
    ctx.conn.execute(
        "UPDATE mint.alerts SET status = 'acknowledged', acknowledged_by = %s"
        " WHERE instance_id = %s AND id = %s",
        (ctx.operator.name, ctx.instance_id, alert_id),
    )
    # 경보에는 상태 버전 열이 없다. 열림 0, 확인 1, 해결 2의 순번을 경보마다 한 번씩 쓴다
    ctx.emit(EventKind.ALERT_ACKNOWLEDGED, alert_id, 1, {"kind": row["kind"]})


@service("alert resolve")
def resolve(ctx: Context, alert_id: str) -> None:
    alert_id = _alert_id(alert_id)
    row = _locked(ctx, alert_id)
    if row["status"] == "resolved":
        raise conflict("이미 해결된 경보입니다.")
    ctx.conn.execute(
        "UPDATE mint.alerts SET status = 'resolved', resolved_at = now()"
        " WHERE instance_id = %s AND id = %s",
        (ctx.instance_id, alert_id),
    )
    ctx.emit(EventKind.ALERT_RESOLVED, alert_id, 2, {"kind": row["kind"]})


def send_test(ctx: Context, settings: Stage2Settings) -> list[dict[str, Any]]:
    """설정된 웹훅 주소마다 시험 본문을 한 번 보낸다. 경보도 전송 행도 남기지 않는다(관리자만)."""
    if ctx.operator.role != "admin":
        raise forbidden("시험 발송은 admin 역할만 할 수 있습니다.", exit_code=4)
    now = datetime.now(UTC)
    row = {"kind": "test", "severity": "low", "subject": {}, "count": 1,
           "first_at": now, "last_at": now}
    hosts = [urlsplit(u).hostname for u in settings.webhook_urls]
    results = []
    with webhook.client() as http:
        for url in settings.webhook_urls:
            webhook.check_url(url, hosts)
            body = webhook.build_body(row, settings.console_url, settings.webhook_format(url))
            sent, attempts = webhook.post(
                http, url, settings.webhook_hmac_key, str(uuid.uuid4()), body
            )
            results.append(
                {"channel": alerts.channel_for(url), "sent": sent, "attempts": attempts}
            )
    return results
