"""주소·목적 폼을 기존 신청 검사 경로에 연결한다."""

import json
from hashlib import sha256

from mint_litellm.console.core import Actor
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import intakes, staff_intakes
from mint_litellm.control.services.base import require_role, transact
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7


def submit(actor: Actor, address: str, purpose: str) -> tuple[str, bool]:
    require_role(actor.ctx, "intake create")
    if not address.strip():
        raise ControlError("서버 주소를 입력하세요.")
    payload, _ = staff_intakes.validate(
        {"url": address, "purpose": purpose}, actor.config.stage2.intake_allowed_ports,
    )
    client = actor.litellm()
    entries = client.list_servers()
    entry = next((e for e in entries if e.get("url") == payload["url"]), None)
    sid = (entry.get("server_id") or entry.get("id")) if entry else payload["server_id"]
    ctx = actor.ctx
    user = ctx.operator.user_id
    if not user:
        raise ControlError("로그인한 사용자를 확인할 수 없습니다.")
    with transact(ctx):
        ctx.conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         (f"{actor.instance}:staff-server:{sid}",))
        known = fetchone(
            actor.conn,
            "SELECT server_id FROM mint.deployment_contracts WHERE instance_id = %s"
            " AND url = %s ORDER BY id DESC LIMIT 1", (actor.instance, payload["url"]),
        )
        if known:
            sid = known["server_id"]
        elif not entry and fetchone(
            actor.conn, "SELECT 1 FROM mint.servers WHERE instance_id = %s AND server_id = %s",
            (actor.instance, sid),
        ):
            sid = sid[:115] + "-" + sha256(payload["url"].encode()).hexdigest()[:12]
        prior = fetchone(
            actor.conn,
            "SELECT id FROM mint.intakes WHERE instance_id = %s AND server_id = %s"
            " AND (status <> 'decided' OR decision IN ('approved', 'exception'))"
            " ORDER BY created_at DESC LIMIT 1", (actor.instance, sid),
        )
        if prior:
            return str(prior["id"]), True
        fields = {k: v for k, v in payload.items() if k not in ("server_id", "url", "transport")}
        if entry:
            return intakes.create(ctx, client, sid, url=payload["url"], owner_user_id=user,
                                  **fields), False
        org = intakes._derive_org(ctx, None, user)
        if org is None:
            raise ControlError("기본 조직을 설정하도록 담당자에게 요청하세요.")
        intakes._ensure_server(ctx, sid, payload["url"], payload["transport"], "none", None,
                               ctx.operator.name)
        intakes._deployment_candidate(ctx, sid, payload["url"], payload["transport"], "none",
                                      None, None, None, None, proposed_by=ctx.operator.name)
        identifier = new_uuid7()
        row = fetchone(
            actor.conn,
            "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, purpose,"
            " data_grade, allowed_resources, provider, owner_user_id, readiness, data_return_terms,"
            " requested_by, staff_registry_required) VALUES"
            " (%s, %s, %s, %s, 'operator', %s, %s, %s::jsonb, %s, %s, %s::jsonb, %s, %s, true)"
            " RETURNING *",
            (identifier, actor.instance, org, sid, payload["purpose"], payload["data_grade"],
             json.dumps(payload["allowed_resources"]), payload["provider"], user,
             json.dumps(payload["readiness"]), payload["data_return_terms"], user),
        )
        ctx.emit(EventKind.INTAKE_RECEIVED, identifier, row["state_version"],
                 {"intake_id": str(identifier), "server_id": sid, "source": "operator",
                  "requested_by": user})
        intakes._enqueue_run(ctx, row, mode="staff")
        return str(identifier), False
