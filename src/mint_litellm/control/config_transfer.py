"""환경 사이 설정 이전(내보내기·가져오기).

내보내기에는 비밀과 키가 없다(운영자 토큰 해시, 제어 평면 키 토큰, LiteLLM 키는 담지 않는다).
가져오기는 기존 도메인 함수로 항목을 만들고(각 항목의 사건이 그대로 남는다) 자연 키로 이미 있는
것은 건너뛰므로 되풀이해도 같은 결과이다. 권한을 주는 항목(승인), 대상 환경이 직접 만들어야 하는
항목(서버 등록·운영자 토큰)은 만들지 않고 "할 일"로만 알린다.
"""

import json
from datetime import UTC, datetime
from typing import Any

import psycopg

from mint_litellm.control import (
    allowlists,
    approvals,
    call_approval_rules,
    orgs,
    relations,
    settings_store,
)
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.types.identity import SubjectType
from mint_litellm.types.settings import Mode

FORMAT = "mint-config-1"
SECTIONS = ("orgs", "org_bindings", "relations", "allowlists", "denials",
            "call_approval_rules")


def _rows(conn: psycopg.Connection, iid: str, sql: str) -> list[dict]:
    return [json.loads(json.dumps(r, default=_plain)) for r in fetchall(conn, sql, (iid,))]


def _plain(value: Any) -> Any:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def export_doc(conn: psycopg.Connection, iid: str) -> dict:
    def q(sql: str) -> list[dict]:
        return _rows(conn, iid, sql)

    settings = q("SELECT mode, observable_reasons, observable_policy_ids, default_org_id,"
                 " require_separate_confirm_key FROM mint.settings WHERE instance_id = %s")
    return {
        "format": FORMAT,
        "exported_at": datetime.now(UTC).isoformat(),
        "instance_id": iid,
        "settings": settings[0] if settings else None,
        "orgs": q("SELECT org_id, name FROM mint.orgs WHERE instance_id = %s"
                  " AND status = 'active' ORDER BY org_id"),
        "org_bindings": q("SELECT org_id, subject_type, subject_id FROM mint.org_bindings"
                          " WHERE instance_id = %s ORDER BY 1, 2, 3"),
        "servers": q("SELECT server_id, identity_kind, transport, auth_type, data_grade, status"
                     " FROM mint.servers WHERE instance_id = %s AND status NOT IN"
                     " ('rejected', 'terminating', 'terminated') ORDER BY server_id"),
        "relations": q("SELECT org_id, team_id, purpose, server_id FROM mint.usage_relations"
                       " WHERE instance_id = %s AND status = 'active' ORDER BY 1, 4, 3"),
        "allowlists": q("SELECT org_id, kind, value, note, valid_from, valid_until"
                        " FROM mint.allowlists WHERE instance_id = %s AND status = 'active'"
                        " AND valid_until > now() ORDER BY 1, 2, 3"),
        "denials": q("SELECT org_id, scope_type, scope_id, server_id, tools, reason"
                     " FROM mint.denials WHERE instance_id = %s AND lifted_at IS NULL"
                     " ORDER BY 1, 2, 3"),
        "call_approval_rules": q(
            "SELECT org_id, principal_type, scope_id AS principal_id, server_id, action_class,"
            " tool_pattern, window_minutes, valid_until FROM mint.call_approval_rules"
            " WHERE instance_id = %s AND status = 'active' ORDER BY 1, 4, 5"),
        # 권한을 주는 항목: 가져오지 않고 대상 환경 승인자가 직접 승인한다.
        "approvals": q("SELECT r.org_id, r.team_id, r.purpose, a.server_id, a.class, a.tools,"
                       " a.scope_type, a.scope_id, a.valid_from, a.valid_until, a.conditions"
                       " FROM mint.approvals a JOIN mint.usage_relations r ON r.id = a.relation_id"
                       " WHERE a.instance_id = %s AND a.status = 'active'"
                       " AND a.valid_until > now() ORDER BY 1, 4"),
        # 토큰은 담지 않는다. 대상 환경에서 operator add로 새로 발급한다.
        "operators": q("SELECT name, role, user_id FROM mint.operators WHERE instance_id = %s"
                       " ORDER BY name"),
        "refill": ["운영자 토큰(operator add)", "제어 평면 키(settings control-key)",
                   "서버 등록(server register)과 서버별 사용자 자격"],
    }


def _dt(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None


def _exists(ctx: Context, sql: str, *params: Any) -> bool:
    return fetchone(ctx.conn, sql, (ctx.instance_id, *params)) is not None


def _item(ctx: Context, kind: str, d: dict) -> str:
    """항목 하나를 가져온다. 돌려주는 값: 만들었으면 ``created``, 있었으면 ``present``."""
    if kind == "orgs":
        if _exists(ctx, "SELECT 1 FROM mint.orgs WHERE instance_id = %s AND org_id = %s",
                   d["org_id"]):
            return "present"
        orgs.add(ctx, d["org_id"], d["name"])
    elif kind == "org_bindings":
        row = fetchone(ctx.conn, "SELECT org_id FROM mint.org_bindings WHERE instance_id = %s"
                       " AND subject_type = %s AND subject_id = %s",
                       (ctx.instance_id, d["subject_type"], d["subject_id"]))
        if row:
            if row["org_id"] != d["org_id"]:
                raise ControlError(f"이미 조직 {row['org_id']}에 묶여 있습니다.")
            return "present"
        orgs.bind(ctx, d["org_id"], SubjectType(d["subject_type"]), d["subject_id"])
    elif kind == "relations":
        if _exists(ctx, "SELECT 1 FROM mint.usage_relations WHERE instance_id = %s AND org_id = %s"
                   " AND server_id = %s AND purpose = %s AND team_id IS NOT DISTINCT FROM %s",
                   d["org_id"], d["server_id"], d["purpose"], d["team_id"]):
            return "present"
        relations.add(ctx, d["org_id"], d["server_id"], d["purpose"], d["team_id"])
    elif kind == "allowlists":
        if _exists(ctx, "SELECT 1 FROM mint.allowlists WHERE instance_id = %s AND status = 'active'"
                   " AND org_id IS NOT DISTINCT FROM %s AND kind = %s AND value = %s",
                   d["org_id"], d["kind"], d["value"]):
            return "present"
        allowlists.add(ctx, d["kind"], d["value"], _dt(d["valid_from"]), _dt(d["valid_until"]),
                       d["org_id"], d["note"])
    elif kind == "denials":
        if _exists(ctx, "SELECT 1 FROM mint.denials WHERE instance_id = %s AND lifted_at IS NULL"
                   " AND org_id IS NOT DISTINCT FROM %s AND scope_type = %s AND scope_id = %s"
                   " AND server_id IS NOT DISTINCT FROM %s AND tools IS NOT DISTINCT FROM %s"
                   " AND reason = %s", d["org_id"], d["scope_type"], d["scope_id"],
                   d["server_id"], d["tools"], d["reason"]):
            return "present"
        approvals.create_denial(ctx, scope_type=d["scope_type"], scope_id=d["scope_id"],
                                server_id=d["server_id"], tools=d["tools"], reason=d["reason"],
                                org_id=d["org_id"])
    else:
        if _exists(ctx, "SELECT 1 FROM mint.call_approval_rules WHERE instance_id = %s"
                   " AND status = 'active' AND org_id = %s AND principal_type IS NOT DISTINCT FROM"
                   " %s AND scope_id IS NOT DISTINCT FROM %s AND server_id IS NOT DISTINCT FROM %s"
                   " AND action_class = %s AND tool_pattern IS NOT DISTINCT FROM %s"
                   " AND window_minutes = %s", d["org_id"], d["principal_type"],
                   d["principal_id"], d["server_id"], d["action_class"], d["tool_pattern"],
                   d["window_minutes"]):
            return "present"
        call_approval_rules.add(
            ctx, org_id=d["org_id"], action_class=d["action_class"],
            window_minutes=d["window_minutes"], principal_type=d["principal_type"],
            principal_id=d["principal_id"], server_id=d["server_id"],
            tool_pattern=d["tool_pattern"], valid_until=_dt(d["valid_until"]))
    return "created"


def _settings(ctx: Context, want: dict | None, ceiling: Mode) -> dict:
    if not want:
        return {}
    now = settings_store.load(ctx.conn, ctx.instance_id)
    changed: dict = {}
    if now["mode"] != want["mode"]:
        settings_store.set_mode(ctx, Mode(want["mode"]), ceiling)
        changed["mode"] = [now["mode"], want["mode"]]
    reasons, ids = sorted(want["observable_reasons"]), sorted(want["observable_policy_ids"])
    if sorted(now["observable_reasons"]) != reasons or sorted(now["observable_policy_ids"]) != ids:
        settings_store.set_observable(ctx, reasons, ids)
        changed["observable"] = True
    if want.get("default_org_id") != now["default_org_id"] and want.get("default_org_id"):
        settings_store.set_default_org(ctx, want["default_org_id"])
        changed["default_org_id"] = [now["default_org_id"], want["default_org_id"]]
    return changed


def apply(ctx: Context, doc: dict, ceiling: Mode) -> dict:
    """문서를 가져온다. 항목 하나가 실패해도 계속하고 ``skipped``에 사유와 함께 남긴다."""
    if doc.get("format") != FORMAT:
        raise ControlError("MINT 설정 파일이 아닙니다.")
    result: dict[str, Any] = {s: {"created": 0, "present": 0} for s in SECTIONS}
    skipped: list[dict] = []
    for kind in SECTIONS:
        for d in doc.get(kind, []):
            try:
                with ctx.conn.transaction():
                    result[kind][_item(ctx, kind, d)] += 1
            except (ControlError, psycopg.Error, KeyError, ValueError) as error:
                skipped.append({"section": kind, "item": d, "reason": str(error)})
    try:
        with ctx.conn.transaction():
            result["settings"] = _settings(ctx, doc.get("settings"), ceiling)
    except (ControlError, psycopg.Error, KeyError) as error:
        skipped.append({"section": "settings", "item": doc.get("settings"), "reason": str(error)})
    have = {r["server_id"] for r in fetchall(
        ctx.conn, "SELECT server_id FROM mint.servers WHERE instance_id = %s", (ctx.instance_id,))}
    ops = {r["name"] for r in fetchall(
        ctx.conn, "SELECT name FROM mint.operators WHERE instance_id = %s", (ctx.instance_id,))}
    result["skipped"] = skipped
    result["todo"] = {
        "servers_to_register": [s["server_id"] for s in doc.get("servers", [])
                                if s["server_id"] not in have],
        "operators_to_add": [o for o in doc.get("operators", []) if o["name"] not in ops],
        "approvals_to_grant": len(doc.get("approvals", [])),
    }
    return result


class DryRun(Exception):
    """가져오기를 실제로 적용하지 않고 되돌리기 위한 신호."""
