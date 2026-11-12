"""승인, 거부, 철회, 호출별 승인."""

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mint_litellm.control import operators, sync_state
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, forbidden, not_found, separation_of_duties
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.services import base
from mint_litellm.types.canonical import credential_scope
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

SCOPE_TYPES = ("key", "user", "team", "org")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIME = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")


# ---------------------------------------------------------------------------
# 승인 조건
# ---------------------------------------------------------------------------


def parse_business_hours(text: str) -> dict:
    """``시간대,요일,시작,끝`` 형식. 요일은 1(월)~7(일)이며 ``1-5`` 또는 ``1/3/5``로 쓴다."""
    parts = [p.strip() for p in text.split(",")]
    if len(parts) != 4:
        raise ControlError(
            "--business-hours는 시간대,요일,시작,끝 형식입니다(예: Asia/Seoul,1-5,09:00,18:00)."
        )
    tz, days_text, start, end = parts
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ControlError(f"알 수 없는 시간대입니다: {tz}") from None
    days: list[int] = []
    for chunk in days_text.split("/"):
        low, _, high = chunk.partition("-")
        try:
            days.extend(range(int(low), int(high or low) + 1))
        except ValueError:
            raise ControlError(f"요일 형식이 올바르지 않습니다: {days_text}") from None
    if not days or any(d not in range(1, 8) for d in days):
        raise ControlError("요일은 1(월)부터 7(일) 사이여야 합니다.")
    if not _TIME.fullmatch(start) or not _TIME.fullmatch(end) or start >= end:
        raise ControlError("시작·끝은 HH:MM 형식이며 시작이 끝보다 빨라야 합니다.")
    return {"tz": tz, "days": sorted(set(days)), "start": start, "end": end}


def build_conditions(
    *,
    high_risk_tools: list[str] | None,
    business_hours_only: bool,
    business_hours: str | None,
    require_consent: str | None,
    allowed_hosts: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    allowed_arg_keys: list[str] | None = None,
    confirm_tools: list[str] | None = None,
    confirm_purpose: str | None = None,
    confirm_fields: list[str] | None = None,
) -> dict:
    """정책이 읽는 승인 조건. 지정하지 않은 조건은 키를 넣지 않는다."""
    conditions: dict = {}
    if confirm_tools:
        purpose = (confirm_purpose or "").strip()
        if not 1 <= len(purpose) <= 128:
            raise ControlError(
                "--confirm-tool에는 1자 이상 128자 이하의 --confirm-purpose가 필요합니다."
            )
        fields = sorted({f.strip() for f in confirm_fields or []})
        if not all(fields):
            raise ControlError("--confirm-field 값이 비어 있습니다.")
        conditions["require_user_confirmation"] = {
            "tools": sorted({t.strip() for t in confirm_tools}),
            "purpose": purpose,
            "display_fields": fields,
        }
    elif confirm_purpose is not None or confirm_fields is not None:
        raise ControlError("--confirm-purpose·--confirm-field는 --confirm-tool과 함께 써야 합니다.")
    if high_risk_tools:
        conditions["high_risk_tools"] = sorted(set(high_risk_tools))
    if business_hours and not business_hours_only:
        raise ControlError("--business-hours는 --business-hours-only와 함께 써야 합니다.")
    if business_hours_only:
        conditions["business_hours_only"] = True
        if business_hours:
            conditions["business_hours"] = parse_business_hours(business_hours)
    if require_consent is not None:
        if not 1 <= len(require_consent.strip()) <= 128:
            raise ControlError("--require-consent의 목적은 1자 이상 128자 이하여야 합니다.")
        conditions["require_consent"] = require_consent.strip()
    for name, values, check in (
        ("allowed_hosts", allowed_hosts, _host_ok),
        ("allowed_paths", allowed_paths, _path_ok),
        ("allowed_arg_keys", allowed_arg_keys, bool),
    ):
        if values:
            cleaned = {v.strip() for v in values}
            for value in cleaned:
                if not check(value):
                    flag = name.replace("_", "-")[:-1]
                    raise ControlError(f"--{flag} 값이 올바르지 않습니다: {value[:64]!r}")
            conditions[name] = sorted(cleaned)
    return conditions


def _host_ok(value: str) -> bool:
    """점이 하나 이상인 호스트 이름(앞의 ``*.`` 허용) 또는 리터럴 주소."""
    value = value.lower().removeprefix("*.").strip("[]")
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    labels = value.split(".")
    return len(labels) >= 2 and all(
        label and not label.startswith("-") and all(c.isalnum() or c in "-_" for c in label)
        for label in labels
    )


def _path_ok(value: str) -> bool:
    flat = value.replace("\\", "/")
    absolute = flat.startswith("/") or (len(flat) > 2 and flat[1] == ":" and flat[2] == "/")
    return absolute and ".." not in flat.split("/")


# ---------------------------------------------------------------------------
# LiteLLM 권한 확인과 조직 범위
# ---------------------------------------------------------------------------


def _derive_org(ctx: Context, team_id: str | None, user_id: str | None) -> str | None:
    """팀 바인딩(팀이 있으면 이것만), 사용자 바인딩, 기본 조직 순으로 조직을 유도한다.

    닫힌 조직은 없는 것과 같다.
    """
    org_id: str | None
    subject = ("team", team_id) if team_id else ("user", user_id) if user_id else None
    row = None
    if subject:
        row = fetchone(
            ctx.conn,
            "SELECT org_id FROM mint.org_bindings WHERE instance_id = %s AND subject_type = %s"
            " AND subject_id = %s",
            (ctx.instance_id, *subject),
        )
    if row:
        org_id = row["org_id"]
    else:
        default = fetchone(
            ctx.conn,
            "SELECT default_org_id FROM mint.settings WHERE instance_id = %s",
            (ctx.instance_id,),
        )
        org_id = default["default_org_id"] if default else None
    if org_id is None:
        return None
    org = fetchone(
        ctx.conn,
        "SELECT status FROM mint.orgs WHERE instance_id = %s AND org_id = %s",
        (ctx.instance_id, org_id),
    )
    return org_id if org and org["status"] == "active" else None


def _require_scope_in_relation(
    ctx: Context, relation: dict, scope_type: str, scope_id: str, target: dict
) -> None:
    team = relation["team_id"]
    org = relation["org_id"]
    if scope_type == "team":
        if team:
            if scope_id != team:
                raise ControlError("승인 범위의 팀이 이용 관계의 팀과 다릅니다.")
        elif not fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.org_bindings WHERE instance_id = %s AND subject_type = 'team'"
            " AND subject_id = %s AND org_id = %s",
            (ctx.instance_id, scope_id, org),
        ):
            raise ControlError(f"팀 {scope_id}이(가) 조직 {org}에 묶여 있지 않습니다(org bind).")
    elif scope_type == "key":
        if team:
            if target.get("team_id") != team:
                raise ControlError("키가 이용 관계의 팀에 속하지 않습니다.")
        elif _derive_org(ctx, target.get("team_id"), target.get("user_id")) != org:
            raise ControlError(f"키의 조직 유도 결과가 이용 관계의 조직 {org}과 다릅니다.")
    else:
        if team:
            teams = target.get("teams") or []
            ids = {t.get("team_id") if isinstance(t, dict) else t for t in teams}
            if team not in ids:
                raise ControlError("사용자가 이용 관계의 팀에 속하지 않습니다.")
        elif _derive_org(ctx, None, scope_id) != org:
            raise ControlError(f"사용자의 조직 유도 결과가 이용 관계의 조직 {org}과 다릅니다.")


def check_scope_and_permission(
    ctx: Context, litellm: LiteLLMAdmin, relation: dict, scope_type: str, scope_id: str
) -> None:
    """승인 범위가 이용 관계에 속하고, 그 대상에 LiteLLM 서버 권한이 있는지 읽어 확인한다.

    ``object_permission.mcp_servers`` 항목은 서버 식별자 형식이어야 하고, 대상에 이 서버의 권한
    (직접 부여 또는 서버가 속한 접근 그룹)이 있어야 승인할 수 있다. 별칭이나 이름은 새 서버가
    같은 문자열을 재사용할 때 권한이 넘어가므로 거부한다.
    """
    server_id = relation["server_id"]
    if scope_type == "key":
        target, label = litellm.get_key(scope_id), "키"
    elif scope_type == "team":
        target, label = litellm.get_team(scope_id), "팀"
    else:
        target, label = litellm.get_user(scope_id), "사용자"
    if target is None:
        raise ControlError(f"LiteLLM에서 {label} {scope_id}을(를) 찾을 수 없습니다.")
    _require_scope_in_relation(ctx, relation, scope_type, scope_id, target)
    if scope_type == "key" and target.get("team_id"):
        # 팀 소속 키의 서버 권한은 팀이 허용한 서버의 부분집합이어야 한다(LiteLLM이 아니면 403).
        if not fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.approvals WHERE instance_id = %s AND scope_type = 'team'"
            " AND scope_id = %s AND server_id = %s AND status IN ('active', 'pending')",
            (ctx.instance_id, target["team_id"], server_id),
        ):
            raise ControlError(
                f"키 {scope_id}가 속한 팀 {target['team_id']}에 서버 {server_id}의 승인이 없어 "
                "승인할 수 없습니다. LiteLLM은 팀이 허용하지 않은 서버를 "
                "팀 소속 키에 주지 않으므로 팀 범위 승인(--scope team)을 먼저 하십시오."
            )
    registry = {s["server_id"]: s for s in litellm.list_servers()}
    permission = target.get("object_permission") or {}
    granted = list(permission.get("mcp_servers") or [])
    bad = [entry for entry in granted if entry not in registry]
    if bad:
        raise ControlError(
            f"{label} {scope_id}의 object_permission.mcp_servers에 서버 식별자가 아닌 항목이 "
            f"있습니다: {', '.join(bad)}. 별칭이나 이름이 아니라 server_id로 바꾼 뒤 다시 "
            "시도하십시오."
        )
    server_groups = set((registry.get(server_id) or {}).get("mcp_access_groups") or [])
    shared_group = server_groups & set(permission.get("mcp_access_groups") or [])
    if server_id not in granted and not shared_group:
        raise ControlError(
            f"{label} {scope_id}에 LiteLLM에서 서버 {server_id}의 권한이 부여되어 있지 않아 "
            "승인할 수 없습니다. 승인은 LiteLLM 권한을 만들지 않으므로, 먼저 LiteLLM에서 "
            f"object_permission.mcp_servers에 {server_id}를 추가하십시오."
        )


def approve(
    ctx: Context,
    litellm: LiteLLMAdmin,
    *,
    relation_id: str,
    scope_type: str,
    scope_id: str,
    tools: list[str],
    valid_from: datetime,
    valid_until: datetime,
    approval_class: str,
    basis_text: str,
    requested_by: str,
    allowlist_ids: list[str],
    second: Operator | None,
    conditions: dict | None = None,
) -> tuple[str, list[str]]:
    conditions = conditions or {}
    if scope_type == "org":
        raise ControlError(
            "MINT-UNSUPPORTED: org 범위 승인은 지원하지 않습니다. 같은 효과가 필요하면 "
            "해당 조직에 묶인 팀을 --scope team으로 승인하십시오."
        )
    if scope_type not in SCOPE_TYPES:
        raise ControlError(f"scope는 {', '.join(SCOPE_TYPES)} 중 하나여야 합니다.")
    if approval_class not in ("standard", "exception"):
        raise ControlError("class는 standard 또는 exception이어야 합니다.")
    if not tools:
        raise ControlError("--tools에 도구를 하나 이상 지정해야 합니다.")
    if not basis_text.strip():
        raise ControlError("--basis(근거)가 필요합니다.")
    if valid_from >= valid_until:
        raise ControlError("valid-until은 valid-from보다 뒤여야 합니다.")
    if valid_until <= datetime.now(UTC):
        raise ControlError("valid-until이 이미 지났습니다.")
    relation = fetchone(
        ctx.conn,
        "SELECT * FROM mint.usage_relations WHERE instance_id = %s AND id = %s FOR UPDATE",
        (ctx.instance_id, relation_id),
    )
    if relation is None or relation["status"] != "active":
        raise not_found(f"활성 상태의 이용 관계 {relation_id}이(가) 없습니다.")
    server = fetchone(
        ctx.conn,
        "SELECT id, status FROM mint.servers WHERE instance_id = %s AND server_id = %s FOR UPDATE",
        (ctx.instance_id, relation["server_id"]),
    )
    if server["status"] not in ("awaiting_approval", "approved"):
        raise ControlError(
            f"서버 {relation['server_id']}가 {server['status']} 상태라 승인할 수 없습니다."
        )
    first_approval = server["status"] == "awaiting_approval"
    if allowlist_ids and not first_approval:
        raise ControlError("근거 허용 목록 참조는 서버의 첫 승인에서만 지정할 수 있습니다.")
    for ref in allowlist_ids:
        found = fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.allowlists WHERE instance_id = %s AND id = %s"
            " AND status = 'active' AND valid_from <= now() AND valid_until > now()"
            " AND (org_id IS NULL OR org_id = %s)",
            (ctx.instance_id, ref, relation["org_id"]),
        )
        if not found:
            raise ControlError(f"유효한 허용 목록 항목이 아닙니다: {ref}")
    second_info = operators.require_distinct_person(ctx.operator, requested_by, second, "승인")
    check_scope_and_permission(ctx, litellm, relation, scope_type, scope_id)
    approval_id = new_uuid7()
    basis = {"text": basis_text, "allowlist_ids": allowlist_ids}
    if second_info:
        basis["second_approver"] = second_info["name"]
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id, tools,"
        " scope_type, scope_id, valid_from, valid_until, conditions, basis, granted_by,"
        " requested_by, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb,"
        " %s::jsonb, %s, %s, 'active') RETURNING state_version",
        (approval_id, ctx.instance_id, relation["org_id"], relation_id, approval_class,
         relation["server_id"], tools, scope_type, scope_id, valid_from, valid_until,
         json.dumps(conditions), json.dumps(basis, ensure_ascii=False), ctx.operator.name,
         requested_by),
    )
    ctx.emit(
        EventKind.APPROVAL_GRANTED,
        approval_id,
        row["state_version"],
        {
            "approval_id": str(approval_id),
            "relation_id": relation_id,
            "server_id": relation["server_id"],
            "org_id": relation["org_id"],
            "scope_type": scope_type,
            "scope_id": scope_id,
            "tools": tools,
            "class": approval_class,
            "valid_from": valid_from.isoformat(),
            "valid_until": valid_until.isoformat(),
            "requested_by": requested_by,
            "granted_by": ctx.operator.name,
            "second_approver": None if second_info is None else second_info["name"],
            "conditions": conditions,
            "basis": basis,
        },
    )
    if first_approval:
        updated = fetchone(
            ctx.conn,
            "UPDATE mint.servers SET status = 'approved', basis_allowlist_ids = %s::uuid[]"
            " WHERE id = %s RETURNING state_version",
            (allowlist_ids, server["id"]),
        )
        ctx.emit(
            EventKind.SERVER_APPROVED,
            server["id"],
            updated["state_version"],
            {"server_id": relation["server_id"], "first_approval_id": str(approval_id),
             "basis_allowlist_ids": allowlist_ids},
        )
    return str(approval_id), []


def revoke(ctx: Context, approval_id: str, reason: str, deny: bool) -> None:
    if not reason.strip():
        raise ControlError("--reason이 필요합니다.")
    row = fetchone(
        ctx.conn,
        "UPDATE mint.approvals SET status = 'revoked', revoked_at = now(), revoke_reason = %s"
        " WHERE instance_id = %s AND id = %s AND status = 'active'"
        " RETURNING state_version, org_id, server_id, scope_type, scope_id, tools",
        (reason, ctx.instance_id, approval_id),
    )
    if row is None:
        raise not_found(f"활성 상태의 승인 {approval_id}이(가) 없습니다.")
    ctx.emit(
        EventKind.APPROVAL_REVOKED,
        approval_id,
        row["state_version"],
        {"approval_id": approval_id, "server_id": row["server_id"], "reason": reason,
         "with_denial": deny},
    )
    if row["scope_type"] in sync_state.SYNC_SCOPES:
        # 철회로 빠진 항목은 같은 수렴 작업이 LiteLLM에서 거둔다(그 항목의 카운터·보류를 지운다)
        sync_state.reset_counters(
            ctx.conn, ctx.instance_id, row["scope_type"], row["scope_id"], row["server_id"]
        )
        base.enqueue_job(
            ctx, "sync_target", sync_state.target_ref(row["scope_type"], row["scope_id"])
        )
    if deny:
        create_denial(
            ctx,
            scope_type=row["scope_type"],
            scope_id=row["scope_id"],
            server_id=row["server_id"],
            tools=row["tools"],
            reason=reason,
            org_id=row["org_id"],
        )


def create_denial(
    ctx: Context,
    *,
    scope_type: str,
    scope_id: str,
    server_id: str | None,
    tools: list[str] | None,
    reason: str,
    org_id: str | None,
) -> str:
    if scope_type not in (*SCOPE_TYPES, "server"):
        raise ControlError("scope는 key, user, team, org, server 중 하나여야 합니다.")
    if not reason.strip():
        raise ControlError("--reason이 필요합니다.")
    if scope_type == "server":
        server_id = scope_id
    if scope_type == "org":
        org_id = scope_id
    if server_id and not fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.servers WHERE instance_id = %s AND server_id = %s",
        (ctx.instance_id, server_id),
    ):
        raise ControlError(f"등록되지 않은 서버입니다: {server_id}")
    denial_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.denials (id, instance_id, org_id, scope_type, scope_id, server_id,"
        " tools, reason, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " RETURNING state_version",
        (denial_id, ctx.instance_id, org_id, scope_type, scope_id, server_id, tools, reason,
         ctx.operator.name),
    )
    ctx.emit(
        EventKind.DENIAL_CREATED,
        denial_id,
        row["state_version"],
        {"denial_id": str(denial_id), "scope_type": scope_type, "scope_id": scope_id,
         "server_id": server_id, "tools": tools, "org_id": org_id, "reason": reason},
    )
    return str(denial_id)


def lift_denial(ctx: Context, denial_id: str) -> None:
    row = fetchone(
        ctx.conn,
        "UPDATE mint.denials SET lifted_at = now(), lifted_by = %s WHERE instance_id = %s"
        " AND id = %s AND lifted_at IS NULL RETURNING state_version, scope_type, scope_id",
        (ctx.operator.name, ctx.instance_id, denial_id),
    )
    if row is None:
        raise not_found(f"해제되지 않은 거부 {denial_id}이(가) 없습니다.")
    ctx.emit(
        EventKind.DENIAL_LIFTED,
        denial_id,
        row["state_version"],
        {"denial_id": denial_id, "scope_type": row["scope_type"], "scope_id": row["scope_id"]},
    )


# ---------------------------------------------------------------------------
# 호출별 승인
# ---------------------------------------------------------------------------

PRINCIPAL_TYPES = ("user", "team_key", "service_account")


def _approved_contract_id(ctx: Context, server_id: str, tool: str):
    """계약 관리 서버의 도구에 지금 승인된 계약. 호출별 승인은 이 계약에 묶인다(아니면 None)."""
    server = fetchone(
        ctx.conn,
        "SELECT auth_type, contract_status FROM mint.servers WHERE instance_id = %s"
        " AND server_id = %s",
        (ctx.instance_id, server_id),
    )
    if server is None or server["contract_status"] != "managed":
        return None
    contract = fetchone(
        ctx.conn,
        "SELECT id FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
        " AND tool = %s AND credential_scope = %s AND status = 'approved' FOR SHARE",
        (ctx.instance_id, server_id, tool, credential_scope(server["auth_type"])),
    )
    if contract is None:
        raise ControlError(f"도구 {tool}에 승인된 계약이 없어 호출별 승인을 요청할 수 없습니다.")
    return contract["id"]


def call_request(
    ctx: Context,
    *,
    org_id: str,
    principal_type: str,
    principal_id: str,
    server_id: str,
    tool: str,
    args_fp: str,
    fp_key_version: int,
    policy_version_id: str | None,
    expires_in_minutes: int,
    requested_by: str,
    target: str | None = None,
    action: str | None = None,
) -> str:
    if principal_type not in PRINCIPAL_TYPES:
        raise ControlError(f"principal-type은 {', '.join(PRINCIPAL_TYPES)} 중 하나여야 합니다.")
    if not _SHA256.fullmatch(args_fp):
        raise ControlError("args-fp는 소문자 16진수 64자여야 합니다.")
    if expires_in_minutes < 1:
        raise ControlError("expires-in-minutes는 1 이상이어야 합니다.")
    if policy_version_id is None:
        active = fetchone(
            ctx.conn,
            "SELECT id FROM mint.policy_versions WHERE instance_id = %s AND status = 'active'",
            (ctx.instance_id,),
        )
        if active is None:
            raise ControlError("활성 정책 판본이 없습니다. policy activate를 먼저 실행하십시오.")
        policy_version_id = active["id"]
    call_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at, contract_id, target, action)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s)"
        " RETURNING state_version",
        (call_id, ctx.instance_id, org_id, principal_type, principal_id, server_id, tool, args_fp,
         fp_key_version, policy_version_id, requested_by,
         datetime.now(UTC) + timedelta(minutes=expires_in_minutes),
         _approved_contract_id(ctx, server_id, tool), target, action),
    )
    ctx.emit(
        EventKind.CALL_APPROVAL_REQUESTED,
        call_id,
        row["state_version"],
        {"call_approval_id": str(call_id), "org_id": org_id, "principal_type": principal_type,
         "principal_id": principal_id, "server_id": server_id, "tool": tool,
         "policy_version_id": policy_version_id, "requested_by": requested_by,
         **({"target": target, "action": action} if action is not None else {})},
    )
    return str(call_id)


def _call_update(
    ctx: Context,
    call_id: str,
    target: str,
    sources: tuple[str, ...],
    kind: EventKind,
    *,
    approver: str | None = None,
    extra: dict | None = None,
) -> dict:
    set_approver = ", approved_by = %s" if approver else ""
    params = (target, *([approver] if approver else []), ctx.instance_id, call_id, list(sources))
    row = fetchone(
        ctx.conn,
        f"UPDATE mint.call_approvals SET status = %s{set_approver} WHERE instance_id = %s"
        " AND id = %s AND status = ANY(%s) AND expires_at > now()"
        " RETURNING state_version, principal_type, principal_id, server_id, tool",
        params,
    )
    if row is None:
        raise ControlError(
            f"{'/'.join(sources)} 상태이고 만료되지 않은 호출별 승인 {call_id}이(가) 없습니다."
        )
    ctx.emit(
        kind,
        call_id,
        row["state_version"],
        {"call_approval_id": call_id, "server_id": row["server_id"], "tool": row["tool"],
         "principal_type": row["principal_type"], "principal_id": row["principal_id"],
         **(extra or {})},
    )
    return row


def call_approve(ctx: Context, call_id: str, second: Operator | None) -> None:
    current = fetchone(
        ctx.conn,
        "SELECT principal_type, principal_id, requested_by FROM mint.call_approvals"
        " WHERE instance_id = %s AND id = %s FOR UPDATE",
        (ctx.instance_id, call_id),
    )
    if current is None:
        raise not_found(f"호출별 승인 {call_id}이(가) 없습니다.")
    if current["principal_type"] == "user" and current["principal_id"] == ctx.operator.user_id:
        raise separation_of_duties(
            "호출 주체와 같은 사용자의 운영자는 호출별 승인을 승인할 수 없습니다."
        )
    second_info = operators.require_distinct_person(
        ctx.operator, current["requested_by"], second, "호출별 승인"
    )
    extra = {"approved_by": ctx.operator.name, "second_approver": None}
    if second_info:
        extra["second_approver"] = second_info["name"]
        extra["second_approver_user_id"] = second_info["user_id"]
    _call_update(ctx, call_id, "approved", ("pending",), EventKind.CALL_APPROVAL_APPROVED,
                 approver=ctx.operator.name, extra=extra)


def call_reject(ctx: Context, call_id: str) -> None:
    _call_update(ctx, call_id, "rejected", ("pending",), EventKind.CALL_APPROVAL_REJECTED)


def call_cancel(ctx: Context, call_id: str) -> None:
    """요청자 본인이나 admin만 취소할 수 있다. 검사와 변경은 같은 트랜잭션에서 한다."""
    current = fetchone(
        ctx.conn,
        "SELECT requested_by FROM mint.call_approvals WHERE instance_id = %s AND id = %s"
        " FOR UPDATE",
        (ctx.instance_id, call_id),
    )
    if current is None:
        raise not_found(f"호출별 승인 {call_id}이(가) 없습니다.")
    is_requester = (
        ctx.operator.user_id is not None and current["requested_by"] == ctx.operator.user_id
    )
    if ctx.operator.role != "admin" and not is_requester:
        raise forbidden("호출별 승인은 요청자 본인이나 admin만 취소할 수 있습니다.")
    _call_update(ctx, call_id, "cancelled", ("pending", "approved"),
                 EventKind.CALL_APPROVAL_CANCELLED)


def expiring_approvals(ctx: Context, within: timedelta) -> list[dict]:
    return fetchall(
        ctx.conn,
        "SELECT id, server_id, scope_type, scope_id, valid_until FROM mint.approvals"
        " WHERE instance_id = %s AND status = 'active' AND valid_until > now()"
        " AND valid_until <= now() + %s ORDER BY valid_until",
        (ctx.instance_id, within),
    )
