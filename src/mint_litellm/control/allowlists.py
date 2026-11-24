"""허용 목록. 종료일이 필수이고 해제는 명시적 행위이다."""

import ipaddress
from dataclasses import replace
from datetime import UTC, datetime

from mint_litellm.control import orgs
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

KINDS = ("provider", "auth_server", "egress_target", "registry_source")


def add(
    ctx: Context,
    kind: str,
    value: str,
    valid_from: datetime,
    valid_until: datetime,
    org_id: str | None,
    note: str | None,
) -> str:
    value = value.strip()
    if kind not in KINDS:
        raise ControlError(f"kind는 {', '.join(KINDS)} 중 하나여야 합니다.")
    if not value:
        raise ControlError("value가 비어 있습니다.")
    if kind == "egress_target" and "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None and network.prefixlen < 8:
            # 이보다 넓은 대역은 사실상 모든 주소를 허용해 목적지 제한을 없앤다.
            raise ControlError("반출 허용 대역은 /8보다 좁아야 합니다.")
    if valid_from >= valid_until:
        raise ControlError("valid-until은 valid-from보다 뒤여야 합니다.")
    if org_id is not None:
        orgs.require_active(ctx, org_id)
    if fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.allowlists WHERE instance_id = %s AND status = 'active'"
        " AND kind = %s AND value = %s AND org_id IS NOT DISTINCT FROM %s",
        (ctx.instance_id, kind, value, org_id),
    ):
        raise ControlError("같은 항목이 이미 활성 상태로 등록되어 있습니다.")
    entry_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.allowlists (id, instance_id, org_id, kind, value, note, valid_from,"
        " valid_until, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " RETURNING state_version",
        (entry_id, ctx.instance_id, org_id, kind, value, note, valid_from, valid_until,
         ctx.operator.name),
    )
    ctx.emit(
        EventKind.ALLOWLIST_ADDED,
        entry_id,
        row["state_version"],
        {
            "allowlist_id": str(entry_id),
            "kind": kind,
            "value": value,
            "org_id": org_id,
            "valid_from": valid_from.isoformat(),
            "valid_until": valid_until.isoformat(),
        },
    )
    return str(entry_id)


# 묶음 만들기용 공식 패키지 저장소. 자동으로 한 번 넣고, 관리자가 해제하면 다시 넣지 않는다.
DEFAULT_EGRESS = (
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "github.com", "codeload.github.com", "objects.githubusercontent.com",
    "raw.githubusercontent.com",
)
DEFAULT_ACTOR = "mint-default"


def ensure_defaults(ctx: Context) -> None:
    far = datetime(2999, 12, 31, tzinfo=UTC)
    for host in DEFAULT_EGRESS:
        if fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.allowlists WHERE instance_id = %s AND kind = 'egress_target'"
            " AND value = %s AND org_id IS NULL AND (status = 'active' OR created_by = %s)",
            (ctx.instance_id, host, DEFAULT_ACTOR),
        ):
            continue
        add(replace(ctx, operator=replace(ctx.operator, name=DEFAULT_ACTOR)), "egress_target",
            host, datetime.now(UTC), far, None, "공식 패키지 저장소")


def lift(ctx: Context, allowlist_id: str) -> None:
    row = fetchone(
        ctx.conn,
        "UPDATE mint.allowlists SET status = 'lifted' WHERE instance_id = %s AND id = %s"
        " AND status = 'active' RETURNING state_version, kind, value",
        (ctx.instance_id, allowlist_id),
    )
    if row is None:
        raise not_found(f"활성 상태의 허용 목록 항목 {allowlist_id}이(가) 없습니다.")
    ctx.emit(
        EventKind.ALLOWLIST_LIFTED,
        allowlist_id,
        row["state_version"],
        {"allowlist_id": allowlist_id, "kind": row["kind"], "value": row["value"]},
    )
