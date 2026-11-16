"""조직과 팀·사용자 바인딩."""

import re

from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.types.events import EventKind
from mint_litellm.types.identity import SubjectType
from mint_litellm.types.ids import new_uuid7

ORG_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def add(ctx: Context, org_id: str, name: str) -> None:
    if not ORG_ID.fullmatch(org_id):
        raise ControlError(
            "조직 식별자는 영문자·숫자로 시작하고 영문자·숫자·점·밑줄·하이픈만 쓰는 "
            "128자 이하여야 합니다."
        )
    if not 1 <= len(name) <= 256:
        raise ControlError("조직 이름은 1자 이상 256자 이하여야 합니다.")
    if fetchone(
        ctx.conn,
        "SELECT 1 AS x FROM mint.orgs WHERE instance_id = %s AND org_id = %s",
        (ctx.instance_id, org_id),
    ):
        raise ControlError(f"조직 {org_id}이(가) 이미 있습니다.")
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.orgs (instance_id, org_id, name) VALUES (%s, %s, %s)"
        " RETURNING state_version",
        (ctx.instance_id, org_id, name),
    )
    ctx.emit(EventKind.ORG_CREATED, org_id, row["state_version"], {"org_id": org_id, "name": name})


def close(ctx: Context, org_id: str) -> None:
    row = fetchone(
        ctx.conn,
        "UPDATE mint.orgs SET status = 'closed' WHERE instance_id = %s AND org_id = %s"
        " AND status = 'active' RETURNING state_version",
        (ctx.instance_id, org_id),
    )
    if row is None:
        raise not_found(f"활성 상태의 조직 {org_id}이(가) 없습니다.")
    ctx.emit(EventKind.ORG_CLOSED, org_id, row["state_version"], {"org_id": org_id})


def require_active(ctx: Context, org_id: str) -> None:
    row = fetchone(
        ctx.conn,
        "SELECT status FROM mint.orgs WHERE instance_id = %s AND org_id = %s",
        (ctx.instance_id, org_id),
    )
    if row is None:
        raise not_found(f"조직 {org_id}이(가) 없습니다.")
    if row["status"] != "active":
        raise ControlError(f"조직 {org_id}은(는) 닫혀 있습니다.")


def bind(ctx: Context, org_id: str, subject_type: SubjectType, subject_id: str) -> None:
    require_active(ctx, org_id)
    existing = fetchone(
        ctx.conn,
        "SELECT org_id FROM mint.org_bindings WHERE instance_id = %s AND subject_type = %s"
        " AND subject_id = %s",
        (ctx.instance_id, subject_type.value, subject_id),
    )
    if existing:
        raise ControlError(
            f"{subject_type.value} {subject_id}은(는) 이미 조직 "
            f"{existing['org_id']}에 묶여 있습니다."
        )
    binding_id = new_uuid7()
    row = fetchone(
        ctx.conn,
        "INSERT INTO mint.org_bindings (id, instance_id, org_id, subject_type, subject_id,"
        " created_by) VALUES (%s, %s, %s, %s, %s, %s) RETURNING state_version",
        (binding_id, ctx.instance_id, org_id, subject_type.value, subject_id, ctx.operator.name),
    )
    ctx.emit(
        EventKind.ORG_BINDING_CREATED,
        binding_id,
        row["state_version"],
        {"org_id": org_id, "subject_type": subject_type.value, "subject_id": subject_id},
    )


def unbind(ctx: Context, subject_type: SubjectType, subject_id: str) -> None:
    row = fetchone(
        ctx.conn,
        "DELETE FROM mint.org_bindings WHERE instance_id = %s AND subject_type = %s"
        " AND subject_id = %s RETURNING id, org_id, state_version",
        (ctx.instance_id, subject_type.value, subject_id),
    )
    if row is None:
        raise not_found(f"{subject_type.value} {subject_id}의 조직 바인딩이 없습니다.")
    # 삭제된 행은 버전을 올릴 수 없으므로 마지막 버전의 다음 값으로 사건 키를 만든다.
    ctx.emit(
        EventKind.ORG_BINDING_REMOVED,
        row["id"],
        row["state_version"] + 1,
        {"org_id": row["org_id"], "subject_type": subject_type.value, "subject_id": subject_id},
    )
