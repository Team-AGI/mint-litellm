"""운영자 등록·인증과 직무 분리 규칙.

토큰은 발급할 때 한 번만 보여 주고 해시만 저장한다. 직무 분리는 LiteLLM 사용자 식별자로
판정하므로 같은 사람이 토큰을 여러 개 가져도 한 사람으로 취급한다.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import psycopg

from mint_litellm.control import ledger
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import AuthError, ControlError, separation_of_duties
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.types.cli_commands import APPROVER_UP, OperatorRole
from mint_litellm.types.events import EventKind

TOKEN_PREFIX = "mint_"
# 사람 사용자로 인정하는 LiteLLM 역할. 최종 사용자(customer)와 서비스 계정은 제외한다.
HUMAN_ROLES = frozenset(
    {"proxy_admin", "proxy_admin_viewer", "internal_user", "internal_user_viewer", "org_admin"}
)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def authenticate(conn: psycopg.Connection, instance_id: str, token: str | None) -> Operator:
    if not token:
        raise AuthError("운영자 토큰이 필요합니다(MINT_OPERATOR_TOKEN 또는 --token-file).")
    row = fetchone(
        conn,
        "SELECT name, role, user_id, expires_at FROM mint.operators"
        " WHERE instance_id = %s AND token_hash = %s",
        (instance_id, hash_token(token)),
    )
    if row is None:
        raise AuthError("운영자 토큰이 올바르지 않습니다.")
    if row["expires_at"] is not None and row["expires_at"] <= datetime.now(UTC):
        raise AuthError("운영자 토큰이 만료되었습니다.")
    return Operator(name=row["name"], role=row["role"], user_id=row["user_id"])


def _require_human_user(litellm: LiteLLMAdmin, user_id: str) -> None:
    user = litellm.get_user(user_id)
    if user is None:
        raise ControlError(f"LiteLLM에 사용자 {user_id}가 없습니다.")
    if user.get("user_role") not in HUMAN_ROLES:
        raise ControlError(f"LiteLLM 사용자 {user_id}는 사람 사용자가 아닙니다.")


def _insert(
    ctx_conn: psycopg.Connection,
    instance_id: str,
    actor: str,
    name: str,
    role: OperatorRole,
    user_id: str | None,
    expires_in_days: int | None,
    emitted: list | None = None,
) -> tuple[str, int]:
    name = name.strip()
    token = issue_token()
    expires_at = None if expires_in_days is None else datetime.now(UTC) + timedelta(
        days=expires_in_days
    )
    taken = fetchone(
        ctx_conn,
        "SELECT (expires_at IS NOT NULL AND expires_at <= now()) AS removed"
        " FROM mint.operators WHERE instance_id = %s AND name = %s",
        (instance_id, name),
    )
    if taken:
        if taken["removed"]:
            # 삭제는 행을 남기고 만료시키므로 같은 이름은 다시 쓸 수 없다.
            raise ControlError(
                f"운영자 {name}은(는) 삭제되어 같은 이름으로 다시 등록할 수 없습니다. "
                "다른 이름을 쓰십시오."
            )
        raise ControlError(f"운영자 {name}이(가) 이미 있습니다.")
    row = fetchone(
        ctx_conn,
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id, expires_at)"
        " VALUES (%s, %s, %s, %s, %s, %s) RETURNING state_version",
        (instance_id, name, role.value, hash_token(token), user_id, expires_at),
    )
    event = ledger.record(
        ctx_conn,
        instance_id,
        EventKind.OPERATOR_ADDED,
        entity_id=name,
        state_version=row["state_version"],
        actor=actor,
        payload={"name": name, "role": role.value, "user_id": user_id,
                 "expires_at": None if expires_at is None else expires_at.isoformat()},
    )
    if emitted is not None:
        emitted.append(event)
    return token, row["state_version"]


def add(
    ctx: Context,
    litellm: LiteLLMAdmin,
    name: str,
    role: OperatorRole,
    user_id: str | None,
    expires_in_days: int | None,
) -> str:
    if role is not OperatorRole.VIEWER and not user_id:
        raise ControlError(f"{role.value} 운영자는 --user-id(LiteLLM 사용자)가 필요합니다.")
    if user_id:
        _require_human_user(litellm, user_id)
    token, _ = _insert(ctx.conn, ctx.instance_id, ctx.operator.name, name, role, user_id,
                       expires_in_days, ctx.emitted)
    return token


def bootstrap(
    conn: psycopg.Connection,
    instance_id: str,
    litellm: LiteLLMAdmin,
    name: str,
    user_id: str,
    emitted: list | None = None,
) -> str:
    """운영자가 하나도 없을 때만 토큰 없이 첫 admin을 만든다."""
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mint-bootstrap:{instance_id}",))
    existing = fetchone(
        conn, "SELECT count(*) AS n FROM mint.operators WHERE instance_id = %s", (instance_id,)
    )
    if existing["n"]:
        raise ControlError("운영자가 이미 있어 bootstrap을 실행할 수 없습니다.")
    _require_human_user(litellm, user_id)
    token, _ = _insert(conn, instance_id, "bootstrap", name, OperatorRole.ADMIN, user_id, None,
                       emitted)
    return token


def require_distinct_person(
    operator: Operator, other_user_id: str | None, second: Operator | None, what: str
) -> dict[str, str] | None:
    """운영자가 ``other_user_id``와 같은 사람이면 다른 사람의 두 번째 승인을 요구한다.

    두 번째 승인자가 쓰였으면 그 이름과 사용자 식별자를 돌려준다.
    """
    if other_user_id is None or operator.user_id != other_user_id:
        return None
    if second is None:
        raise separation_of_duties(
            f"{what}의 요청자와 같은 사용자이므로 승인할 수 없습니다. "
            "다른 사용자의 운영자 토큰을 --second-approver로 함께 제시하십시오."
        )
    if second.role not in {r.value for r in APPROVER_UP} or second.user_id in (None, other_user_id):
        raise separation_of_duties(
            "두 번째 승인자는 요청자와 다른 사용자에 결속된 approver 이상이어야 합니다."
        )
    return {"name": second.name, "user_id": second.user_id}
