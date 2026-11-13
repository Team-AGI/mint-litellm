"""정책 판본 활성화와 시험 적용 서비스."""

from mint_litellm.control import policy_versions
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services.base import require_role, transact
from mint_litellm.types.events import EventKind


def activate(
    ctx: Context, database_url: str, version_id: str, source: policy_versions.PolicySource
) -> dict | None:
    """판본을 활성화하고 남은 ``policy_activated`` 사건 행을 돌려준다.

    번들 게시와 정책 엔진 확인은 외부 호출이라 이 연결의 트랜잭션 밖에서 하며, 판본 전환과 사건은
    정책 모듈이 자기 연결의 트랜잭션에서 기록한다. 실패하면 ``ActivationError``이다. 시험 중이던
    판본을 활성화하면 시험은 끝난다.
    """
    require_role(ctx, "policy activate")
    policy_versions.activate(
        ctx.conn, database_url, ctx.instance_id, ctx.operator.name, version_id, source
    )
    with transact(ctx):
        _end_shadow(ctx, version_id)
    return fetchone(
        ctx.conn,
        "SELECT event_id, kind, source_key FROM mint.events WHERE instance_id = %s"
        " AND kind = 'policy_activated' AND source_key LIKE %s ORDER BY inserted_at DESC LIMIT 1",
        (ctx.instance_id, f"policy_version:{version_id}:%"),
    )


def _end_shadow(ctx: Context, version_id: str) -> None:
    """활성화한 판본이 시험 판본이면 시험을 끝낸다."""
    ctx.conn.execute(
        "UPDATE mint.policy_shadow SET version_id = NULL, bundle_sha256 = NULL, set_by = NULL,"
        " set_at = NULL, state_version = state_version + 1"
        " WHERE instance_id = %s AND version_id = %s",
        (ctx.instance_id, version_id),
    )


def shadow_set(
    ctx: Context,
    database_url: str,
    version_id: str,
    source: policy_versions.PolicySource,
) -> None:
    """판본을 시험 판본으로 정한다. 이전 시험 판본은 바뀐다. 호출의 판정은 달라지지 않는다."""
    require_role(ctx, "policy shadow")
    sha = policy_versions.prepare_shadow(
        ctx.conn, database_url, ctx.instance_id, version_id, source
    )
    with transact(ctx):
        row = fetchone(
            ctx.conn,
            "INSERT INTO mint.policy_shadow AS p"
            " (instance_id, version_id, bundle_sha256, set_by, set_at)"
            " VALUES (%s, %s, %s, %s, now()) ON CONFLICT (instance_id) DO UPDATE SET"
            " version_id = EXCLUDED.version_id, bundle_sha256 = EXCLUDED.bundle_sha256,"
            " set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at,"
            " state_version = p.state_version + 1"
            " RETURNING state_version",
            (ctx.instance_id, version_id, sha, ctx.operator.name),
        )
        ctx.emit(
            EventKind.POLICY_SHADOW_SET, version_id, row["state_version"],
            {"policy_version_id": version_id, "bundle_sha256": sha},
        )


def shadow_cancel(ctx: Context) -> str:
    """시험 판본을 비운다. 비운 판본 식별자를 돌려준다."""
    require_role(ctx, "policy shadow-cancel")
    with transact(ctx):
        current = fetchone(
            ctx.conn,
            "SELECT version_id FROM mint.policy_shadow WHERE instance_id = %s FOR UPDATE",
            (ctx.instance_id,),
        )
        if current is None or current["version_id"] is None:
            raise ControlError("시험 중인 정책 판본이 없습니다.")
        row = fetchone(
            ctx.conn,
            "UPDATE mint.policy_shadow SET version_id = NULL, bundle_sha256 = NULL, set_by = NULL,"
            " set_at = NULL, state_version = state_version + 1 WHERE instance_id = %s"
            " RETURNING state_version",
            (ctx.instance_id,),
        )
        ctx.emit(
            EventKind.POLICY_SHADOW_CLEARED, current["version_id"], row["state_version"],
            {"policy_version_id": current["version_id"]},
        )
        return current["version_id"]
