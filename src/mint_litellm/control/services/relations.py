"""이용 관계 서비스."""

from mint_litellm.control import relations as domain
from mint_litellm.control.context import Context
from mint_litellm.control.errors import forbidden
from mint_litellm.control.services import evidence
from mint_litellm.control.services.base import lock_version, service, transact


@service("relation add")
def add(
    ctx: Context, org_id: str, server_id: str, purpose: str, team_id: str | None
) -> str:
    return domain.add(ctx, org_id, server_id, purpose, team_id)


@service("relation terminate")
def terminate(
    ctx: Context, relation_id: str, *, expected_version: int | None = None
) -> None:
    lock_version(ctx, "usage_relations", relation_id, expected_version)
    domain.terminate(ctx, relation_id)


def finish(ctx: Context, relation_id: str, *, expected_version: int | None = None) -> None:
    """종료 중인 이용 관계를 종료됨으로 닫는다. 삭제·반환 증빙이 있어야 한다."""
    if ctx.operator.role != "admin":
        raise forbidden(f"관계 종료 완료는 {ctx.operator.role} 역할로 실행할 수 없습니다.",
                        exit_code=4)
    with transact(ctx):
        lock_version(ctx, "usage_relations", relation_id, expected_version)
        domain.finish(
            ctx, relation_id, lambda: evidence.require(ctx, "finish", "relation", relation_id)
        )
