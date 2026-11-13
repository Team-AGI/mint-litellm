"""조직과 팀·사용자 바인딩 서비스."""

from mint_litellm.control import orgs as domain
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.errors import ControlError, not_found
from mint_litellm.control.services.base import lock_version, service, transact
from mint_litellm.types.identity import SubjectType


@service("org add")
def add(ctx: Context, org_id: str, name: str) -> None:
    domain.add(ctx, org_id, name)


@service("org close")
def close(ctx: Context, org_id: str, *, expected_version: int | None = None) -> None:
    lock_version(ctx, "orgs", org_id, expected_version)
    domain.close(ctx, org_id)


@service("org bind")
def bind(ctx: Context, org_id: str, subject_type: SubjectType, subject_id: str) -> None:
    domain.bind(ctx, org_id, subject_type, subject_id)


@service("org unbind")
def unbind(ctx: Context, subject_type: SubjectType, subject_id: str) -> None:
    domain.unbind(ctx, subject_type, subject_id)


def _suggestions(ctx: Context, where: str, args: tuple) -> list[dict]:
    return fetchall(
        ctx.conn,
        "SELECT id, subject_type, subject_id, org_id, rule, matched, calls, status"
        f" FROM mint.org_suggestions WHERE instance_id = %s AND {where}"
        " ORDER BY calls DESC, subject_type, subject_id",
        (ctx.instance_id, *args),
    )


def list_suggestions(ctx: Context, status: str = "open") -> list[dict]:
    return _suggestions(ctx, "status = %s", (status,))


def _decide(ctx: Context, row: dict, status: str) -> None:
    ctx.conn.execute(
        "UPDATE mint.org_suggestions SET status = %s, decided_by = %s, decided_at = now()"
        " WHERE id = %s",
        (status, ctx.operator.name, row["id"]),
    )


def _open(ctx: Context, suggestion_id: str) -> dict:
    rows = _suggestions(ctx, "id::text = %s AND status = 'open'", (suggestion_id,))
    if not rows:
        raise not_found(f"열린 조직 연결 제안 {suggestion_id}이(가) 없습니다.")
    return rows[0]


def _apply_row(ctx: Context, row: dict) -> None:
    domain.bind(ctx, row["org_id"], SubjectType(row["subject_type"]), row["subject_id"])
    _decide(ctx, row, "applied")


@service("org suggest apply")
def apply_suggestion(ctx: Context, suggestion_id: str) -> None:
    _apply_row(ctx, _open(ctx, suggestion_id))


@service("org suggest apply")
def apply_rule(ctx: Context, rule: str) -> int:
    """한 규칙의 열린 제안을 모두 적용한다. 적용할 수 없는 제안(이미 묶임·닫힌 조직)은 건너뛴다."""
    done = 0
    for row in _suggestions(ctx, "status = 'open' AND rule = %s", (rule,)):
        try:
            with transact(ctx):
                _apply_row(ctx, row)
            done += 1
        except ControlError:
            continue
    return done


@service("org suggest ignore")
def ignore_suggestion(ctx: Context, suggestion_id: str) -> None:
    _decide(ctx, _open(ctx, suggestion_id), "ignored")


def list_domains(ctx: Context) -> list[dict]:
    return fetchall(
        ctx.conn,
        "SELECT domain, org_id FROM mint.org_suggest_domains WHERE instance_id = %s"
        " ORDER BY domain",
        (ctx.instance_id,),
    )


@service("org domain set")
def set_domain(ctx: Context, domain_name: str, org_id: str) -> None:
    name = domain_name.strip().lower().removeprefix("@")
    if not name or "@" in name or " " in name:
        raise ControlError(f"도메인 {domain_name!r}이(가) 올바르지 않습니다.")
    domain.require_active(ctx, org_id)
    ctx.conn.execute(
        "INSERT INTO mint.org_suggest_domains (instance_id, domain, org_id) VALUES (%s, %s, %s)"
        " ON CONFLICT (instance_id, domain) DO UPDATE SET org_id = EXCLUDED.org_id",
        (ctx.instance_id, name, org_id),
    )


@service("org domain unset")
def unset_domain(ctx: Context, domain_name: str) -> None:
    name = domain_name.strip().lower().removeprefix("@")
    cur = ctx.conn.execute(
        "DELETE FROM mint.org_suggest_domains WHERE instance_id = %s AND domain = %s",
        (ctx.instance_id, name),
    )
    if cur.rowcount == 0:
        raise not_found(f"도메인 {name}의 대응이 없습니다.")
