"""서비스 틀. 모든 상태 변경은 서비스 함수 하나를 거친다.

서비스 함수는 입력 검증, 행위자의 역할 확인, 한 트랜잭션(상태 변경, 사건, 작업 등록)을 맡고
명령줄과 HTTP API는 호출만 한다. 한 호출은 하나의 세이브포인트(바깥 트랜잭션이 없으면
트랜잭션)로 감싸므로 사건 기록이 실패하면 상태 변경도 함께 되돌아간다. 외부 호출은 트랜잭션 안에서
하지 않으며 필요한 후속 작업은 ``jobs`` 행으로 같은 트랜잭션에 등록한다.
"""

import functools
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from mint_litellm.control import jobs
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import conflict, forbidden, not_found
from mint_litellm.types.cli_commands import COMMANDS, OperatorRole
from mint_litellm.types.ids import new_uuid7

F = TypeVar("F", bound=Callable[..., Any])

_COMMANDS = {command.name: command for command in COMMANDS}

# 낙관적 잠금이 가능한 표: 표 -> (대상 열, 버전 열)
_VERSIONED = {
    "servers": ("server_id", "state_version"),
    "usage_relations": ("id", "state_version"),
    "approvals": ("id", "state_version"),
    "denials": ("id", "state_version"),
    "call_approvals": ("id", "state_version"),
    "call_approval_rules": ("id", "state_version"),
    "consents": ("id", "state_version"),
    "litellm_grants": ("id", "state_version"),
    "allowlists": ("id", "state_version"),
    "orgs": ("org_id", "state_version"),
    "settings": ("instance_id", "settings_version"),
    "operators": ("name", "state_version"),
}


def require_role(ctx: Context, command: str) -> None:
    """명령 표의 역할 집합에 행위자의 역할이 들어 있어야 한다. 토큰 없는 명령은 확인하지 않는다."""
    entry = _COMMANDS[command]
    if entry.unauthenticated:
        return
    if OperatorRole(ctx.operator.role) not in entry.roles:
        raise forbidden(
            f"{command}은(는) {ctx.operator.role} 역할로 실행할 수 없습니다.", exit_code=4
        )


@contextmanager
def transact(ctx: Context) -> Iterator[None]:
    """한 세이브포인트(바깥 트랜잭션이 없으면 트랜잭션). 실패하면 이 구간의 사건도 버린다."""
    mark = len(ctx.emitted)
    try:
        with ctx.conn.transaction():
            yield
    except BaseException:
        del ctx.emitted[mark:]
        raise


def service(command: str) -> Callable[[F], F]:
    """``command`` 표 항목의 역할을 확인하고 ``transact`` 안에서 실행한다.

    외부 호출이 필요한 서비스는 이 장식자를 쓰지 않고 ``require_role``, ``Prefetched``,
    ``transact``를 직접 이어 쓴다(외부 읽기를 트랜잭션 앞에서 끝내기 위해서).
    """

    def decorate(function: F) -> F:
        @functools.wraps(function)
        def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
            require_role(ctx, command)
            with transact(ctx):
                return function(ctx, *args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate


class Prefetched:
    """LiteLLM 읽기 결과를 트랜잭션 앞에서 미리 읽어 두고 같은 호출에 같은 값을 돌려준다.

    도메인 함수는 ``LiteLLMAdmin``과 같은 메서드 이름으로 읽으므로 이 객체를 그대로 받는다.
    미리 읽지 않은 호출은 오류이다(트랜잭션 안에서 외부를 부르지 않는다).
    """

    def __init__(self, litellm: Any) -> None:
        self._litellm = litellm
        self._values: dict[tuple[str, tuple], Any] = {}

    def prefetch(self, method: str, *args: Any) -> "Prefetched":
        self._values[(method, args)] = getattr(self._litellm, method)(*args)
        return self

    def __getattr__(self, method: str) -> Callable[..., Any]:
        def read(*args: Any) -> Any:
            try:
                return self._values[(method, args)]
            except KeyError:
                message = f"{method}{args}을(를) 트랜잭션 앞에서 읽지 않았습니다."
                raise RuntimeError(message) from None

        return read


def lock_version(ctx: Context, table: str, key: str, expected: int | None) -> int | None:
    """대상 행을 잠그고 ``expected``(요청의 ``state_version``)와 비교한다.

    ``expected``가 None이면 아무것도 하지 않는다(명령줄은 읽은 값으로 채우는 것과 같다).
    행이 없으면 ``NOT-FOUND``, 값이 다르면 ``CONFLICT``이다.
    """
    if expected is None:
        return None
    column, version = _VERSIONED[table]
    row = fetchone(
        ctx.conn,
        f"SELECT {version} AS v FROM mint.{table} WHERE instance_id = %s AND {column} = %s"
        " FOR UPDATE",
        (ctx.instance_id, key if table != "settings" else ctx.instance_id),
    )
    if row is None:
        raise not_found(f"{table} 대상 {key}이(가) 없습니다.")
    if row["v"] != expected:
        raise conflict(
            f"{key}의 상태 버전이 요청({expected})과 다릅니다(현재 {row['v']}). "
            "다시 읽은 뒤 시도하십시오."
        )
    return row["v"]


def enqueue_job(
    ctx: Context, kind: str, target_ref: str, idempotency_key: str | None = None
) -> str:
    """후속 작업을 같은 트랜잭션에 등록한다. 이미 있으면 그 작업을 쓴다(수렴).

    수렴 작업(``jobs.KINDS``의 ``convergent``)은 멱등 키 없이 같은 종류·대상의 대기 행 하나로,
    나머지는 멱등 키 하나로 수렴한다. 모르는 종류만 거부한다. 처리기가 아직 없는 종류도 등록되고
    ``pending``으로 남으며 실행기는 처리기가 붙기 전까지 임대하지 않는다.
    같은 대상에 실행 중인 행만 있으면 새 대기 행을 만든다. 작업 식별자를 돌려준다.
    """
    spec = jobs.KINDS.get(kind)
    if spec is None:
        raise ValueError(f"알 수 없는 작업 종류: {kind}")
    if spec.convergent != (idempotency_key is None):
        raise ValueError(
            f"{kind}은(는) 멱등 키를 "
            + ("쓰지 않습니다(수렴 작업)." if spec.convergent else "써야 합니다.")
        )
    if idempotency_key is None:
        conflict_target = (
            "(instance_id, kind, target_ref) WHERE status = 'pending' AND idempotency_key IS NULL"
        )
        lookup = (
            "kind = %s AND target_ref = %s AND status = 'pending' AND idempotency_key IS NULL",
            (kind, target_ref),
        )
    else:
        conflict_target = "(instance_id, idempotency_key)"
        lookup = ("idempotency_key = %s", (idempotency_key,))
    for _ in range(2):  # 조회 직전에 대기 작업이 실행 중으로 넘어가면 한 번 더 등록한다
        row = fetchone(
            ctx.conn,
            "INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key)"
            f" VALUES (%s, %s, %s, %s, %s) ON CONFLICT {conflict_target} DO NOTHING RETURNING id",
            (new_uuid7(), ctx.instance_id, kind, target_ref, idempotency_key),
        )
        if row is None:
            row = fetchone(
                ctx.conn,
                f"SELECT id FROM mint.jobs WHERE instance_id = %s AND {lookup[0]}",
                (ctx.instance_id, *lookup[1]),
            )
        if row is not None:
            return str(row["id"])
    raise conflict("작업을 등록하지 못했습니다. 다시 시도하십시오.")
