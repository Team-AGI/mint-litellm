"""저장된 설정(모드, 관측 가능 사유, 기본 조직)."""

import hashlib

import psycopg

from mint_litellm.control import orgs
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.types.events import EventKind
from mint_litellm.types.reason_codes import OBSERVATION_CANDIDATES
from mint_litellm.types.settings import Mode, effective_mode

# 1단계 기본 정책 가운데 관측 모드로 전환할 수 있다고 선언된 정책
DEFAULT_OBSERVABLE_POLICY_IDS = ("R1", "R3")


def ensure(conn: psycopg.Connection, instance_id: str) -> int | None:
    """설정 행이 없으면 만들고 새 ``settings_version``을, 이미 있으면 None을 돌려준다."""
    row = fetchone(
        conn,
        "INSERT INTO mint.settings (instance_id, observable_policy_ids) VALUES (%s, %s)"
        " ON CONFLICT (instance_id) DO NOTHING RETURNING settings_version",
        (instance_id, list(DEFAULT_OBSERVABLE_POLICY_IDS)),
    )
    return None if row is None else row["settings_version"]


def load(conn: psycopg.Connection, instance_id: str, *, lock: bool = False) -> dict:
    """설정 행. ``lock``이면 같은 트랜잭션이 끝날 때까지 다른 변경을 기다리게 한다."""
    row = fetchone(
        conn,
        "SELECT * FROM mint.settings WHERE instance_id = %s" + (" FOR UPDATE" if lock else ""),
        (instance_id,),
    )
    if row is None:
        raise ControlError("설정이 없습니다. init을 먼저 실행하십시오.")
    return row


def _changed(ctx: Context, row: dict, what: dict) -> None:
    ctx.emit(EventKind.SETTINGS_CHANGED, ctx.instance_id, row["settings_version"], what)


def set_default_org(ctx: Context, org_id: str | None) -> None:
    load(ctx.conn, ctx.instance_id)
    if org_id is not None:
        orgs.require_active(ctx, org_id)
    row = fetchone(
        ctx.conn,
        "UPDATE mint.settings SET default_org_id = %s WHERE instance_id = %s"
        " RETURNING settings_version",
        (org_id, ctx.instance_id),
    )
    _changed(ctx, row, {"default_org_id": org_id})


def set_mode(ctx: Context, mode: Mode, ceiling: Mode) -> None:
    load(ctx.conn, ctx.instance_id)
    if effective_mode(ceiling, mode) is not mode:
        raise ControlError("환경 변수 MINT_MODE가 enforce이므로 observe로 바꿀 수 없습니다.")
    row = fetchone(
        ctx.conn,
        "UPDATE mint.settings SET mode = %s WHERE instance_id = %s RETURNING settings_version",
        (mode.value, ctx.instance_id),
    )
    _changed(ctx, row, {"mode": mode.value})


def set_observable(
    ctx: Context, reasons: list[str] | None, policy_ids: list[str] | None
) -> None:
    current = load(ctx.conn, ctx.instance_id, lock=True)
    if reasons is None and policy_ids is None:
        raise ControlError("--reasons 또는 --policy-ids 중 하나는 지정해야 합니다.")
    allowed = {r.value for r in OBSERVATION_CANDIDATES}
    unknown = sorted(set(reasons or []) - allowed)
    if unknown:
        raise ControlError(
            f"관측으로 전환할 수 없는 사유 계열입니다: {', '.join(unknown)}. "
            f"가능한 값: {', '.join(sorted(allowed))}"
        )
    new_reasons = current["observable_reasons"] if reasons is None else sorted(set(reasons))
    new_ids = current["observable_policy_ids"] if policy_ids is None else sorted(set(policy_ids))
    row = fetchone(
        ctx.conn,
        "UPDATE mint.settings SET observable_reasons = %s, observable_policy_ids = %s"
        " WHERE instance_id = %s RETURNING settings_version",
        (new_reasons, new_ids, ctx.instance_id),
    )
    _changed(ctx, row, {"observable_reasons": new_reasons, "observable_policy_ids": new_ids})


def control_key_token(key: str) -> str:
    """LiteLLM이 키 객체에 쓰는 토큰(키의 SHA-256 16진수)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def set_control_key(ctx: Context, key: str | None, *, keep_existing: bool = False) -> str:
    """제어 평면 키의 토큰을 정한다(``None``이면 해제). 결과는 ``set``·``cleared``·``differs``이다.

    ``keep_existing``이면 이미 값이 있을 때 바꾸지 않는다. 같은 키면 ``set``, 다른 키면
    ``differs``를 돌려준다(``init`` 재실행이 운영자가 바꾼 값을 덮지 않는다).
    """
    current = load(ctx.conn, ctx.instance_id, lock=True)["control_key_token"]
    token = None if key is None else control_key_token(key)
    if keep_existing and current is not None:
        return "set" if current == token else "differs"
    state = "set" if token else "cleared"
    if token == current:
        return state
    row = fetchone(
        ctx.conn,
        "UPDATE mint.settings SET control_key_token = %s WHERE instance_id = %s"
        " RETURNING settings_version",
        (token, ctx.instance_id),
    )
    _changed(ctx, row, {"control_key": state})
    return state
