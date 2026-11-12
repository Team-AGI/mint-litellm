"""권한 동기화의 계산과 기록: 원하는 상태, 소유 항목, 쓸 전체 목록, ``litellm_grants`` 행.

원하는 상태는 따로 저장하지 않는다. 작업이 실행될 때 DB에서 계산한다. LiteLLM은 키·팀의
``mcp_servers``와 ``mcp_tool_permissions``를 각각 통째로 바꾸므로 쓸 값은 언제나 전체 목록·맵이고,
MINT가 넣지 않은 항목은 그대로 둔다.

``litellm_grants`` 행의 뜻(대상 하나·항목 하나·서버 하나):

- ``observed``가 NULL이면 MINT가 관리하지 않는 행(철회로 거둔 뒤)이다. NULL이 아니면 MINT가 반영한
  항목이다(참: 마지막 확인에 LiteLLM에 있었다, 거짓: 없다고 보았거나 보류 중).
- ``preexisting``이 참이면 MINT가 쓰기 전에 이미 있던 항목이라 철회해도 지우지 않는다.
- ``tool_permission`` 행의 ``tools``는 MINT가 더한 도구뿐이다(원래 있던 도구는 넣지 않는다).
"""

from dataclasses import dataclass, field
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.types.canonical import credential_scope, sha256
from mint_litellm.types.ids import new_uuid7

ACTOR = "mint-worker"
SYNC_SCOPES = ("key", "team")


def target_ref(kind: str, target_id: str) -> str:
    return f"{kind}:{target_id}"


def split_ref(ref: str) -> tuple[str, str]:
    kind, _, target_id = ref.partition(":")
    if kind not in SYNC_SCOPES or not target_id:
        raise ValueError(f"동기화 대상 형식이 올바르지 않습니다: {ref}")
    return kind, target_id


# --- 원하는 상태 ----------------------------------------------------------------


@dataclass(frozen=True)
class Desired:
    servers: frozenset[str]
    tools: dict[str, frozenset[str]]
    # 이 계산에 들어간 승인(활성과 대기)
    approvals: tuple[str, ...] = ()


def server_scope(conn: psycopg.Connection, instance_id: str, server_id: str) -> str | None:
    """계약을 관리하는 서버의 자격 범위 하나(배포 계약의 인증 방식에서). 관리 서버가 아니면 None."""
    row = fetchone(
        conn,
        "SELECT auth_type FROM mint.servers WHERE instance_id = %s AND server_id = %s"
        " AND contract_status = 'managed'",
        (instance_id, server_id),
    )
    return None if row is None else credential_scope(row["auth_type"])


def expected_pin(
    conn: psycopg.Connection, instance_id: str, server_id: str, *, lock: bool = False
) -> dict[str, str] | None:
    """계약을 관리하는 서버의 승인 계약 ``{도구: pin 해시}``(그 서버의 자격 범위 하나만).

    관리 서버가 아니면 None, 승인 계약이 하나도 없으면 빈 맵이다.
    """
    scope = server_scope(conn, instance_id, server_id)
    if scope is None:
        return None
    rows = fetchall(
        conn,
        "SELECT tool, pin_sha256 FROM mint.tool_contracts WHERE instance_id = %s"
        " AND server_id = %s AND credential_scope = %s AND status = 'approved' ORDER BY tool"
        + (" FOR SHARE" if lock else ""),
        (instance_id, server_id, scope),
    )
    return {r["tool"]: r["pin_sha256"] for r in rows}


def pin_satisfied(
    conn: psycopg.Connection, instance_id: str, server_id: str, *, lock: bool = False
) -> bool:
    """서버의 고정(pin)이 승인 계약과 맞는가. 계약을 관리하지 않는 서버는 언제나 참이다.

    맞다는 것은 ``observed``이고 ``applied_sha256``이 승인 계약의 해시 맵과 같다는 뜻이다.
    승인 계약이 하나도 없는 관리 서버는 거짓이다(활성화하지 않는다). ``lock``이면 승인 계약 행을
    공유 잠금, 고정 행을 갱신 잠금으로 읽는다(활성화 트랜잭션 안에서 다시 확인할 때).
    """
    expected = expected_pin(conn, instance_id, server_id, lock=lock)
    if expected is None:
        return True
    if not expected:
        return False
    row = fetchone(
        conn,
        "SELECT observed, applied_sha256 FROM mint.litellm_grants WHERE instance_id = %s"
        " AND target_type = 'server' AND target_id = %s AND item = 'pin' AND server_id = %s"
        + (" FOR UPDATE" if lock else ""),
        (instance_id, server_id, server_id),
    )
    return bool(row and row["observed"] is True and row["applied_sha256"] == sha256(expected))


def desired_for_target(
    conn: psycopg.Connection, instance_id: str, scope_type: str, scope_id: str
) -> Desired:
    """대상(키·팀)의 활성 승인과, 고정이 맞는 대기 승인에서 원하는 서버·도구를 계산한다.

    활성 승인은 지금 유효 기간 안일 때만 센다(기간 밖의 권한을 LiteLLM에 열어 두지 않는다).
    """
    rows = fetchall(
        conn,
        "SELECT a.id, a.server_id, a.tools, a.status FROM mint.approvals a"
        " JOIN mint.servers s ON s.instance_id = a.instance_id AND s.server_id = a.server_id"
        " WHERE a.instance_id = %s AND a.scope_type = %s AND a.scope_id = %s"
        " AND s.identity_kind = 'remote' AND ("  # 로컬 서버는 LiteLLM 권한으로 옮기지 않는다
        " (a.status = 'active' AND a.valid_from <= now() AND a.valid_until > now())"
        " OR (a.status = 'pending' AND a.valid_until > now()))",
        (instance_id, scope_type, scope_id),
    )
    servers: set[str] = set()
    tools: dict[str, set[str]] = {}
    ids: list[str] = []
    for row in rows:
        if row["status"] == "pending" and not pin_satisfied(conn, instance_id, row["server_id"]):
            continue
        servers.add(row["server_id"])
        tools.setdefault(row["server_id"], set()).update(row["tools"])
        ids.append(str(row["id"]))
    return Desired(
        frozenset(servers), {s: frozenset(t) for s, t in tools.items()}, tuple(sorted(ids))
    )


# --- 계획 ---------------------------------------------------------------------


@dataclass
class Item:
    item: str  # mcp_server | tool_permission
    server_id: str
    preexisting: bool
    tools: list[str] | None  # tool_permission: MINT가 더하는(철회면 거두는) 도구
    want: bool  # 참이면 반영할 항목, 거짓이면 거둘 항목
    want_tools: frozenset[str] = frozenset()


@dataclass
class Plan:
    servers: list[str]
    tools: dict[str, list[str]]
    changed: bool
    items: list[Item] = field(default_factory=list)


def _normalise(tools: dict[str, Any]) -> dict[str, list[str]]:
    return {k: sorted(set(v)) for k, v in tools.items()}


def make_plan(
    current_servers: list[str],
    current_tools: dict[str, list[str]],
    desired: Desired,
    rows: list[dict],
) -> Plan:
    """LiteLLM의 현재 값과 MINT 소유 행에서 쓸 전체 목록·맵을 계산한다(순수 함수).

    MINT 소유 항목만 원하는 상태로 맞추고, 보류(``held``)된 항목은 더하지도 거두지도 않는다.
    """
    active = {(r["item"], r["server_id"]): r for r in rows if r["observed"] is not None}
    held = {key for key, r in active.items() if r["held"]}
    servers = list(current_servers)
    items: list[Item] = []

    for (item, server_id), row in sorted(active.items()):
        if item != "mcp_server" or (item, server_id) in held or server_id in desired.servers:
            continue
        items.append(Item(item, server_id, row["preexisting"], None, want=False))
        if not row["preexisting"]:
            servers = [s for s in servers if s != server_id]
    for server_id in sorted(desired.servers):
        if ("mcp_server", server_id) in held:
            continue
        row = active.get(("mcp_server", server_id))
        preexisting = row["preexisting"] if row else server_id in current_servers
        items.append(Item("mcp_server", server_id, preexisting, None, want=True))
        if server_id not in servers:
            servers.append(server_id)

    tools = {k: list(v) for k, v in current_tools.items()}
    touched = {s for (i, s) in active if i == "tool_permission"} | set(desired.tools)
    for server_id in sorted(touched):
        if ("tool_permission", server_id) in held:
            continue
        row = active.get(("tool_permission", server_id))
        owned = set(row["tools"] or ()) if row else set()
        base = set(current_tools.get(server_id, ())) - owned
        want = set(desired.tools.get(server_id, ()))
        preexisting = row["preexisting"] if row else server_id in current_tools
        entry = base | want
        if entry:
            tools[server_id] = sorted(entry)
        elif row is not None and preexisting:
            tools[server_id] = []  # 원래 빈 항목이 있었다
        else:
            tools.pop(server_id, None)
        if want:
            items.append(
                Item("tool_permission", server_id, preexisting, sorted(want - base), True,
                     frozenset(want))
            )
        elif row is not None:
            items.append(Item("tool_permission", server_id, preexisting, sorted(owned), False))

    changed = sorted(set(servers)) != sorted(set(current_servers)) or _normalise(
        tools
    ) != _normalise(current_tools)
    return Plan(servers, tools, changed, items)


def present(item: Item, servers: list[str], tools: dict[str, list[str]]) -> bool:
    """항목이 이 값에 반영되어 있는가(``want``면 있어야, 아니면 MINT가 더한 것이 없어야 참)."""
    if item.item == "mcp_server":
        return (item.server_id in servers) == item.want
    have = set(tools.get(item.server_id, ()))
    if item.want:
        return item.want_tools <= have
    return not (set(item.tools or ()) & have)


def permission_of(record: dict | None) -> tuple[list[str], dict[str, list[str]]]:
    permission = (record or {}).get("object_permission") or {}
    return (
        list(permission.get("mcp_servers") or []),
        {k: list(v) for k, v in (permission.get("mcp_tool_permissions") or {}).items()},
    )


# --- 행 --------------------------------------------------------------------------


def load_rows(
    conn: psycopg.Connection,
    instance_id: str,
    target_type: str,
    target_id: str,
    *,
    lock: bool = False,
) -> list[dict]:
    """대상의 행. ``lock``이면 행을 잠그고 읽는다(트랜잭션 안에서 갱신 직전에 다시 읽을 때)."""
    return fetchall(
        conn,
        "SELECT * FROM mint.litellm_grants WHERE instance_id = %s AND target_type = %s"
        " AND target_id = %s" + (" ORDER BY id FOR UPDATE" if lock else ""),
        (instance_id, target_type, target_id),
    )


def mark_observed(conn: psycopg.Connection, grant_id: Any) -> dict:
    """원하는 항목이 이미 LiteLLM에 있음을 확인했다(쓰기 직후 확인이 늦어 남은 행을 바로잡는다)."""
    return fetchone(
        conn,
        "UPDATE mint.litellm_grants SET observed = true, observed_at = now(),"
        " last_applied_at = now() WHERE id = %s"
        " RETURNING id, state_version",
        (grant_id,),
    )


def upsert_grant(
    conn: psycopg.Connection,
    instance_id: str,
    target_type: str,
    target_id: str,
    item: str,
    server_id: str,
    *,
    tools: list[str] | None,
    preexisting: bool,
    observed: bool | None,
    applied: bool = False,
    applied_sha256: str | None = None,
) -> dict:
    """행을 만들거나 바꾼다. 관리하지 않던 행(``observed`` NULL)을 되살리면 카운터를 지운다."""
    return fetchone(
        conn,
        "INSERT INTO mint.litellm_grants (id, instance_id, target_type, target_id, item,"
        " server_id, tools, preexisting, observed, observed_at, last_applied_at, applied_sha256)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now(), CASE WHEN %s THEN now() END, %s)"
        " ON CONFLICT (instance_id, target_type, target_id, item, server_id) DO UPDATE SET"
        " tools = EXCLUDED.tools, preexisting = EXCLUDED.preexisting,"
        " observed = EXCLUDED.observed, observed_at = now(),"
        " applied_sha256 = EXCLUDED.applied_sha256,"
        " last_applied_at = CASE WHEN %s THEN now() ELSE mint.litellm_grants.last_applied_at END,"
        " missing_count = CASE WHEN mint.litellm_grants.observed IS NULL THEN 0"
        "  ELSE mint.litellm_grants.missing_count END,"
        " missing_window_start = CASE WHEN mint.litellm_grants.observed IS NULL THEN NULL"
        "  ELSE mint.litellm_grants.missing_window_start END,"
        " held = CASE WHEN mint.litellm_grants.observed IS NULL THEN false"
        "  ELSE mint.litellm_grants.held END,"
        " held_at = CASE WHEN mint.litellm_grants.observed IS NULL THEN NULL"
        "  ELSE mint.litellm_grants.held_at END"
        " RETURNING id, state_version",
        (new_uuid7(), instance_id, target_type, target_id, item, server_id, tools, preexisting,
         observed, applied, applied_sha256, applied),
    )


def withdraw_grant(conn: psycopg.Connection, grant_id: Any) -> dict:
    """MINT가 더 이상 관리하지 않는 행으로 만든다(항목은 LiteLLM에서 이미 거뒀거나 원래 있던 것)."""
    return fetchone(
        conn,
        "UPDATE mint.litellm_grants SET observed = NULL, tools = NULL, preexisting = false,"
        " observed_at = now(), missing_count = 0, missing_window_start = NULL, held = false,"
        " held_at = NULL WHERE id = %s RETURNING id, state_version",
        (grant_id,),
    )


def reset_counters(
    conn: psycopg.Connection,
    instance_id: str,
    target_type: str,
    target_id: str,
    server_id: str | None = None,
) -> int:
    """철회·새 승인·``sync resume``: 외부 삭제 카운터와 보류를 지운다."""
    return conn.execute(
        "UPDATE mint.litellm_grants SET missing_count = 0, missing_window_start = NULL,"
        " held = false, held_at = NULL WHERE instance_id = %s AND target_type = %s"
        " AND target_id = %s AND (%s::text IS NULL OR server_id = %s)"
        " AND (missing_count > 0 OR held OR missing_window_start IS NOT NULL)",
        (instance_id, target_type, target_id, server_id, server_id),
    ).rowcount
