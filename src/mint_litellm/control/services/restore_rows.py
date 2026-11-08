"""복원: 파일의 행 스냅숏으로 복구 DB의 부정 상태 행을 되돌린다.

없는 행은 같은 id로 그대로 다시 넣고(철회 이력·종료 관계·거부 사유 등 차단 근거 보존),
``state_version``이나 상태가 파일보다 뒤처진 행은 파일 내용으로 되돌린다. 새 행은 표의 상태
트리거가 허용하는 처음 상태로 넣은 뒤 허용된 전이를 따라 파일의 상태까지 옮긴다. 이미 맞는 행은
건드리지 않으므로 반복해도 같은 결과다(멱등).
"""

from collections import deque
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from mint_litellm.control.db.connection import fetchone

# 종류 -> (표, 식별 열, 상태 열, 처음 상태, 전이)
_META: dict[str, tuple[str, str, str | None, str | None, dict[str, list[str]]]] = {
    "org": ("orgs", "org_id", "status", "active", {"active": ["closed"]}),
    "server": ("servers", "server_id", "status", "awaiting_approval", {
        "awaiting_approval": ["approved", "rejected"],
        "approved": ["suspended", "terminating"],
        "suspended": ["approved", "terminating"],
        "terminating": ["terminated"],
    }),
    "relation": ("usage_relations", "id", "status", "active",
                 {"active": ["terminating"], "terminating": ["terminated"]}),
    "allowlist": ("allowlists", "id", "status", "active", {"active": ["lifted"]}),
    "approval": ("approvals", "id", "status", "active", {"active": ["revoked"]}),
    "denial": ("denials", "id", None, None, {}),
    "consent": ("consents", "id", None, None, {}),
    "operator": ("operators", "name", None, None, {}),
}
# 부모 행을 먼저 되돌린다.
ORDER = ("org", "server", "relation", "allowlist", "approval", "denial", "consent", "operator")
_ONCE = {  # 상태 전이와 함께 채우는 한 번 쓰기 열
    "approval": ("revoked_at", "revoke_reason"),
}
MAX_VERSION_STEPS = 1000


def _rank(role: str) -> int:
    return {"admin": 3, "approver": 2}.get(role, 1)


def _path(graph: dict[str, list[str]], start: str, goal: str) -> list[str] | None:
    seen, queue = {start: None}, deque([start])
    while queue:
        node = queue.popleft()
        if node == goal:
            steps: list[str] = []
            while seen[node] is not None:
                steps.append(node)
                node = seen[node]
            return steps[::-1]
        for nxt in graph.get(node, []):
            if nxt not in seen:
                seen[nxt] = node
                queue.append(nxt)
    return None


def _current(conn: psycopg.Connection, instance_id: str, kind: str, ident: str):
    table, column, *_ = _META[kind]
    row = fetchone(
        conn,
        f"SELECT to_jsonb(t) AS row FROM mint.{table} t"
        f" WHERE t.instance_id = %s AND t.{column}::text = %s",
        (instance_id, ident),
    )
    return None if row is None else row["row"]


def _insert(conn: psycopg.Connection, kind: str, snapshot: dict[str, Any]) -> None:
    table, _, status, initial, _graph = _META[kind]
    row = dict(snapshot)
    if status is not None:
        row[status] = initial
        for column in _ONCE.get(kind, ()):
            row[column] = None
    conn.execute(
        f"INSERT INTO mint.{table} SELECT * FROM jsonb_populate_record(NULL::mint.{table}, %s)",
        (Jsonb(row),),
    )


def _move(conn, instance_id: str, kind: str, ident: str, current: str, goal: str, snap) -> None:
    table, column, status, _initial, graph = _META[kind]
    steps = _path(graph, current, goal)
    if steps is None:
        raise ValueError(f"{kind} {ident}: {current}에서 {goal}로 옮길 수 없습니다.")
    for step in steps:
        sets, params = [f"{status} = %s"], [step]
        if step == goal:
            for once in _ONCE.get(kind, ()):
                sets.append(f"{once} = %s")
                params.append(snap.get(once))
        conn.execute(
            f"UPDATE mint.{table} SET {', '.join(sets)}"
            f" WHERE instance_id = %s AND {column}::text = %s",
            (*params, instance_id, ident),
        )


def restore_item(conn: psycopg.Connection, instance_id: str, item: dict[str, Any]) -> bool:
    """항목 하나를 되돌린다. 바꾼 것이 있으면 참이다. 되돌릴 수 없으면 예외를 낸다."""
    kind, ident, snap = item["kind"], item["id"], item["row"]
    table, column, status, _initial, _graph = _META[kind]
    current = _current(conn, instance_id, kind, ident)
    changed = False
    if current is None:
        _insert(conn, kind, snap)
        current = _current(conn, instance_id, kind, ident)
        changed = True
    if status is not None:
        if current[status] != snap[status]:
            _move(conn, instance_id, kind, ident, current[status], snap[status], snap)
            changed = True
    elif kind == "consent":
        if current["revoked_at"] is None:
            conn.execute(
                "UPDATE mint.consents SET revoked_at = %s WHERE instance_id = %s AND id::text = %s",
                (snap["revoked_at"], instance_id, ident),
            )
            changed = True
    elif kind == "operator":
        # 파일보다 권한이 높은 열만 파일 값으로 낮춘다(역할은 낮출 때만, 만료는 앞당길 때만).
        # 이미 낮거나 같은 쪽은 그대로 둔다.
        if _rank(current["role"]) > _rank(snap["role"]):
            conn.execute(
                "UPDATE mint.operators SET role = %s WHERE instance_id = %s AND name = %s",
                (snap["role"], instance_id, ident),
            )
            changed = True
        if snap["expires_at"] is not None:
            moved = conn.execute(
                "UPDATE mint.operators SET expires_at = %s::timestamptz"
                " WHERE instance_id = %s AND name = %s AND (expires_at IS NULL"
                " OR expires_at > %s::timestamptz)",
                (snap["expires_at"], instance_id, ident, snap["expires_at"]),
            )
            changed = changed or moved.rowcount > 0
    elif kind == "denial" and current["lifted_at"] is not None:
        raise ValueError(f"denial {ident}: 이미 해제된 거부는 다시 걸 수 없습니다.")
    # 상태 버전이 파일보다 뒤처지면 값 변경 없는 갱신으로 올린다(트리거가 한 칸씩 올린다).
    for _ in range(MAX_VERSION_STEPS):
        now = _current(conn, instance_id, kind, ident)["state_version"]
        if now >= item["state_version"]:
            break
        conn.execute(
            f"UPDATE mint.{table} SET {column} = {column} WHERE instance_id = %s"
            f" AND {column}::text = %s",
            (instance_id, ident),
        )
        changed = True
    return changed
