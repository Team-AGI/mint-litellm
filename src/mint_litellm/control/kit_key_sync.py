"""단말 게이트웨이 MCP 키의 LiteLLM 서버 권한: MINT 승인에서 계산해 키에 쓴다.

게이트웨이 키는 MINT가 만들어 단말에 둔 키라 키의 서버 권한 전부를 MINT가 소유한다. 그 사용자·팀·
키(·조직)에 적용되는 활성 승인(원격 서버, 지금 유효 기간 안, 서버가 활성)의 서버와 도구를 그대로
``object_permission``으로 쓴다. 승인이 없으면 빈 권한이라 LiteLLM이 모든 호출을 막는다.
"""

import psycopg

from mint_litellm.control.db.connection import fetchall
from mint_litellm.control.litellm_write import LiteLLMSync
from mint_litellm.control.sync_state import permission_of

Permission = tuple[list[str], dict[str, list[str]]]

_APPLICABLE = """
SELECT a.server_id, a.tools FROM mint.approvals a
JOIN mint.servers s ON s.instance_id = a.instance_id AND s.server_id = a.server_id
WHERE a.instance_id = %(iid)s AND a.status = 'active'
  AND a.valid_from <= now() AND a.valid_until > now()
  AND s.identity_kind = 'remote' AND s.status = 'approved'
  AND ((a.scope_type = 'key' AND a.scope_id = %(key)s)
    OR (a.scope_type = 'user' AND a.scope_id = %(user)s)
    OR (a.scope_type = 'team' AND a.scope_id = %(team)s)
    OR (a.scope_type = 'org' AND a.scope_id IN (
        SELECT org_id FROM mint.org_bindings WHERE instance_id = %(iid)s
          AND ((subject_type = 'team' AND subject_id = %(team)s)
            OR (subject_type = 'user' AND subject_id = %(user)s))
        UNION SELECT default_org_id FROM mint.settings
          WHERE instance_id = %(iid)s AND default_org_id IS NOT NULL)))
ORDER BY a.server_id
"""


def desired_permission(
    conn: psycopg.Connection, instance_id: str, user_id: str, team_id: str | None, key_token: str
) -> Permission:
    """사용자·팀·키 범위의 활성 승인에서 게이트웨이 키가 가져야 할 서버 목록과 도구 맵."""
    servers: list[str] = []
    tools: dict[str, set[str]] = {}
    for row in fetchall(
        conn, _APPLICABLE,
        {"iid": instance_id, "key": key_token, "user": user_id, "team": team_id or ""},
    ):
        if row["server_id"] not in servers:
            servers.append(row["server_id"])
        tools.setdefault(row["server_id"], set()).update(row["tools"] or ())
    return servers, {s: sorted(t) for s, t in tools.items() if t}


def sync_kit_keys(conn: psycopg.Connection, instance_id: str, client: LiteLLMSync) -> int:
    """활성 설치마다 게이트웨이 키의 권한을 승인에 맞춘다. 바꾼 키 수를 돌려준다."""
    rows = fetchall(
        conn,
        "SELECT user_id, team_id, mcp_key_token FROM mint.endpoint_installs"
        " WHERE instance_id = %s AND revoked_at IS NULL AND mcp_key_token IS NOT NULL",
        (instance_id,),
    )
    changed = 0
    for row in rows:
        servers, tools = desired_permission(
            conn, instance_id, row["user_id"], row["team_id"], row["mcp_key_token"]
        )
        current = client.get_key(row["mcp_key_token"])
        if current is None:
            continue  # LiteLLM에서 지워진 키(해제 중)
        servers, tools = _within_team(client, row["team_id"], servers, tools)
        have_servers, have_tools = permission_of(current)
        if sorted(have_servers) == sorted(servers) and {
            k: sorted(v) for k, v in have_tools.items()
        } == tools:
            continue
        client.update_key_permission(row["mcp_key_token"], servers, tools)
        changed += 1
    return changed


def _within_team(
    client: LiteLLMSync, team_id: str | None, servers: list[str], tools: dict[str, list[str]]
) -> Permission:
    """LiteLLM은 팀이 서버 목록을 정해 두었으면 팀 소속 키에 그 안의 서버만 준다."""
    allowed = permission_of(client.get_team(team_id) if team_id else None)[0]
    if not allowed:
        return servers, tools
    return [s for s in servers if s in allowed], {k: v for k, v in tools.items() if k in allowed}

