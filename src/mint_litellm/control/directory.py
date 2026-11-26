"""사람 명부: 비밀번호·개인 키·SSO가 모두 같은 LiteLLM 사용자 한 사람에 닿게 한다.

LiteLLM이 사용자·팀·키의 정본이고 이 명부는 로그인 때와 주기 동기화 때
읽어 온 사본이다. 사람이 입력할 것은 없다. LiteLLM ``proxy_admin``은
로그인하면 MINT 관리자 행을 자동으로 받고, 그 밖의 사람은 운영자 행 없이
직원 화면으로 들어간다. 이미 정해진 운영자 행(사람이 만들었거나 지운 것)은
그대로 둔다. 자동으로 만든 행은 LiteLLM 역할이 내려가면 거둔다. 팀 이동·키
폐기는 다음 로그인이나 동기화에서 사본에 반영하고, 세션은 기존 세션
재확인이 끊는다.
"""

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import psycopg

from mint_litellm.control import ledger, operators
from mint_litellm.control.context import Context, Operator
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.litellm_admin import LiteLLMAdmin
from mint_litellm.control.services import console_sessions
from mint_litellm.control.services.base import enqueue_job
from mint_litellm.types.cli_commands import OperatorRole
from mint_litellm.types.events import EventKind

log = logging.getLogger(__name__)

ACTOR = "directory"
ADMIN_ROLE = "proxy_admin"
# LiteLLM이 화면 세션용으로 만드는 키의 팀. 사람의 개인 키가 아니다.
DASHBOARD_TEAM = "litellm-dashboard"
SYNC_INTERVAL = timedelta(minutes=15)
# 점검 작업이 5분마다 돌아 「15분 미만이면 건너뜀」만으로는 15분에서 몇 초 모자란
# 차례를 놓쳐 20분이 된다(QA-BUG-304).
SYNC_SLACK = timedelta(seconds=60)


def kind_of(key_token: str) -> str:
    """콘솔 세션의 key_token으로 본 로그인 수단."""
    if key_token.startswith(console_sessions.PASSWORD_PREFIX):
        return "password"
    if key_token.startswith(console_sessions.SSO_PREFIX):
        return "sso"
    return "key"


def _teams(user: dict) -> list[str]:
    return list(console_sessions.teams_of_user(user))


def _upsert_user(
    conn: psycopg.Connection, instance_id: str, user_id: str, user: dict, teams: list[str]
) -> dict:
    return fetchone(
        conn,
        "INSERT INTO mint.directory_users (instance_id, user_id, email, litellm_role, team_ids)"
        " VALUES (%s, %s, %s, %s, %s::jsonb)"
        " ON CONFLICT (instance_id, user_id) DO UPDATE SET email = EXCLUDED.email,"
        " litellm_role = EXCLUDED.litellm_role, team_ids = EXCLUDED.team_ids,"
        " gone_at = NULL, synced_at = now()"
        " RETURNING litellm_role, auto_operator",
        (instance_id, user_id, user.get("user_email") or None,
         user.get("user_role") or "internal_user", json.dumps(teams)),
    )


def _operator_name(conn: psycopg.Connection, instance_id: str, user_id: str, email: str | None):
    base = re.sub(r"[^A-Za-z0-9._-]", "-", email or user_id).strip("-._")[:100] or "user"
    if not base[0].isalnum():
        base = "u" + base
    name, n = base, 1
    while fetchone(
        conn, "SELECT 1 AS x FROM mint.operators WHERE instance_id = %s AND name = %s",
        (instance_id, name),
    ):
        n += 1
        name = f"{base}-{n}"
    return name


def _reconcile_operator(
    conn: psycopg.Connection, instance_id: str, user_id: str, email: str | None, role: str,
    auto_name: str | None,
) -> str | None:
    """LiteLLM 역할에 맞춰 자동 운영자 행을 만들거나 거둔다. 자동 행의 이름(없으면 None)."""
    rows = fetchall(
        conn,
        "SELECT name, state_version, (expires_at IS NULL OR expires_at > now()) AS active"
        " FROM mint.operators WHERE instance_id = %s AND user_id = %s",
        (instance_id, user_id),
    )
    if role == ADMIN_ROLE:
        if rows:  # 이미 정한 MINT 역할(사람이 만들었거나 지운 것)은 유지한다
            return auto_name
        name = _operator_name(conn, instance_id, user_id, email)
        operators._insert(conn, instance_id, ACTOR, name, OperatorRole.ADMIN, user_id, None)
        return name
    mine = next((r for r in rows if r["name"] == auto_name and r["active"]), None)
    if mine is None:
        return None
    others = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.operators WHERE instance_id = %s AND role = 'admin'"
        " AND name <> %s AND (expires_at IS NULL OR expires_at > now())",
        (instance_id, auto_name),
    )
    if not others["n"]:  # 마지막 관리자는 거두지 않는다
        return auto_name
    row = fetchone(
        conn,
        "UPDATE mint.operators SET expires_at = now() WHERE instance_id = %s AND name = %s"
        " RETURNING state_version",
        (instance_id, auto_name),
    )
    ledger.record(
        conn, instance_id, EventKind.OPERATOR_REMOVED, entity_id=auto_name,
        state_version=row["state_version"], actor=ACTOR,
        payload={"name": auto_name, "user_id": user_id, "reason": "litellm_role_changed"},
    )
    console_sessions.revoke_user_sessions(
        conn, instance_id, user_id, actor=ACTOR, reason="operator_changed"
    )
    return None


def _sync_operator(
    conn: psycopg.Connection, instance_id: str, user_id: str, row: dict, user: dict
) -> None:
    auto = _reconcile_operator(
        conn, instance_id, user_id, user.get("user_email"), row["litellm_role"],
        row["auto_operator"],
    )
    if auto != row["auto_operator"]:
        conn.execute(
            "UPDATE mint.directory_users SET auto_operator = %s WHERE instance_id = %s"
            " AND user_id = %s", (auto, instance_id, user_id),
        )


def record_login(
    conn: psycopg.Connection, instance_id: str, user_id: str, key_token: str, user: dict,
    team_ids: tuple[str, ...] | None = None,
) -> None:
    """로그인에 쓴 자격을 그 사람에 잇고 LiteLLM 사용자·팀·역할을 사본에 맞춘다.

    세션을 열기 전에 불러, 운영자 행이 없는 LiteLLM 관리자도 첫 로그인에 들어온다."""
    with conn.transaction():
        teams = list(team_ids) if team_ids else _teams(user)
        row = _upsert_user(conn, instance_id, user_id, user, teams)
        conn.execute(
            "INSERT INTO mint.directory_credentials (instance_id, kind, ref, user_id,"
            " last_login_at) VALUES (%s, %s, %s, %s, now())"
            " ON CONFLICT (instance_id, kind, ref) DO UPDATE SET user_id = EXCLUDED.user_id,"
            " last_login_at = now(), gone_at = NULL",
            (instance_id, kind_of(key_token), key_token, user_id),
        )
        _sync_operator(conn, instance_id, user_id, row, user)


def _follow_team(conn: psycopg.Connection, instance_id: str, user_id: str, ids: list[str]) -> int:
    """그 사람의 살아 있는 단말 설치·앱 행의 팀을 지금 소속에 맞춘다.

    아직 소속이면 그대로 두고, 아니면 현재 팀 중 첫째(없으면 비움)로 바꾼다. 바뀐 행 수를 돌려준다.
    """
    first = ids[0] if ids else None
    changed = 0
    for table in ("endpoint_installs", "endpoint_apps"):
        changed += conn.execute(
            f"UPDATE mint.{table} SET team_id = %s WHERE instance_id = %s AND user_id = %s"
            " AND revoked_at IS NULL AND team_id IS DISTINCT FROM %s"
            " AND (team_id IS NULL OR NOT (team_id = ANY(%s)))",
            (first, instance_id, user_id, first, ids),
        ).rowcount
    return changed


@dataclass(frozen=True)
class SyncResult:
    users: int
    keys: int
    gone_users: int
    gone_keys: int


def sync(conn: psycopg.Connection, instance_id: str, admin: LiteLLMAdmin) -> SyncResult:
    """LiteLLM 사용자·팀·키를 끝까지 읽어 명부에 맞춘다.

    읽기가 한 번이라도 실패하면 예외가 그대로 나가 아무것도 지우지 않는다.
    """
    users = admin.list_users()
    teams = admin.list_teams()
    keys = admin.list_keys()
    members: dict[str, set[str]] = {}
    for team in teams:
        for member in team.get("members_with_roles") or []:
            uid = member.get("user_id") if isinstance(member, dict) else None
            if isinstance(uid, str) and uid:
                members.setdefault(uid, set()).add(str(team.get("team_id")))
    humans = {
        u["user_id"]: u for u in users
        if isinstance(u.get("user_id"), str) and u.get("user_role") in operators.HUMAN_ROLES
        and u["user_id"] not in operators.SERVICE_ACCOUNTS  # 배포 서비스 계정은 사람이 아니다
    }
    moved = 0
    with conn.transaction():
        for user_id, user in humans.items():
            ids = sorted({*_teams(user), *members.get(user_id, ())} - {DASHBOARD_TEAM})
            row = _upsert_user(conn, instance_id, user_id, user, ids)
            _sync_operator(conn, instance_id, user_id, row, user)
            moved += _follow_team(conn, instance_id, user_id, ids)
        listed = {
            k["token"] for k in keys
            if isinstance(k.get("token"), str) and k.get("user_id") in humans
            and k.get("team_id") != DASHBOARD_TEAM and not k.get("blocked")
        }
        for key in keys:
            if key.get("token") in listed:
                conn.execute(
                    "INSERT INTO mint.directory_credentials (instance_id, kind, ref, user_id)"
                    " VALUES (%s, 'key', %s, %s) ON CONFLICT (instance_id, kind, ref)"
                    " DO UPDATE SET user_id = EXCLUDED.user_id, gone_at = NULL",
                    (instance_id, key["token"], key["user_id"]),
                )
        gone_keys = conn.execute(
            "UPDATE mint.directory_credentials SET gone_at = now() WHERE instance_id = %s"
            " AND kind = 'key' AND gone_at IS NULL AND NOT (ref = ANY(%s))",
            (instance_id, sorted(listed)),
        ).rowcount
        # 사용자 목록이 비어 있으면 읽기 이상으로 보고 아무도 지우지 않는다
        gone_users = 0
        if humans:
            gone_users = conn.execute(
                "UPDATE mint.directory_users SET gone_at = now() WHERE instance_id = %s"
                " AND gone_at IS NULL AND NOT (user_id = ANY(%s))",
                (instance_id, sorted(humans)),
            ).rowcount
            # 명부에서 빠진 사람은 팀 범위도 잃는다
            for table in ("endpoint_installs", "endpoint_apps"):
                moved += conn.execute(
                    f"UPDATE mint.{table} SET team_id = NULL WHERE instance_id = %s"
                    " AND revoked_at IS NULL AND team_id IS NOT NULL AND NOT (user_id = ANY(%s))",
                    (instance_id, sorted(humans)),
                ).rowcount
        if moved:  # 단말 게이트웨이 키의 권한도 새 팀으로 다시 맞춘다
            enqueue_job(
                Context(conn, instance_id, Operator("directory", "system", None)),
                "kit_key_sync", "all",
            )
    return SyncResult(len(humans), len(listed), gone_users, gone_keys)


def sync_if_due(
    conn: psycopg.Connection, instance_id: str, admin: LiteLLMAdmin
) -> SyncResult | None:
    """마지막 동기화가 오래됐을 때만 ``sync``를 돌린다."""
    last = fetchone(
        conn, "SELECT max(synced_at) AS at FROM mint.directory_users WHERE instance_id = %s",
        (instance_id,),
    )["at"]
    if last is not None and datetime.now(UTC) - last < SYNC_INTERVAL - SYNC_SLACK:
        return None
    return sync(conn, instance_id, admin)


def credentials_of(conn: psycopg.Connection, instance_id: str, user_id: str) -> list[dict]:
    """그 사람에 이어진 자격(수단·참조·마지막 로그인·사라진 시각)."""
    return fetchall(
        conn,
        "SELECT kind, ref, last_login_at, gone_at FROM mint.directory_credentials"
        " WHERE instance_id = %s AND user_id = %s ORDER BY kind, first_seen_at",
        (instance_id, user_id),
    )
