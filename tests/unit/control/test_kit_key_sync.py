"""단말 게이트웨이 키의 서버 권한: 승인에서 계산해 키에 쓰고, 승인이 바뀌면 다시 맞춘다.

MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import hashlib

import pytest
from ctl_fixtures import INSTANCE

pytest.importorskip("psycopg")

from mint_litellm.control import endpoint_kits, kit_key_sync  # noqa: E402
from mint_litellm.control.services import orgs, relations  # noqa: E402
from mint_litellm.control.services import servers as services  # noqa: E402


class Issuer:
    def __init__(self):
        self.made = []

    def generate_kit_key(self, *, user_id, team_id, alias, permission=None):
        self.made.append((alias, permission))
        return f"sk-{alias}"

    def delete_kit_keys(self, aliases):
        pass


class Client:
    """LiteLLM 관리 클라이언트 대역: 키 하나와 팀 하나."""

    def __init__(self, team=None):
        self.key = {"object_permission": {}}
        self.team = team
        self.written = []

    def get_key(self, token):
        return self.key

    def get_team(self, team_id):
        return self.team

    def update_key_permission(self, token, servers, tools):
        self.written.append((token, servers, tools))
        self.key = {"object_permission": {"mcp_servers": servers, "mcp_tool_permissions": tools}}


def approve(conn, relation, scope_type, scope_id, tools=("echo",), status="active", days=30):
    return conn.execute(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, basis, granted_by, requested_by,"
        " status) VALUES (gen_random_uuid(), %s, 'acme', %s, 'standard', 'ctl-everything',"
        " %s, %s, %s, now() - interval '10 days', now() + make_interval(days => %s), '{}', 'root',"
        " 'someone', %s) RETURNING id",
        (INSTANCE, relation, list(tools), scope_type, scope_id, days, status),
    ).fetchone()[0]


def revoke(conn, approval):
    conn.execute(
        "UPDATE mint.approvals SET status = 'revoked', revoked_at = now(), revoke_reason = 'x'"
        " WHERE id = %s", (approval,),
    )


@pytest.fixture
def world(conn, ctx, litellm):
    orgs.add(ctx, "acme", "ACME")
    services.register(ctx, litellm, "ctl-everything", "http://upstream.test/mcp")
    relation = relations.add(ctx, "acme", "ctl-everything", "ops", None)
    conn.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'ctl-everything'")
    issuer = Issuer()
    kit_key = endpoint_kits.issue_key(
        conn, issuer, INSTANCE, user_id="u1", team_id="t1", issued_by="u1"
    )
    gateway = endpoint_kits.issue_gateway_key(
        conn, issuer, INSTANCE, user_id="u1", team_id="t1", kit_key=kit_key
    )
    return relation, issuer, hashlib.sha256(gateway.encode()).hexdigest()


def test_the_gateway_key_is_created_with_the_users_approvals_and_recorded_by_hash(conn, world):
    relation, issuer, token = world
    (alias, permission) = issuer.made[-1]
    assert alias.startswith("mint-kit-mcp-")
    assert permission == {"mcp_servers": [], "mcp_tool_permissions": {}}  # 승인 전에는 비어 있다
    stored = conn.execute("SELECT mcp_key_token FROM mint.endpoint_installs").fetchone()[0]
    assert stored == token


def test_user_team_and_key_scoped_approvals_all_reach_the_gateway_key(conn, world):
    relation, _, token = world
    assert kit_key_sync.desired_permission(conn, INSTANCE, "u1", "t1", token) == ([], {})
    approve(conn, relation, "user", "u1", ("a",))
    approve(conn, relation, "team", "t1", ("b",))
    approve(conn, relation, "user", "someone-else", ("zz",))
    servers, tools = kit_key_sync.desired_permission(conn, INSTANCE, "u1", "t1", token)
    assert servers == ["ctl-everything"] and tools == {"ctl-everything": ["a", "b"]}


def test_expired_pending_and_revoked_approvals_and_non_approved_servers_grant_nothing(conn, world):
    relation, _, token = world
    approve(conn, relation, "user", "u1", status="pending")
    approve(conn, relation, "user", "u1", days=-1)
    revoke(conn, approve(conn, relation, "user", "u1"))
    assert kit_key_sync.desired_permission(conn, INSTANCE, "u1", "t1", token) == ([], {})
    approve(conn, relation, "user", "u1")
    assert kit_key_sync.desired_permission(conn, INSTANCE, "u1", "t1", token)[0] == [
        "ctl-everything"
    ]
    conn.execute("UPDATE mint.servers SET status = 'suspended' WHERE server_id = 'ctl-everything'")
    assert kit_key_sync.desired_permission(conn, INSTANCE, "u1", "t1", token) == ([], {})


def test_the_sync_writes_changes_only_and_follows_a_revocation(conn, world):
    relation, _, token = world
    client = Client()
    assert kit_key_sync.sync_kit_keys(conn, INSTANCE, client) == 0  # 이미 같다
    approval = approve(conn, relation, "user", "u1")
    assert kit_key_sync.sync_kit_keys(conn, INSTANCE, client) == 1
    assert client.written == [(token, ["ctl-everything"], {"ctl-everything": ["echo"]})]
    assert kit_key_sync.sync_kit_keys(conn, INSTANCE, client) == 0
    revoke(conn, approval)
    assert kit_key_sync.sync_kit_keys(conn, INSTANCE, client) == 1
    assert client.written[-1] == (token, [], {})


def test_a_team_that_lists_servers_limits_the_key_to_them(conn, world):
    relation, _, token = world
    approve(conn, relation, "user", "u1")
    client = Client(team={"object_permission": {"mcp_servers": ["other"]}})
    kit_key_sync.sync_kit_keys(conn, INSTANCE, client)
    assert client.written == []  # 팀이 허용하지 않은 서버는 키에 쓰지 않는다


def test_a_revoked_install_is_left_alone(conn, world):
    relation, issuer, _ = world
    approve(conn, relation, "user", "u1")
    conn.execute("UPDATE mint.endpoint_installs SET revoked_at = now()")
    client = Client()
    assert kit_key_sync.sync_kit_keys(conn, INSTANCE, client) == 0 and client.written == []
