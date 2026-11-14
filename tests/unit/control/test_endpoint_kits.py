"""단말 설치 묶음의 서버 쪽: 승인된 계약 읽기, 사용자별 키 발급·교체·해제, 보고 열의 권한.

MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import asyncio
import hashlib
import threading
import time

import pytest
from ctl_fixtures import INSTANCE

psycopg = pytest.importorskip("psycopg")
from psycopg import errors  # noqa: E402
from psycopg.conninfo import conninfo_to_dict, make_conninfo  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

from mint_litellm.control import endpoint_kits, servers  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.plugin.snapshot import PluginDatabase  # noqa: E402
from mint_litellm.types.exec_contract import ExecContract  # noqa: E402

CONTRACT = ExecContract(
    executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
)


class Issuer:
    """키 발급 클라이언트 대역. 만든 별칭과 지운 별칭을 기록한다."""

    def __init__(self):
        self.made, self.deleted = [], []

    def generate_kit_key(self, *, user_id, team_id, alias):
        self.made.append((user_id, team_id, alias))
        return f"sk-{alias}"

    def delete_kit_keys(self, aliases):
        self.deleted.append(list(aliases))


def token(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def issue(conn, issuer, user="u1", team="t1"):
    return endpoint_kits.issue_key(
        conn, issuer, INSTANCE, user_id=user, team_id=team, issued_by=user
    )


def approve(conn, server_id):
    conn.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = %s", (server_id,))


def test_only_approved_local_servers_are_packed_with_their_current_contract(ctx, conn):
    servers.register_local(ctx, "local-1", CONTRACT)
    assert endpoint_kits.approved_contracts(conn, INSTANCE) == {}
    approve(conn, "local-1")
    assert endpoint_kits.approved_contracts(conn, INSTANCE) == {"local-1": CONTRACT.document()}
    newer = CONTRACT.model_copy(update={"argv": ("/opt/srv/v2.js",)})
    servers.register_local(ctx, "local-1", newer)
    assert endpoint_kits.approved_contracts(conn, INSTANCE) == {"local-1": newer.document()}


def test_a_key_is_recorded_by_its_hash_and_the_next_download_replaces_it(conn):
    issuer = Issuer()
    first = issue(conn, issuer)
    issue(conn, issuer, user="u2")
    ((_, _, first_alias),) = issuer.made[:1]
    assert first == f"sk-{first_alias}" and issuer.deleted == []
    second = issue(conn, issuer)
    assert issuer.deleted == [[first_alias]]  # 같은 사용자의 이전 키만 지워진다.
    rows = conn.execute(
        "SELECT key_token, revoked_at IS NOT NULL FROM mint.endpoint_installs"
        " WHERE user_id = 'u1' ORDER BY issued_at"
    ).fetchall()
    assert rows == [(token(first), True), (token(second), False)]
    assert [r["state"] for r in endpoint_kits.installs(conn, INSTANCE, "u2")] == ["pending"]


def test_two_downloads_at_once_leave_one_active_key(fresh_db):
    """첫 연결이 잠금을 쥐고 둘째 연결이 그 잠금을 기다리는 것을 확인한 뒤 진행한다."""
    issuer = Issuer()
    with psycopg.connect(fresh_db) as first, psycopg.connect(fresh_db) as second:
        issue(first, issuer)
        done = threading.Event()

        def later():
            issue(second, issuer)
            second.commit()
            done.set()

        worker = threading.Thread(target=later)
        worker.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            waiting = first.execute(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted"
            ).fetchone()[0]
            if waiting:
                break
            time.sleep(0.05)
        assert waiting == 1 and not done.is_set()
        first.commit()
        worker.join(10)
        assert done.is_set()
        active = first.execute(
            "SELECT count(*) FROM mint.endpoint_installs WHERE revoked_at IS NULL"
        ).fetchone()[0]
        assert active == 1 and len(issuer.deleted) == 1


def test_revoking_deletes_the_keys_and_a_second_revoke_has_nothing_to_do(conn):
    issuer = Issuer()
    issue(conn, issuer)
    assert endpoint_kits.revoke_keys(conn, issuer, INSTANCE, "u1") == 1
    assert [r["state"] for r in endpoint_kits.installs(conn, INSTANCE)] == ["revoked"]
    with pytest.raises(ControlError, match="해제할 단말 연결이 없습니다"):
        endpoint_kits.revoke_keys(conn, issuer, INSTANCE, "u1")


def test_only_the_report_columns_can_change_and_a_report_needs_its_time(conn):
    key = issue(conn, Issuer())
    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE mint.endpoint_installs SET user_id = 'u9'")
    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE mint.endpoint_installs SET install_mode = 'managed'")
    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute(
            "UPDATE mint.endpoint_installs SET install_mode = 'root', reported_at = now()"
        )
    conn.execute("SET LOCAL ROLE mint_plugin")
    updated = conn.execute(
        "UPDATE mint.endpoint_installs SET install_mode = 'user', kit_version = 'k',"
        " mcp_servers = '[]'::jsonb, reported_at = now() WHERE key_token = %s", (token(key),)
    )
    assert updated.rowcount == 1
    with pytest.raises(errors.InsufficientPrivilege), conn.transaction():
        conn.execute("UPDATE mint.endpoint_installs SET key_alias = 'mint-kit-x'")
    with pytest.raises(errors.InsufficientPrivilege), conn.transaction():
        conn.execute("INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id,"
                     " key_alias, issued_by) VALUES ('inst1', 't', 'u', 'mint-kit-y', 'u')")
    conn.execute("RESET ROLE")
    assert [r["state"] for r in endpoint_kits.installs(conn, INSTANCE)] == ["user"]


@pytest.fixture
def plugin_dsn(fresh_db, login_roles):
    params = conninfo_to_dict(fresh_db)
    params.update(user="mint_plugin_app", password="pw-plugin")
    return make_conninfo(**params)


def test_the_decision_process_records_a_report_for_an_active_key_only(fresh_db, plugin_dsn):
    pytest.importorskip("psycopg_pool")
    with psycopg.connect(fresh_db) as admin:
        for name in ("tok-live", "tok-gone"):
            admin.execute(
                "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
                " issued_by) VALUES (%s, %s, 'u1', %s, 'u1')",
                (INSTANCE, name, f"mint-kit-{name}"),
            )
        admin.execute(
            "UPDATE mint.endpoint_installs SET revoked_at = now() WHERE key_token = 'tok-gone'"
        )

    async def run():
        database = PluginDatabase(plugin_dsn)
        try:
            fields = {"mode": "managed", "kit_version": "k", "claude_version": None,
                      "mcp_servers": ["srv-1"]}  # fmt: skip
            return [
                await database.report_install(INSTANCE, name, **fields)
                for name in ("tok-live", "tok-gone", "tok-unknown")
            ]
        finally:
            await database.close()

    assert asyncio.run(run()) == ["recorded", "unknown", "unknown"]
    with psycopg.connect(fresh_db) as admin:
        row = admin.execute(
            "SELECT install_mode, mcp_servers FROM mint.endpoint_installs"
            " WHERE key_token = 'tok-live'"
        ).fetchone()
    assert row == ("managed", ["srv-1"])


def test_a_new_key_expires_after_its_lifetime_and_a_report_near_the_end_extends_it(
    fresh_db, plugin_dsn
):
    pytest.importorskip("psycopg_pool")
    with psycopg.connect(fresh_db) as admin:
        for name, left in (("tok-new", "90 days"), ("tok-near", "10 days"), ("tok-old", "-1 day")):
            admin.execute(
                "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
                " issued_by, expires_at, ttl_days) VALUES (%s, %s, 'u1', %s, 'u1',"
                " now() + %s::interval, 90)",
                (INSTANCE, name, f"mint-kit-{name}", left),
            )

    async def run():
        database = PluginDatabase(plugin_dsn)
        try:
            fields = {"mode": "managed", "kit_version": "k", "claude_version": None,
                      "mcp_servers": []}  # fmt: skip
            return [
                await database.report_install(INSTANCE, name, **fields)
                for name in ("tok-new", "tok-near", "tok-old")
            ]
        finally:
            await database.close()

    assert asyncio.run(run()) == ["recorded", "renewed", "expired"]
    with psycopg.connect(fresh_db) as admin:
        days = dict(admin.execute(
            "SELECT key_token, round(extract(epoch FROM expires_at - now()) / 86400)"
            " FROM mint.endpoint_installs"
        ).fetchall())
        reported = dict(admin.execute(
            "SELECT key_token, reported_at IS NOT NULL FROM mint.endpoint_installs"
        ).fetchall())
    assert (days["tok-new"], days["tok-near"], days["tok-old"]) == (90, 90, -1)
    assert reported == {"tok-new": True, "tok-near": True, "tok-old": False}


def test_issuing_a_key_sets_the_expiry_and_the_plugin_role_cannot_change_the_lifetime(conn):
    key = endpoint_kits.issue_key(
        conn, Issuer(), INSTANCE, user_id="u1", team_id=None, issued_by="u1", ttl_days=30
    )
    row = conn.execute(
        "SELECT ttl_days, round(extract(epoch FROM expires_at - now()) / 86400)"
        " FROM mint.endpoint_installs WHERE key_token = %s", (token(key),)
    ).fetchone()
    assert row == (30, 30)
    conn.execute("SET LOCAL ROLE mint_plugin")
    with pytest.raises(errors.InsufficientPrivilege), conn.transaction():
        conn.execute("UPDATE mint.endpoint_installs SET ttl_days = 365")
    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE mint.endpoint_installs SET expires_at = NULL")
    conn.execute("RESET ROLE")


# -- 단말의 관리 대상이 아닌 MCP 항목 ---------------------------------------------------------


def entry(name, target="npx", **extra):
    return {"harness": "claude", "name": name, "kind": "stdio", "target": target,
            "package": None} | extra


def test_the_unmanaged_mcp_list_keeps_first_seen_and_is_replaced_by_the_next_report(
    fresh_db, plugin_dsn
):
    pytest.importorskip("psycopg_pool")
    with psycopg.connect(fresh_db) as admin:
        admin.execute(
            "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
            " issued_by) VALUES (%s, 'tok-a', 'u1', 'mint-kit-a', 'u1')", (INSTANCE,))

    async def report(**extra):
        database = PluginDatabase(plugin_dsn)
        try:
            return await database.report_install(
                INSTANCE, "tok-a", mode="managed", kit_version="k", claude_version=None,
                mcp_servers=[], **extra)
        finally:
            await database.close()

    def stored():
        with psycopg.connect(fresh_db) as admin:
            return admin.execute(
                "SELECT local_mcp FROM mint.endpoint_installs WHERE key_token = 'tok-a'"
            ).fetchone()[0]

    assert asyncio.run(report()) == "recorded" and stored() is None
    asyncio.run(report(local_mcp=[entry("a"), entry("b")]))
    first = {i["name"]: i["first_seen"] for i in stored()}
    assert set(first) == {"a", "b"} and all(first.values())
    asyncio.run(report(local_mcp=[entry("a"), entry("c")]))
    again = {i["name"]: i["first_seen"] for i in stored()}
    assert set(again) == {"a", "c"} and again["a"] == first["a"]  # 지속된 항목은 처음 시각을 유지
    asyncio.run(report())  # 목록이 없는 보고(이전 묶음·SYSTEM)는 앞서 보고한 목록을 둔다.
    assert {i["name"] for i in stored()} == {"a", "c"}
    asyncio.run(report(local_mcp=[]))
    assert stored() == []


def test_the_inventory_counts_the_endpoints_that_share_an_entry_and_skips_dead_installs(conn):
    issuer = Issuer()
    keys = {user: issue(conn, issuer, user=user) for user in ("u1", "u2", "u3", "u4")}
    modes = {"u1": "managed", "u2": "user", "u3": "managed", "u4": "removed"}
    shared = entry(
        "files", package="@scope/server-files@1.2.0", first_seen="2026-01-02T03:04:05+00:00"
    )
    for user, key in keys.items():
        items = [shared, entry("only-" + user, "node")]
        conn.execute(
            "UPDATE mint.endpoint_installs SET install_mode = %s, reported_at = now(),"
            " local_mcp = %s WHERE key_token = %s",
            (modes[user], Jsonb(items), token(key)),
        )
    endpoint_kits.revoke_keys(conn, issuer, INSTANCE, "u3")
    rows = endpoint_kits.local_mcp_inventory(conn, INSTANCE)
    assert {(r["user_id"], r["name"]) for r in rows} == {
        ("u1", "files"), ("u1", "only-u1"), ("u2", "files"), ("u2", "only-u2")}
    files = [r for r in rows if r["name"] == "files"]
    assert {r["endpoints"] for r in files} == {2}
    assert {r["endpoints"] for r in rows if r["name"] != "files"} == {1}
    assert files[0]["first_seen"].year == 2026 and files[0]["last_seen"] is not None
    assert {r["state"] for r in files} == {"managed", "user"}


def test_the_plugin_role_may_write_the_unmanaged_list_but_nothing_else_of_the_row(conn):
    key = issue(conn, Issuer())
    conn.execute("SET LOCAL ROLE mint_plugin")
    conn.execute("UPDATE mint.endpoint_installs SET local_mcp = '[]'::jsonb WHERE key_token = %s",
                 (token(key),))
    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE mint.endpoint_installs SET local_mcp = '{}'::jsonb")
    conn.execute("RESET ROLE")


def test_a_report_stores_the_tool_list_once_per_server_and_key(fresh_db, plugin_dsn):
    pytest.importorskip("psycopg_pool")
    with psycopg.connect(fresh_db) as admin:
        admin.execute(
            "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
            " issued_by) VALUES (%s, 'tok-t', 'u1', 'mint-kit-t', 'u1')", (INSTANCE,))

    async def run(tools):
        database = PluginDatabase(plugin_dsn)
        try:
            return await database.report_install(
                INSTANCE, "tok-t", mode="managed", kit_version="k", claude_version=None,
                mcp_servers=[], tool_lists=[{"server": "loc", "truncated": False,
                                             "tools": tools}])
        finally:
            await database.close()

    one = [{"name": "a", "description": "", "input_schema": {"type": "object"}}]
    assert asyncio.run(run(one)) == "recorded"
    assert asyncio.run(run(one)) == "recorded"
    asyncio.run(run(one + [{"name": "b", "description": "", "input_schema": {}}]))
    with psycopg.connect(fresh_db) as admin:
        rows = admin.execute("SELECT tools FROM mint.endpoint_tool_lists").fetchall()
    assert len(rows) == 1 and [t["name"] for t in rows[0][0]] == ["a", "b"]
