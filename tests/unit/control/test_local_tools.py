"""단말이 보고한 로컬 서버 도구 목록: 저장·임시 계약·드리프트·승인.

MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import json

import pytest
from ctl_fixtures import INSTANCE

psycopg = pytest.importorskip("psycopg")
from psycopg.types.json import Jsonb  # noqa: E402

from mint_litellm.control import local_tools, servers  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.services import contracts  # noqa: E402
from mint_litellm.types.exec_contract import ExecContract  # noqa: E402

CONTRACT = ExecContract(
    executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
)

SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}}


def tools(*names, schema=SCHEMA, description="d"):
    return [{"name": n, "description": description, "input_schema": schema} for n in names]


@pytest.fixture
def local(ctx, conn):
    servers.register_local(ctx, "loc", CONTRACT)
    conn.execute("UPDATE mint.servers SET status='approved' WHERE server_id='loc'")
    conn.execute(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
        " issued_by) VALUES (%s, 'tok', 'u1', 'kit-u1', 'u1')", (INSTANCE,))
    return ctx


def report(conn, items):
    conn.execute(
        "INSERT INTO mint.endpoint_tool_lists (instance_id, server_id, key_token, tools,"
        " tools_sha256) VALUES (%s, 'loc', 'tok', %s, %s) ON CONFLICT (instance_id, server_id,"
        " key_token) DO UPDATE SET tools = EXCLUDED.tools, tools_sha256 = EXCLUDED.tools_sha256",
        (INSTANCE, Jsonb(items), "a" * 64))


def rows(conn):
    return {r["tool"]: r for r in fetchall(
        conn, "SELECT * FROM mint.provisional_contracts WHERE server_id='loc'")}


def test_a_reported_list_becomes_provisional_contracts_with_default_keys(local, conn):
    report(conn, tools("read_file") + tools("run_shell", schema={"properties": {"command": {}}}))
    assert local_tools.consume(local) == 1
    got = rows(conn)
    assert got["read_file"]["action_type"] == "read" and got["read_file"]["input_keys"] == ["path"]
    assert got["run_shell"]["action_type"] == "exec"
    assert got["read_file"]["reported_by"] == "kit-u1"


def test_a_changed_definition_raises_drift_and_a_removed_tool_disappears(local, conn):
    report(conn, tools("read_file", "list_dir"))
    local_tools.consume(local)
    report(conn, tools("read_file", schema={"type": "object", "properties": {"p": {}}}))
    local_tools.consume(local)
    got = rows(conn)
    assert set(got) == {"read_file"} and got["read_file"]["input_keys"] == ["p"]
    alert = fetchone(conn, "SELECT severity FROM mint.alerts WHERE kind='contract_drift'")
    assert alert["severity"] == "high"


def test_a_server_that_is_not_an_approved_stdio_server_is_ignored(local, ctx, conn):
    conn.execute("UPDATE mint.servers SET status='suspended' WHERE server_id='loc'")
    report(conn, tools("read_file"))
    assert local_tools.consume(ctx) == 0 and rows(conn) == {}


def test_approving_turns_the_provisional_contract_into_an_approved_one(local, ctx, conn):
    report(conn, tools("read_file") + tools("run_shell", schema={"properties": {"command": {}}}))
    local_tools.consume(ctx)
    version = fetchone(conn, "SELECT state_version FROM mint.servers WHERE server_id='loc'")
    done = contracts.approve_provisional(ctx, "loc", expected_version=version["state_version"])
    assert done["approved"] == ["read_file"]
    contract = fetchone(conn, "SELECT * FROM mint.tool_contracts WHERE tool='read_file'")
    assert contract["status"] == "approved" and contract["source"] == "observed"
    assert contract["input_keys"] == ["path"] and contract["action_type"] == "read"
    assert set(rows(conn)) == {"run_shell"}  # 실행 유형은 옮기지 않는다
    # 이어지는 관측은 승인본과 같으면 드리프트가 없고, 바뀌면 승인본에 표시한다.
    local_tools.consume(ctx)
    assert fetchone(conn, "SELECT drift FROM mint.tool_contracts WHERE tool='read_file'")[
        "drift"] == "none"
    report(conn, tools("read_file", schema={"type": "object", "properties": {"q": {}}}))
    local_tools.consume(ctx)
    assert fetchone(conn, "SELECT drift FROM mint.tool_contracts WHERE tool='read_file'")[
        "drift"] == "input_schema"
    assert "read_file" in rows(conn)  # 달라진 정의는 다시 임시 계약으로 보인다
    with pytest.raises(ControlError):
        contracts.approve_provisional(ctx, "missing")
    assert json.loads(contract["canonical_text"])["name"] == "read_file"
