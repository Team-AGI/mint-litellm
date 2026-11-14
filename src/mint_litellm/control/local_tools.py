"""로컬(stdio) 서버의 관측된 도구 목록으로 임시 계약을 만든다.

단말 실행기가 서버의 ``tools/list`` 응답에서 본 목록(단말의 주장)을 서버마다 가장 최근 보고 하나로
읽는다. 승인된 계약이 있는 도구는 관측 드리프트 판정(``record_tools``)을 그대로 거치고, 그 밖의
도구(승인된 계약이 없거나 관측한 정의가 승인본과 달라진 도구)는 이름·설명·입력 정의로 행위 유형과
위험 등급을 추정해 임시 계약으로 둔다. 임시 계약은 승인한 계약이 아니며 허용을 넓히지 않는다.
"""

import json
from typing import Any

from mint_litellm.control import contract_observe
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services.base import transact
from mint_litellm.plugin.policy.provisional import infer
from mint_litellm.types.canonical import credential_scope, sha256

LOCAL_SCOPE = credential_scope("none")


def _tools(raw: Any) -> dict[str, dict]:
    """보고된 목록을 업스트림 목록과 같은 모양으로 검사한다(잘못되면 ValueError)."""
    return contract_observe.normalize_tools(
        {
            "tools": [
                {"name": t.get("name"), "description": t.get("description", ""),
                 "inputSchema": t.get("input_schema")}
                for t in raw if isinstance(t, dict)
            ]
        }
    )


def input_keys(schema: dict) -> list[str]:
    props = schema.get("properties")
    return sorted(props) if isinstance(props, dict) else []


def _reported(ctx: Context) -> list[dict]:
    return fetchall(
        ctx.conn,
        "SELECT DISTINCT ON (l.server_id) l.server_id, l.tools, i.key_alias, s.state_version"
        " FROM mint.endpoint_tool_lists l"
        " JOIN mint.endpoint_installs i ON i.instance_id = l.instance_id"
        "  AND i.key_token = l.key_token AND i.revoked_at IS NULL"
        " JOIN mint.servers s ON s.instance_id = l.instance_id AND s.server_id = l.server_id"
        "  AND s.identity_kind = 'stdio' AND s.status = 'approved'"
        " WHERE l.instance_id = %s ORDER BY l.server_id, l.reported_at DESC",
        (ctx.instance_id,),
    )


def _provisional(ctx: Context, row: dict, tools: dict[str, dict]) -> None:
    """승인본이 없거나 달라진 도구의 임시 계약을 쓰고, 관측에서 사라진 도구의 행을 지운다."""
    server_id = row["server_id"]
    approved = {
        c["tool"]: c
        for c in fetchall(
            ctx.conn,
            "SELECT tool, canonical_text, drift FROM mint.tool_contracts WHERE instance_id=%s"
            " AND server_id=%s AND credential_scope=%s AND status='approved'",
            (ctx.instance_id, server_id, LOCAL_SCOPE),
        )
    }
    before = {
        r["tool"]: r
        for r in fetchall(
            ctx.conn,
            "SELECT * FROM mint.provisional_contracts WHERE instance_id=%s AND server_id=%s",
            (ctx.instance_id, server_id),
        )
    }
    wanted = {
        name: value
        for name, value in tools.items()
        if name not in approved
        or contract_observe.drift_kind(json.loads(approved[name]["canonical_text"]), value)
        != "none"
    }
    for name, value in wanted.items():
        keys = input_keys(value["input_schema"])
        guess = infer(name, value["description"], keys)
        old = before.get(name)
        if old is not None:
            drift = contract_observe.drift_kind(
                {"description": old["description"], "input_schema": old["input_schema"]}, value
            )
            if drift != "none":
                contract_observe._alert(
                    ctx, f"{server_id}/{name}", sha256(value),
                    "high" if drift == "input_schema" else "medium",
                    {"server_id": server_id, "tool": name, "drift": drift,
                     "contract": "provisional"},
                )
        ctx.conn.execute(
            "INSERT INTO mint.provisional_contracts AS p (instance_id, server_id, tool,"
            " action_type, risk_grade, description, input_schema, input_keys, reported_by)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)"
            " ON CONFLICT (instance_id, server_id, tool) DO UPDATE SET"
            " action_type=EXCLUDED.action_type, risk_grade=EXCLUDED.risk_grade,"
            " description=EXCLUDED.description, input_schema=EXCLUDED.input_schema,"
            " input_keys=EXCLUDED.input_keys, reported_by=EXCLUDED.reported_by,"
            " observed_at=clock_timestamp()"
            " WHERE (p.description, p.input_schema, p.reported_by, p.action_type)"
            " IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.input_schema,"
            " EXCLUDED.reported_by, EXCLUDED.action_type)",
            (ctx.instance_id, server_id, name, guess.action_type, guess.risk_grade,
             value["description"], json.dumps(value["input_schema"]), keys, row["key_alias"]),
        )
    stale = sorted(before.keys() - wanted.keys())
    if stale:
        ctx.conn.execute(
            "DELETE FROM mint.provisional_contracts WHERE instance_id=%s AND server_id=%s"
            " AND tool = ANY(%s)",
            (ctx.instance_id, server_id, stale),
        )


def consume(ctx: Context) -> int:
    """보고된 도구 목록을 읽어 임시 계약과 드리프트를 갱신한다. 처리한 서버 수를 돌려준다."""
    done = 0
    for row in _reported(ctx):
        try:
            tools = _tools(row["tools"])
        except ValueError:
            continue
        has_approved = fetchone(
            ctx.conn,
            "SELECT 1 AS x FROM mint.tool_contracts WHERE instance_id=%s AND server_id=%s"
            " AND credential_scope=%s AND status='approved' LIMIT 1",
            (ctx.instance_id, row["server_id"], LOCAL_SCOPE),
        )
        if has_approved:
            try:
                contract_observe.record_tools(
                    ctx, row["server_id"], LOCAL_SCOPE, tools, row["state_version"], local=True
                )
            except ControlError:  # 관측 중 서버가 바뀌었으면 다음 주기에 다시 본다
                continue
        with transact(ctx):
            _provisional(ctx, row, tools)
        done += 1
    return done
