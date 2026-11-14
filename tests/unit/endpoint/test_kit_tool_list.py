"""실행기가 서버의 ``tools/list`` 응답만 보고, 바뀐 목록만 보고기에 넘긴다."""

import io
import json

from kit_loader import load

agent = load("mint_agent")
kit = load("mint_kit")

LIST_REQ = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}).encode() + b"\n"
CALL_REQ = json.dumps(
    {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
     "params": {"name": "t", "arguments": {"secret": "x"}}}
).encode() + b"\n"


def answer(tools, rid=7, **result):
    return json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"tools": tools, **result}}).encode()


def tool(name="read_file", **extra):
    return {"name": name, "description": "d", "inputSchema": {
        "type": "object", "properties": {"path": {"type": "string"}}}, **extra}


def stored(tmp_path):
    return json.loads((tmp_path / "tools" / "srv.json").read_text())


def tapped(tmp_path):
    return agent.ToolListTap(str(tmp_path), "srv")


def test_the_relay_forwards_every_byte_and_the_tap_saves_the_list(tmp_path):
    tap = tapped(tmp_path)
    src, out = io.BytesIO(LIST_REQ + CALL_REQ), io.BytesIO()
    agent.relay(src, out, tap.client_line)
    assert out.getvalue() == LIST_REQ + CALL_REQ
    reply = answer([tool()]) + b"\n"
    out = io.BytesIO()
    agent.relay(io.BytesIO(reply), out, tap.server_line)
    assert out.getvalue() == reply
    doc = stored(tmp_path)
    assert doc["tools"] == [{"name": "read_file", "description": "d", "input_schema":
                             tool()["inputSchema"]}]
    assert "secret" not in json.dumps(doc)


def test_an_unrequested_or_foreign_response_is_ignored(tmp_path):
    tap = tapped(tmp_path)
    tap.server_line(answer([tool()]))
    tap.client_line(LIST_REQ)
    tap.server_line(answer([tool()], rid=99))
    assert not (tmp_path / "tools").exists()


def test_pages_are_joined_and_an_unchanged_list_is_not_rewritten(tmp_path):
    tap = tapped(tmp_path)
    tap.client_line(LIST_REQ)
    tap.server_line(answer([tool("a")], nextCursor="c"))
    assert not (tmp_path / "tools").exists()
    tap.client_line(json.dumps({"id": 9, "method": "tools/list", "params": {"cursor": "c"}})
                    .encode())
    tap.server_line(answer([tool("b")], rid=9))
    assert [t["name"] for t in stored(tmp_path)["tools"]] == ["a", "b"]
    path = tmp_path / "tools" / "srv.json"
    before = path.stat().st_mtime_ns
    tap.client_line(LIST_REQ)
    tap.server_line(answer([tool("a")], nextCursor="c"))
    tap.client_line(json.dumps({"id": 9, "method": "tools/list", "params": {"cursor": "c"}})
                    .encode())
    tap.server_line(answer([tool("b")], rid=9))
    assert path.stat().st_mtime_ns == before


def test_limits_cut_descriptions_big_schemas_and_tool_count(tmp_path):
    big = {"type": "object", "properties": {f"k{i}": {"type": "string", "description": "x" * 200}
                                            for i in range(60)}}
    tools = [{"name": "big", "description": "y" * 900, "inputSchema": big}]
    tools += [tool(f"t{i}") for i in range(150)]
    cleaned, cut = agent.clean_tools(tools)
    assert cut and len(cleaned) == agent.TOOLS_MAX
    first = cleaned[0]
    assert len(first["description"]) == agent.TOOL_DESC_MAX
    assert first["input_schema"]["properties"]["k0"] == {"type": "string"}


def test_a_line_over_the_limit_is_forwarded_but_not_parsed(tmp_path):
    tap = tapped(tmp_path)
    tap.client_line(LIST_REQ)
    huge = answer([tool("x" * 10)]) + b" " * (agent.LINE_MAX + 10) + b"\n"
    out = io.BytesIO()
    agent.relay(io.BytesIO(huge), out, tap.server_line)
    assert out.getvalue() == huge and not (tmp_path / "tools").exists()


def test_the_reporter_sends_only_changed_lists(tmp_path):
    tap = tapped(tmp_path)
    tap.client_line(LIST_REQ)
    tap.server_line(answer([tool()]))
    home = tmp_path.parent / (tmp_path.name + "-home")
    state = home / kit.STATE_REL
    (state / "tools").mkdir(parents=True)
    (state / "tools" / "srv.json").write_text((tmp_path / "tools" / "srv.json").read_text())
    (item,) = kit.scan_tool_lists(home)
    assert item["server"] == "srv" and item["tools"][0]["name"] == "read_file"
    kit.mark_tool_lists_sent(home, [item])
    assert kit.scan_tool_lists(home) == []
