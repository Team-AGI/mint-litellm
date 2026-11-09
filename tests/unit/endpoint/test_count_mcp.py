import json
import subprocess
import sys
from pathlib import Path

import mint_litellm

SERVER = Path(mint_litellm.__file__).resolve().parents[2] / "tests" / "endpoint" / "count_mcp.py"


def talk(tmp_path, *messages):
    log = tmp_path / "count.log"
    done = subprocess.run(
        [sys.executable, str(SERVER), str(log)],
        input="\n".join(json.dumps(m) for m in messages) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    replies = [json.loads(line) for line in done.stdout.splitlines()]
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return replies, events


def call(id_, name, **arguments):
    return {
        "jsonrpc": "2.0",
        "id": id_,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def test_start_and_calls_are_counted_separately(tmp_path):
    replies, events = talk(
        tmp_path,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        call(3, "echo", text="a"),
        call(4, "echo", text="b"),
        call(5, "missing"),
    )
    assert [e["ev"] for e in events] == ["start", "call", "call"]
    assert replies[1]["result"]["tools"][0]["name"] == "echo"
    assert replies[2]["result"]["content"][0]["text"] == "a"
    assert replies[4]["error"]["code"] == -32602
