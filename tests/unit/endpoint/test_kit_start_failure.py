"""도구 목록을 내기 전에 죽은 로컬 서버는 짧은 사유만 남기고, 보고기가 읽어 간다."""

import json
import sys

from kit_loader import load

agent = load("mint_agent")
kit = load("mint_kit")


def test_a_server_that_dies_before_listing_tools_leaves_a_short_reason(tmp_path, capfd):
    code = (
        "import sys;sys.stderr.write('ImportError: cannot import name X');sys.exit(1)"
    )
    tap = agent.ToolListTap(str(tmp_path), "srv")
    assert agent.spawn_and_relay(sys.executable, [sys.executable, "-c", code], {}, tap) == 1
    saved = json.loads((tmp_path / "start-failed/srv.json").read_text(encoding="utf-8"))
    assert saved == {"server": "srv", "reason": "의존 라이브러리 판본 불일치"}
    assert "cannot import" not in json.dumps(saved, ensure_ascii=False)


def test_the_reporter_reads_failures_and_a_tool_list_clears_them(tmp_path):
    folder = tmp_path / kit.STATE_REL / "start-failed"
    folder.mkdir(parents=True)
    (folder / "srv.json").write_text(
        json.dumps({"server": "srv", "reason": "종료 코드 3"}), encoding="utf-8")
    assert kit.scan_start_failures(tmp_path) == [{"server": "srv", "reason": "종료 코드 3"}]
    tap = agent.ToolListTap(str(tmp_path / kit.STATE_REL), "srv")
    tap.pages = [{"name": "t", "description": "d", "inputSchema": {"type": "object"}}]
    tap.save()
    assert kit.scan_start_failures(tmp_path) == []
