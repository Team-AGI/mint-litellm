"""단말 로컬 신청 화면: 실행 묶음 탭, 좁히기 입력, 출처 배지, 직원 로컬 실행 안내."""

import json
import re
from pathlib import Path

from mint_litellm.console import labels, pack_view

from .test_intake_contract_screens import add_intake, litellm_permission  # noqa: F401
from .test_screen_polish import render

SHA = "ab" * 32
MANIFEST = {
    "schema": 1,
    "package": {"index": "pypi", "name": "pyghidra-mcp", "version": "0.3.1", "extras": []},
    "entry": "pyghidra_mcp.server:main",
    "files": [{"name": "pyghidra_mcp-0.3.1-py3-none-any.whl", "sha256": "cd" * 32, "size": 123}],
}
CONTRACT = {
    "file_access": [{"path": "/data/a", "mode": "ro"}, {"path": "/data/b", "mode": "rw"}],
    "network": "hosts", "allowed_hosts": ["pypi.org"], "executable": "/usr/bin/python3",
}
ROW = {"pack_sha256": SHA, "pack_manifest": MANIFEST, "exec_contract": CONTRACT,
       "pack_spec": {"observed_tools": [{"name": "reported_tool"}]}}


def test_the_view_lists_the_pack_files_and_only_narrower_network_choices():
    view = pack_view.view(ROW, "passed")
    assert view["sha12"] == SHA[:12] and view["files"][0]["sha"] == "cd" * 6
    assert view["entry"] == "pyghidra_mcp.server:main"
    assert [v for v, _ in view["network_choices"]] == ["keep", "none"]
    assert [v for v, _ in pack_view.narrower_networks("none")] == ["keep"]


def test_the_stages_show_the_missing_pack_as_waiting():
    assert pack_view.view(None, "received")["stages"] == [
        ("ok", "접수"), ("wait", "묶음 준비"), ("off", "검사")]
    assert pack_view.stages("passed", True)[2] == ("ok", "검사")


def test_the_pack_tab_shows_hash_files_mounts_and_reported_tools():
    html = render("_intake_pack.html", pack=pack_view.view(ROW, "passed"), tools=[], ICONS={
        "ok": "", "wait": "", "error": "", "off": ""}, L=labels)
    for text in (SHA[:12], "pyghidra_mcp-0.3.1-py3-none-any.whl", "묶음 폴더", "임시 폴더",
                 "/usr/bin/python3", "단말 보고", "reported_tool", "허용 호스트만"):
        assert text in html


def test_the_waiting_pack_tab_shows_only_the_steps():
    html = render("_intake_pack.html", pack=pack_view.view(None, "received"), tools=[],
                  ICONS={"ok": "", "wait": "", "error": "", "off": ""},
                  L=labels)
    assert "묶음 준비" in html and "묶음 해시" not in html


def test_the_staff_form_offers_local_run_with_a_command_example():
    root = Path(pack_view.__file__).parent
    html = (root / "templates" / "staff_intake_new.html").read_text(encoding="utf-8")
    assert 'value="stdio"' in html and "mint add" in html and "이 PC 터미널에서 신청" in html
    assert "has(option[value=stdio]:checked)" in (root / "static" / "console.css").read_text(
        encoding="utf-8")


def make_local(world):
    intake = add_intake(world)
    world.query("ALTER TABLE mint.intakes DISABLE TRIGGER USER")
    world.query("UPDATE mint.intakes SET source = 'endpoint', endpoint_key_token = 'k'"
                " WHERE id = %s",
                intake)
    world.query("ALTER TABLE mint.intakes ENABLE TRIGGER USER")
    world.query("UPDATE mint.deployment_contracts SET pack_sha256 = %s, pack_manifest = %s,"
                " exec_contract = %s, pack_spec = %s", SHA, json.dumps(MANIFEST),
                json.dumps(CONTRACT), json.dumps(ROW["pack_spec"]))
    return intake


def test_a_local_intake_shows_the_tab_badge_and_a_narrowing_only_form(world):
    intake = make_local(world)
    client = world.session_client("approver")
    detail = client.get(f"/intakes/{intake}").text
    assert "실행 묶음" in detail and "단말" in detail
    html = client.get(f"/intakes/{intake}?tab=pack").text
    assert SHA[:12] in html and "단말 보고" in html
    form = re.search(r'name="narrow_network">(.*?)</select>', html, re.S).group(1)
    assert 'value="none"' in form and 'value="keep"' in form and "hosts" not in form
    assert html.count('name="narrow_file_access"') == 2
    assert "단말" in client.get("/intakes").text
    assert intake in client.get("/intakes?source=endpoint").text
    assert intake not in client.get("/intakes?source=staff").text


def test_an_intake_without_pack_columns_still_renders(world):
    intake = add_intake(world)
    html = world.session_client("approver").get(f"/intakes/{intake}").text
    assert "실행 묶음" not in html
