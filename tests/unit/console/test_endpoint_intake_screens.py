"""단말 로컬 신청 화면: 실행 묶음 탭, 좁히기 입력, 출처 배지, 직원 로컬 실행 안내."""

import json
import re
import uuid
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


def make_local(world, **intake_fields):
    intake = add_intake(world, **intake_fields)
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


def make_inspectable(world, intake=None):
    intake = intake or add_intake(world, status="indeterminate", result="indeterminate")
    world.query("ALTER TABLE mint.intakes DISABLE TRIGGER USER")
    world.query("UPDATE mint.intakes SET source = 'endpoint', endpoint_key_token = 'kit-key'"
                " WHERE id = %s", intake)
    world.query("ALTER TABLE mint.intakes ENABLE TRIGGER USER")
    world.query("UPDATE mint.deployment_contracts SET pack_sha256 = %s, pack_manifest = %s,"
                " exec_contract = %s, pack_spec = %s", SHA, json.dumps(MANIFEST),
                json.dumps({**CONTRACT, "schema_version": 2}), json.dumps(ROW["pack_spec"]))
    world.query("INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
                " issued_by) VALUES ('inst1', 'kit-key', 'human-9', 'kit-alias', 'root')")
    return intake


def post_form(world, client, path, **data):
    return client.post(path, data={"csrf": world.csrf(client), **data})


def test_an_operator_can_withdraw_their_own_endpoint_intake_from_its_detail(world):
    intake = make_local(world, requested_by="human-1")
    path = f"/intakes/{intake}"
    action = f'action="{path}/withdraw"'
    owner = world.session_client("admin")
    reviewer = world.session_client("approver")
    assert path in owner.get("/intakes?source=endpoint").text
    assert action not in reviewer.get(path).text
    page = owner.get(path)
    assert page.status_code == 200
    assert action in page.text
    version = re.search(r'name="state_version" value="(\d+)"', page.text).group(1)
    withdrawal = post_form(world, owner, path + "/withdraw", state_version=version,
                           reason="단말 신청 중복", confirm="yes")
    assert withdrawal.status_code == 303, withdrawal.text
    for client in (owner, reviewer):
        detail = client.get(path).text
        assert "철회됨" in detail and "단말 신청 중복" in detail
        assert action not in detail

    submitted = str(uuid.uuid4())
    world.query("INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source,"
                " requested_by) VALUES (%s, 'inst1', 'acme', 'srv-wait', 'submission', 'human-1')",
                submitted)
    submission_path = f"/intakes/{submitted}"
    submission = owner.get(submission_path)
    assert submission.status_code == 200
    assert f'action="{submission_path}/withdraw"' not in submission.text


def test_an_admin_grants_and_withdraws_an_inspection_approval_from_the_intake_screen(world):
    intake = make_inspectable(world)
    client = world.session_client("admin")
    html = client.get(f"/intakes/{intake}").text
    assert "단말 검사" in html and f"/intakes/{intake}/inspect" in html
    assert "검사용 승인" in html and "단말 검사 대기" not in html
    assert post_form(world, client, f"/intakes/{intake}/inspect").status_code == 303
    html = client.get(f"/intakes/{intake}").text
    assert re.search(r"단말 검사 대기 · 남은 시간 (59|60)분", html)
    assert "검사용 승인 철회" in html and f"/intakes/{intake}/inspect" not in html.replace(
        "/inspect-revoke", "")
    again = post_form(world, client, f"/intakes/{intake}/inspect")
    assert again.status_code == 409 and "이미 열려" in again.text
    inspection = world.query("SELECT id FROM mint.endpoint_inspections")[0][0]
    assert post_form(world, client, f"/intakes/{intake}/inspect-revoke",
                     inspection_id=str(inspection)).status_code == 303
    html = client.get(f"/intakes/{intake}").text
    assert "단말 검사 대기" not in html and f"/intakes/{intake}/inspect\"" in html
    assert "철회" in client.get(f"/intakes/{intake}?tab=pack").text


def test_the_inspection_button_needs_a_local_indeterminate_intake_and_a_pack(world):
    other = add_intake(world, status="indeterminate", result="indeterminate")
    client = world.session_client("admin")
    assert f"/intakes/{other}/inspect" not in client.get(f"/intakes/{other}").text
    intake = make_inspectable(world, other)
    assert f"/intakes/{intake}/inspect" in client.get(f"/intakes/{intake}").text
    world.query("UPDATE mint.deployment_contracts SET pack_sha256 = NULL")
    assert f"/intakes/{intake}/inspect" not in client.get(f"/intakes/{intake}").text


def test_a_device_inspection_is_labelled_in_the_check_table_and_the_tool_list(world):
    intake = make_inspectable(world)
    world.query("INSERT INTO mint.intake_checks (id, instance_id, intake_id, \"check\", attempt,"
                " result, reason_code, method) VALUES (gen_random_uuid(), 'inst1', %s,"
                " 'inspection', 9, 'indeterminate', 'ENDPOINT_INSPECTED', 'endpoint:tools_list')",
                intake)
    client = world.session_client("approver")
    html = client.get(f"/intakes/{intake}").text
    assert "단말 검사로 받음" in html and html.count("단말 검사") >= 2
    assert "단말 검사 도구" in client.get(f"/intakes/{intake}?tab=pack").text
