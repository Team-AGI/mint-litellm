"""직원 화면(WP-03): 권한 요청, 카드 상태, 중복 신청 이동, PC 한 대 해제, 사용량 차트."""

import json
import uuid

import pytest
from ctl_fixtures import INSTANCE

from mint_litellm.console import staff_pages

from . import test_staff_intakes as intake_tests
from . import test_staff_pages as staff_tests
from .test_staff_pages import OTHER_KEY, STAFFER, add_approval, csrf, download, kits, logged_in

sworld = staff_tests.sworld
kits = kits
OPEN = "/staff?open=acme%7Csrv-ok"


def add_contract(world, tool, status="candidate"):
    world.query(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (gen_random_uuid(), %s, 'srv-ok', 'server', %s, '{}', %s, %s, 'low', 'read',"
        " 'intake', %s)", INSTANCE, tool, "a" * 64, "b" * 64, status)


def block_call(world, user, tool, code):
    payload = {"server_id": "srv-ok", "tool": tool, "outcome": "blocked",
               "stop": {"reason_code": code}}
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, subject,"
        " payload) VALUES (gen_random_uuid(), %s, 'decision_evaluated', %s, 'plugin',"
        " %s::jsonb, %s::jsonb)", INSTANCE, f"decision:{uuid.uuid4()}:1",
        json.dumps({"principal_type": "user", "principal_id": user}), json.dumps(payload))


def ask(client, **fields):
    data = {"csrf": csrf(client), "server_id": "srv-ok", "tool": "ping",
            "reason_code": "TOOL_NOT_IN_APPROVAL", "note": "보고서 작성", **fields}
    return client.post("/staff/access-requests", data=data)


def rows(world):
    return world.query("SELECT requested_by, server_id, tool, reason_code, note, status"
                       " FROM mint.access_requests ORDER BY created_at")


def test_the_drawer_tool_table_offers_a_request_for_a_blocked_tool(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    add_contract(sworld, "ping")
    page = logged_in(sworld).get(OPEN).text
    assert "승인 범위 밖" in page and "검사 후보" in page and "사용 가능" in page
    assert 'name="tool" value="ping"' in page
    assert 'name="reason_code" value="TOOL_NOT_IN_APPROVAL"' in page
    assert 'name="tool" value="echo"' not in page  # 허용된 도구에는 요청 단추가 없다


def test_a_request_is_opened_deduplicated_and_cancelled(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    add_contract(sworld, "ping")
    client = logged_in(sworld)
    first = ask(client)
    assert first.status_code == 303 and "tab=access" in first.headers["location"]
    assert first.headers["location"].endswith("ok=access_requested")
    assert rows(sworld) == [(STAFFER, "srv-ok", "ping", "TOOL_NOT_IN_APPROVAL", "보고서 작성",
                             "open")]
    again = ask(client, note="또 보냄")
    assert again.headers["location"].endswith("ok=access_existing") and len(rows(sworld)) == 1
    page = client.get("/staff/confirmations?tab=access").text
    assert "ping" in page and "대기" in page and "요청 취소" in page and "승인 범위 밖 도구" in page
    assert "요청 대기 중" in client.get(OPEN).text  # 서랍은 같은 요청을 다시 받지 않는다
    (request_id,) = [r[0] for r in sworld.query("SELECT id FROM mint.access_requests")]
    stranger = logged_in(sworld, OTHER_KEY)
    refused = stranger.post(f"/staff/access-requests/{request_id}/cancel",
                            data={"csrf": csrf(stranger)})
    assert refused.status_code == 400 and rows(sworld)[0][-1] == "open"
    done = client.post(f"/staff/access-requests/{request_id}/cancel", data={"csrf": csrf(client)})
    assert done.status_code == 303 and done.headers["location"].endswith("ok=access_cancelled")
    assert rows(sworld)[0][-1] == "cancelled"
    assert "취소됨" in client.get("/staff/confirmations?tab=access").text


def test_a_decided_request_shows_its_result_and_reason(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    client = logged_in(sworld)
    ask(client)
    sworld.query("UPDATE mint.access_requests SET status = 'rejected', decided_by = 'admin',"
                 " decision_note = '업무 범위 밖', decided_at = now()")
    page = client.get("/staff/confirmations?tab=access").text
    assert "거절됨" in page and "업무 범위 밖" in page and "요청 취소" not in page


def test_a_request_for_an_unseen_server_is_refused(sworld):
    client = logged_in(sworld)
    refused = ask(client, server_id="srv-nothing")
    assert refused.status_code == 400 and "요청할 수 없습니다" in refused.text
    assert ask(client, reason_code="NOPE", server_id="srv-ok").status_code == 400
    assert rows(sworld) == []


def test_a_server_the_organization_uses_can_be_requested_without_its_tools(sworld):
    page = logged_in(sworld).get("/staff").text  # 승인이 하나도 없다
    assert "조직에서 쓰는 서버" in page and "사용 요청" in page
    assert "srv-ok" in page and "ping" not in page
    client = logged_in(sworld)
    done = ask(client, tool="", reason_code="APPROVAL_ABSENT")
    assert done.status_code == 303 and rows(sworld)[0][2] is None
    assert "요청 대기 중" in client.get("/staff").text


def test_a_blocked_call_in_my_calls_has_a_request_button_with_prefilled_values(sworld):
    block_call(sworld, STAFFER, "send_mail", "TOOL_NOT_IN_APPROVAL")
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    client = logged_in(sworld)
    page = client.get("/staff?tab=calls").text
    assert 'name="tool" value="send_mail"' in page
    assert 'name="reason_code" value="TOOL_NOT_IN_APPROVAL"' in page
    assert 'name="server_id" value="srv-ok"' in page
    ask(client, tool="send_mail")
    assert "요청 대기 중" in client.get("/staff?tab=calls").text


def test_a_resolution_link_opens_the_drawer_and_the_form_only_for_visible_targets(sworld):
    add_approval(sworld, "user", STAFFER, tools=("echo",))
    add_contract(sworld, "ping")
    client = logged_in(sworld)
    link = "/staff?request=srv-ok&tool=ping&reason=TOOL_NOT_IN_APPROVAL"
    page = client.get(link).text
    assert 'role="dialog"' in page and "권한 요청" in page and "요청 보내기" in page
    assert 'name="tool" value="ping"' in page
    for hidden in ("/staff?request=srv-ok&tool=nothing", "/staff?request=srv-wait",
                   "/staff?request=nowhere&tool=ping"):
        assert "요청 보내기" not in client.get(hidden).text
    odd = client.get("/staff?request=srv-ok&tool=ping&reason=<x>").text
    assert 'name="reason_code" value="APPROVAL_ABSENT"' in odd  # 모르는 사유는 기본값으로


@pytest.mark.parametrize("row, stages, pcs, phase, text", [
    ({"stopped": True}, set(), 1, "stopped", "그만둔"),
    ({"seen": "t"}, set(), 1, "ready", ""),
    ({"start_failed": True, "start_reason": "의존성 없음"}, set(), 1, "failed",
     "시작 실패 · 의존성 없음"),
    ({"preparing": True}, set(), 1, "preparing", "확인하는 중"),
    ({"local": False}, set(), 0, "ready", ""),
    ({}, set(), 0, "preparing", "연결된 PC가 없습니다"),
    ({}, set(), 1, "preparing", "아직 받지 않았습니다"),
    ({}, {"device_received"}, 1, "preparing", "내 PC가 받았습니다"),
])
def test_a_local_card_is_ready_only_after_the_pc_reports_its_tools(row, stages, pcs, phase, text):
    base = {"stopped": False, "seen": None, "start_failed": False, "start_reason": "",
            "preparing": False, "local": True}
    got, note = staff_pages.card_phase({**base, **row}, stages, pcs)
    assert got == phase and text in note


def test_a_local_server_card_moves_from_waiting_for_the_pc_to_ready(kits):
    client = logged_in(kits)
    page = client.get("/staff").text
    assert "연결된 PC가 없습니다" in page and 'class="badge ok">사용 가능' not in page
    download(client)
    kits.query("UPDATE mint.endpoint_installs SET install_mode = 'managed', reported_at = now()")
    assert "아직 받지 않았습니다" in client.get("/staff").text
    kits.query(
        "INSERT INTO mint.endpoint_tool_lists (instance_id, server_id, key_token, tools,"
        " tools_sha256) SELECT instance_id, 'local-1', key_token,"
        " '[{\"name\": \"read_file\"}]'::jsonb, %s FROM mint.endpoint_installs", "c" * 64)
    ready = client.get("/staff").text
    assert 'class="badge ok">사용 가능' in ready and "도구 발견" in ready
    drawer = client.get("/staff?open=acme%7Clocal-1").text
    assert "read_file" in drawer and "내 PC가 확인" in drawer


def test_the_same_repository_request_goes_to_the_existing_application(sworld, monkeypatch):
    intake_tests.resolved(monkeypatch)
    client = logged_in(sworld)

    def submit():
        return client.post("/staff/intakes", data={
            "csrf": csrf(client), "request_id": str(uuid.uuid4()), "url": intake_tests.REPO,
            "purpose": "분석 보조", "step": "submit", "name": "ghidra_mcp",
            "commit": intake_tests.SHA, "command": intake_tests.COMMAND})

    first = submit()
    assert first.status_code == 303 and first.headers["location"].endswith("ok=intake_created")
    again = submit()
    assert again.status_code == 303 and again.headers["location"].endswith("ok=intake_existing")
    assert again.headers["location"].split("?")[0] == first.headers["location"].split("?")[0]
    assert sworld.query("SELECT count(*) FROM mint.intakes") == [(1,)]
    assert "이미 신청한 서버입니다" in client.get(again.headers["location"]).text
    for step in ("checking", "passed"):
        sworld.query("UPDATE mint.intakes SET status = %s", step)
    sworld.query("UPDATE mint.intakes SET status = 'decided', decision = 'approved',"
                 " decided_by = 'admin', decided_at = now()")  # 승인된 신청이어도 그 상세로
    assert submit().headers["location"].split("?")[0] == first.headers["location"].split("?")[0]


def test_one_pc_can_be_disconnected_without_touching_the_others(kits):
    client = logged_in(kits)
    download(client)
    download(client)
    first, second = [r[0] for r in kits.query(
        "SELECT key_alias FROM mint.endpoint_installs ORDER BY issued_at")]
    page = client.get("/staff/endpoint").text
    assert page.count("이 PC 연결 해제") >= 4 and "내 PC 2대의 연결을 모두 해제합니다" in page
    done = client.post("/staff/endpoint/revoke", data={"csrf": csrf(client), "key_alias": first})
    assert done.status_code == 303 and done.headers["location"].endswith("ok=kit_revoked_one")
    assert kits.query("SELECT key_alias, revoked_at IS NOT NULL FROM mint.endpoint_installs"
                      " ORDER BY issued_at") == [(first, True), (second, False)]
    stranger = logged_in(kits, OTHER_KEY)
    refused = stranger.post("/staff/endpoint/revoke",
                            data={"csrf": csrf(stranger), "key_alias": second})
    assert refused.status_code == 400
    assert kits.query("SELECT count(*) FROM mint.endpoint_installs WHERE revoked_at IS NULL") == [
        (1,)]
    assert "내 PC 2대" not in client.get("/staff/endpoint").text  # 한 대만 남으면 모두 해제는 없다


def test_the_staff_usage_page_loads_the_chart_script_itself(sworld):
    client = logged_in(sworld)
    assert "/static/echarts.min.js" in client.get("/staff/usage").text
    moved = client.get("/staff/usage?period=7d", headers={"HX-Boosted": "true"})
    assert moved.headers["HX-Redirect"] == "/staff/usage?period=7d"
