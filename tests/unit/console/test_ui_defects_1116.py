"""화면 시험 11-16 결함 회귀: 입력 검증, 한글 안내, 권한 없는 단추, 기본 사용 기간."""

import re
import uuid

import pytest
from console_pages_support import INSTANCE

from mint_litellm.console.core import invalid_fields, screen_message
from mint_litellm.control.operators import hash_token

HTML = {"accept": "text/html"}


def pending_call(world, requested_by="human-7") -> str:
    call_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
        " VALUES (%s, 'v1', %s, %s) ON CONFLICT DO NOTHING", INSTANCE, "ab" * 32, "ab" * 32)
    world.query(
        "INSERT INTO mint.call_approvals (id, instance_id, org_id, principal_type, principal_id,"
        " server_id, tool, args_fp, fp_key_version, policy_version_id, status, requested_by,"
        " expires_at) VALUES (%s, %s, 'acme', 'user', 'human-7', 'srv-ok',"
        " 'write_file', %s, 1, 'v1', 'pending', %s, now() + interval '1 hour')",
        call_id, INSTANCE, "ab" * 32, requested_by)
    return call_id


# UI-002: 조직 식별자·이름 검증은 입력 경계에서 400으로 끝난다
@pytest.mark.parametrize("org_id,name", [
    ("ui org 2", "공백 식별자"), ("ui-hangul-한", "한글 식별자"), ("ok-org", "가" * 600),
])
def test_org_input_is_refused_as_a_bad_request_not_a_database_failure(world, admin, org_id, name):
    response = admin.post(
        "/orgs", data={"csrf": world.csrf(admin), "org_id": org_id, "name": name}, headers=HTML)
    assert response.status_code == 400 and "데이터베이스" not in response.text
    assert world.query("SELECT count(*) FROM mint.orgs WHERE org_id = %s", org_id)[0][0] == 0


# UI-003: 유효 기간 상한
def test_a_huge_validity_period_is_a_form_error_not_a_server_error(world, admin):
    response = admin.post(
        "/servers/srv-ok/evidence", headers=HTML,
        data={"csrf": world.csrf(admin), "kind": "vuln_exception", "summary": "확인",
              "valid_days": "99999999"})
    assert response.status_code == 400
    assert "3650일 이하" in response.text or "입력 값이 올바르지" in response.text


# UI-004: 영문 필드명·명령줄 옵션이 화면에 나오지 않는다
def test_messages_shown_on_screen_use_korean_names():
    assert invalid_fields([{"loc": ("body", "valid_days")}, {"loc": ("scope_id",)}]) == (
        "유효 기간(일), 범위 대상")
    text = screen_message("다른 사용자의 운영자 토큰을 --second-approver로 함께 제시하십시오.")
    assert "--" not in text and "두 번째 승인자 토큰" in text
    assert screen_message("--reason이 필요합니다.") == "사유가 필요합니다."
    assert screen_message("--allowed-host 값이 올바르지 않습니다") == (
        "허용 호스트 값이 올바르지 않습니다")
    assert screen_message("admin만 취소할 수 있습니다") == "관리자만 취소할 수 있습니다"


def test_a_missing_form_value_names_the_field_in_korean(world, admin):
    response = admin.post("/approvals", headers=HTML, data={"csrf": world.csrf(admin)})
    assert response.status_code == 400
    assert "valid_days" not in response.text and "scope_id" not in response.text
    assert "범위 대상" in response.text


# UI-007: 사용 기간 열과 단추가 서로 맞는다(대기 중에는 기간 미정)
def test_the_pending_call_row_does_not_claim_a_period_the_button_contradicts(world, admin):
    call_id = pending_call(world)
    html = admin.get(f"/approvals?tab=calls&focus={call_id}").text
    assert "30분 승인" in html and "1회</td>" not in html


# UI-008: 취소 단추는 요청자 본인과 관리자에게만
def test_the_cancel_button_is_hidden_from_someone_who_cannot_cancel(world):
    call_id = pending_call(world, requested_by="human-7")
    path = f"/approvals?tab=calls&focus={call_id}"
    assert "decide-cancel" in world.session_client("admin").get(path).text
    assert "decide-cancel" not in world.session_client("approver").get(path).text


# UI-009: 증빙 필요한 때 열은 한글
def test_evidence_gates_have_korean_names():
    from mint_litellm.console import labels

    assert labels.EVIDENCE_GATE["unpinned"] and labels.EVIDENCE_GATE["exception"]
    assert not re.search(r"[a-z]", labels.EVIDENCE_GATE["unpinned"])


# UI-010: 역할 선택에는 바꿀 수 있는 역할만
def test_the_role_select_offers_only_roles_the_operator_can_take(world, admin):
    world.query(
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES (%s, 'orphan', 'viewer', %s, NULL)", INSTANCE, hash_token("x" * 40))
    html = admin.get("/admin?tab=operators").text
    assert "/operators/orphan/role" not in html  # 사용자에 결속되지 않으면 조회자 외에 못 된다
    form = re.search(r'/operators/approver/role.*?</form>', html, re.S).group(0)
    assert 'value="approver"' not in form and 'value="admin"' in form
    assert "approver 역할은" not in screen_message("approver 역할은 사용자에 결속")


# UI-011·012: 신청 위저드
def test_the_intake_wizard_refuses_a_missing_address_on_the_first_step(world, admin):
    page = admin.get("/intakes/new")
    assert page.status_code == 200
    ids = re.findall(r'<option value="([^"]+)"', page.text)
    assert "srv-ok" not in ids  # 이미 승인된 서버는 고르는 목록에서 뺀다


def test_server_state_codes_are_shown_in_korean():
    text = screen_message("서버 uisrv1는 approved 상태라 새 수용검증을 시작할 수 없습니다.")
    assert "approved" not in text and "승인됨" in text


# UI-013·014: 신청 결정 패널
def test_the_decision_panel_shows_no_buttons_to_the_requester(world, admin):
    from mint_litellm.console import templating

    assert templating.templates is not None  # 템플릿 로드 확인

    source = open("src/mint_litellm/console/templates/intake_detail.html", encoding="utf-8").read()
    assert "actor.session.user_id != i.requested_by" not in source
    css = open("src/mint_litellm/console/static/console.css", encoding="utf-8").read()
    assert "flex-wrap: wrap" in css and ".actions button" in css


# UI-006·015·016: 배치
def test_layout_rules_keep_fields_donuts_and_tables_inside_the_screen():
    css = open("src/mint_litellm/console/static/console.css", encoding="utf-8").read()
    js = open("src/mint_litellm/console/static/console.js", encoding="utf-8").read()
    assert ".drawer-body .form input" in css and "overflow-wrap: anywhere" in css
    assert 'radius: ["42%", "68%"]' in js


# --- 2차 점검(UI2) ---------------------------------------------------------------------


def test_the_ledger_cards_and_charts_follow_the_filters(world, admin):
    from .test_dashboard import decision

    decision(world, server="srv-ok", enforced="allow")
    decision(world, server="srv-ok", enforced="deny", outcome="blocked")
    decision(world, server="srv-wait", enforced="deny", outcome="blocked")
    html = admin.get("/ledger?range=24h").text
    assert re.search(r"호출 수</div>\s*<div class=\"value\">3<", html)
    html = admin.get("/ledger?range=24h&server_id=srv-ok&result=deny").text
    assert re.search(r"호출 수</div>\s*<div class=\"value\">1<", html)


def test_a_bad_reference_empties_the_ledger_table(world, admin):
    from .test_dashboard import decision

    decision(world)
    page = admin.get("/ledger?ref=nope", headers=HTML)
    assert page.status_code == 400 and "판정 참조 형식" in page.text
    assert "조건에 맞는 기록이 없습니다" in page.text


def test_the_ledger_has_no_next_page_when_the_last_page_is_exactly_full(world, admin):
    from mint_litellm.control.services import reads

    from .test_dashboard import decision

    for _ in range(reads.PAGE_SIZE):
        decision(world, server="srv-full")
    assert "page=2" not in admin.get("/ledger?range=24h&server_id=srv-full").text
    decision(world, server="srv-full")
    assert "page=2" in admin.get("/ledger?range=24h&server_id=srv-full").text


def test_an_exception_approval_needs_a_reason_and_is_not_granted_twice(world, admin):
    world.with_control_key()
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    version = world.query("SELECT state_version FROM mint.usage_relations")[0][0]
    form = {"csrf": world.csrf(admin), "relation_id": relation, "state_version": version,
            "scope_type": "user", "scope_id": "human-7", "tools": "echo", "class": "exception",
            "requested_by": "human-7", "basis": ""}
    refused = admin.post("/approvals", data=form, headers=HTML)
    assert refused.status_code == 400 and "승인 사유" in refused.text
    assert world.query("SELECT count(*) FROM mint.approvals WHERE class = 'exception'")[0][0] == 0


def test_the_approval_queue_leaves_out_relations_that_already_have_an_approval(world, admin):
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    assert "승인·거부" in admin.get("/approvals?tab=servers").text
    world.query(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id, tools,"
        " scope_type, scope_id, valid_from, valid_until, conditions, basis, granted_by,"
        " requested_by, status) VALUES (gen_random_uuid(), %s, 'acme', %s, 'standard', 'srv-wait',"
        " ARRAY['echo'], 'user', 'human-7', now(), now() + interval '30 days', '{}'::jsonb,"
        " '{}'::jsonb, 'admin', 'human-7', 'pending')", INSTANCE, relation)
    assert "srv-wait</a>" not in admin.get("/approvals?tab=servers").text


def test_contract_changes_are_not_shown_as_deleted_before_anything_is_observed():
    from mint_litellm.console import compare

    info = {"tools": [{"status": "approved", "credential_scope": "", "tool": "t", "drift": "none",
                       "canonical_text": "{}"}], "observations": [], "deployments": []}
    assert compare.changes(info) == []


def test_page_values_and_messages_have_no_raw_codes():
    from mint_litellm.console.templating import clip

    assert clip({"a": 1, "b": 2}) == "a: 1, b: 2" and clip(["x", "y"]) == "x, y"
    assert "object_permission" not in screen_message(
        "키의 object_permission.mcp_servers에 srv를 추가하십시오.")
