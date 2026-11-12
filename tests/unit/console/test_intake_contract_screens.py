"""화면 3·5(신청·수용검증, 계약 변경 비교·재승인): 권한, 직무 분리, 증거 만료, 이스케이프."""

import json
import re
import uuid

import pytest
from console_fixtures import HEX, TOKENS

from mint_litellm.control.errors import AdminCode

INSTANCE = "inst1"
CHECKS = ["url_guard", "oauth_issuer_allowlist", "connection", "definitions", "description_scan",
          "risk_grade", "termination_readiness", "supply_chain"]
READINESS = json.dumps({"credential_notice": True, "revocation_record": True,
                        "audit_access_days": 30})


def bearer(role: str) -> dict:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def add_intake(world, *, requested_by="human-9", status="passed", result="pass",
               server="srv-wait", stale=False, reason="X_CODE") -> str:
    intake_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, purpose, data_grade,"
        " allowed_resources, provider, owner_user_id, readiness, data_return_terms, requested_by)"
        " VALUES (%s, %s, 'acme', %s, 'operator', '문서 검색', 'internal', %s, '제공자',"
        " 'human-9', %s, '반환 조건', %s)",
        intake_id, INSTANCE, server, json.dumps(["docs"]), READINESS, requested_by)
    if status != "received":
        world.query("UPDATE mint.intakes SET status = 'checking' WHERE id = %s", intake_id)
        world.query("UPDATE mint.intakes SET status = %s WHERE id = %s", status, intake_id)
    for name in CHECKS:
        age = "26 hours" if stale and name == "connection" else "1 minute"
        outcome = result if name == "supply_chain" else "pass"
        world.query(
            "INSERT INTO mint.intake_checks (id, instance_id, intake_id, \"check\", attempt,"
            " result, reason_code, method, evidence_sha256, evidence_valid_until, ran_at)"
            " VALUES (%s, %s, %s, %s, 1, %s, %s, 'm', %s, now() + interval '5 days',"
            " now() - interval '" + age + "')",
            uuid.uuid4(), INSTANCE, intake_id, name, outcome,
            "URL_QUERY" if name == "url_guard" and reason == "URL_QUERY" else "X_CODE", HEX)
    world.query(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (%s, %s, %s, 'server', 'echo', '{}', %s, %s, 'low', 'read', 'intake',"
        " 'candidate')", uuid.uuid4(), INSTANCE, server, HEX, HEX)
    world.query(
        "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text, sha256,"
        " url, url_sha256, transport, auth_type, status) VALUES (%s, %s, %s, 'x', %s,"
        " 'http://c.example', %s, 'http', 'none', 'candidate')",
        uuid.uuid4(), INSTANCE, server, HEX, HEX)
    if status != "received":
        world.query(
            "INSERT INTO mint.policy_evidence (id, instance_id, kind, subject_kind, subject_id,"
            " summary, attached_by, valid_until) SELECT gen_random_uuid(), %s, k, 'intake', %s,"
            " '시험', 'root', now() + interval '30 days' FROM unnest(%s::text[]) AS k",
            INSTANCE, intake_id,
            ["trial_call", "provider_terms", "least_privilege", "prompt_review",
             "transfer_approval"])
    return intake_id


def version(world, intake_id: str) -> int:
    return world.query("SELECT state_version FROM mint.intakes WHERE id = %s", intake_id)[0][0]


def decide(world, intake_id, role="admin", **body):
    body.setdefault("state_version", version(world, intake_id))
    return world.client.post(f"/api/v1/intakes/{intake_id}/decision", headers=bearer(role),
                             json=body)


# --- 화면 3 ----------------------------------------------------------------------------------


def test_the_intake_list_shows_the_oldest_first_with_korean_names(world):
    first = add_intake(world, status="passed")
    second = add_intake(world, status="indeterminate", result="indeterminate", server="srv-ok")
    client = world.session_client("viewer")
    html = client.get("/intakes").text
    assert html.index(first) < html.index(second)
    assert "검사 통과" in html and "판별 불가" in html and "운영자 등록" in html
    only = client.get("/intakes?status=indeterminate").text
    assert second in only and first not in only


def test_an_empty_intake_list_has_one_next_action(world):
    html = world.session_client("viewer").get("/intakes").text
    assert "조건에 맞는 신청이 없습니다" in html and html.count('class="empty"') == 1


def test_the_detail_shows_eight_checks_risk_grade_and_the_evidence_expiry(world):
    intake = add_intake(world)
    html = world.session_client("approver").get(f"/intakes/{intake}").text
    for name in ("주소 검사", "인증 서버 허용 목록", "연결", "도구 정의", "설명 검사", "위험 등급",
                 "종료 준비", "공급망"):
        assert name in html
    assert "증거 만료" in html and "낮음" in html and "읽기" in html
    assert "X_CODE" in html and "<code>X_CODE</code>" not in html and "human-9" in html
    assert 'name="valid_days" value="90"' in html


def test_the_default_period_is_thirty_days_for_high_risk_tools(world):
    intake = add_intake(world)
    world.query("UPDATE mint.tool_contracts SET risk_grade = 'high'")
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert 'name="valid_days" value="30"' in html


def test_a_viewer_sees_no_decision_buttons(world):
    intake = add_intake(world)
    html = world.session_client("viewer").get(f"/intakes/{intake}").text
    assert "/decision" not in html and "재검사" not in html


def test_assigning_a_requester_needs_the_control_key(world):
    intake = add_intake(world, requested_by=None, status="received")
    admin = world.session_client("admin")
    assert "제어 평면 키가 없어" in admin.get(f"/intakes/{intake}").text
    response = world.client.post(
        f"/api/v1/intakes/{intake}/requester", headers=bearer("admin"),
        json={"user_id": "human-9", "state_version": version(world, intake)})
    assert response.status_code == 403 and "제어 평면 키" in response.json()["message"]


def test_assigning_a_requester_from_the_screen_and_the_assigner_cannot_decide(world):
    world.with_control_key()
    world.stub.routes[("/user/info", "control-plane-key", "human-9")] = (
        200, {"user_id": "human-9",
              "user_info": {"user_id": "human-9", "user_role": "internal_user"}})
    intake = add_intake(world, requested_by=None, status="received")
    admin = world.session_client("admin")
    assert 'name="user_id"' in admin.get(f"/intakes/{intake}").text
    response = admin.post(f"/intakes/{intake}/requester", data={
        "csrf": world.csrf(admin), "user_id": "human-9", "state_version": version(world, intake)})
    assert response.status_code == 303 and "requester_assigned" in response.headers["location"]
    assert world.query("SELECT requested_by FROM mint.intakes")[0][0] == "human-9"
    world.query("UPDATE mint.intakes SET status = 'checking'")
    world.query("UPDATE mint.intakes SET status = 'passed'")
    refused = decide(world, intake, decision="approve")
    assert refused.status_code == 403
    assert refused.json()["code"] == AdminCode.SEPARATION_OF_DUTIES


def test_the_requester_cannot_decide_their_own_intake(world):
    intake = add_intake(world, requested_by="human-2")
    response = decide(world, intake, role="approver", decision="approve")
    assert response.status_code == 403
    assert response.json()["code"] == AdminCode.SEPARATION_OF_DUTIES
    assert world.query("SELECT status FROM mint.intakes")[0][0] == "passed"


def test_a_viewer_cannot_decide_and_a_stale_version_conflicts(world):
    intake = add_intake(world)
    assert decide(world, intake, role="viewer", decision="reject", reason="x").status_code == 403
    stale = decide(world, intake, decision="reject", reason="x", state_version=99)
    assert stale.status_code == 409 and stale.json()["code"] == AdminCode.CONFLICT


def test_rejecting_needs_a_reason_and_records_the_decision(world):
    intake = add_intake(world)
    assert decide(world, intake, decision="reject").status_code == 400
    response = decide(world, intake, decision="reject", reason="위험이 큼")
    assert response.status_code == 200, response.text
    assert world.query("SELECT status, decision FROM mint.intakes")[0] == ("decided", "rejected")


def test_approving_registers_the_approval_with_the_default_period(world):
    intake = add_intake(world)
    response = decide(world, intake, decision="approve")
    assert response.status_code == 200, response.text
    assert world.query("SELECT status, decision FROM mint.intakes")[0] == ("decided", "approved")
    span = world.query("SELECT extract(day FROM valid_until - valid_from) FROM mint.approvals")
    assert 89 <= span[0][0] <= 90


def test_an_exception_needs_a_reason_a_second_approver_and_at_most_ninety_days(world):
    intake = add_intake(world, status="indeterminate", result="indeterminate")
    base = {"decision": "except", "reason": "수동 확인함"}
    assert decide(world, intake, **base, valid_days=91).status_code == 400
    alone = decide(world, intake, **base)
    assert alone.status_code == 403 and alone.json()["code"] == AdminCode.SEPARATION_OF_DUTIES
    same = decide(world, intake, **base, second_approver_token=TOKENS["admin"])
    assert same.status_code == 403
    ok = decide(world, intake, **base, second_approver_token=TOKENS["approver"])
    assert ok.status_code == 200, ok.text
    assert world.query("SELECT decision FROM mint.intakes")[0][0] == "exception"


def test_stale_evidence_blocks_the_decision_and_the_screen_offers_a_recheck(world):
    intake = add_intake(world, stale=True)
    response = decide(world, intake, decision="approve")
    assert response.status_code == 409 and response.json()["code"] == AdminCode.STALE_EVIDENCE
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert "24시간을 넘었습니다" in html and f"/intakes/{intake}/recheck" in html


def test_a_recheck_registers_a_job_and_a_decided_intake_cannot_be_rechecked(world):
    intake = add_intake(world)
    response = world.client.post(f"/api/v1/intakes/{intake}/recheck", headers=bearer("admin"),
                                 json={"state_version": version(world, intake)})
    assert response.status_code == 200, response.text
    assert world.query("SELECT count(*) FROM mint.jobs WHERE kind = 'intake_run'")[0][0] == 1
    decide(world, intake, decision="reject", reason="x")
    again = world.client.post(f"/api/v1/intakes/{intake}/recheck", headers=bearer("admin"),
                              json={"state_version": version(world, intake)})
    assert again.status_code == 409


def test_deciding_from_the_screen_needs_the_csrf_field(world):
    intake = add_intake(world)
    admin = world.session_client("admin")
    data = {"decision": "reject", "reason": "x", "state_version": version(world, intake)}
    assert admin.post(f"/intakes/{intake}/decision", data=data).status_code == 403
    ok = admin.post(f"/intakes/{intake}/decision", data={**data, "csrf": world.csrf(admin)})
    assert ok.status_code == 303 and "intake_rejected" in ok.headers["location"]


# --- 화면 5 ----------------------------------------------------------------------------------

APPROVED = {"description": "승인본 설명", "input_schema": {"type": "object"}}
SCRIPTED = {"description": "<script>alert(1)</script>", "input_schema": {"type": "object"}}


def canon(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def seed_drift(world, server="srv-ok"):
    world.query("UPDATE mint.servers SET contract_status = 'managed' WHERE server_id = %s", server)
    for tool in ("echo", "gone"):
        world.query(
            "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
            " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
            " VALUES (%s, %s, %s, 'server', %s, %s, %s, %s, 'low', 'read', 'intake',"
            " 'candidate')", uuid.uuid4(), INSTANCE, server, tool, canon(APPROVED), HEX, HEX)
    world.query("UPDATE mint.tool_contracts SET status = 'approved' WHERE server_id = %s"
                " AND source = 'intake' AND canonical_text <> '{}'", server)
    for name, value in (("echo", SCRIPTED), ("fresh", APPROVED)):
        world.query(
            "INSERT INTO mint.contract_observations (instance_id, server_id, kind, scope, name,"
            " entity_id, observed_sha256, canonical_text, change_seq) VALUES (%s, %s, 'tool',"
            " 'server', %s, %s, %s, %s, 1)",
            INSTANCE, server, name, uuid.uuid4(), HEX, canon(value))


def test_the_drift_list_shows_only_servers_with_changes(world):
    seed_drift(world)
    world.query("UPDATE mint.tool_contracts SET drift = 'description' WHERE tool = 'echo'")
    html = world.session_client("viewer").get("/contracts").text
    assert "srv-ok" in html and "srv-wait" not in html and "비교" in html


def test_an_empty_drift_list_has_one_next_action(world):
    html = world.session_client("viewer").get("/contracts").text
    assert "계약 변경이 있는 서버가 없습니다" in html and html.count('class="empty"') == 1


def test_the_comparison_lists_added_removed_and_changed_items(world):
    seed_drift(world)
    html = world.session_client("viewer").get("/contracts/srv-ok").text
    pattern = r"<td>(\w+)</td><td><span class=\"badge \w+\"><span[^>]*>.</span>(\S+?)</span>"
    assert dict(re.findall(pattern, html)) == {"echo": "변경", "gone": "삭제", "fresh": "추가"}


def test_a_selected_item_shows_both_sides_with_changed_lines_marked_and_escaped(world):
    seed_drift(world)
    client = world.session_client("viewer")
    response = client.get("/contracts/srv-ok?scope=server&name=echo")
    html = response.text
    assert "승인본" in html and "현재본" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)" not in html
    assert html.count('class="changed"') == 2  # 승인본 한 줄, 현재본 한 줄
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_a_deployment_change_is_listed(world):
    seed_drift(world)
    world.query(
        "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text, sha256,"
        " url, url_sha256, transport, auth_type, status) VALUES (%s, %s, 'srv-ok', %s, %s,"
        " 'http://a.example', %s, 'http', 'none', 'candidate')",
        uuid.uuid4(), INSTANCE, canon({"url": "http://a.example"}), HEX, HEX)
    world.query("UPDATE mint.deployment_contracts SET status = 'approved'")
    world.query(
        "INSERT INTO mint.contract_observations (instance_id, server_id, kind, scope, name,"
        " entity_id, observed_sha256, canonical_text, change_seq) VALUES (%s, 'srv-ok',"
        " 'deployment', 'server', 'deployment', %s, %s, %s, 1)",
        INSTANCE, uuid.uuid4(), HEX, canon({"url": "http://b.example"}))
    assert "(배포)" in world.session_client("viewer").get("/contracts/srv-ok").text


def test_the_reapproval_form_lists_candidates_and_states_that_only_a_plan_is_registered(world):
    seed_drift(world)
    intake = add_intake(world, server="srv-ok")
    html = world.session_client("admin").get("/contracts/srv-ok").text
    assert "후보 도구 계약" in html and "계획만 등록합니다" in html and "재승인 계획 등록" in html
    assert intake in html
    assert "재승인 계획 등록" not in world.session_client("viewer").get("/contracts/srv-ok").text


def test_reapproval_without_matching_evidence_is_refused_and_a_viewer_is_forbidden(world):
    seed_drift(world)
    intake = add_intake(world, server="srv-ok")
    body = {"intake_id": intake, "tool_contract_ids": [], "state_version": 1}
    path = "/api/v1/servers/srv-ok/contracts/reapprove"
    assert world.client.post(path, headers=bearer("viewer"), json=body).status_code == 403
    refused = world.client.post(path, headers=bearer("admin"), json=body)
    assert refused.status_code in (403, 409)
    assert refused.json()["code"] in (AdminCode.CONFLICT, AdminCode.STALE_EVIDENCE,
                                      AdminCode.SEPARATION_OF_DUTIES)


def test_the_plan_progress_is_shown(world):
    seed_drift(world)
    intake = add_intake(world, server="srv-ok")
    world.query(
        "INSERT INTO mint.contract_reapproval_plans (id, instance_id, server_id, intake_id,"
        " requested_by, requested_user_id, plan) VALUES (%s, %s, 'srv-ok', %s, 'admin', 'human-1',"
        " %s)", uuid.uuid4(), INSTANCE, intake, json.dumps({}))
    viewer = world.session_client("viewer")
    html = viewer.get("/contracts/srv-ok").text
    assert "반영 대기" in html and "작업 실행기가 반영하는 중" in html
    assert "반영 대기" in viewer.get("/contracts").text


def test_the_contract_api_returns_changes_and_the_drift_list(world):
    seed_drift(world)
    world.query("UPDATE mint.tool_contracts SET drift = 'description' WHERE tool = 'echo'")
    path = "/api/v1/servers/srv-ok/contracts/diff"
    response = world.client.get(path, headers=bearer("viewer"))
    assert response.status_code == 200
    assert {c["name"]: c["change"] for c in response.json()["changes"]} == {
        "echo": "changed", "gone": "removed", "fresh": "added"}
    listing = world.client.get("/api/v1/contracts", headers=bearer("viewer")).json()["items"]
    assert [r["server_id"] for r in listing] == ["srv-ok"]


@pytest.mark.parametrize("path", ["/intakes", "/contracts"])
def test_the_new_screens_need_a_session_and_carry_the_security_headers(world, path):
    assert world.client.get(path).status_code == 303
    response = world.session_client("viewer").get(path)
    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_the_requester_assigner_cannot_be_the_second_approver_of_an_exception(world):
    intake = add_intake(world, status="indeterminate", result="indeterminate")
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
        " VALUES (%s, %s, 'intake_requester_assigned', %s, 'approver', %s)",
        uuid.uuid4(), INSTANCE, f"intake:{intake}:2:intake_requester_assigned",
        json.dumps({"intake_id": intake}))
    response = decide(world, intake, decision="except", reason="수동 확인함",
                      second_approver_token=TOKENS["approver"])
    assert response.status_code == 403
    assert response.json()["code"] == AdminCode.SEPARATION_OF_DUTIES
    assert "지정자" in response.json()["message"]
    assert world.query("SELECT status FROM mint.intakes")[0][0] == "indeterminate"


def test_a_comparison_within_the_limit_finishes_quickly():
    import time

    from mint_litellm.console import compare

    left = json.dumps({f"k{i}": i for i in range(900)})
    right = json.dumps({f"k{i}": i + (i % 3 == 0) for i in range(900)})
    started = time.monotonic()
    sides = compare.side_by_side(left, right)
    assert not sides["skipped"] and time.monotonic() - started < 5
    same = json.dumps({"a": ["x"] * 1500})
    other = json.dumps({"a": ["y"] * 1500})
    started = time.monotonic()
    assert not compare.side_by_side(same, other)["skipped"]
    assert time.monotonic() - started < 5


def test_a_comparison_over_the_limit_is_skipped_with_hashes_and_sizes_only():
    import time

    from mint_litellm.console import compare

    big = json.dumps({"description": "x" * 300_000})
    lines = json.dumps(["v"] * 2500)
    started = time.monotonic()
    for text in (big, lines):
        sides = compare.side_by_side(text, "{}")
        assert sides["skipped"] is True
        assert sides["approved"]["bytes"] == len(text.encode())
        assert len(sides["observed"]["sha256"]) == 64
    assert time.monotonic() - started < 2


def test_an_oversized_schema_shows_the_skip_notice_on_the_screen(world):
    seed_drift(world)
    world.query("UPDATE mint.contract_observations SET canonical_text = %s WHERE name = 'echo'",
                canon({"description": "x" * 300_000}))
    viewer = world.session_client("viewer")
    html = viewer.get("/contracts/srv-ok?scope=server&name=echo").text
    assert "크기가 커서 줄 비교를 생략했습니다" in html and html.count("<code>") >= 2
    assert 'class="changed"' not in html


def test_bad_form_values_are_a_korean_400_on_the_screen(world):
    intake = add_intake(world)
    admin = world.session_client("admin")
    response = admin.post(f"/intakes/{intake}/decision", data={
        "csrf": world.csrf(admin), "decision": "zz", "state_version": version(world, intake)})
    assert response.status_code == 400 and "입력 값이 올바르지 않습니다" in response.text
    role = admin.post("/operators/viewer/role", data={
        "csrf": world.csrf(admin), "role": "zz", "state_version": 1})
    assert role.status_code == 400 and "입력 값이 올바르지 않습니다" in role.text


def test_the_detail_shows_korean_reasons_and_no_english_codes(world):
    intake = add_intake(world, reason="URL_QUERY")
    html = world.session_client("viewer").get(f"/intakes/{intake}").text
    assert "주소에 질의 문자열 포함" in html and "URL_QUERY" not in html
    assert "<code>passed</code>" not in html


def test_an_approved_intake_of_a_managed_server_offers_and_accepts_a_recheck(world):
    """승인된 신청의 재검사: 화면 버튼과 API가 evidence 모드 작업을 등록한다."""
    intake = add_intake(world, server="srv-ok")
    world.query("UPDATE mint.servers SET contract_status = 'managed' WHERE server_id = 'srv-ok'")
    world.query("UPDATE mint.intakes SET status = 'decided', decision = 'approved',"
                " decided_by = 'x', decided_at = now() WHERE id = %s", intake)
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert f"/intakes/{intake}/recheck" in html
    response = world.client.post(f"/api/v1/intakes/{intake}/recheck", headers=bearer("admin"),
                                 json={"state_version": version(world, intake)})
    assert response.status_code == 200, response.text
    assert world.query("SELECT target_ref FROM mint.jobs WHERE kind = 'intake_run'")[0][0] == (
        f"{intake}/evidence")


def test_the_console_recheck_takes_a_url_and_reports_a_hash_mismatch(world):
    intake = add_intake(world, server="srv-ok")
    world.query("UPDATE mint.servers SET contract_status = 'managed' WHERE server_id = 'srv-ok'")
    world.query("UPDATE mint.intakes SET status = 'decided', decision = 'approved',"
                " decided_by = 'x', decided_at = now() WHERE id = %s", intake)
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert 'name="url"' in html and 'name="transport"' in html
    response = world.client.post(f"/api/v1/intakes/{intake}/recheck", headers=bearer("admin"),
                                 json={"state_version": version(world, intake),
                                       "url": "http://x.test/mcp"})
    assert response.status_code in (400, 409, 422), response.text
