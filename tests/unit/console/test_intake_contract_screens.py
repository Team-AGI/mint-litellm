"""화면 3·5(신청·수용검증, 계약 변경 비교·재승인): 권한, 직무 분리, 증거 만료, 이스케이프."""

import json
import re
import uuid
from datetime import timedelta

import pytest
from console_fixtures import HEX, TOKENS

from mint_litellm.control.errors import AdminCode

INSTANCE = "inst1"
CHECKS = ["url_guard", "oauth_issuer_allowlist", "connection", "definitions", "description_scan",
          "risk_grade", "termination_readiness", "supply_chain"]
READINESS = json.dumps({"credential_notice": True, "revocation_record": True,
                        "audit_access_days": 30})


@pytest.fixture(autouse=True)
def litellm_permission(world, monkeypatch):
    """승인은 연결 승인과 같은 LiteLLM 권한 확인을 거친다. 여기서는 확인 자체를 기록만 한다."""
    from mint_litellm.control.services import intakes

    world.with_control_key()
    seen = []
    monkeypatch.setattr(
        intakes, "check_scope_and_permission",
        lambda ctx, litellm, relation, scope_type, scope_id: seen.append((scope_type, scope_id)),
    )
    return seen


@pytest.fixture(autouse=True)
def distinct_approver(monkeypatch):
    """직무 분리를 켠 설치의 동작을 시험한다. 꺼진 기본 동작은 단독 승인 시험이 맡는다."""
    monkeypatch.setenv("MINT_REQUIRE_DISTINCT_APPROVER", "1")


def bearer(role: str) -> dict:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def add_intake(
    world,
    *,
    requested_by="human-9",
    status="passed",
    result="pass",
    server="srv-wait",
    stale=False,
    reason="X_CODE",
    with_evidence=True,
    url_blocked=False,
    source="operator",
) -> str:
    intake_id = str(uuid.uuid4())
    world.query(
        "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source, purpose, data_grade,"
        " allowed_resources, provider, owner_user_id, readiness, data_return_terms, requested_by)"
        " VALUES (%s, %s, 'acme', %s, %s, '문서 검색', 'internal', %s, '제공자',"
        " 'human-9', %s, '반환 조건', %s)",
        intake_id, INSTANCE, server, source, json.dumps(["docs"]), READINESS, requested_by)
    if status != "received":
        world.query("UPDATE mint.intakes SET status = 'checking' WHERE id = %s", intake_id)
        world.query("UPDATE mint.intakes SET status = %s WHERE id = %s", status, intake_id)
    for name in CHECKS:
        age = "26 hours" if stale and name == "connection" else "1 minute"
        outcome = (
            "fail"
            if url_blocked and name == "url_guard"
            else (result if name == "supply_chain" else "pass")
        )
        world.query(
            "INSERT INTO mint.intake_checks (id, instance_id, intake_id, \"check\", attempt,"
            " result, reason_code, method, evidence_sha256, evidence_valid_until, ran_at)"
            " VALUES (%s, %s, %s, %s, 1, %s, %s, 'm', %s, now() + interval '5 days',"
            " now() - interval '" + age + "')",
            uuid.uuid4(),
            INSTANCE,
            intake_id,
            name,
            outcome,
            "PROVIDER_NOT_ALLOWED"
            if url_blocked and name == "url_guard"
            else ("URL_QUERY" if name == "url_guard" and reason == "URL_QUERY" else "X_CODE"),
            HEX,
        )
    world.query(
        "INSERT INTO mint.tool_contracts (id, instance_id, server_id, credential_scope, tool,"
        " canonical_text, sha256, pin_sha256, risk_grade, action_type, source, status)"
        " VALUES (%s, %s, %s, 'server', 'echo', '{}', %s, %s, 'low', 'read', 'intake',"
        " 'candidate')", uuid.uuid4(), INSTANCE, server, HEX, HEX)
    world.query(
        "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text, sha256,"
        " url, url_sha256, transport, auth_type, status) VALUES (%s, %s, %s, 'x', %s,"
        " 'http://c.example', %s, 'http', 'none', 'candidate')",
        uuid.uuid4(),
        INSTANCE,
        server,
        HEX,
        HEX,
    )
    if status != "received" and with_evidence:
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
    assert "X_CODE" in html and "<code>X_CODE</code>" not in html
    assert "human-9" in world.session_client("approver").get(f"/intakes/{intake}?tab=info").text
    assert 'placeholder="기한 없음"' in html




def test_a_viewer_sees_no_decision_buttons(world):
    intake = add_intake(world)
    html = world.session_client("viewer").get(f"/intakes/{intake}").text
    assert "/decision" not in html and "재검사" not in html


def test_assigning_a_requester_needs_the_control_key(world):
    object.__setattr__(world.config, "litellm_admin", None)
    intake = add_intake(world, requested_by=None, status="received")
    admin = world.session_client("admin")
    assert "/requester" not in admin.get(f"/intakes/{intake}").text
    response = world.client.post(
        f"/api/v1/intakes/{intake}/requester", headers=bearer("admin"),
        json={"user_id": "human-9", "state_version": version(world, intake)})
    assert response.status_code == 403 and "게이트웨이 관리 키" in response.json()["message"]


def test_assigning_a_requester_from_the_screen_leaves_the_admin_able_to_decide(world):
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
    assert decide(world, intake, decision="approve").status_code == 200


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
    year = world.query("SELECT extract(year FROM valid_until) FROM mint.approvals")
    assert year[0][0] >= 2999  # 기한을 정하지 않으면 기한 없음


def test_an_exception_needs_a_reason_a_second_approver_and_at_most_ninety_days(world):
    intake = add_intake(world, status="indeterminate", result="indeterminate")
    base = {"decision": "except", "reason": "수동 확인함"}
    assert decide(world, intake, role="approver", **base, valid_days=91).status_code == 400
    alone = decide(world, intake, role="approver", **base)
    assert alone.status_code == 403 and alone.json()["code"] == AdminCode.SEPARATION_OF_DUTIES
    same = decide(world, intake, role="approver", **base, second_approver_token=TOKENS["approver"])
    assert same.status_code == 403
    ok = decide(world, intake, role="approver", **base, second_approver_token=TOKENS["admin"])
    assert ok.status_code == 200, ok.text
    assert world.query("SELECT decision FROM mint.intakes")[0][0] == "exception"




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
    html = world.session_client("viewer").get("/servers?filter=changed").text
    assert "srv-ok" in html and "srv-wait" not in html and "tab=contract" in html


def test_an_empty_drift_list_has_one_next_action(world):
    html = world.session_client("viewer").get("/servers?filter=changed").text
    assert "계약 변경이 있는 MCP 서버가 없습니다" in html and html.count('class="empty"') == 1


def test_the_comparison_lists_added_removed_and_changed_items(world):
    seed_drift(world)
    html = world.session_client("viewer").get("/servers/srv-ok?tab=contract").text
    pattern = r"<td>(\w+)</td><td><span class=\"badge \w+\"><span[^>]*>.</span>(\S+?)</span>"
    assert dict(re.findall(pattern, html)) == {"echo": "변경", "gone": "삭제", "fresh": "추가"}


def test_a_selected_item_shows_both_sides_with_changed_lines_marked_and_escaped(world):
    seed_drift(world)
    client = world.session_client("viewer")
    response = client.get("/servers/srv-ok?tab=contract&scope=server&name=echo")
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
    assert "(배포)" in world.session_client("viewer").get("/servers/srv-ok?tab=contract").text


def test_the_reapproval_form_lists_the_candidates(world):
    seed_drift(world)
    intake = add_intake(world, server="srv-ok")
    html = world.session_client("admin").get("/servers/srv-ok?tab=contract").text
    assert "후보 도구 계약" in html and "재승인 계획 등록" in html
    assert intake in html
    viewer = world.session_client("viewer")
    assert "재승인 계획 등록" not in viewer.get("/servers/srv-ok?tab=contract").text


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
    html = viewer.get("/servers/srv-ok?tab=contract").text
    assert "반영 대기" in html
    assert "반영 대기" in viewer.get("/servers?filter=changed").text


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


@pytest.mark.parametrize("path", ["/intakes", "/servers?filter=changed"])
def test_the_new_screens_need_a_session_and_carry_the_security_headers(world, path):
    assert world.client.get(path).status_code == 303
    response = world.session_client("viewer").get(path)
    assert response.status_code == 200
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_the_requester_assigner_cannot_be_the_second_approver_of_an_exception(world):
    intake = add_intake(world, status="indeterminate", result="indeterminate")
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, kind, source_key, actor, payload)"
        " VALUES (%s, %s, 'intake_requester_assigned', %s, 'admin', %s)",
        uuid.uuid4(), INSTANCE, f"intake:{intake}:2:intake_requester_assigned",
        json.dumps({"intake_id": intake}))
    response = decide(world, intake, role="approver", decision="except", reason="수동 확인함",
                      second_approver_token=TOKENS["admin"])
    assert response.status_code == 403
    assert response.json()["code"] == AdminCode.SEPARATION_OF_DUTIES
    assert "다른 승인자" in response.json()["message"]
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
    html = viewer.get("/servers/srv-ok?tab=contract&scope=server&name=echo").text
    assert "크기가 커서 줄 비교를 생략했습니다" in html and "<code>" not in html
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


# --- 새 화면 구성 ----------------------------------------------------------------------------


def test_the_list_shows_the_stage_chart_and_marks_a_stalled_intake(world, monkeypatch):
    intake = add_intake(world, status="passed")
    admin = world.session_client("admin")
    html = admin.get("/intakes").text
    assert 'data-chart="' in html and "/intakes/new" in html and "신청 등록" in html
    assert " style=" not in html
    assert f'href="/intakes/{intake}"' in html and "24시간 넘게 정체" in html
    assert "/intakes?status=stalled" in html
    assert intake not in admin.get("/intakes?status=stalled").text
    monkeypatch.setattr("mint_litellm.console.pages.servers.STALL", timedelta(0))
    assert intake in admin.get("/intakes?status=stalled").text
    assert "신청 등록" not in world.session_client("viewer").get("/intakes").text


def test_the_detail_shows_progress_steps_tabs_and_equal_decision_buttons(world):
    intake = add_intake(world)
    admin = world.session_client("admin")
    html = admin.get(f"/intakes/{intake}").text
    assert "결정 대기" in html and "다음 행동" in html
    assert 'name="decision" value="approve"' in html and 'name="decision" value="reject"' in html
    assert 'class="danger"' not in html.split('name="decision" value="reject"')[0][-200:]
    for tab in ("overview", "info", "evidence"):
        assert admin.get(f"/intakes/{intake}?tab={tab}").status_code == 200


def test_rejecting_from_the_decision_form_needs_a_reason_and_records_it(world):
    intake = add_intake(world)
    admin = world.session_client("admin")
    data = {"csrf": world.csrf(admin), "decision": "reject",
            "state_version": version(world, intake), "scope_type": "user",
            "scope_id": "human-9", "valid_days": "90"}
    ok = admin.post(f"/intakes/{intake}/decision", data={**data, "reason": "위험이 큼"})
    assert ok.status_code == 303 and "intake_rejected" in ok.headers["location"]
    assert world.query("SELECT decision FROM mint.intakes")[0][0] == "rejected"






def test_approving_an_intake_in_the_console_checks_litellm_permission(world, litellm_permission):
    intake = add_intake(world)
    response = decide(world, intake, decision="approve")
    assert response.status_code == 200, response.text
    assert litellm_permission == [("user", "human-9")]


def test_intake_address_resolves_the_registered_server_without_a_selector(world, monkeypatch):
    seen = {}
    admin_api = world.config.litellm_admin
    monkeypatch.setattr(
        admin_api, "list_servers", lambda: [{"server_id": "docs", "server_name": "문서 서버",
                                           "url": "https://example.com/mcp"}]
    )
    monkeypatch.setattr(
        "mint_litellm.console.pages.servers.intake_service.create",
        lambda *args, **kw: seen.update(kw) or str(uuid.uuid4()),
    )
    client = world.session_client("admin")
    html = client.get("/intakes/new").text
    assert 'name="server_id"' not in html and 'name="server_url"' in html
    response = client.post(
        "/intakes",
        data={
            "csrf": world.csrf(client),
            "server_id": "docs",
            "server_url": "https://example.com/mcp",
            "purpose": "검색",
        },
    )
    assert response.status_code == 303
    assert seen["url"] == "https://example.com/mcp" and seen["provider"] == "example.com"


def test_missing_evidence_does_not_disable_the_approve_button(world):
    intake = add_intake(world, with_evidence=False)
    html = world.session_client("approver").get(f"/intakes/{intake}").text
    assert 'name="decision" value="approve"' in html and "승인할 수 없습니다" not in html
    assert "disabled" not in html.split('id="decision"')[1].split("</form>")[0]


def test_decided_failed_check_does_not_show_passed_progress(world, monkeypatch):
    monkeypatch.setenv("MINT_REQUIRE_PROVIDER_ALLOWLIST", "true")
    intake = add_intake(world, url_blocked=True)
    world.query(
        "UPDATE mint.intakes SET status = 'decided', decision = 'rejected', "
        "decided_by = 'admin', decided_at = now() WHERE id = %s",
        intake,
    )
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert "검사 실패" in html and "제공자 허용" in html and "다시 신청" in html


def test_a_held_unlisted_provider_asks_for_a_recheck_not_a_new_request(world, monkeypatch):
    monkeypatch.setenv("MINT_REQUIRE_PROVIDER_ALLOWLIST", "true")
    intake = add_intake(world, url_blocked=True, status="indeterminate")
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert "제공자 허용" in html and "재검사하세요" in html and "다시 신청" not in html


def test_missing_registry_address_returns_to_the_form_with_saved_values(world, monkeypatch):
    from mint_litellm.control.errors import ControlError

    def missing(*args, **kwargs):
        raise ControlError("제어 평면 키에 URL이 없습니다. --url로 지정하십시오.")

    monkeypatch.setattr("mint_litellm.console.pages.servers.intake_service.create", missing)
    client = world.session_client("admin")
    response = client.post(
        "/intakes",
        data={
            "csrf": world.csrf(client),
            "server_id": "docs",
            "purpose": "검색",
        },
    )
    assert response.status_code == 400
    assert "서버 주소를 입력하세요" in response.text and "--url" not in response.text
    assert "검색" in response.text


def test_intake_and_approval_pages_prioritize_server_name_and_address(world, monkeypatch):
    intake = add_intake(world)
    monkeypatch.setattr(
        world.config.litellm_admin,
        "list_servers",
        lambda: [{"server_id": "srv-wait", "server_name": "문서 서버"}],
    )
    client = world.session_client("admin")
    relation = world.query("SELECT id FROM mint.usage_relations WHERE server_id = 'srv-wait'")[0][0]
    for path in ("/intakes", "/approvals?tab=servers", f"/approvals/review/{relation}"):
        html = client.get(path).text
        assert "문서 서버" in html and "http://c.example" in html
        assert 'data-copy="srv-wait"' in html
    assert str(intake) in client.get("/intakes").text


def test_intake_ignores_a_posted_identifier_and_uses_the_address(world, monkeypatch):
    world.query("UPDATE mint.settings SET default_org_id='acme'")
    monkeypatch.setattr(
        world.config.litellm_admin,
        "list_servers",
        lambda: [{"server_id": "docs", "url": "https://real.example/mcp"}],
    )
    client = world.session_client("admin")
    response = client.post(
        "/intakes",
        data={
            "csrf": world.csrf(client),
            "server_id": "docs",
            "server_url": "https://wrong.example/mcp",
            "purpose": "검색",
        },
    )
    assert response.status_code == 303, response.text
    assert world.query("SELECT server_id FROM mint.intakes") == [("wrong_example",)]


# --- 2인 예외 승인: 화면에서 두 번째 승인자 확인 ----------------------------------------------


def hold_it(world, intake, role="approver", **extra):
    client = world.session_client(role)
    data = {"decision": "except", "reason": "수동 확인함", "csrf": world.csrf(client),
            "state_version": version(world, intake), **extra}
    return client.post(f"/intakes/{intake}/decision", data=data)


def hold_id(world) -> str:
    return str(world.query("SELECT id FROM mint.exception_holds WHERE status = 'pending'")[0][0])


def hold_step(world, hold, role, step):
    client = world.session_client(role)
    return client.post(f"/exceptions/{hold}/{step}", data={"csrf": world.csrf(client)})


def exception_intake(world):
    return add_intake(world, status="indeterminate", result="indeterminate")


def test_an_exception_request_waits_without_approving_and_the_form_has_no_token_field(world):
    intake = exception_intake(world)
    html = world.session_client("approver").get(f"/intakes/{intake}").text
    assert "second_approver_token" not in html and "두 번째 승인자 토큰" not in html
    response = hold_it(world, intake)
    assert response.status_code == 303 and "exception_requested" in response.headers["location"]
    assert world.query("SELECT status FROM mint.intakes")[0][0] == "indeterminate"
    assert world.query("SELECT count(*) FROM mint.approvals")[0][0] == 0
    assert "두 번째 승인 대기" in world.session_client("approver").get(f"/intakes/{intake}").text
    assert world.query("SELECT count(*) FROM mint.events WHERE kind = 'intake_exception_requested'"
                       )[0][0] == 1


def test_the_other_approver_sees_the_waiting_request_and_confirming_approves_it(world):
    intake = exception_intake(world)
    hold_it(world, intake, valid_days=20)
    page = world.session_client("admin").get("/approvals?tab=second").text
    assert "srv-wait" in page and "확인" in page and "/exceptions/" in page
    response = hold_step(world, hold_id(world), "admin", "confirm")
    assert response.status_code == 303 and "exception_confirmed" in response.headers["location"]
    assert world.query("SELECT status, decision, decided_by FROM mint.intakes")[0] == (
        "decided", "exception", "approver")
    row = world.query("SELECT class, granted_by, basis->>'second_approver',"
                      " extract(day FROM valid_until - valid_from) FROM mint.approvals")[0]
    assert row[:3] == ("exception", "approver", "admin") and 19 <= row[3] <= 20
    assert world.query("SELECT status FROM mint.exception_holds")[0][0] == "confirmed"


def test_the_first_approver_and_the_requester_cannot_confirm(world):
    intake = exception_intake(world)
    hold_it(world, intake)
    assert hold_step(world, hold_id(world), "approver", "confirm").status_code == 403
    assert world.query("SELECT status FROM mint.exception_holds")[0][0] == "pending"
    mine = add_intake(world, status="indeterminate", result="indeterminate", server="srv-ok")
    hold_it(world, mine)
    world.query("ALTER TABLE mint.intakes DISABLE TRIGGER USER")
    world.query("UPDATE mint.intakes SET requested_by = 'human-2' WHERE id = %s", mine)
    world.query("ALTER TABLE mint.intakes ENABLE TRIGGER USER")
    held = str(world.query("SELECT h.id FROM mint.exception_holds h JOIN mint.intakes i"
                           " ON i.id = h.intake_id WHERE i.id = %s", mine)[0][0])
    assert hold_step(world, held, "approver", "confirm").status_code == 403
    state = world.query("SELECT status FROM mint.intakes WHERE id = %s", mine)[0][0]
    assert state == "indeterminate"


@pytest.mark.parametrize("step", ["confirm", "reject"])
def test_an_expired_exception_request_is_closed_without_a_decision(world, step):
    intake = exception_intake(world)
    hold_it(world, intake)
    hold = hold_id(world)
    assert hold_step(world, hold, "viewer", step).status_code == 403
    world.query("UPDATE mint.exception_holds SET expires_at = now() - interval '1 minute'")
    assert "srv-wait" not in world.session_client("admin").get("/approvals?tab=second").text
    assert hold_step(world, hold, "admin", step).status_code == 409
    assert world.query("SELECT status FROM mint.exception_holds")[0][0] == "expired"
    assert world.query("SELECT status FROM mint.intakes")[0][0] == "indeterminate"
    assert hold_step(world, hold, "admin", step).status_code == 409
    assert world.query("SELECT payload->>'reason' FROM mint.events"
                       " WHERE kind = 'intake_exception_cancelled'") == [("expired",)]
    assert hold_it(world, intake).status_code == 303  # 만료 뒤 다시 요청할 수 있다


def test_rejecting_cancels_the_request_and_a_new_request_supersedes_the_old(world):
    intake = exception_intake(world)
    hold_it(world, intake)
    first = hold_id(world)
    hold_it(world, intake)
    assert world.query("SELECT status FROM mint.exception_holds WHERE id = %s", first)[0][0] \
        == "superseded"
    assert hold_step(world, hold_id(world), "admin", "reject").status_code == 303
    assert world.query("SELECT count(*) FROM mint.exception_holds WHERE status = 'rejected'"
                       )[0][0] == 1
    assert world.query("SELECT status FROM mint.intakes")[0][0] == "indeterminate"


def test_the_cli_token_path_still_approves_an_exception_directly(world):
    intake = exception_intake(world)
    ok = decide(world, intake, decision="except", reason="수동 확인함",
                second_approver_token=TOKENS["approver"])
    assert ok.status_code == 200, ok.text


@pytest.mark.parametrize("status", ["indeterminate", "failed"])
def test_a_plain_approve_is_refused_when_inspection_did_not_pass(world, status):
    intake = add_intake(world, status=status, result="indeterminate")
    refused = decide(world, intake, decision="approve")
    assert refused.status_code == 400 and "예외 승인" in refused.json()["message"]
    assert "수용검증" not in refused.text
    assert world.query("SELECT status FROM mint.intakes")[0][0] == status
    html = world.session_client("admin").get(f"/intakes/{intake}").text
    assert 'name="decision" value="approve"' not in html
    assert 'id="exception"' in html


def test_exception_approve_still_works_and_a_passed_approve_states_a_true_reason(world):
    intake = add_intake(world, status="failed", result="indeterminate")
    ok = decide(world, intake, role="approver", decision="except", reason="수동 확인함",
                second_approver_token=TOKENS["admin"])
    assert ok.status_code == 200, ok.text
    assert world.query("SELECT decision, decision_reason FROM mint.intakes")[0] == (
        "exception", "수동 확인함")
    passed = add_intake(world, server="srv-ok")
    assert decide(world, passed, decision="approve").status_code == 200
    reason = world.query("SELECT decision_reason FROM mint.intakes WHERE id = %s", passed)[0][0]
    assert reason == "검사를 통과해 승인했습니다." and "수용검증" not in reason
