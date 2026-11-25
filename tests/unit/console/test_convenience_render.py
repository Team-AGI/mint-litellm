"""데이터베이스 없이 화면 구조와 기존 서비스로 보낼 제출 값을 확인한다."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from mint_litellm.console.pages import approvals, dashboard, servers

from .test_screen_polish import ledger_html, render


@pytest.mark.parametrize("status, checked", [("approved", "true"), ("suspended", "false")])
def test_server_switch_has_a_saved_state_and_one_confirmation(status, checked):
    row = {"server_id": "docs", "server_name": "문서 서버", "status": status,
           "state_version": 4, "server_url": None}
    html = render("_approvals_servers.html", queue=[], permissions=[row])
    assert f'role="switch" aria-checked="{checked}"' in html
    assert html.count("<dialog ") == 1
    assert 'data-confirm=' not in html
    assert 'name="next" value="/approvals?tab=servers"' in html
    assert 'name="state_version" value="4"' in html


def test_viewers_see_a_permission_label_without_a_switch():
    actor = SimpleNamespace(role="viewer", csrf="t")
    html = render("_approvals_servers.html", queue=[], actor=actor, permissions=[{
        "server_id": "docs", "server_name": "문서 서버", "status": "approved",
        "state_version": 1, "server_url": None,
    }])
    assert "허용" in html and 'role="switch"' not in html and "<dialog" not in html


def test_admin_form_has_no_registry_selector():
    html = render("intake_new.html", f={"server_url": "", "purpose": ""})
    form = html.split('action="/intakes"')[1].split("</form>")[0]
    assert 'name="server_url"' in form and 'name="purpose"' in form
    assert "<select" not in form and 'name="server_id"' not in form


@pytest.mark.parametrize("existing", [True, False])
def test_admin_submission_redirects_to_the_returned_application(monkeypatch, existing):
    monkeypatch.setattr(servers.intake_submission, "submit", lambda *args: ("request", existing))
    response = servers.create_intake(
        Mock(), server_url="https://docs.example.test/mcp", purpose="문서 검색", step="", name="",
        commit="", command="", owner_user_id="", local="", found="", actor=Mock())
    notice = "intake_existing" if existing else "intake_created"
    assert response.status_code == 303
    assert response.headers["location"] == f"/intakes/request?ok={notice}"


def test_unblock_form_has_an_optional_reason_and_no_checkbox():
    proposal = {
        "id": "proposal", "key_alias": "직원 키", "signal": "secret_exposure", "user_id": "user",
        "status": "applied", "mint_blocked": True, "state_version": 3, "team_id": None,
        "expires_at": None, "applied_at": None,
    }
    html = render("_approvals_blocks.html", blocks=[proposal], focus="proposal",
                  block_view=lambda row: {"lines": [], "events": 1})
    form = html.split('action="/key-blocks/proposal/unblock"')[1].split("</form>")[0]
    assert "해제 사유(선택)" in form and "required" not in form
    assert 'type="checkbox"' not in form


def test_unblock_submits_the_default_reason_in_one_action(monkeypatch):
    action = Mock()
    monkeypatch.setattr(approvals.key_block, "request_unblock", action)
    actor = Mock()
    response = approvals.decide_key_block("proposal", "unblock", Mock(), 3, "key", "", actor)
    assert response.status_code == 303
    assert action.call_args.kwargs == {
        "reason": "관리자 차단 해제", "acknowledge": True, "expected_version": 3,
    }


@pytest.mark.parametrize("result", ["allow", "deny"])
def test_ledger_actions_use_one_confirmation_per_target(result):
    html = ledger_html([{
        "event_id": "call", "inserted_at": datetime.now(UTC), "kind": "decision_evaluated",
        "actor": "user", "server_id": "docs", "result": result,
        "targets": {"tool": "read", "user": "user"},
    }])
    assert "이 도구 차단" in html and "이 사용자 차단" in html
    assert html.count('action="/ledger/call/block"') == 2
    assert 'name="target" value="tool"' in html and 'name="target" value="user"' in html


def test_ledger_targets_only_identify_real_users_and_call_decisions():
    row = {"kind": "decision_evaluated", "result": "allow", "server_id": "docs",
           "payload": {"tool": "read"}}
    assert dashboard.ledger_targets(row, {"principal_type": "key", "principal_id": "token"}) == {
        "tool": "read", "user": None}
    row["kind"] = "call_response_received"
    assert dashboard.ledger_targets(row, {"principal_type": "user", "principal_id": "user"}) == {}


def application(status="received"):
    return {"id": "request", "server_id": "docs", "purpose": "문서 검색", "status": status,
            "source": "staff", "decision": None, "state_version": 2, "created_at": None}


def test_staff_history_has_a_single_cancel_confirmation():
    html = render("_staff_applications.html", applications=[application()])
    assert "대기 취소" in html and html.count("<dialog ") == 1
    assert 'name="state_version" value="2"' in html
    assert 'name="confirm" value="yes"' in html and 'name="reason" value="신청자 취소"' in html
    assert 'type="checkbox"' not in html and "required" not in html
    # 진행 중(검사·관리자 결정 대기)에도 취소할 수 있고, 끝난 신청에는 취소가 없다.
    for waiting in ("checking", "passed", "indeterminate"):
        html = render("_staff_applications.html", applications=[application(waiting)])
        assert "대기 취소" in html
    for done in ("failed", "approved"):
        html = render("_staff_applications.html", applications=[application(done)])
        assert "대기 취소" not in html


def test_staff_catalog_and_application_history_have_distinct_tabs():
    row = {"ref": "acme|docs", "server_name": "문서 서버", "org_name": "우리 회사",
           "state": "free", "seen": None, "tools": ["read"], "valid_until": None}
    context = {"rows": [row], "catalog": [row], "need": 0, "expiring": 0,
               "selected": None, "form": {}, "search": "", "applications": [application()]}
    html = render("staff_servers.html", **context, tab="servers")
    assert 'class="catalog-card"' in html and "문서 서버" in html
    assert 'name="q"' in html and "내 신청 이력" in html
    assert "/staff/intakes/new" in html
    history = render("staff_servers.html", **context, tab="applications")
    assert "문서 검색" in history and "대기 취소" in history
