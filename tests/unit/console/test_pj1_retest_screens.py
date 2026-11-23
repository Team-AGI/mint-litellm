"""pj1 재시험 화면 결함: 두 번째 승인 표시·원인 우선·긴 상세 레이아웃. 데이터베이스가 필요 없다."""

from pathlib import Path

from mint_litellm.console import labels
from mint_litellm.console.pages import servers
from mint_litellm.console.templating import templates
from mint_litellm.endpoint import intake_text

ROOT = Path(__file__).parents[3]
CONSOLE = ROOT / "src/mint_litellm/console"


def render(name: str, **ctx) -> str:
    source = (CONSOLE / "templates" / name).read_text(encoding="utf-8")
    return templates.env.from_string(source).render(L=labels, **ctx)


def test_progress_shows_the_second_approval_and_dims_proof_when_the_cause_is_missing_tools():
    intake = {"status": "indeterminate"}
    assert servers.intake_progress(intake, ["a"], [], hold=True)[3] == ("wait", "두 번째 승인 대기")
    assert servers.intake_progress(intake, ["a"], [])[2][0] == "error"
    assert servers.intake_progress(intake, ["a"], [], cause=True)[2] == ("off", "증빙")


def test_the_long_failure_detail_is_confined_to_a_wrapping_scrolling_box():
    css = (CONSOLE / "static/console.css").read_text(encoding="utf-8")
    assert ".grid > * { min-width: 0; }" in css
    rule = css[css.index("pre.out {"): css.index("}", css.index("pre.out {"))]
    assert "max-width: 100%" in rule and "overflow: auto" in rule and "pre-wrap" in rule
    html = (CONSOLE / "templates/intake_detail.html").read_text(encoding="utf-8")
    assert '<pre class="out">' in html


def test_the_second_approval_tab_hides_confirm_from_the_first_approver_and_requester():
    hold = {"id": "h", "intake_id": "i", "server_id": "s", "requested_by": "emp",
            "first_name": "a1", "first_user_id": "u-first", "params": {}, "expires_at": None}

    def tab(user: str) -> str:
        actor = type("A", (), {"role": "approver", "session": type("S", (), {"user_id": user})(),
                               "csrf": "x"})()
        return templates.env.from_string(
            "{% import 'macros.html' as m %}"
            + (CONSOLE / "templates/_approvals_second.html").read_text(encoding="utf-8")
            .split("{% import \"macros.html\" as m %}", 1)[-1]
        ).render(L=labels, holds=[hold], actor=actor)

    for blocked in ("u-first", "emp"):
        html = tab(blocked)
        assert "다른 승인자 확인 필요" in html and "/confirm" not in html
    assert "/confirm" in tab("u-other")


def test_the_separation_message_names_the_rule_in_plain_words():
    source = (ROOT / "src/mint_litellm/control/services/intakes.py").read_text(encoding="utf-8")
    assert "요청한 사람과 다른 승인자가 확인해야 합니다." in source
    assert "신청자 지정자와 다른" not in source


def test_the_staff_row_follows_the_inspection_state():
    row = {"status": "indeterminate", "reason": "check_failed:INSPECTION_FAILED", "inspect": True}
    assert intake_text.next_of(row) == "단말 검사 필요 · s로 시작"
    assert intake_text.reason_of(row) == "단말 검사가 필요합니다"
    plain = {**row, "inspect": False}
    assert intake_text.next_of(plain) == "관리자 검토 중"
    assert intake_text.reason_of(plain) == "검사 중 서버가 도구 목록을 내지 못했습니다"


def test_approved_intake_hides_missing_proof_step():
    intake = {"status": "decided", "decision": "approved"}
    steps = servers.intake_progress(intake, ["a", "b"], [{"result": "pass"}])
    assert steps[2] == ("off", "증빙 해당 없음")


def test_refused_first_call_is_failure_not_answer():
    receipts = [{"stage": s, "decision_version": 1, "reason": None} for s in
                ("approved", "device_received", "started", "discovered")]
    steps = servers.delivery_progress(
        receipts, local=True, called=False, failure=("first_response", "계약 변경 차단"))
    assert steps[-1] == ("error", "첫 응답 실패 · 계약 변경 차단")
    assert steps[-2][0] == "ok"


def test_old_start_failure_traceback_gets_korean_reason():
    check = {"result": "indeterminate", "reason_code": "INSPECTION_INCOMPLETE",
             "inputs": {"detail": {"stage": "start", "stderr_tail": "ModuleNotFoundError: x"}}}
    assert "의존 라이브러리" in labels.check_reason(check)
    check["inputs"]["detail"]["stderr_tail"] = "boom"
    assert labels.check_reason(check) == labels.CHECK_REASON["SERVER_START_FAILED"]
