"""대시보드 처리할 일, 호출 기록 기본 보기·차단·되돌리기, 경보 구분, 정책 확인 창, 차트 규칙."""

import json
import re
import uuid

from console_pages_support import INSTANCE, form_post

from .test_approval_metrics import seed
from .test_dashboard import alert, decision, shown
from .test_wp05_access_requests import seed_request


def call_event(world, result="deny", reason=None):
    event = str(uuid.uuid4())
    payload = {"resolved_server_id": "srv-ok", "tool": "echo", "enforced_action": result}
    if reason:
        payload["stop"] = {"status": "stop", "reason_code": reason}
    world.query(
        "INSERT INTO mint.events(event_id, instance_id, kind, source_key, invocation_id,"
        " attempt_id, subject, payload)"
        " VALUES(%s,%s,'decision_evaluated',%s,%s,1,%s::jsonb,%s::jsonb)",
        event, INSTANCE, f"call:{event}", event,
        json.dumps({"principal_type": "user", "principal_id": "caller"}), json.dumps(payload))
    return event


def test_todo_cards_are_sentences_that_link_to_filtered_screens_without_repeats(world, admin):
    seed(world)
    seed_request(world)
    alert(world, severity="high")
    html = admin.get("/").text
    for text, href in (
        (r"승인 대기 신청 \d건", "/approvals"), (r"권한 요청 1건", "/approvals?tab=access"),
        (r"치명·높음 경보 1건", "/alerts?status=open"),
    ):
        assert re.search(text, shown(html)) and f'href="{href}"' in html
    assert shown(html).count("승인 대기") == 1  # 같은 내용을 다른 카드로 또 내지 않는다
    assert 'class="stat wait" href="/approvals"' not in html
    assert "처리할 일 없음" not in html


def test_an_empty_queue_says_so_in_one_line_and_zero_cards_are_hidden(world, admin):
    html = admin.get("/").text
    text = shown(html[html.index('aria-label="지금 처리할 일"'):html.index('class="filterbar"')])
    assert "권한 요청" not in text and "보고 끊긴 PC" not in text and "가입 요청" not in text
    assert "처리할 일 없음" in shown(world.session_client("viewer").get("/").text)


def test_a_viewer_is_not_offered_approval_cards(world):
    seed(world)
    seed_request(world)
    text = shown(world.session_client("viewer").get("/").text)
    assert "승인 대기 신청" not in text and "권한 요청" not in text


def test_the_ledger_opens_on_the_last_24_hours_and_a_range_widens_it(world, admin):
    recent = decision(world, "blocked", enforced="deny", hours_ago=3)
    old = decision(world, "blocked", enforced="deny", hours_ago=72)
    first = admin.get("/ledger").text
    assert recent in first and old not in first
    assert 'aria-current="true"><strong>24시간</strong>' in first
    assert old in admin.get("/ledger?range=7d").text
    order = re.findall(r'class="segment"[^>]*>(?:<strong>)?([^<]+)', first)
    assert order.index("차단") < order.index("허용")  # 차단을 먼저 고를 수 있다


def test_a_blocked_row_gives_its_reason_in_the_words_of_the_first_line(world, admin):
    call_event(world, "deny", reason="SERVER_NOT_APPROVED")
    assert "승인되지 않은 서버의 호출이 막혔습니다" in admin.get("/ledger").text


def test_blocking_from_a_row_asks_first_then_offers_undo_and_keeps_filters(world, admin):
    event = call_event(world)
    html = admin.get("/ledger?range=7d").text
    for word in ("영향", "즉시", "늦게", "취소 불가", "되돌리기"):
        assert f"<dt>{word}</dt>" in html
    assert 'class="danger-outline"' in html and 'class="danger"' not in html
    done = form_post(world, admin, f"/ledger/{event}/block", target="tool",
                     back="range=7d&open=x&evil=1")
    assert done.status_code == 303
    where = done.headers["location"]
    assert where.startswith("/ledger?range=7d&denial=") and "evil" not in where
    band = admin.get(where).text
    assert "차단했습니다" in band and "되돌리기</button>" in band
    denial = world.query("SELECT id FROM mint.denials WHERE lifted_at IS NULL")[0][0]
    version = world.query("SELECT state_version FROM mint.denials")[0][0]
    undone = form_post(world, admin, f"/ledger/denials/{denial}/undo", state_version=version,
                       back="range=7d")
    assert undone.status_code == 303 and undone.headers["location"].startswith("/ledger?range=7d")
    assert world.query("SELECT count(*) FROM mint.denials WHERE lifted_at IS NULL") == [(0,)]
    assert "되돌리기</button>" not in admin.get(where).text  # 이미 풀렸으면 띠가 없다


def test_a_viewer_gets_no_undo_band(world, admin):
    event = call_event(world)
    where = form_post(world, admin, f"/ledger/{event}/block", target="tool").headers["location"]
    assert "되돌리기</button>" not in world.session_client("viewer").get(where).text


def test_alert_severity_is_a_dot_and_operational_checks_are_marked(world, admin):
    world.query(
        "INSERT INTO mint.alerts (id, instance_id, kind, severity, dedup_key, subject)"
        " VALUES (%s, %s, 'operational_check', 'high', 'operational_check:disk', %s::jsonb)",
        uuid.uuid4(), INSTANCE, json.dumps({"check": "disk", "detail": "여유 100MiB"}))
    alert(world, severity="medium", kind="sync_divergence")
    html = admin.get("/alerts").text
    assert "badge sev-high" in html and "badge sev-medium" in html
    assert "내보내기 디스크 점검: 여유 100MiB" in html
    rows = html.split("<tbody>")[1].split("</tr>")
    marked = [r for r in rows if "운영 점검" in shown(r)]
    assert len(marked) == 1 and "내보내기 디스크" in marked[0]


def test_the_policy_mode_confirmation_has_the_four_lines_and_a_count(world, admin):
    decision(world, "blocked", enforced="deny", hours_ago=2)
    html = admin.get("/policy").text
    assert "최근 24시간 차단 1건" in html
    for word in ("영향", "즉시", "늦게", "취소 불가", "되돌리기"):
        assert f"<dt>{word}</dt>" in html
    assert "환경 상한이 집행이라 관측은 고를 수 없습니다" in html


def test_a_small_sample_shows_numbers_with_the_unit_and_a_large_one_draws_a_chart(world, admin):
    decision(world, "blocked", enforced="deny", reason="SERVER_NOT_APPROVED")
    small = admin.get("/").text
    assert "단위 건" in small and "단위 밀리초" in small
    assert 'class="small-sample"' in small
    for _ in range(5):
        decision(world, "blocked", enforced="deny", reason="SERVER_NOT_APPROVED")
    assert "data-chart=" in admin.get("/").text


def test_usage_and_audit_empty_states_use_one_sentence_and_units(world, admin):
    assert "이 기간에 기록이 없습니다" in admin.get("/reports/usage").text
    decision(world, "blocked", enforced="deny")
    usage = admin.get("/reports/usage").text
    assert "호출(건)" in usage and "단위 건" in usage
    audit = admin.get("/reports/audit").text
    assert "해당 없음" not in audit


def test_builtin_tools_use_the_shared_confirmation_and_viewers_get_a_reason(world, admin):
    html = admin.get("/builtin-tools").text
    assert 'data-dialog-open="block-claude-Bash"' in html and 'class="danger"' not in html
    assert "<dt>되돌리기</dt>" in html
    viewer = world.session_client("viewer").get("/builtin-tools").text
    assert "관리자만 바꿀 수 있습니다" in viewer
