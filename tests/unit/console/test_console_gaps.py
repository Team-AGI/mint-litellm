"""화면 시험: 승인 센터 처리 기한, 엔드포인트·운영자 카드, 서버 증빙 첨부, 승인 지표 색인."""

import re

import psycopg
from console_pages_support import form_post

from .test_approval_metrics import seed


def card(html: str, label: str) -> str:
    return re.search(rf'<(?:a|div) class="card kpi[^"]*"[^>]*>\s*<div class="label">{label}</div>'
                     r'\s*<div class="value">([^<]*)</div>', html).group(1)


def test_the_sla_card_counts_calls_waiting_longer_than_the_chosen_limit(world, admin):
    seed(world, age="10 minutes")
    seed(world, age="20 minutes")
    seed(world, age="1 minute")
    html = admin.get("/approvals").text
    assert card(html, "처리 기한 초과") == "2" and "5분 넘게 대기" in html
    assert 'class="card kpi danger"' in html
    assert card(admin.get("/approvals?sla=15").text, "처리 기한 초과") == "1"
    assert card(admin.get("/approvals?sla=60").text, "처리 기한 초과") == "0"
    # 허용 값이 아니면 기본
    assert card(admin.get("/approvals?sla=7").text, "처리 기한 초과") == "2"


def test_the_endpoint_and_operator_cards_show_the_unmanaged_count_and_role_split(world, admin):
    html = admin.get("/endpoints").text
    assert card(html, "관리 밖 MCP") == "0" and 'href="/endpoints?tab=local-mcp"' in html
    ops = admin.get("/admin").text
    assert re.search(r"관리자 \d+ · 승인자 \d+ · 조회자 \d+", ops)


def test_attaching_evidence_from_the_server_detail_records_it(world, admin):
    page = admin.get("/servers/srv-ok?tab=usage").text
    assert 'action="/servers/srv-ok/evidence"' in page and "증빙 첨부" in page
    response = form_post(world, admin, "/servers/srv-ok/evidence", kind="version_review",
                         summary="취약점 없음 확인", ref="doc-1", valid_days="10")
    assert response.status_code == 303
    assert response.headers["location"] == "/servers/srv-ok?tab=usage&ok=evidence_attached"
    count = world.query("SELECT count(*) FROM mint.policy_evidence WHERE subject_id = 'srv-ok'")
    assert count[0][0] == 1
    shown = admin.get(response.headers["location"]).text
    row = re.search(r"되돌릴 판본의 보안 문제 확인</td>(.*?)</tr>", shown, re.S).group(1)
    assert "증빙을 첨부했습니다" in shown and "없음" not in row and "만료</" not in row


def test_a_bad_evidence_post_is_refused_and_a_viewer_cannot_attach(world, admin):
    bad = form_post(world, admin, "/servers/srv-ok/evidence", kind="nope", summary="x")
    assert bad.status_code == 400
    empty = form_post(world, admin, "/servers/srv-ok/evidence", kind="version_review",
                      summary=" ")
    assert empty.status_code == 400
    viewer = world.session_client("viewer")
    refused = form_post(world, viewer, "/servers/srv-ok/evidence", kind="version_review",
                        summary="x")
    assert refused.status_code == 403
    assert world.query("SELECT count(*) FROM mint.policy_evidence")[0][0] == 0


def test_the_last_observed_time_shows_on_the_detail_and_updates(world, admin):
    html = admin.get("/servers/srv-ok").text
    assert card(html, "마지막 관측") == "—"
    world.query("UPDATE mint.servers SET last_observed_at = now() - interval '3 minutes'"
                " WHERE server_id = 'srv-ok'")
    shown = card(admin.get("/servers/srv-ok").text, "마지막 관측")
    assert shown != "—"


def test_the_approval_metrics_scan_can_use_the_requested_index(world):
    for _ in range(3):
        seed(world)
    with psycopg.connect(world.admin_url, autocommit=True) as conn:
        assert conn.execute("SELECT 1 FROM pg_indexes WHERE indexname = 'call_approvals_requested'"
                            ).fetchone()
        conn.execute("SET enable_seqscan = off")
        plan = "\n".join(r[0] for r in conn.execute(
            "EXPLAIN SELECT count(*) FROM mint.call_approvals WHERE instance_id = 'inst1'"
            " AND requested_at >= now() - make_interval(hours => 24)").fetchall())
    assert "call_approvals_requested" in plan


def test_the_approval_center_shows_one_row_of_at_most_six_cards_and_an_inline_sla_picker(
    world, admin
):
    html = admin.get("/approvals").text
    assert html.count('class="card kpi') <= 6
    assert 'class="stats-line"' in html and "결정 중앙값" in html
    bar = re.search(r'<form class="filterbar".*?</form>', html, re.S).group(0)
    assert 'name="sla"' in bar and "data-autosubmit" in bar
    assert 'class="actions"><input type="hidden" name="tab"' not in html


def test_the_policy_screen_names_policies_instead_of_showing_internal_ids(world, admin):
    html = admin.get("/policy").text
    assert "관측 허용 정책" in html and "관측으로 전환할 수 있는" not in html
    assert re.search(r"<dt>관측 허용 정책</dt><dd>[^<]*[가-힣]", html)
    assert "R1, R3" not in html


def test_an_empty_fleet_shows_a_dash_instead_of_a_zero_over_zero_rate(world, admin):
    assert card(admin.get("/endpoints").text, "적용률") == "—"


def test_every_page_links_a_static_icon_and_the_icon_exists(world, admin):
    from pathlib import Path

    for path in ("/", "/ledger", "/approvals"):
        assert 'rel="icon"' in admin.get(path).text
    assert admin.get("/static/favicon.svg").status_code == 200
    assert Path(__file__).exists()


def test_narrow_screens_scroll_wide_blocks_inside_their_container():
    from pathlib import Path

    css = (Path(__file__).parents[3] / "src/mint_litellm/console/static/console.css").read_text(
        encoding="utf-8"
    )
    narrow = css[css.index("@media (max-width: 767px)") :]
    assert "table { display: block" in narrow and "overflow-x: auto" in narrow
    assert "button.copy" in narrow and ".segments" in narrow
