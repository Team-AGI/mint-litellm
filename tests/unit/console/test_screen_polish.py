"""화면 표시 규칙: 한국어 표시명, 조직 시간대, 키보드 이동, 대비. 데이터베이스가 필요 없다."""

import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from mint_litellm.console import labels
from mint_litellm.console.core import ConsoleConfig
from mint_litellm.console.templating import MENU, STAFF_MENU, local_time, templates
from mint_litellm.control import alerts, sync_state
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import intakes
from mint_litellm.types.events import EventKind

CONSOLE = Path(__file__).parents[3] / "src" / "mint_litellm" / "console"
Y = "2026-"
ENV = {
    "MINT_DATABASE_URL": "postgresql://x/y", "MINT_LITELLM_URL": "http://x",
    "MINT_EXPORT_DIR": "/tmp/x", "MINT_EXPORT_HMAC_KEY": "A" * 43,
}


def render(name: str, **context) -> str:
    actor = SimpleNamespace(
        csrf="t", role="admin", user_id="u", session=SimpleNamespace(operator_name="n"),
    )
    base = {"actor": actor, "path": "/ledger", "notice": None, "error": None, "zone_label": "z"}
    return templates.get_template(name).render({**base, **context})


def ledger_html(rows=(), **context) -> str:
    return render(
        "ledger.html", rows=list(rows), filters={"kinds": ["decision_evaluated"], "actors": [
            "intake_run", "worker", "acc-1"]},
        q={k: "" for k in ("since", "until", "kind", "actor", "server_id", "result")},
        start=datetime(2026, 11, 3, tzinfo=UTC), start_day=f"{Y}11-03", page=1,
        servers=["srv"], **context,
    )


# --- 표시명 -----------------------------------------------------------------------------------


def test_every_event_kind_has_a_korean_name():
    assert {k.value for k in EventKind} == set(labels.EVENT_KIND)
    assert all(re.search("[가-힣]", text) for text in labels.EVENT_KIND.values())


def test_system_actors_are_shown_with_korean_names():
    for name in (intakes.SYSTEM_ACTOR, alerts.AUTO_ACTOR, sync_state.ACTOR, "worker",
                 "session_verify", "contract-observer", "init", "bootstrap"):
        assert re.search("[가-힣]", labels.actor(name)), name
    assert labels.actor("acc-1") == "acc-1" and labels.actor(None) == "—"


def test_the_result_filter_has_one_option_per_name():
    assert len(set(labels.RESULT_FILTER.values())) == len(labels.RESULT_FILTER)
    assert set(labels.RESULT_FILTER) <= set(labels.RESULT)


def test_the_menu_says_contract_change_not_drift():
    assert ("/contracts", "계약 변경") in MENU
    for _, text in MENU + STAFF_MENU:
        assert "드리프트" not in text


def test_no_screen_text_says_drift():
    for path in (CONSOLE / "templates").glob("*.html"):
        assert "드리프트" not in path.read_text(encoding="utf-8"), path.name


# --- 시간대 -----------------------------------------------------------------------------------


def test_times_are_shown_in_the_organisation_time_zone():
    moment = datetime(2026, 11, 3, 0, 4, tzinfo=UTC)
    assert local_time(moment) == f"{Y}11-03 09:04"
    assert local_time(moment, "UTC") == f"{Y}11-03 00:04"
    assert local_time(moment, "America/New_York") == f"{Y}11-02 19:04"
    assert local_time(moment.replace(tzinfo=None)) == f"{Y}11-03 09:04"
    assert local_time(f"{Y}11-03T00:04:00+00:00") == f"{Y}11-03 09:04"
    assert local_time(None) == "—" and local_time("") == "—"
    assert "UTC" not in local_time(moment)


def test_the_time_zone_defaults_to_seoul_and_can_be_set():
    assert ConsoleConfig.from_env(ENV).time_zone == "Asia/Seoul"
    assert ConsoleConfig.from_env({**ENV, "MINT_CONSOLE_TIME_ZONE": " UTC "}).time_zone == "UTC"
    with pytest.raises(ControlError, match="MINT_CONSOLE_TIME_ZONE"):
        ConsoleConfig.from_env({**ENV, "MINT_CONSOLE_TIME_ZONE": "Mars/Base"})


def test_a_template_renders_times_in_the_zone_of_the_app():
    row = {"inserted_at": datetime(2026, 11, 3, 0, 4, tzinfo=UTC), "kind": "org_created",
           "actor": "worker", "server_id": None, "result": None}
    html = ledger_html([row])
    assert f"{Y}11-03 09:04" in html and "UTC" not in html


# --- 원장 화면 --------------------------------------------------------------------------------


def test_the_ledger_shows_no_raw_values_or_identifier_column():
    row = {"inserted_at": datetime(2026, 11, 3, tzinfo=UTC), "kind": "alert_resolved",
           "actor": "intake_run", "server_id": "srv", "result": "stop",
           "source_key": "alert:01a1c4b3:2:alert_resolved"}
    html = ledger_html([row])
    assert "intake_run" in html  # 선택 값(value)으로만 남는다
    shown = re.sub(r"<[^>]+>", "\n", html)
    assert "intake_run" not in shown and "alert_resolved" not in shown
    assert "수용검증" in shown and "작업 실행기" in shown and "경보 해결" in shown
    assert "<code>" not in html and "alert:01a1c4b3" not in html
    assert "<th>키</th>" not in html and "조회 범위" not in html


def test_the_blocked_result_is_one_filter_option():
    html = ledger_html()
    assert html.count(">차단</option>") == 1


def test_the_ledger_filters_are_plain_controls_in_the_natural_tab_order():
    html = ledger_html()
    assert 'type="date"' not in html  # 날짜 칸이 구획마다 초점을 잡아 Tab이 갇히지 않게 한다
    assert 'name="since"' in html and f'value="{Y}11-03"' in html
    assert "tabindex" not in html
    form = re.search(r"<form method=\"get\".*?</form>", html, re.S).group(0)
    names = re.findall(r"<(?:input|select|button|a)\b[^>]*", form)
    assert [re.search(r'name="(\w+)"', n).group(1) for n in names[:6]] == [
        "since", "until", "kind", "actor", "server_id", "result"]


def test_time_and_kind_cells_do_not_wrap():
    row = {"inserted_at": datetime(2026, 11, 3, tzinfo=UTC), "kind": "decision_evaluated",
           "actor": None, "server_id": None, "result": "allow"}
    html = ledger_html([row])
    assert html.count('<td class="nowrap">') == 2
    cells = f'<td class="nowrap">{Y}11-03 09:00</td><td class="nowrap">호출 판정</td>'
    assert cells in html


# --- 모든 화면 공통 ---------------------------------------------------------------------------


def test_no_template_has_positive_tab_order_or_date_inputs_or_raw_code_cells():
    allowed_code = {"contract_detail.html", "approval_new.html", "server_detail.html"}
    for path in (CONSOLE / "templates").glob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r'tabindex="[1-9]', text), path.name
        assert 'type="date"' not in text, path.name
        if path.name not in allowed_code:
            assert "<code>" not in text, path.name


def test_detail_screens_do_not_show_raw_codes():
    server = (CONSOLE / "templates" / "server_detail.html").read_text(encoding="utf-8")
    assert "s.status }}</code>" not in server and "t.risk_grade }}" not in server
    intake = (CONSOLE / "templates" / "intake_detail.html").read_text(encoding="utf-8")
    assert "reason_code | blank" not in intake


def test_both_layouts_wrap_the_menu_for_full_height_and_show_the_time_zone():
    for name in ("base.html", "staff_base.html"):
        text = (CONSOLE / "templates" / name).read_text(encoding="utf-8")
        assert '<body class="shell"' in text and '<div class="menu">' in text
        assert "{{ zone_label }}" in text


# --- 대비 -------------------------------------------------------------------------------------


def luminance(color: str) -> float:
    channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(foreground: str, background: str) -> float:
    high, low = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_every_text_color_has_at_least_4_5_contrast_on_every_surface():
    css = (CONSOLE / "static" / "console.css").read_text(encoding="utf-8")
    tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-f]{6});", css))
    surfaces = [tokens["bg"], tokens["bg-subtle"], "#eaeef2", "#ddf4ff", "#fff0f0", "#f0fff4"]
    for name in ("text", "muted", "accent", "ok", "wait", "danger", "off"):
        for surface in surfaces:
            assert ratio(tokens[name], surface) >= 4.5, (name, surface)
    for name in ("accent", "danger"):  # 단추 바탕 위의 흰 글자
        assert ratio("#ffffff", tokens[name]) >= 4.5, name


def test_the_decided_badge_is_readable():
    css = (CONSOLE / "static" / "console.css").read_text(encoding="utf-8")
    tokens = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-f]{6});", css))
    assert labels.INTAKE["decided"].level == "off"
    assert ".badge.off { color: var(--off); }" in css
    assert ratio(tokens["off"], tokens["bg"]) >= 4.5


def test_the_endpoint_install_screens_show_korean_states_only():
    rows = [
        {"user_id": "u1", "team_id": "team-a", "state": state, "claude_version": None,
         "mcp_servers": ["srv"], "issued_at": datetime(2026, 11, 3, tzinfo=UTC),
         "reported_at": None}
        for state in ("managed", "user", "pending", "removed", "revoked")
    ]  # fmt: skip
    for name in ("endpoints.html", "staff_endpoint.html"):
        html = render(name, rows=rows, active=True)
        for text in ("관리형", "관리되지 않음", "보고 전", "제거됨", "연결 해제"):
            assert text in html, (name, text)
        for enum in ("managed", "pending", "removed", "revoked"):
            assert enum not in html, (name, enum)
    assert "team-a" in render("endpoints.html", rows=rows)
    assert "team-a" in render("staff_endpoint.html", rows=rows, active=True)
    assert "설치 묶음 내려받기" in render("staff_endpoint.html", rows=[], active=False)
    assert "다시 내려받기" in render("staff_endpoint.html", rows=rows, active=True)


# --- 경보 화면 --------------------------------------------------------------------------------

ALERT_ID = "0197c0de-0000-7000-8000-000000000001"


def alert_row(**cols):
    row = {
        "id": ALERT_ID, "kind": "sync_divergence", "severity": "high", "status": "open",
        "subject": {"server_id": "srv", "reason": "registry_missing", "unknown_key": "x"},
        "first_at": datetime(2026, 11, 3, tzinfo=UTC), "last_at": datetime(2026, 11, 3, tzinfo=UTC),
        "count": 2, "acknowledged_by": None, "resolved_at": None, "server_id": "srv",
        "summary": "요약", "link": ("/servers/srv", "서버 상세"),
    }
    return {**row, **cols}


def alerts_html(rows=()):
    return render(
        "alerts.html", rows=list(rows), page=1,
        filters={"kinds": ["job_failed"], "servers": ["srv"]},
        q={k: "" for k in ("status", "severity", "kind", "server_id")},
    )


def test_every_raised_alert_kind_has_a_korean_name():
    import mint_litellm.control as control
    from mint_litellm.types.events import AlertKind

    found = set(re.findall(r'kind="([a-z_]+)"', "".join(
        p.read_text(encoding="utf-8") for p in Path(control.__file__).parent.rglob("*.py")
    )))
    found |= {k.value for k in AlertKind}
    found |= {"approval_recert_due", "approval_recert_held", "package_vulnerable",
              "package_vuln_due", "vuln_feed_unreachable"}
    assert found - {"exec", "deployment", "negative_state", "checkpoint"} <= set(labels.ALERT_KIND)
    assert all(re.search("[가-힣]", t) for t in labels.ALERT_KIND.values())


def test_the_alert_list_shows_korean_values_and_a_link():
    html = alerts_html([alert_row()])
    shown = re.sub(r"<[^>]+>", "\n", html)
    for raw in ("sync_divergence", "registry_missing", "open", "high"):
        assert raw not in shown
    assert "LiteLLM 설정 불일치" in shown and "높음" in shown and "열림" in shown
    assert 'href="/servers/srv"' in html and f'href="/alerts/{ALERT_ID}"' in html
    assert "<code>" not in html and "<th>키</th>" not in html


def test_the_alert_list_has_an_empty_state():
    assert "조건에 맞는 경보가 없습니다" in alerts_html()


def alert_detail_html(status="open", role="admin", **cols):
    from mint_litellm.console import alert_view

    row = alert_row(status=status, **cols)
    actor = SimpleNamespace(csrf="t", role=role, session=SimpleNamespace(operator_name="n"))
    return render(
        "alert_detail.html", a=row, actor=actor,
        summary=alert_view.summary(row["kind"], row["subject"]),
        fields=alert_view.subject_rows(row["subject"], "Asia/Seoul"),
        link=alert_view.link(row["kind"], row["subject"]),
    )


def test_the_alert_detail_is_a_labelled_table_without_raw_keys_or_json():
    html = alert_detail_html()
    shown = re.sub(r"<[^>]+>", "\n", html)
    assert "레지스트리에 없음" in shown and "unknown_key" not in shown
    assert "registry_missing" not in shown and "server_id" not in shown and "{" not in shown
    assert '/acknowledge"' in html


def test_acknowledge_is_only_offered_to_admins_on_open_alerts():
    assert "/acknowledge" not in alert_detail_html(role="viewer")
    assert "/acknowledge" not in alert_detail_html(status="acknowledged", acknowledged_by="kim")


def test_nested_subject_values_are_flattened_to_korean_lines():
    from mint_litellm.console import alert_view

    rows = dict(alert_view.subject_rows({
        "axes": {"exec": {"verdict": "widened", "added": ["a"], "removed": []}},
        "valid_until": "2026-11-03T00:00:00+00:00", "exploited": True,
        "packages": [{"ecosystem": "npm", "name": "x", "version": None}],
    }, "Asia/Seoul"))
    assert rows["축별 변화"] == ["실행: 판정: 확대, 추가: a, 제거: —"]
    assert rows["유효 기한"] == [f"{Y}11-03 09:00"] and rows["악용 확인"] == ["예"]
    assert rows["패키지"] == ["제공처: npm · 이름: x · 버전: —"]


def test_the_menu_has_the_alert_screen_with_a_badge_for_urgent_alerts():
    assert ("/alerts", "경보") in MENU
    assert ">3</span>" in render("alerts.html", rows=[], page=1, alert_badge=3,
                                 filters={"kinds": [], "servers": []},
                                 q={k: "" for k in ("status", "severity", "kind", "server_id")})
