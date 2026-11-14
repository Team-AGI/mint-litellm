"""새로 모은 자료(의존 취약점, 결과 검사 항목, 단말 격리·호스트 제한)가 화면에 한국어로 보인다."""

import re
from datetime import UTC, datetime, timedelta

from mint_litellm.console import alert_view, labels
from mint_litellm.types.events import AlertKind

from .test_screen_polish import ledger_html, render


def shown(html: str) -> str:
    return re.sub(r"<[^>]+>", "\n", html)


def vuln(path, deadline, severity="critical"):
    return {
        "name": "lib",
        "version": "1.0",
        "path": path,
        "vuln_id": "CVE-2026-0001",
        "severity": severity,
        "cvss": None,
        "exploited": False,
        "first_seen_at": deadline,
        "deadline_at": deadline,
    }


def server(vulns):
    return {
        "server_id": "srv",
        "status": "approved",
        "transport": "stdio",
        "auth_type": "none",
        "registered_by": "u",
        "last_observed_at": None,
        "identity_kind": "http",
        "url_sha256": "x",
        "vulns": vulns,
        "tools": [],
        "relations": [],
        "approvals": [],
        "state_version": 1,
    }


def test_server_detail_marks_direct_and_dependency_and_counts_down():
    soon = datetime.now(UTC) + timedelta(hours=30)
    html = render(
        "server_detail.html",
        s=server([vuln(None, soon), vuln("A → B → lib", soon, "high")]),
        evidence=[],
    )
    text = shown(html)
    assert "직접 사용" in text and "의존 패키지" in text and "A → B → lib" in text
    assert "29시간" in text and "남음" in text
    late = shown(
        render("server_detail.html", s=server([vuln(None, soon - timedelta(days=3))]), evidence=[])
    )
    assert "기한 지남" in late


def test_ledger_shows_scan_findings_in_korean():
    payload = {
        "sensitive_findings": {"high_entropy_token": 2, "email": 1},
        "scan_truncated": True,
        "finding_paths": ["$.items[0].note"],
    }
    row = {
        "inserted_at": datetime(2026, 11, 3, tzinfo=UTC),
        "kind": "call_response_received",
        "actor": "worker",
        "server_id": "srv",
        "result": "allow",
        "payload": payload,
    }
    text = shown(ledger_html([row]))
    assert "비밀로 보이는 긴 문자열 2건" in text and "이메일 주소 1건" in text
    assert "검사 상한을 넘어 끝까지 보지 못함" in text and "$.items[0].note" in text
    assert "high_entropy_token" not in text and "scan_truncated" not in text


def test_every_sensitive_kind_has_a_korean_name():
    from mint_litellm.plugin.policy import sensitive_scan as scan

    kinds = {k for k, *_ in scan._DETECTORS}
    assert kinds <= set(labels.SENSITIVE_KIND)


def test_endpoint_list_shows_sandbox_and_egress_state():
    row = {
        "user_id": "u",
        "team_id": "t",
        "state": "managed",
        "claude_version": "1",
        "mcp_servers": ["a"],
        "issued_at": None,
        "reported_at": None,
        "processes": [
            {"server": "a", "sandbox": "appcontainer", "egress_unfiltered": True},
            {"server": "b", "sandbox": "bwrap", "egress_refused": 3},
            {"server": "c", "sandbox": "none"},
            {"server": "d", "sandbox": "unsupported"},
        ],
    }
    text = shown(render("endpoints.html", rows=[row]))
    for want in (
        "격리됨 · 호스트 제한 미집행",
        "격리됨 · 허용 밖 접속 3건 거절",
        "격리 없음",
        "격리 미지원",
    ):
        assert want in text
    assert "appcontainer" not in text and "egress" not in text


def test_every_alert_kind_has_a_label_and_a_summary():
    for kind in (k.value for k in AlertKind):
        assert kind in labels.ALERT_KIND, kind
        assert kind in alert_view.SUMMARY, kind
    assert not set(labels.ALERT_KIND) - set(alert_view.SUMMARY)


def test_endpoint_list_shows_processes_running_outside_the_runner():
    row = {
        "user_id": "u", "team_id": "t", "state": "managed", "claude_version": "1",
        "mcp_servers": [], "issued_at": None, "reported_at": None, "processes": [],
        "outside_processes": [
            {"package": "left-pad", "ecosystem": "npm", "count": 2},
            {"package": "mcp-x", "ecosystem": "pypi", "count": 1},
            {"package": "img/app", "ecosystem": "container", "count": 3},
        ],
    }  # fmt: skip
    text = shown(render("endpoints.html", rows=[row]))
    for want in ("left-pad (npm) 2개", "mcp-x (PyPI) 1개", "img/app (컨테이너 이미지) 3개"):
        assert want in text
    assert "pypi" not in text and "container" not in text


def test_outside_alerts_have_label_and_summary():
    for kind in ("endpoint_outside_retired", "endpoint_outside_unapproved"):
        assert re.search("[가-힣]", labels.ALERT_KIND[kind])
        text = alert_view.summary(kind, {"key_alias": "k", "package": "left-pad"})
        assert "left-pad" in text and "{" not in text
