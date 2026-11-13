"""취약점 조회: 응답 해석, 등급 매핑, 48시간 기한 상태, 기한이 지난 서버 차단."""

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from mint_litellm.control import vuln

NOW = datetime(2030, 1, 10, 12, 0, tzinfo=UTC)
V3 = "CVSS:3.1/"
MEDIUM_VECTOR = V3 + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

# 조회처가 돌려주는 모양을 그대로 기록한 응답(쓰지 않는 날짜 필드는 뺐다)
BATCH = {"results": [
    {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}, {"id": "GHSA-dddd-eeee-ffff"}]},
    {},
    {"vulns": [{"id": "PYSEC-1"}]},
]}
DETAILS = {
    "GHSA-aaaa-bbbb-cccc": {
        "summary": "원격 코드 실행",
        "severity": [{"type": "CVSS_V3", "score": V3 + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "CRITICAL"},
    },
    "GHSA-dddd-eeee-ffff": {"summary": "경로 노출", "database_specific": {"severity": "MODERATE"}},
    "PYSEC-1": {"details": "악용 확인",
                "database_specific": {"known_exploited": True, "severity": "HIGH"}},
}


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_base_scores(vector, score):
    assert vuln.cvss3(V3 + vector) == score


def test_other_or_broken_vectors_have_no_score():
    assert vuln.cvss3(None) is None
    assert vuln.cvss3("CVSS:4.0/AV:N/AC:L") is None
    assert vuln.cvss3(V3 + "AV:N/AC:L") is None


def test_severity_takes_the_higher_of_score_and_label():
    top = vuln.rate(DETAILS["GHSA-aaaa-bbbb-cccc"])
    assert (top["severity"], top["cvss"], top["exploited"]) == ("critical", 9.8, False)
    assert vuln.rate(DETAILS["GHSA-dddd-eeee-ffff"])["severity"] == "medium"
    mixed = {"severity": [{"type": "CVSS_V3", "score": MEDIUM_VECTOR}],
             "database_specific": {"severity": "LOW"}}
    assert vuln.rate(mixed)["severity"] == "medium"
    assert vuln.rate({})["severity"] == "unknown"
    assert vuln.rate(DETAILS["PYSEC-1"])["exploited"] is True


def test_critical_means_critical_severity_or_a_known_exploit():
    assert vuln.is_critical({"severity": "critical", "exploited": False})
    assert vuln.is_critical({"severity": "low", "exploited": True})
    assert not vuln.is_critical({"severity": "high", "exploited": False})


def test_batch_results_follow_the_query_order_and_a_mismatch_is_refused():
    assert vuln.parse_batch(BATCH, 3) == [
        ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"], [], ["PYSEC-1"]]
    with pytest.raises(ValueError):
        vuln.parse_batch(BATCH, 2)


def feed(seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            assert queries[0] == {"package": {"name": "left-pad", "ecosystem": "npm"},
                                  "version": "1.0.0"}
            assert queries[2]["package"]["ecosystem"] == "PyPI"
            return httpx.Response(200, json=BATCH)
        return httpx.Response(200, json=DETAILS[request.url.path.rsplit("/", 1)[1]])
    return httpx.Client(transport=httpx.MockTransport(handler))


KEYS = [("npm", "left-pad", "1.0.0"), ("npm", "clean", "2.0.0"), ("pypi", "old", "0.1")]


def test_fetch_queries_the_batch_endpoint_and_reads_each_new_vulnerability_once():
    seen = []
    with feed(seen) as http:
        out = vuln.fetch(http, "https://feed.test", KEYS, known={})
    assert seen[0] == ("POST", "/v1/querybatch") and len(seen) == 4
    assert set(out[KEYS[0]]) == {"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}
    assert out[KEYS[1]] == {} and out[KEYS[2]]["PYSEC-1"]["exploited"]


def test_known_vulnerabilities_are_not_fetched_again():
    known = {v: vuln.rate(d) for v, d in DETAILS.items()}
    seen = []
    with feed(seen) as http:
        vuln.fetch(http, "https://feed.test", KEYS, known)
    assert seen == [("POST", "/v1/querybatch")]


def test_an_unreachable_feed_raises_so_the_job_can_alert_without_blocking():
    def refuse(request):
        raise httpx.ConnectError("offline")

    with httpx.Client(transport=httpx.MockTransport(refuse)) as http:
        with pytest.raises(httpx.HTTPError):
            vuln.fetch(http, "https://feed.test", KEYS, known={})


@pytest.mark.parametrize(
    ("hours", "state"),
    [(0, "running"), (23, "running"), (24, "escalated"), (47, "escalated"), (48, "overdue"),
     (500, "overdue")],
)
def test_the_clock_runs_from_first_detection(hours, state):
    assert vuln.clock(NOW - timedelta(hours=hours), NOW) == state


def finding(hours, server="srv", severity="critical", exploited=False):
    return {
        "server_id": server, "vuln_blocked_at": None, "ecosystem": "npm", "name": "left-pad",
        "version": "1.0.0", "vuln_id": f"V-{hours}-{server}", "severity": severity, "cvss": 9.8,
        "exploited": exploited, "summary": None, "first_seen_at": NOW - timedelta(hours=hours),
    }


def kinds(wanted):
    return [(k, d.split(":")[1] if k == vuln.KIND_DUE else "") for k, d, _, _ in wanted]


def test_a_fresh_critical_finding_alerts_immediately_and_does_not_block():
    wanted, blocked = vuln.plan([finding(1)], set(), NOW)
    assert kinds(wanted) == [(vuln.KIND_VULNERABLE, "")] and blocked == set()
    assert wanted[0][2] == "critical"


def test_the_clock_escalates_with_a_day_left_and_blocks_when_overdue():
    wanted, blocked = vuln.plan([finding(30)], set(), NOW)
    assert (vuln.KIND_DUE, "escalated") in kinds(wanted) and blocked == set()
    wanted, blocked = vuln.plan([finding(49)], set(), NOW)
    assert (vuln.KIND_DUE, "overdue") in kinds(wanted) and blocked == {"srv"}
    due = next(w for w in wanted if w[0] == vuln.KIND_DUE)
    assert due[3]["deadline_at"] == (NOW - timedelta(hours=1)).isoformat()


def test_an_exception_lifts_the_block_but_keeps_the_alert():
    wanted, blocked = vuln.plan([finding(60)], {"srv"}, NOW)
    assert blocked == set() and (vuln.KIND_DUE, "overdue") in kinds(wanted)
    assert next(w for w in wanted if w[0] == vuln.KIND_DUE)[3]["excepted"] is True


def test_only_the_overdue_servers_are_blocked():
    rows = [finding(60, "late"), finding(60, "fine", severity="high"), finding(2, "new")]
    assert vuln.plan(rows, set(), NOW)[1] == {"late"}


def test_a_known_exploit_counts_as_critical_whatever_the_score():
    _, blocked = vuln.plan([finding(60, severity="low", exploited=True)], set(), NOW)
    assert blocked == {"srv"}


def test_non_critical_findings_only_alert():
    wanted, blocked = vuln.plan([finding(500, severity="high")], set(), NOW)
    assert kinds(wanted) == [(vuln.KIND_VULNERABLE, "")] and blocked == set()
