"""의존 그래프 조회: 응답 해석, 경로, 하루 한 번만 받기, 조회 실패."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from mint_litellm.console import alert_view
from mint_litellm.control import depgraph, vuln

NOW = datetime(2030, 1, 10, 12, 0, tzinfo=UTC)

# deps.dev 응답 모양: app -> mid -> leaf, app -> other
GRAPH = {
    "nodes": [
        {"versionKey": {"system": "NPM", "name": "app", "version": "1.0.0"}, "relation": "SELF"},
        {"versionKey": {"system": "NPM", "name": "mid", "version": "2.0.0"}, "relation": "DIRECT"},
        {
            "versionKey": {"system": "NPM", "name": "leaf", "version": "3.1.0"},
            "relation": "INDIRECT",
        },
        {
            "versionKey": {"system": "NPM", "name": "other", "version": "0.9.0"},
            "relation": "DIRECT",
        },
    ],
    "edges": [
        {"fromNode": 0, "toNode": 1},
        {"fromNode": 1, "toNode": 2},
        {"fromNode": 0, "toNode": 3},
        {"fromNode": 3, "toNode": 2},
    ],
}


def test_parse_lists_every_dependency_with_its_shortest_path():
    deps = depgraph.parse(GRAPH, "app", "1.0.0")
    assert sorted(deps) == [
        ("leaf", "3.1.0", "app → mid → leaf"),
        ("mid", "2.0.0", "app → mid"),
        ("other", "0.9.0", "app → other"),
    ]


def test_parse_refuses_an_answer_without_the_package_itself():
    with pytest.raises(ValueError):
        depgraph.parse({"nodes": [GRAPH["nodes"][1]], "edges": []}, "app", "1.0.0")
    with pytest.raises(ValueError):
        depgraph.parse({"nodes": "x"}, "app", "1.0.0")


def client(seen, status=200, doc=GRAPH):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        if status == 200:
            return httpx.Response(200, json=doc)
        return httpx.Response(status)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_request_shape_for_scoped_npm_and_normalized_pypi_names():
    seen = []
    with client(seen) as http:
        depgraph.fetch_one(http, "https://g.test", "npm", "@scope/app", "1.0.0")
        depgraph.fetch_one(http, "https://g.test", "pypi", "My_Pkg.X", "2.0")
    assert seen == [
        "/v3/systems/npm/packages/%40scope%2Fapp/versions/1.0.0:dependencies",
        "/v3/systems/pypi/packages/my-pkg-x/versions/2.0:dependencies",
    ]


def test_a_package_the_service_does_not_know_has_no_dependencies():
    with client([], status=404) as http:
        assert depgraph.fetch_one(http, "https://g.test", "npm", "app", "1.0.0") == []


KEY = ("npm", "app", "1.0.0")


def test_resolve_fetches_missing_and_stale_graphs_but_not_fresh_ones():
    seen = []
    with client(seen) as http:
        fresh, err = depgraph.resolve(http, "https://g.test", [KEY], {}, NOW)
        assert err is None and len(fresh[KEY]) == 3 and len(seen) == 1
        cached = {KEY: NOW - timedelta(hours=23)}
        assert depgraph.resolve(http, "https://g.test", [KEY], cached, NOW) == ({}, None)
        assert len(seen) == 1
        stale = {KEY: NOW - timedelta(hours=25)}
        assert KEY in depgraph.resolve(http, "https://g.test", [KEY], stale, NOW)[0]
        assert len(seen) == 2


def test_an_unreachable_service_stops_the_round_and_reports_the_error():
    def refuse(request):
        raise httpx.ConnectError("offline")

    with httpx.Client(transport=httpx.MockTransport(refuse)) as http:
        fresh, err = depgraph.resolve(http, "https://g.test", [KEY, ("npm", "b", "1.0.0")], {}, NOW)
    assert fresh == {} and isinstance(err, httpx.HTTPError)


def test_the_dependencies_join_the_batch_query_once_each():
    graph = {
        KEY: [("leaf", "3.1.0", "app → leaf")],
        ("npm", "b", "1.0.0"): [("leaf", "3.1.0", "b → leaf"), ("x", "1.0.0", "b → x")],
    }
    tops = [KEY, ("npm", "b", "1.0.0")]
    assert vuln.with_deps(tops, graph) == [
        KEY,
        ("npm", "b", "1.0.0"),
        ("npm", "leaf", "3.1.0"),
        ("npm", "x", "1.0.0"),
    ]


def finding(path=None, server="srv"):
    return {
        "server_id": server,
        "vuln_blocked_at": None,
        "ecosystem": "npm",
        "name": "leaf",
        "version": "3.1.0",
        "vuln_id": "V1",
        "severity": "critical",
        "cvss": 9.8,
        "exploited": False,
        "summary": None,
        "path": path,
        "first_seen_at": NOW - timedelta(hours=49),
    }


def test_a_transitive_critical_names_the_path_and_blocks_after_48_hours():
    wanted, blocked = vuln.plan([finding("app → mid → leaf")], set(), NOW)
    assert blocked == {"srv"}
    assert all(w[3]["path"] == "app → mid → leaf" for w in wanted)
    text = alert_view.summary(wanted[0][0], wanted[0][3])
    assert "srv" in text and "leaf" in text and "app → mid → leaf" in text


def test_a_direct_finding_wins_over_the_same_one_reached_through_a_dependency():
    wanted, _ = vuln.plan([finding("app → leaf"), finding(None)], set(), NOW)
    assert [w for w in wanted if w[0] == vuln.KIND_VULNERABLE][0][3].get("path") is None
    assert len([w for w in wanted if w[0] == vuln.KIND_VULNERABLE]) == 1
