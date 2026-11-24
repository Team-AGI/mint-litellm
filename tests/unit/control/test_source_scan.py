"""로컬 신청의 공급망 검사(SBOM·SCA·코드·비밀 검사)."""

import json
import threading
from pathlib import Path

import httpx

from mint_litellm.control import source_scan

MANIFEST = {"entry": "pkg.cli:main", "files": [
    {"name": "ghidra_mcp-1.0-py3-none-any.whl", "size": 10, "sha256": "a" * 64},
    {"name": "requests-2.19.0-py2.py3-none-any.whl", "size": 20, "sha256": "b" * 64},
    {"name": "notes.txt", "size": 1, "sha256": "c" * 64},
]}


def test_the_sbom_lists_every_wheel_in_the_pack_with_purl_and_hash():
    doc = source_scan.sbom(MANIFEST, "ghidra_mcp", "8dbbb1f")
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert [c["purl"] for c in doc["components"]] == [
        "pkg:pypi/ghidra-mcp@1.0", "pkg:pypi/requests@2.19.0"]
    assert doc["components"][1]["hashes"] == [{"alg": "SHA-256", "content": "b" * 64}]
    assert source_scan.sbom_outcome(MANIFEST).inputs["components"] == 2
    assert source_scan.sbom_outcome(None).result == "indeterminate"


def _feed(vulns: dict[str, list[dict]]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": v["id"]} for v in vulns.get(q["package"]["name"], [])]}
                for q in queries]})
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        doc = next(v for vs in vulns.values() for v in vs if v["id"] == vuln_id)
        return httpx.Response(200, json=doc)
    return lambda: httpx.Client(transport=httpx.MockTransport(handler), base_url="https://osv.test")


def test_a_critical_dependency_fails_and_lists_the_finding():
    feed = _feed({"requests": [{"id": "GHSA-1", "database_specific": {"severity": "CRITICAL"}}]})
    out = source_scan.dependency_outcome(MANIFEST, "https://osv.test", feed)
    assert out.result == "fail" and out.reason == "CRITICAL_VULNERABILITY"
    assert out.inputs["critical"] == 1 and out.inputs["packages"] == 2
    assert out.inputs["findings"][0] == {"id": "GHSA-1", "package": "requests",
                                        "version": "2.19.0", "severity": "critical"}


def test_medium_findings_pass_with_counts_and_an_unreachable_feed_is_indeterminate():
    feed = _feed({"requests": [{"id": "GHSA-2", "database_specific": {"severity": "MODERATE"}}]})
    out = source_scan.dependency_outcome(MANIFEST, "https://osv.test", feed)
    assert out.result == "pass" and out.inputs["medium"] == 1

    def down(request):
        raise httpx.ConnectError("down")
    broken = lambda: httpx.Client(transport=httpx.MockTransport(down))  # noqa: E731
    out = source_scan.dependency_outcome(MANIFEST, "https://osv.test", broken)
    assert out.result == "indeterminate" and out.reason == "VULN_FEED_UNREACHABLE"


def test_the_scanner_gets_the_pinned_commit_or_the_servers_own_wheel():
    spec = {"index": "git", "git": "https://github.com/o/r", "version": "f" * 40, "name": "r"}
    assert source_scan.scan_request(spec, None) == {
        "kind": "git", "repo": "https://github.com/o/r", "commit": "f" * 40}
    pypi = {"index": "pypi", "name": "ghidra-mcp", "version": "1.0"}
    assert source_scan.scan_request(pypi, ("d" * 64, MANIFEST)) == {
        "kind": "wheel", "pack_sha256": "d" * 64, "wheel": "ghidra_mcp-1.0-py3-none-any.whl"}
    assert source_scan.scan_request(pypi, None) is None
    assert source_scan.code_outcome(None).reason == "SOURCE_UNAVAILABLE"


def test_the_scan_result_comes_back_through_the_shared_folder(tmp_path: Path):
    (tmp_path / ".alive").write_text("1")

    def scanner():
        for _ in range(200):
            for folder in tmp_path.glob("*"):
                if (folder / "request.json").exists():
                    (folder / "result.json").write_text(json.dumps({
                        "status": "ok", "files": 12,
                        "code": {"high": 1, "medium": 0, "low": 0, "findings": [
                            {"severity": "high", "rule": "python-subprocess-shell",
                             "file": "a.py", "line": 3}]},
                        "secrets": {"count": 1, "findings": [
                            {"rule": "generic-api-key", "file": "b.py", "line": 9}]}}))
                    return
            threading.Event().wait(0.05)

    worker = threading.Thread(target=scanner)
    worker.start()
    result = source_scan.request_scan({"kind": "git"}, directory=tmp_path, timeout=10)
    worker.join()
    out = source_scan.code_outcome(result)
    assert out.result == "pass" and out.inputs["code_high"] == 1 and out.inputs["secrets"] == 1
    assert out.inputs["secret_findings"][0]["file"] == "b.py"
    assert [p.name for p in tmp_path.iterdir()] == [".alive"]  # 요청 폴더는 지운다


def test_a_stale_or_absent_scanner_signal_fails_at_once(tmp_path: Path):
    gone = {"status": "error", "reason": "SCANNER_UNAVAILABLE"}
    assert source_scan.request_scan({"kind": "git"}, directory=tmp_path, timeout=30) == gone
    assert list(tmp_path.iterdir()) == []  # 요청도 남기지 않는다
    alive = tmp_path / ".alive"
    alive.write_text("1")
    assert source_scan.scanner_alive(tmp_path)
    assert not source_scan.scanner_alive(tmp_path, now=alive.stat().st_mtime + 61)
    assert source_scan.SCAN_WAIT == 600


def test_trivy_findings_and_the_source_record_reach_the_outcome():
    result = {"status": "ok", "files": 4, "tree_sha256": "a" * 64,
              "request": {"kind": "git", "repo": "https://github.com/o/r", "commit": "f" * 40},
              "code": {"high": 0}, "secrets": {"count": 0},
              "vulns": {"critical": 0, "high": 1, "findings": [
                  {"id": "CVE-1", "package": "x", "version": "1", "severity": "high"}]},
              "misconfig": {"high": 1, "findings": [
                  {"id": "DS002", "severity": "high", "file": "Dockerfile"}]},
              "licenses": {"repository": ["MIT"], "findings": []}}
    out = source_scan.code_outcome(result)
    assert out.result == "pass" and out.inputs["misconfig_high"] == 1
    assert out.inputs["source"] == {"tree_sha256": "a" * 64, "repo": "https://github.com/o/r",
                                    "commit": "f" * 40, "license": "MIT"}
    assert source_scan.review_needed(out.inputs)
    assert not source_scan.review_needed({"code_high": 0, "secrets": 0, "misconfig_high": 0})
    failed = source_scan.code_outcome({**result, "vulns": {"critical": 1, "findings": []}})
    assert failed.result == "fail" and failed.reason == "CRITICAL_VULNERABILITY"
    skipped = source_scan.code_outcome({**result, "trivy_failed": True})
    assert skipped.result == "pass" and skipped.inputs["trivy_failed"]


def test_a_missing_scanner_is_reported_not_waited_for(tmp_path: Path):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    result = source_scan.request_scan({"kind": "git"}, directory=blocked, timeout=5)
    assert result == {"status": "error", "reason": "SCANNER_UNAVAILABLE"}
    assert source_scan.code_outcome(result).result == "indeterminate"


def test_a_risky_code_scan_is_shown_as_needing_review_but_stays_a_pass():
    from mint_litellm.console import labels
    from mint_litellm.console.pages.servers import shown_result

    risky = {"check": "code_scan", "result": "pass", "inputs": {"secrets": 2}}
    assert shown_result(risky) == "review" and risky["result"] == "pass"
    assert shown_result({**risky, "inputs": {"secrets": 0, "code_high": 0}}) == "pass"
    assert labels.CHECK_RESULT["review"].text == "검토 필요"
    summary = labels.scan_summary({"check": "code_scan", "inputs": {
        "files": 3, "vuln_critical": 0, "vuln_high": 2, "misconfig_high": 1,
        "license_findings": [{}]}})
    assert "취약점 심각 0 높음 2" in summary and "라이선스 주의 1" in summary


NPM_SPEC = {"index": "npm", "name": "@o/srv", "version": "1.0.0", "command": "srv",
            "integrity": "sha512-" + "A" * 86 + "=="}


def _registry(root: dict, versions: dict[str, list[str]], integrity: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/@o/srv/1.0.0":
            return httpx.Response(200, json={
                "dist": {"integrity": integrity or NPM_SPEC["integrity"]}, "dependencies": root})
        name = path.lstrip("/")
        if name in versions:
            return httpx.Response(200, json={"versions": {
                v: {"dist": {"integrity": "sha512-x"}} for v in versions[name]}})
        return httpx.Response(404)
    return lambda: httpx.Client(transport=httpx.MockTransport(handler),
                                base_url="https://registry.test")


def test_a_range_resolves_to_the_newest_release_it_allows():
    pick = source_scan.newest_in
    seen = ["1.0.0", "1.2.3", "1.9.0", "2.0.0", "2.1.0-beta.1", "0.3.4", "0.3.9", "0.4.0"]
    assert pick("^1.2.0", seen) == "1.9.0" and pick("~1.2.0", seen) == "1.2.3"
    assert pick("^0.3.4", seen) == "0.3.9" and pick(">=1 <2", seen) == "1.9.0"
    assert pick("1.x", seen) == "1.9.0" and pick("*", seen) == "2.0.0"
    assert pick("1.0.0 - 1.5.0", seen) == "1.2.3" and pick("^0.4.0 || ^2.0.0", seen) == "2.0.0"
    assert pick("2.1.0-beta.1", seen) is None and pick("github:o/r", seen) is None


def test_an_npm_inventory_lists_the_package_and_its_resolved_dependencies():
    client = _registry({"zod": "^3.0.0", "gone": "^1.0.0"},
                       {"zod": ["3.1.0", "3.9.1", "4.0.0"], "gone": ["0.1.0"]})
    inventory = source_scan.npm_inventory(NPM_SPEC, client)
    assert [(c["name"], c["version"]) for c in inventory["components"]] == [
        ("@o/srv", "1.0.0"), ("zod", "3.9.1")]
    assert inventory["unresolved"] == 1
    outcome = source_scan.sbom_outcome(None, inventory)
    assert outcome.result == "pass" and outcome.inputs["components"] == 2


def test_a_registry_hash_that_differs_from_the_pin_fails_and_an_outage_is_indeterminate():
    changed = source_scan.npm_inventory(NPM_SPEC, _registry({}, {}, "sha512-" + "B" * 86 + "=="))
    assert changed == {"error": "INTEGRITY_MISMATCH"}
    assert source_scan.sbom_outcome(None, changed).result == "fail"
    assert source_scan.dependency_outcome(None, "https://osv.test", npm=changed).result == "fail"
    down = source_scan.npm_inventory(NPM_SPEC, lambda: httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(503))))
    assert source_scan.sbom_outcome(None, down).reason == "REGISTRY_UNREACHABLE"


def test_npm_dependencies_are_asked_of_the_vulnerability_feed_as_npm_packages():
    inventory = {"components": [{"name": "@o/srv", "version": "1.0.0", "integrity": None},
                                {"name": "zod", "version": "3.9.1", "integrity": None}],
                 "unresolved": 0}
    feed = _feed({"zod": [{"id": "GHSA-1", "database_specific": {"severity": "CRITICAL"}}]})
    outcome = source_scan.dependency_outcome(None, "https://osv.test", feed, npm=inventory)
    assert outcome.result == "fail" and outcome.reason == "CRITICAL_VULNERABILITY"
    assert outcome.inputs["packages"] == 2 and outcome.inputs["findings"][0]["package"] == "zod"


def test_an_npm_source_is_scanned_from_its_commit_or_else_its_tarball():
    assert source_scan.scan_request(NPM_SPEC, None) == {
        "kind": "npm", "name": "@o/srv", "version": "1.0.0", "integrity": NPM_SPEC["integrity"]}
    with_git = {**NPM_SPEC, "git": "https://github.com/o/srv", "commit": "c" * 40}
    assert source_scan.scan_request(with_git, None) == {
        "kind": "git", "repo": "https://github.com/o/srv", "commit": "c" * 40}
