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
    assert list(tmp_path.iterdir()) == []  # 요청 폴더는 지운다


def test_a_missing_scanner_is_reported_not_waited_for(tmp_path: Path):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    result = source_scan.request_scan({"kind": "git"}, directory=blocked, timeout=5)
    assert result == {"status": "error", "reason": "SCANNER_UNAVAILABLE"}
    assert source_scan.code_outcome(result).result == "indeterminate"
