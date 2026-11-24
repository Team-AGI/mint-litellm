"""소스 검사기(deploy/scanner/scan.py)의 순수 함수: Trivy 결과 정리와 소스 트리 지문."""

import importlib.util
from pathlib import Path, PurePosixPath

import pytest

_PATH = Path(__file__).parents[3] / "deploy" / "scanner" / "scan.py"
_SPEC = importlib.util.spec_from_file_location("scanner_scan", _PATH)
scan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(scan)

ROOT = PurePosixPath("/tmp/scan-x/src")
REPORT = {"SchemaVersion": 2, "Results": [
    {"Target": "/tmp/scan-x/src/package-lock.json", "Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-1", "PkgName": "lodash", "InstalledVersion": "4.0.0",
         "Severity": "CRITICAL", "Description": "긴 설명은 버린다"},
        {"VulnerabilityID": "CVE-2024-2", "PkgName": "left", "InstalledVersion": "1.0",
         "Severity": "LOW"}]},
    {"Target": "Dockerfile", "Class": "config", "Misconfigurations": [
        {"ID": "DS002", "Severity": "HIGH", "Message": "root로 실행",
         "CauseMetadata": {"Code": "x"}}]},
    {"Target": "LICENSE", "Class": "license-file", "Licenses": [
        {"Name": "MIT", "Severity": "LOW", "FilePath": "LICENSE"}]},
    {"Target": "Node.js", "Class": "license", "Licenses": [
        {"PkgName": "gpl-pkg", "Name": "GPL-3.0", "Severity": "HIGH"},
        {"PkgName": "mit-pkg", "Name": "MIT", "Severity": "LOW"}]},
]}


def test_trivy_report_keeps_only_ids_packages_versions_severities_files_and_licenses():
    got = scan.trivy_summary(REPORT, ROOT)
    assert got["vulns"]["critical"] == 1 and got["vulns"]["low"] == 1
    assert got["vulns"]["findings"][0] == {"id": "CVE-2024-1", "package": "lodash",
                                           "version": "4.0.0", "severity": "critical",
                                           "file": "package-lock.json"}
    assert got["misconfig"]["high"] == 1
    assert got["misconfig"]["findings"] == [{"id": "DS002", "severity": "high",
                                             "file": "Dockerfile"}]
    assert got["licenses"]["repository"] == ["MIT"]
    assert got["licenses"]["findings"] == [{"package": "gpl-pkg", "license": "GPL-3.0",
                                            "severity": "high", "file": "Node.js"}]
    text = str(got)
    assert "설명" not in text and "root로" not in text and "Code" not in text


def test_a_report_without_a_schema_version_is_a_failed_scan():
    with pytest.raises(scan.ScanError):
        scan.trivy_summary({}, ROOT)


def test_the_tree_fingerprint_follows_paths_and_contents(tmp_path: Path):
    (tmp_path / "a.txt").write_text("1")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b.txt").write_text("2")
    first = scan.tree_sha256(tmp_path)
    assert first == scan.tree_sha256(tmp_path) and len(first) == 64
    (tmp_path / "d" / "b.txt").write_text("3")
    assert scan.tree_sha256(tmp_path) != first
