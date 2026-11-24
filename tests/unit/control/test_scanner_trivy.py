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


def _tarball(files: dict[str, bytes]) -> bytes:
    import io
    import tarfile

    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def test_an_npm_tarball_is_unpacked_only_when_its_hash_is_the_pinned_one(tmp_path, monkeypatch):
    import base64
    import hashlib
    import urllib.request

    data = _tarball({"package/index.js": b"x", "../evil": b"y", "package/lib/a.js": b"z"})
    pinned = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()

    class Reply:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return data

    seen = []
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda url, timeout: seen.append(url) or Reply())
    request = {"kind": "npm", "name": "@o/srv", "version": "1.0.0", "integrity": pinned}
    scan._from_npm(request, tmp_path)
    assert seen == ["https://registry.npmjs.org/@o/srv/-/srv-1.0.0.tgz"]
    files = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert files == ["index.js", "lib/a.js"]
    with pytest.raises(scan.ScanError, match="INTEGRITY_MISMATCH"):
        scan._from_npm({**request, "integrity": "sha512-" + "A" * 86 + "=="}, tmp_path / "x")
    with pytest.raises(scan.ScanError, match="SOURCE_UNSUPPORTED"):
        scan._from_npm({**request, "name": "../x"}, tmp_path / "y")
