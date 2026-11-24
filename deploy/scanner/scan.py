"""공유 볼륨의 소스 검사 요청을 처리한다(코드·비밀·취약점·설정 오류·라이선스 검사).

요청: /scan/<id>/request.json
  {"kind": "git", "repo": "https://github.com/조직/저장소", "commit": "<40자>"}
  {"kind": "wheel", "pack_sha256": "<묶음 해시>", "wheel": "<묶음 안 휠 파일 이름>"}
결과: 같은 폴더의 result.json. 비밀 값과 코드 줄은 담지 않는다(규칙·파일·줄 번호만).
"""

import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

REQUESTS = Path("/scan")
PACKS = Path("/packs")
RULES = Path("/opt/mint/rules")
MAX_SOURCE = 200 * 1024 * 1024
MAX_FILES = 50000
TIMEOUT = 180
FINDINGS = 50
ALIVE = REQUESTS / ".alive"
LEVELS = ("critical", "high", "medium", "low", "unknown")
_SHA = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"https://github\.com/([A-Za-z0-9._-]{1,100})/([A-Za-z0-9._-]{1,100})")
SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


class ScanError(Exception):
    pass


def _safe(name: str) -> PurePosixPath | None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        return None
    return path


def _from_git(request: dict, target: Path) -> None:
    match = _REPO.fullmatch(str(request.get("repo", "")))
    commit = str(request.get("commit", ""))
    if not match or not _SHA.fullmatch(commit):
        raise ScanError("SOURCE_UNSUPPORTED")
    url = f"https://codeload.github.com/{match[1]}/{match[2]}/tar.gz/{commit}"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 (고정 호스트)
        data = response.read(MAX_SOURCE + 1)
    if len(data) > MAX_SOURCE:
        raise ScanError("SOURCE_TOO_LARGE")
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES:
            raise ScanError("SOURCE_TOO_LARGE")
        for member in members:
            path = _safe(member.name)
            if path is None or not member.isfile() or len(path.parts) < 2:
                continue  # 링크·장치·윗폴더 탈출은 풀지 않는다. 첫 폴더(저장소-커밋)는 벗긴다
            total += member.size
            if total > MAX_SOURCE:
                raise ScanError("SOURCE_TOO_LARGE")
            dest = target.joinpath(*path.parts[1:])
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, dest.open("xb") as output:
                shutil.copyfileobj(source, output)


def _from_wheel(request: dict, target: Path) -> None:
    digest, name = str(request.get("pack_sha256", "")), str(request.get("wheel", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or "/" in name or not name.endswith(".whl"):
        raise ScanError("SOURCE_UNSUPPORTED")
    wheel = PACKS / digest / name
    if not wheel.is_file():
        raise ScanError("SOURCE_UNAVAILABLE")
    total = 0
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ScanError("SOURCE_TOO_LARGE")
        for info in entries:
            path = _safe(info.filename)
            if path is None or info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            total += info.file_size
            if total > MAX_SOURCE:
                raise ScanError("SOURCE_TOO_LARGE")
            dest = target.joinpath(*path.parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, dest.open("xb") as output:
                shutil.copyfileobj(source, output)


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT, check=False)


def _relative(path: str, root: Path) -> str:
    prefix = str(root).rstrip("/") + "/"
    return path[len(prefix):] if path.startswith(prefix) else path


def tree_sha256(root: Path) -> str:
    """소스 트리 지문: 파일 경로·내용 해시를 경로순으로 이어 붙인 SHA-256."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        with path.open("rb") as handle:
            content = hashlib.file_digest(handle, "sha256").hexdigest()
        digest.update(f"{path.relative_to(root).as_posix()}\0{content}\n".encode())
    return digest.hexdigest()


def _level(item: dict) -> str:
    level = str(item.get("Severity", "")).lower()
    return level if level in LEVELS else "unknown"


def trivy_summary(doc: dict, root: Path) -> dict:
    """Trivy 보고서에서 ID·패키지·판본·심각도·파일·라이선스 이름만 뽑는다(설명·코드 줄은 버린다)."""
    if not isinstance(doc, dict) or not doc.get("SchemaVersion"):
        raise ScanError("DEPENDENCY_SCAN_FAILED")
    vulns, config = dict.fromkeys(LEVELS, 0), dict.fromkeys(LEVELS, 0)
    vuln_found, config_found, license_found, licenses = [], [], [], set()
    for result in doc.get("Results") or []:
        target = _relative(str(result.get("Target", "")), root)[:200]
        for item in result.get("Vulnerabilities") or []:
            vulns[_level(item)] += 1
            vuln_found.append({"id": str(item.get("VulnerabilityID", ""))[:80],
                               "package": str(item.get("PkgName", ""))[:100],
                               "version": str(item.get("InstalledVersion", ""))[:64],
                               "severity": _level(item), "file": target})
        for item in result.get("Misconfigurations") or []:
            config[_level(item)] += 1
            config_found.append({"id": str(item.get("ID", ""))[:80], "severity": _level(item),
                                "file": target})
        for item in result.get("Licenses") or []:
            name = str(item.get("Name", ""))[:100]
            if not item.get("PkgName") and "/" not in target:  # 저장소 맨 위의 라이선스 파일
                licenses.add(name)
            elif item.get("PkgName") and _level(item) in ("critical", "high"):
                license_found.append({"package": str(item["PkgName"])[:100], "license": name,
                                      "severity": _level(item), "file": target})
    rank = {level: n for n, level in enumerate(LEVELS)}
    for found in (vuln_found, config_found, license_found):
        found.sort(key=lambda f: rank[f["severity"]])
    return {"vulns": {**vulns, "findings": vuln_found[:FINDINGS]},
            "misconfig": {**config, "findings": config_found[:FINDINGS]},
            "licenses": {"findings": license_found[:FINDINGS], "repository": sorted(licenses)}}


def trivy(root: Path, work: Path) -> dict:
    report = work / "trivy.json"
    _run(["trivy", "fs", "--scanners", "vuln,misconfig,license", "--license-full",
          "--format", "json", "--output", str(report), "--exit-code", "0", "--quiet",
          "--skip-version-check", str(root)])
    if not report.exists():
        raise ScanError("DEPENDENCY_SCAN_FAILED")
    return trivy_summary(json.loads(report.read_text(encoding="utf-8") or "{}"), root)


def semgrep(root: Path, work: Path) -> dict:
    report = work / "semgrep.json"
    done = _run(["semgrep", "scan", "--config", str(RULES / "semgrep-mcp.yml"), "--json",
                 "--output", str(report), "--metrics", "off", "--quiet", str(root)])
    if not report.exists():
        raise ScanError("CODE_SCAN_FAILED")
    doc = json.loads(report.read_text(encoding="utf-8") or "{}")
    if not isinstance(doc.get("results"), list) or done.returncode not in (0, 1):
        raise ScanError("CODE_SCAN_FAILED")
    counts = {"high": 0, "medium": 0, "low": 0}
    findings = []
    for item in doc["results"]:
        extra = item.get("extra") or {}
        level = SEVERITY.get(str(extra.get("severity", "INFO")).upper(), "low")
        counts[level] += 1
        rule = str(item.get("check_id", "")).rsplit(".", 1)[-1][:80]
        findings.append({"severity": level, "rule": rule,
                         "file": _relative(str(item.get("path", "")), root)[:200],
                         "line": (item.get("start") or {}).get("line")})
    return {**counts, "findings": findings[:FINDINGS]}


def gitleaks(root: Path, work: Path) -> dict:
    report = work / "gitleaks.json"
    _run(["gitleaks", "dir", str(root), "--no-banner", "--redact=100", "--exit-code=0",
          "--report-format=json", f"--report-path={report}", "--ignore-gitleaks-allow",
          f"--config={RULES / 'gitleaks.toml'}", "--gitleaks-ignore-path=/dev/null"])
    if not report.exists():
        raise ScanError("SECRET_SCAN_FAILED")
    doc = json.loads(report.read_text(encoding="utf-8") or "[]")
    if not isinstance(doc, list):
        raise ScanError("SECRET_SCAN_FAILED")
    # 비밀 값·코드 줄(Match·Secret)은 옮기지 않는다
    findings = [{"rule": str(i.get("RuleID", ""))[:80],
                 "file": _relative(str(i.get("File", "")), root)[:200],
                 "line": i.get("StartLine")} for i in doc if isinstance(i, dict)]
    return {"count": len(findings), "findings": findings[:FINDINGS]}


def _dependencies(root: Path, work: Path) -> dict:
    """취약점 DB를 못 받는 등 Trivy만 실패해도 나머지 검사 결과는 살린다."""
    try:
        return trivy(root, work)
    except (ScanError, OSError, ValueError, subprocess.TimeoutExpired):
        return {"trivy_failed": True}


def handle(request: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="scan-") as temp:
        work = Path(temp)
        root = work / "src"
        root.mkdir()
        try:
            if request.get("kind") == "git":
                _from_git(request, root)
            elif request.get("kind") == "wheel":
                _from_wheel(request, root)
            else:
                raise ScanError("SOURCE_UNSUPPORTED")
            files = sum(1 for p in root.rglob("*") if p.is_file())
            return {"status": "ok", "files": files, "tree_sha256": tree_sha256(root),
                    "code": semgrep(root, work), "secrets": gitleaks(root, work),
                    **_dependencies(root, work)}
        except ScanError as error:
            return {"status": "error", "reason": str(error)}
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile,
                subprocess.TimeoutExpired):
            return {"status": "error", "reason": "SOURCE_UNAVAILABLE"}


def beat() -> None:
    """살아 있다는 표시를 5초마다 갱신한다(검사 중에도). 서버는 이 파일이 낡으면 바로 포기한다."""
    while True:
        try:
            ALIVE.write_text(str(int(time.time())), encoding="utf-8")
        except OSError:
            pass
        time.sleep(5)


def main() -> None:
    threading.Thread(target=beat, daemon=True).start()
    while True:
        for folder in sorted(REQUESTS.glob("*")):
            request_file, result_file = folder / "request.json", folder / "result.json"
            if not request_file.is_file() or result_file.exists():
                continue
            try:
                request = json.loads(request_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                request = {}
            result = {**handle(request), "request": request}
            temporary = folder / "result.tmp"
            temporary.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
            temporary.replace(result_file)
        time.sleep(1)


if __name__ == "__main__":
    main()
