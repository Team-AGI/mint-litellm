"""로컬 신청의 공급망 검사: 구성요소 목록(SBOM)·의존성 취약점(SCA)·코드·비밀 검사(SAST).

- SBOM은 서버에서 만든 실행 묶음의 휠 목록(이름·판본·해시)으로 만든다. 실제로 PC에 깔리는 것과 같다.
- npm 출처는 묶음이 없다. 레지스트리의 그 판본(과 의존성 1단계)이 구성요소이고, 레지스트리의
  무결성 해시가 신청에 고정된 값과 같아야 한다.
- SCA는 그 구성요소를 취약점 조회처(OSV 형식)에 묻는다. 심각(또는 악용 중) 취약점이 있으면 실패다.
- 코드·비밀·취약점·설정 오류·라이선스 검사는 소스 검사기 컨테이너가 고정 커밋의 소스(또는 서버
  패키지 휠)에 돌린다. 검사기가 60초 넘게 신호가 없으면 기다리지 않고 바로 응답 없음으로 본다.
"""

import json
import os
import re
import shutil
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from mint_litellm.control import vuln
from mint_litellm.control.intake_checks import Outcome

_WHEEL = re.compile(r"(?P<name>[A-Za-z0-9_.]+)-(?P<version>[A-Za-z0-9_.!+]+)-.+\.whl")
FINDINGS = 20
ALIVE_SECONDS = 60
SCAN_WAIT = 600


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def components(manifest: dict | None) -> list[dict]:
    """묶음 휠마다 {name, version, sha256, file}. 휠이 아닌 파일은 뺀다."""
    out = []
    for f in (manifest or {}).get("files", []):
        match = _WHEEL.fullmatch(str(f.get("name", "")))
        if match:
            out.append({"name": _norm(match["name"]), "version": match["version"],
                        "sha256": f.get("sha256"), "file": f["name"]})
    return out


NPM_REGISTRY = "https://registry.npmjs.org"
MAX_NPM_DEPS = 60
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _bounds(rule: str) -> tuple[tuple, tuple | None] | None:
    """비교자 하나(``^1.2``·``~1``·``>=1.2.3``·``1.x`` 등)의 [아래, 위) 구간. 모르는 형태는 None."""
    match = re.fullmatch(r"(\^|~|>=|<=|>|<|=|)\s*v?([0-9xX*]+(?:\.[0-9xX*]+){0,2})", rule)
    if not match:
        return None
    parts = [None if p in ("x", "X", "*") else int(p) for p in match[2].split(".")]
    given = [p for p in parts if p is not None]
    if len(given) != next((i for i, p in enumerate(parts) if p is None), len(parts)):
        return None
    low = tuple([*given, 0, 0, 0][:3])
    n = len(given)
    next_up = None if n == 0 else (low[0], low[1], low[2] + 1) if n == 3 else (
        (low[0], low[1] + 1, 0) if n == 2 else (low[0] + 1, 0, 0))
    op = match[1]
    if op == "^":
        high = (low[0] + 1, 0, 0) if low[0] or n == 1 else (
            (0, low[1] + 1, 0) if low[1] or n == 2 else (0, 0, low[2] + 1))
        return low, high
    if op == "~":
        return low, ((low[0], low[1] + 1, 0) if n >= 2 else (low[0] + 1, 0, 0))
    if op == ">=":
        return low, None
    if op == ">":
        return (next_up or (0, 0, 0)), None
    if op == "<":
        return (0, 0, 0), low
    if op == "<=":
        return (0, 0, 0), next_up
    return low, next_up


def newest_in(rng: str, versions: list[str]) -> str | None:
    """npm 범위(``||``·공백 이음·``A - B``·^·~·x)에 맞는 가장 높은 정식 판본. 못 풀면 None."""
    text = re.sub(r"(\S+)\s+-\s+(\S+)", r">=\1 <=\2", rng.strip())
    text = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", text)
    clauses = []
    for clause in (text or "*").split("||"):
        cuts = [_bounds(r) for r in clause.split()] or [((0, 0, 0), None)]
        if None in cuts:
            return None
        clauses.append(cuts)
    best = None
    for version in versions:
        found = _VERSION.fullmatch(version)  # 시험판은 범위에 들지 않는다
        if not found:
            continue
        number = tuple(map(int, found.groups()))
        if any(all(lo <= number and (hi is None or number < hi) for lo, hi in cuts)
               for cuts in clauses) and (best is None or number > best[0]):
            best = (number, version)
    return best and best[1]


def npm_inventory(spec: dict, client: Callable[[], Any] | None = None) -> dict:
    """npm 신청의 구성요소: 그 판본과 의존성(1단계)이 레지스트리에서 풀리는 판본.

    ``{"components": [...], "unresolved": n}`` 또는 ``{"error": 사유}``. 레지스트리의 무결성
    해시가 신청에 고정된 값과 다르면 ``INTEGRITY_MISMATCH``이다.
    """
    name, version = spec["name"], spec["version"]
    try:
        with (client or (lambda: httpx.Client(timeout=20)))() as http:
            doc = http.get(f"{NPM_REGISTRY}/{name}/{version}").raise_for_status().json()
            if (doc.get("dist") or {}).get("integrity") != spec.get("integrity"):
                return {"error": "INTEGRITY_MISMATCH"}
            found = [{"name": name, "version": version, "integrity": spec["integrity"]}]
            wanted = sorted((doc.get("dependencies") or {}).items())
            unresolved = max(len(wanted) - MAX_NPM_DEPS, 0)
            for dep, rng in wanted[:MAX_NPM_DEPS]:
                listing = http.get(f"{NPM_REGISTRY}/{dep}", headers={
                    "Accept": "application/vnd.npm.install-v1+json"}).raise_for_status().json()
                picked = newest_in(str(rng), list(listing.get("versions") or {}))
                if picked is None:
                    unresolved += 1
                    continue
                dist = listing["versions"][picked].get("dist") or {}
                found.append({"name": dep, "version": picked, "integrity": dist.get("integrity")})
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        return {"error": "REGISTRY_UNREACHABLE"}
    return {"components": found, "unresolved": unresolved}


def _npm_failure(inventory: dict, method: str) -> Outcome | None:
    code = inventory.get("error")
    if code == "INTEGRITY_MISMATCH":
        return Outcome("fail", code, method)
    return Outcome("indeterminate", code, method) if code else None


def sbom(manifest: dict | None, server_id: str, version: str | None) -> dict:
    """CycloneDX 1.5 문서(구성요소는 PyPI purl·SHA-256)."""
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": server_id,
                                   "version": version or ""},
                     "tools": [{"name": "MINT"}]},
        "components": [
            {"type": "library", "name": c["name"], "version": c["version"],
             "purl": f"pkg:pypi/{c['name']}@{c['version']}",
             "hashes": [{"alg": "SHA-256", "content": c["sha256"]}] if c["sha256"] else []}
            for c in components(manifest)
        ],
    }


def sbom_outcome(manifest: dict | None, npm: dict | None = None) -> Outcome:
    if npm is not None:
        method = "sbom:npm_registry"
        return _npm_failure(npm, method) or Outcome("pass", None, method, {
            "components": len(npm["components"]), "unresolved": npm["unresolved"],
            "format": "CycloneDX 1.5"})
    method = "sbom:pack_manifest"
    found = components(manifest)
    if not found:
        return Outcome("indeterminate", "PACK_UNAVAILABLE", method)
    return Outcome("pass", None, method, {"components": len(found), "format": "CycloneDX 1.5"})


def dependency_outcome(manifest: dict | None, feed: str,
                       client: Callable[[], Any] | None = None, npm: dict | None = None) -> Outcome:
    method = "sca:osv"
    if npm is not None:
        failed = _npm_failure(npm, method)
        if failed:
            return failed
        keys = [("npm", c["name"], c["version"]) for c in npm["components"]]
    else:
        found = components(manifest)
        if not found:
            return Outcome("indeterminate", "PACK_UNAVAILABLE", method)
        keys = [("pypi", c["name"], c["version"]) for c in found]
    try:
        with (client or (lambda: httpx.Client(timeout=20)))() as http:
            hits = vuln.fetch(http, feed, keys, {})
    except (httpx.HTTPError, ValueError, KeyError):
        return Outcome("indeterminate", "VULN_FEED_UNREACHABLE", method, {"packages": len(keys)})
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    findings = []
    critical = False
    for (_, name, version), vulns in hits.items():
        for vuln_id, info in vulns.items():
            counts[info["severity"]] = counts.get(info["severity"], 0) + 1
            critical = critical or vuln.is_critical(info)
            findings.append({"id": vuln_id, "package": name, "version": version,
                             "severity": info["severity"]})
    findings.sort(key=lambda f: -vuln.RANK.get(f["severity"], 0))
    inputs = {"packages": len(keys), **counts, "findings": findings[:FINDINGS]}
    if npm is not None:
        inputs["unresolved"] = npm["unresolved"]
    if critical:
        return Outcome("fail", "CRITICAL_VULNERABILITY", method, inputs)
    return Outcome("pass", None, method, inputs)


def scan_request(spec: dict | None, pack: tuple[str, dict] | None) -> dict | None:
    """검사기에 보낼 소스: git·npm 출처는 고정 커밋(npm은 없으면 tarball), PyPI 출처는 휠."""
    spec = spec or {}
    if spec.get("index") == "npm":
        if spec.get("git") and spec.get("commit"):
            return {"kind": "git", "repo": spec["git"], "commit": spec["commit"]}
        return {"kind": "npm", "name": spec.get("name"), "version": spec.get("version"),
                "integrity": spec.get("integrity")}
    if spec.get("index") == "git" and spec.get("git"):
        return {"kind": "git", "repo": spec["git"], "commit": spec.get("version")}
    if pack is None:
        return None
    own = _norm(str(spec.get("name", "")))
    wheel = next((c["file"] for c in components(pack[1]) if c["name"] == own), None)
    return {"kind": "wheel", "pack_sha256": pack[0], "wheel": wheel} if wheel else None


def scanner_alive(root: Path, now: float | None = None) -> bool:
    """검사기가 남기는 신호 파일이 60초 안에 갱신됐는가."""
    try:
        return (now or time.time()) - (root / ".alive").stat().st_mtime <= ALIVE_SECONDS
    except OSError:
        return False


def request_scan(request: dict, *, directory=None, timeout: float = SCAN_WAIT,
                 wait: Callable[[], None] | None = None) -> dict:
    """공유 볼륨으로 검사를 맡기고 결과를 기다린다. ``wait``는 기다리는 동안의 취소 확인이다."""
    root = Path(directory or os.environ.get("MINT_SCAN_DIR", "/var/lib/mint/scan"))
    if not scanner_alive(root):  # 검사기가 안 떠 있으면 작업 실행기를 붙잡지 않는다
        return {"status": "error", "reason": "SCANNER_UNAVAILABLE"}
    folder = root / str(uuid.uuid4())
    try:
        folder.mkdir(parents=True)
        temporary = folder / "request.tmp"
        temporary.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
        temporary.replace(folder / "request.json")
    except OSError:  # 공유 볼륨이 없다(검사기 미설치)
        return {"status": "error", "reason": "SCANNER_UNAVAILABLE"}
    end = time.monotonic() + timeout
    try:
        while time.monotonic() < end:
            if wait:
                wait()
            try:
                return json.loads((folder / "result.json").read_text(encoding="utf-8"))
            except FileNotFoundError:
                time.sleep(1)
            except (ValueError, OSError):
                break
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return {"status": "error", "reason": "SCANNER_UNAVAILABLE"}


def tree_source(result: dict, request: dict | None) -> dict:
    """검사한 소스의 출처 기록: 트리 지문·저장소·커밋·라이선스."""
    request = request or {}
    licenses = (result.get("licenses") or {}).get("repository") or []
    out = {"tree_sha256": result.get("tree_sha256"),
           "repo": request.get("repo"), "commit": request.get("commit"),
           "license": ", ".join(licenses[:5]) or None}
    return {k: v for k, v in out.items() if v}


def review_needed(inputs: dict | None) -> bool:
    """코드 높음·비밀 의심·설정 오류 높음 이상이 있으면 승인자가 따로 살펴야 한다."""
    i = inputs or {}
    return bool(i.get("code_high") or i.get("secrets") or i.get("misconfig_high")
                or i.get("misconfig_critical"))


def code_outcome(result: dict | None) -> Outcome:
    method = "scan:semgrep_gitleaks_trivy"
    if result is None:
        return Outcome("indeterminate", "SOURCE_UNAVAILABLE", method)
    if result.get("status") != "ok":
        reason = result.get("reason")
        return Outcome("indeterminate", reason if isinstance(reason, str) else "SCAN_INCOMPLETE",
                       method)
    code, secrets = result.get("code") or {}, result.get("secrets") or {}
    vulns, config = result.get("vulns") or {}, result.get("misconfig") or {}
    licenses = result.get("licenses") or {}
    inputs = {
        "files": result.get("files", 0),
        "code_high": code.get("high", 0), "code_medium": code.get("medium", 0),
        "code_low": code.get("low", 0), "secrets": secrets.get("count", 0),
        "findings": (code.get("findings") or [])[:FINDINGS],
        "secret_findings": (secrets.get("findings") or [])[:FINDINGS],
        "source": tree_source(result, result.get("request")),
    }
    if result.get("trivy_failed"):
        inputs["trivy_failed"] = True
    else:
        inputs |= {
            "vuln_critical": vulns.get("critical", 0), "vuln_high": vulns.get("high", 0),
            "vuln_medium": vulns.get("medium", 0), "vuln_low": vulns.get("low", 0),
            "misconfig_critical": config.get("critical", 0),
            "misconfig_high": config.get("high", 0),
            "misconfig_medium": config.get("medium", 0),
            "vuln_findings": (vulns.get("findings") or [])[:FINDINGS],
            "misconfig_findings": (config.get("findings") or [])[:FINDINGS],
            "license_findings": (licenses.get("findings") or [])[:FINDINGS],
        }
    # ponytail: 단독형처럼 코드·비밀 발견은 거절하지 않고 승인자에게 「검토 필요」로 보인다.
    # 시험용 가짜 키 때문에 오탐 거절이 잦으면 안 되기 때문이다. 심각 취약점만 실패로 둔다.
    if inputs.get("vuln_critical"):
        return Outcome("fail", "CRITICAL_VULNERABILITY", method, inputs)
    return Outcome("pass", None, method, inputs)
