"""패키지 형태의 로컬 신청: ``uvx 패키지==판본``·PyPI 이름·``npx 패키지@판본``·npm 이름.

레지스트리에서 판본을 조회해 고정한다. PyPI는 판본으로, npm은 그 판본의 소스 커밋으로
고정해 접수한다(신청 명세는 ``mint add``와 같은 모양이다). 네트워크는 ``fetch``로 바꾼다.
"""

import json
import re
import shlex
import urllib.error
import urllib.parse

COMMIT = re.compile(r"[0-9a-f]{40}")
MANUAL = "커밋과 실행 명령을 직접 입력하십시오."
_NPM_NAME = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
_PYPI_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_VERSION = r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}"
PYPI_PIN = re.compile(rf"({_PYPI_NAME})(?:\[([A-Za-z0-9._,-]+)\])?==({_VERSION})")
_PYPI_REF = re.compile(rf"({_PYPI_NAME})(?:==({_VERSION}))?")
_NPM_REF = re.compile(rf"({_NPM_NAME})(?:@({_VERSION}))?")
_GITHUB = re.compile(r"github(?:\.com[:/]|:)([A-Za-z0-9._-]{1,100})/([A-Za-z0-9._-]{1,100}?)"
                     r"(?:\.git)?/?(?:#.*)?")


def package_ref(text: str) -> tuple[str, str, str | None, list[str]] | None:
    """패키지 형태 신청: (종류 pypi|npm|any, 이름, 판본 또는 None, 인자). 아니면 None.

    ``uvx 이름==판본``은 PyPI, ``npx 이름@판본``은 npm, 명령 없이 이름만 적으면 PyPI를 먼저 본다.
    """
    text = text.strip()
    if not text or "://" in text:
        return None
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    if not tokens:
        return None
    runner = tokens[0] if tokens[0] in ("uvx", "npx") else None
    rest = tokens[1:] if runner else tokens
    if runner == "npx" and rest[:1] == ["-y"]:
        rest = rest[1:]
    if runner == "uvx" and rest[:1] == ["--from"]:
        rest = rest[1:]
    if not rest or rest[0].startswith(("-", "git+")):
        return None
    ref, argv = rest[0], rest[1:]
    if runner == "uvx" or (not runner and "==" in ref):
        found = _PYPI_REF.fullmatch(ref)
        return ("pypi", found[1], found[2], argv) if found else None
    found = _NPM_REF.fullmatch(ref)
    if not found:
        return None
    return ("npm" if runner == "npx" or "@" in ref else "any", found[1], found[2], argv)


def _json(fetch, url: str) -> dict | None:
    raw = fetch(url)
    doc = json.loads(raw) if raw else None
    return doc if isinstance(doc, dict) else None


def slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", name.rsplit("/", 1)[-1]).strip("_") or "mcp"


def _pypi(name: str, version: str | None, argv: list[str], fetch) -> dict | None:
    suffix = "/" + urllib.parse.quote(version) if version else ""
    info = (_json(fetch, f"https://pypi.org/pypi/{urllib.parse.quote(name)}{suffix}/json")
            or {}).get("info") or {}
    if not info.get("version"):
        return None
    command = " ".join(["uvx", f"{info['name']}=={info['version']}", *map(shlex.quote, argv)])
    return {"repo": f"PyPI · {info['name']}", "url": command, "name": slug(info["name"]),
            "commit": info["version"], "command": command, "kind": "pypi", "note": ""}


def _npm_source(doc: dict, fetch) -> tuple[str, str, str] | None:
    """npm 판본의 (소유자, 저장소, 커밋). GitHub 저장소가 아니거나 커밋을 못 찾으면 None."""
    repository = doc.get("repository")
    text = repository.get("url") if isinstance(repository, dict) else repository
    if not isinstance(text, str) or (isinstance(repository, dict) and repository.get("directory")):
        return None
    found = _GITHUB.fullmatch(text.removeprefix("git+").removeprefix("git://")
                              .removeprefix("https://"))
    if not found:
        return None
    owner, repo = found[1], found[2]
    sha = str(doc.get("gitHead") or "")
    if not COMMIT.fullmatch(sha):
        for tag in (f"v{doc['version']}", doc["version"]):
            head = fetch(f"https://api.github.com/repos/{owner}/{repo}/commits/{tag}")
            sha = str(json.loads(head).get("sha", "")) if head else ""
            if COMMIT.fullmatch(sha):
                break
    return (owner, repo, sha) if COMMIT.fullmatch(sha) else None


def _npm(name: str, version: str | None, argv: list[str], fetch) -> dict | None:
    doc = _json(fetch, f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}/"
                f"{urllib.parse.quote(version or 'latest')}")
    if not doc or not doc.get("version"):
        return None
    out = {"repo": f"npm · {name}", "url": "", "name": slug(name), "commit": "", "command": "",
           "kind": "npm", "note": ""}
    source = _npm_source(doc, fetch)
    if source is None:
        out["note"] = f"{name} {doc['version']}의 커밋을 못 찾았습니다. 저장소 주소로 신청하십시오."
        return out
    owner, repo, sha = source
    base = f"https://github.com/{owner}/{repo}"
    command = " ".join(["npx", "-y", f"github:{owner}/{repo}#{sha}", *map(shlex.quote, argv)])
    return out | {"repo": base, "url": base, "commit": sha, "command": command,
                  "note": f"{name} {doc['version']}의 소스 커밋으로 고정합니다."}


def resolve(ref: tuple, fetch) -> dict | None:
    """신청 화면 미리보기 값. 레지스트리에 없으면 None, 연결 실패는 ``note``에 사유."""
    kind, name, version, argv = ref
    failed = {"repo": name, "url": name, "name": slug(name), "commit": "", "command": ""}
    try:
        found = _pypi(name, version, argv, fetch) if kind in ("pypi", "any") else None
        return found or (_npm(name, version, argv, fetch) if kind in ("npm", "any") else None)
    except urllib.error.HTTPError as error:
        why = "호출 한도에 걸렸습니다" if error.code in (403, 429) else "응답하지 않습니다"
        return failed | {"note": f"패키지 저장소가 {why}. " + MANUAL}
    except (OSError, ValueError, KeyError, TypeError):
        return failed | {"note": "패키지 저장소에 연결하지 못했습니다. " + MANUAL}


def pypi_spec(command: str, version: str) -> dict | None:
    """``uvx 이름==판본 [인자]``(또는 ``--from`` 형태)를 신청 명세로. 아니면 None."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    rest = tokens[1:]
    if tokens[:1] != ["uvx"] or not rest or (rest[0] == "--from" and rest[1:2] == [] or
                                              rest[0] == "--from" and rest[1].startswith("git+")):
        return None
    entry = None
    if rest[0] == "--from":
        pin, entry, argv = rest[1], (rest[2:3] or [None])[0], rest[3:]
    else:
        pin, argv = rest[0], rest[1:]
    found = PYPI_PIN.fullmatch(pin)
    if not found or found[3] != version:
        return None
    return {"index": "pypi", "name": found[1], "version": version,
            "extras": sorted(e for e in (found[2] or "").split(",") if e),
            "command": entry or found[1], "argv": argv}
