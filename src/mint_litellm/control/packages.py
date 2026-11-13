"""로컬 실행(stdio) 서버의 실행 계약에서 쓰는 패키지(제공처·이름·버전)를 뽑는다.

npm(``npx``·``npm exec``·``pnpm dlx``·``bunx``), PyPI(``uvx``·``pipx run``·``uv tool run``·
``python -m``), 컨테이너 이미지(``docker run``)를 알아본다. 버전이 정확히 하나로 정해지지 않은
지정(``latest``·범위·버전 없음)은 ``pinned=False``이다. 실행 파일은 계약이 이미 담은 내용 해시를
그대로 한 항목으로 더한다. 알려진 호출 형태만 해석하며 모르는 형태는 패키지로 세지 않는다.
"""

import ntpath
import posixpath
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

ECOSYSTEMS = ("npm", "pypi", "container", "executable")
# 취약점 조회 대상 생태계 -> 조회처(OSV)의 생태계 이름
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}
NPM_REGISTRY = "registry.npmjs.org"
PYPI_REGISTRY = "pypi.org"
DOCKER_REGISTRY = "docker.io"

_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_PYVER = re.compile(r"[0-9][0-9A-Za-z.+!_-]*")
_SOURCE = re.compile(r"(?:github|gitlab|bitbucket|git\+\w+|git|file|link|https?):", re.I)
_COMMIT = re.compile(r"[0-9a-f]{7,40}")
_PY_SPEC = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(===|==)\s*(\S+)|@\s*(\S+)|(\S*))"
)
# 값을 따로 받는 docker run 옵션(``--옵션=값`` 꼴이 아니면 다음 토큰이 값이다)
_DOCKER_VALUE_FLAGS = frozenset(
    "-e --env -v --volume -p --publish --name -w --workdir -u --user --network --net --entrypoint"
    " --mount -l --label --env-file --add-host --platform -m --memory --cpus -h --hostname --pull"
    " --restart --cap-add --cap-drop --security-opt --device --log-driver --tmpfs --dns"
    " --group-add --ulimit --shm-size -a --attach --cidfile --ipc --pid --runtime".split()
)


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str | None  # 지정한 버전 문자열(범위·태그 포함). 지정이 없으면 None
    pinned: bool  # 정확히 하나의 버전(또는 이미지 다이제스트)으로 정해졌는가
    registry: str  # 제공처(레지스트리 호스트, 소스 지정이면 그 호스트, 로컬이면 ``local``)

    def label(self) -> str:
        return f"{self.name} {self.version if self.version else '버전 미지정'}"


def _base(executable: str) -> str:
    name = (ntpath if "\\" in executable else posixpath).basename(executable).lower()
    return re.sub(r"\.(exe|cmd|bat)$", "", name)


def _flag_values(args: list[str], names: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """``names`` 옵션의 값들과, 그 옵션과 값을 뺀 나머지 인자를 돌려준다."""
    values, rest, skip = [], [], False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        head, eq, tail = arg.partition("=")
        if head in names:
            if eq:
                values.append(tail)
            elif i + 1 < len(args):
                values.append(args[i + 1])
                skip = True
            continue
        rest.append(arg)
    return values, rest


def _first_positional(args: list[str]) -> str | None:
    return next((a for a in args if not a.startswith("-")), None)


def _source_host(spec: str) -> str:
    if "://" in spec:
        url = spec.split("+", 1)[-1] if spec.startswith("git+") else spec
        return urlsplit(url).hostname or "source"
    return spec.split(":", 1)[0].lower()


def _npm(spec: str, registry: str) -> Package:
    if _SOURCE.match(spec):
        base, _, ref = spec.partition("#")
        return Package("npm", base, ref or None, bool(_COMMIT.fullmatch(ref)), _source_host(spec))
    at = spec.find("@", 1)
    name, version = (spec, None) if at < 0 else (spec[:at], spec[at + 1:] or None)
    return Package("npm", name, version, bool(version and _SEMVER.fullmatch(version)), registry)


def _pypi(spec: str, registry: str) -> Package:
    if _SOURCE.match(spec):
        return Package("pypi", spec, None, False, _source_host(spec))
    match = _PY_SPEC.fullmatch(spec.strip())
    if not match:
        return Package("pypi", spec, None, False, registry)
    name, op, exact, at, other = match.groups()
    version = exact if op else at or other or None
    pinned = bool((op or at) and version and "*" not in version and _PYVER.fullmatch(version))
    return Package("pypi", name, version, pinned, registry)


def _npm_packages(args: list[str]) -> list[Package]:
    registries, args = _flag_values(args, ("--registry",))
    registry = urlsplit(registries[0]).hostname if registries else NPM_REGISTRY
    specs, args = _flag_values(args, ("-p", "--package"))
    if not specs:
        # 명령이 실행할 패키지 하나(첫 위치 인자)
        first = _first_positional(args)
        specs = [first] if first else []
    return [_npm(s, registry or NPM_REGISTRY) for s in specs]


def _pypi_packages(args: list[str], from_flags: tuple[str, ...]) -> list[Package]:
    indexes, args = _flag_values(args, ("--index-url", "--index", "-i", "--default-index"))
    registry = (urlsplit(indexes[0]).hostname if indexes else None) or PYPI_REGISTRY
    specs, args = _flag_values(args, from_flags)
    _, args = _flag_values(args, ("--with", "--python", "--with-requirements"))
    if not specs:
        first = _first_positional(args)
        specs = [first] if first else []
    return [_pypi(s, registry) for s in specs]


def _container(args: list[str]) -> list[Package]:
    rest = args[1:] if args and args[0] == "run" else args[2:]  # ``container run``
    image = None
    skip = False
    for arg in rest:
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = "=" not in arg and arg in _DOCKER_VALUE_FLAGS
        else:
            image = arg
            break
    if image is None:
        return []
    ref, _, digest = image.partition("@")
    tail = ref.rsplit("/", 1)[-1]
    tag = tail.split(":", 1)[1] if ":" in tail else None
    name = ref[: -(len(tag) + 1)] if tag else ref
    first = name.split("/", 1)[0]
    explicit = "/" in name and ("." in first or ":" in first or first == "localhost")
    version = digest or tag
    return [
        Package(
            "container",
            name,
            version,
            bool(digest) or (tag is not None and tag != "latest"),
            first if explicit else DOCKER_REGISTRY,
        )
    ]


def extract(contract: dict[str, Any]) -> list[Package]:
    """실행 계약 문서(``ExecContract.document()``)에서 패키지 목록을 만든다. 중복은 한 번만 낸다."""
    exe = _base(contract.get("executable") or "")
    argv = list(contract.get("argv") or ())
    found: list[Package] = []
    if exe in ("npx", "bunx"):
        found = _npm_packages(argv)
    elif exe in ("npm", "pnpm", "yarn", "bun") and argv and argv[0] in ("exec", "x", "dlx"):
        found = _npm_packages(argv[1:])
    elif exe == "uvx":
        found = _pypi_packages(argv, ("--from",))
    elif exe == "pipx" and argv[:1] == ["run"]:
        found = _pypi_packages(argv[1:], ("--spec",))
    elif exe == "uv" and argv[:2] == ["tool", "run"]:
        found = _pypi_packages(argv[2:], ("--from",))
    elif exe.startswith("python") and "-m" in argv and argv.index("-m") + 1 < len(argv):
        found = [Package("pypi", argv[argv.index("-m") + 1], None, False, "local")]
    elif exe in ("docker", "podman") and (argv[:1] == ["run"] or argv[:2] == ["container", "run"]):
        found = _container(argv)
    found.append(
        Package(
            "executable",
            contract.get("executable") or "",
            contract.get("executable_sha256"),
            True,
            "local",
        )
    )
    return list(dict.fromkeys(found))


def unpinned(packages: list[Package]) -> list[Package]:
    return [p for p in packages if not p.pinned and p.ecosystem != "executable"]


def changes(approved: dict[str, Any], reported: dict[str, Any]) -> list[str]:
    """두 계약 사이 패키지 변화를 한국어 문장으로 낸다(같으면 빈 목록)."""
    old = {(p.ecosystem, p.name): p for p in extract(approved)}
    new = {(p.ecosystem, p.name): p for p in extract(reported)}
    out = []
    for key, p in new.items():
        before = old.get(key)
        if p.ecosystem == "executable":
            if before and before.version != p.version:
                out.append("실행 파일 내용 변경")
        elif before is None:
            out.append(f"새 패키지 {p.name} {p.version or '버전 미지정'}({p.registry})")
        elif (before.version, before.registry) != (p.version, p.registry):
            out.append(
                f"패키지 {p.name} {before.version or '버전 미지정'} → {p.version or '버전 미지정'}"
            )
    out += [f"패키지 제외 {k[1]}" for k in old if k not in new]
    return out
