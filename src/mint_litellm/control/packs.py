"""PyPI wheel을 검증하고 내용 주소로 저장한다."""

import configparser
import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

MAX_BYTES = 512 * 1024 * 1024
_NAME = re.compile(r"^[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")


class PackError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _metadata(name: str, version: str) -> dict:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        if response.geturl().split("/", 3)[2] != "pypi.org":
            raise ValueError("unexpected metadata host")
        return json.load(response)


# 이미지는 보안을 위해 pip를 지운다. 묶음 만들기만 설치하지 않은 pip wheel을 직접 실행한다.
PIP_WHEEL = "/opt/mint/pip.whl"


def _pip() -> list[str]:
    wheel = os.environ.get("MINT_PIP_WHEEL", PIP_WHEEL)
    if os.path.isfile(wheel):
        return [sys.executable, wheel + "/pip"]
    return [sys.executable, "-m", "pip"]


def _download(requirement: str, destination: Path, python: str, before: str | None = None) -> None:
    # 의존 라이브러리는 고정 판본이 나온 시점까지의 것으로 풀어, 이후에 나온 호환 안 되는 판본을
    # 피한다(pip 26.1 이상의 옵션).
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PIP_")}
    env["PIP_CONFIG_FILE"] = os.devnull
    subprocess.run(
        [
            *_pip(),
            "download",
            "--only-binary=:all:",
            "--index-url",
            "https://pypi.org/simple",
            "--platform",
            "manylinux2014_x86_64",
            "--platform",
            "manylinux_2_28_x86_64",
            "--python-version",
            python,
            "--implementation",
            "cp",
            "--abi",
            "cp" + python.replace(".", ""),
            "--no-cache-dir",
            "--disable-pip-version-check",
            *(["--uploaded-prior-to", before] if before else []),
            requirement,
            "-d",
            str(destination),
        ],
        check=True,
        env=env,
        capture_output=True,
        timeout=300,
    )


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_GIT_URL = re.compile(r"^https://github\.com/([A-Za-z0-9._-]{1,100})/([A-Za-z0-9._-]{1,100})$")


def _build_git(url: str, destination: Path) -> None:
    """고정된 커밋의 압축본을 pip로 wheel로 만든다(의존 라이브러리는 받지 않는다)."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PIP_")}
    env["PIP_CONFIG_FILE"] = os.devnull
    subprocess.run(
        [*_pip(), "wheel", "--no-deps", "--no-cache-dir", "--disable-pip-version-check",
         "--index-url", "https://pypi.org/simple", "-w", str(destination), url],
        check=True, env=env, capture_output=True, timeout=600,
    )


def _git_wheel(build, root: Path, repo, commit: str, download, stage: Path, python: str) -> str:
    """커밋을 wheel로 만들어 stage에 두고 의존 라이브러리를 받는다. 만든 wheel의 이름을 낸다."""
    scratch = Path(tempfile.mkdtemp(dir=root, prefix=".src-"))
    try:
        build(f"https://github.com/{repo.group(1)}/{repo.group(2)}/archive/{commit}.zip", scratch)
        found = sorted(scratch.glob("*.whl"))
        if len(found) != 1:
            raise PackError("PACK_RESOLVE_FAILED")
        download(str(found[0]), stage, python, None)
        if not (stage / found[0].name).exists():
            shutil.copy2(found[0], stage / found[0].name)
        return found[0].name
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _entry(wheels: list[Path], command: str, spec: dict) -> str:
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if name.endswith(".dist-info/entry_points.txt"):
                    parser = configparser.ConfigParser(interpolation=None)
                    parser.optionxform = str
                    parser.read_string(archive.read(name).decode("utf-8"))
                    if parser.has_option("console_scripts", command):
                        value = parser.get("console_scripts", command).split("[", 1)[0].strip()
                        if re.fullmatch(
                            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*",
                            value,
                        ):
                            return value
    argv = spec.get("argv", [])
    if command in ("python", "python3") and len(argv) >= 2 and argv[0] == "-m":
        module = argv[1]
        if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
            return module + ":__main__"
    raise PackError("PACK_ENTRY_NOT_FOUND")


def _direct_url(wheels: list[Path]) -> bool:
    """Requires-Dist에 `이름 @ 주소` 꼴(직접 URL)이 있는가."""
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                if name.endswith(".dist-info/METADATA") and name.count("/") == 1:
                    for line in archive.read(name).decode("utf-8", "replace").splitlines():
                        if line.startswith("Requires-Dist:") and (
                            "@" in line.split(";", 1)[0] or "://" in line.split(";", 1)[0]
                        ):
                            return True
    return False


def _released_at(name: str, version: str, metadata) -> str | None:
    """고정 판본이 올라온 가장 늦은 시각(ISO 8601). 알 수 없으면 None(제한 없이 푼다)."""
    try:
        times = [u["upload_time_iso_8601"] for u in metadata(name, version).get("urls", [])]
        return max(times) if times else None
    except Exception:
        return None


def build_pack(
    spec: dict,
    allowlists: list[dict],
    *,
    python: str = "3.12",
    packs_dir: str | Path | None = None,
    download=None,
    metadata=None,
    build=None,
) -> tuple[str, dict]:
    """네트워크 경계는 시험에서 download·metadata·build로 대체할 수 있다.

    ``index``가 ``git``이면 GitHub 저장소의 고정 커밋(40자)을 wheel로 만들고, 의존 라이브러리는
    PyPI에서 받는다.
    """
    hosts = {
        item.get("value", "").lower() for item in allowlists if item.get("kind") == "egress_target"
    }
    git = spec.get("index") == "git"
    needed = {"pypi.org", "files.pythonhosted.org"} | ({"github.com", "codeload.github.com"}
                                                       if git else set())
    if spec.get("index") not in ("pypi", "git") or not needed <= hosts:
        raise PackError("PACK_INDEX_NOT_ALLOWED")
    repo = _GIT_URL.fullmatch(str(spec.get("git", ""))) if git else None
    if git and (not repo or not _COMMIT.fullmatch(str(spec.get("version", "")))):
        raise PackError("PACK_INDEX_NOT_ALLOWED")  # 고정되지 않았거나 GitHub가 아닌 출처
    name, version, extras = spec.get("name"), spec.get("version"), spec.get("extras", [])
    if (
        not isinstance(name, str)
        or not _NAME.fullmatch(name)
        or not isinstance(version, str)
        or not _VERSION.fullmatch(version)
        or not isinstance(extras, list)
        or any(not isinstance(x, str) or not _NAME.fullmatch(x) for x in extras)
        or not re.fullmatch(r"3\.\d+", python)
    ):
        raise PackError("PACK_RESOLVE_FAILED")
    download, metadata = download or _download, metadata or _metadata
    root = Path(packs_dir or os.environ.get("MINT_PACKS_DIR", "/var/lib/mint/packs"))
    root.mkdir(parents=True, exist_ok=True)
    requirement = name + ("[" + ",".join(sorted(extras)) + "]" if extras else "") + "==" + version
    before = None if git else _released_at(name, version, metadata)
    built: str | None = None
    with tempfile.TemporaryDirectory(dir=root, prefix=".pack-") as temp:
        stage = Path(temp)
        try:
            if git:
                built = _git_wheel(build or _build_git, root, repo, version, download, stage,
                                   python)
            else:
                download(requirement, stage, python, before)
        except (OSError, subprocess.SubprocessError):
            if git:
                raise PackError("PACK_RESOLVE_FAILED") from None
            try:
                releases = metadata(name, version).get("urls", [])
                if releases and not any(
                    item.get("filename", "").endswith(".whl") for item in releases
                ):
                    raise PackError("PACK_SDIST_ONLY")
            except PackError:
                raise
            except Exception:
                pass
            raise PackError("PACK_RESOLVE_FAILED") from None
        wheels = sorted(stage.iterdir())
        if not wheels or any(
            not p.is_file() or p.is_symlink() or p.suffix != ".whl" for p in wheels
        ):
            raise PackError("PACK_RESOLVE_FAILED")
        try:
            if _direct_url(wheels):
                raise PackError("PACK_DIRECT_URL")
        except (zipfile.BadZipFile, UnicodeError):
            raise PackError("PACK_RESOLVE_FAILED") from None
        files, size = [], 0
        for wheel in wheels:
            parts = wheel.name.split("-")
            if len(parts) < 5 or not _NAME.fullmatch(parts[0]) or not _VERSION.fullmatch(parts[1]):
                raise PackError("PACK_RESOLVE_FAILED")
            size += wheel.stat().st_size
            if size > MAX_BYTES:
                raise PackError("PACK_TOO_LARGE")
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            if wheel.name == built:
                files.append({"name": wheel.name, "sha256": digest, "size": wheel.stat().st_size})
                continue  # 커밋에서 직접 만든 wheel은 저장소 쪽 해시가 없다(커밋 고정이 무결성)
            try:
                releases = metadata(parts[0], parts[1])["urls"]
                expected = next(
                    item["digests"]["sha256"] for item in releases if item["filename"] == wheel.name
                )
            except Exception:
                raise PackError("PACK_RESOLVE_FAILED") from None
            if digest != expected:
                raise PackError("PACK_DIGEST_MISMATCH")
            files.append({"name": wheel.name, "sha256": digest, "size": wheel.stat().st_size})
        try:
            entry = _entry(wheels, spec.get("command", ""), spec)
        except (zipfile.BadZipFile, UnicodeError, configparser.Error):
            raise PackError("PACK_RESOLVE_FAILED") from None
        manifest = {
            "schema": 1,
            "package": {
                "index": spec["index"],
                "name": name,
                "version": version,
                "extras": sorted(extras),
                **({"git": spec["git"]} if git else {}),
            },
            "platform": {"os": "linux", "arch": "x86_64", "glibc": "2.28", "python": python},
            "entry": entry,
            "files": files,
        }
        raw = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (stage / "manifest.json").write_bytes(raw)
        target = root / digest
        if (target / "manifest.json").is_file():
            # 같은 내용의 묶음이 이미 있다(재검사). Linux는 비어 있지 않은 폴더로의 이름 바꾸기를
            # FileExistsError가 아닌 OSError(ENOTEMPTY)로 거절하므로 먼저 확인한다.
            shutil.rmtree(stage, ignore_errors=True)
            return digest, manifest
        try:
            stage.rename(target)
        except OSError as exc:
            if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            shutil.rmtree(stage, ignore_errors=True)  # 동시에 만든 쪽이 먼저 옮겼다
        return digest, manifest
