"""PyPI wheel을 검증하고 내용 주소로 저장한다."""

import configparser
import hashlib
import json
import os
import re
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


def _download(requirement: str, destination: Path, python: str) -> None:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("PIP_")}
    env["PIP_CONFIG_FILE"] = os.devnull
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
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
            requirement,
            "-d",
            str(destination),
        ],
        check=True,
        env=env,
        capture_output=True,
        timeout=300,
    )


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


def build_pack(
    spec: dict,
    allowlists: list[dict],
    *,
    python: str = "3.12",
    packs_dir: str | Path | None = None,
    download=None,
    metadata=None,
) -> tuple[str, dict]:
    """네트워크 경계는 시험에서 download와 metadata로 대체할 수 있다."""
    hosts = {
        item.get("value", "").lower() for item in allowlists if item.get("kind") == "egress_target"
    }
    if spec.get("index") != "pypi" or not {"pypi.org", "files.pythonhosted.org"} <= hosts:
        raise PackError("PACK_INDEX_NOT_ALLOWED")
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
    with tempfile.TemporaryDirectory(dir=root, prefix=".pack-") as temp:
        stage = Path(temp)
        try:
            download(requirement, stage, python)
        except (OSError, subprocess.SubprocessError):
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
                "index": "pypi",
                "name": name,
                "version": version,
                "extras": sorted(extras),
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
        try:
            stage.rename(root / digest)
        except FileExistsError:
            pass
        return digest, manifest
