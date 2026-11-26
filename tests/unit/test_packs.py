import hashlib
import json
import re
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mint_litellm.control import packs


class PackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.spec = {
            "index": "pypi",
            "name": "example",
            "version": "1.0",
            "extras": [],
            "command": "example",
            "argv": [],
        }
        self.allow = [
            {"kind": "egress_target", "value": host}
            for host in ("pypi.org", "files.pythonhosted.org")
        ]
        self.digest = ""

    def download(self, requirement, destination, python, before=None):
        wheel = destination / "example-1.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as z:
            z.writestr(
                "example-1.0.dist-info/entry_points.txt", "[console_scripts]\nexample = pkg:main\n"
            )
        self.digest = hashlib.sha256(wheel.read_bytes()).hexdigest()

    def metadata(self, name, version):
        return {
            "urls": [
                {"filename": "example-1.0-py3-none-any.whl", "digests": {"sha256": self.digest}}
            ]
        }

    def build(self, **kwargs):
        return packs.build_pack(
            self.spec,
            self.allow,
            packs_dir=self.temp.name,
            download=kwargs.get("download", self.download),
            metadata=kwargs.get("metadata", self.metadata),
        )

    def test_success(self):
        digest, manifest = self.build()
        raw = (Path(self.temp.name) / digest / "manifest.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        self.assertEqual(json.loads(raw), manifest)
        self.assertEqual(manifest["entry"], "pkg:main")

    def test_building_the_same_pack_again_reuses_it(self):
        # 재검사는 같은 묶음을 다시 만든다. 실패하지 않고 임시 폴더도 남지 않는다.
        first, _ = self.build()
        second, _ = self.build()
        self.assertEqual(first, second)
        self.assertEqual(sorted(p.name for p in Path(self.temp.name).iterdir()), [first])

    def test_digest_mismatch(self):
        with self.assertRaisesRegex(packs.PackError, "PACK_DIGEST_MISMATCH"):
            self.build(
                metadata=lambda *_: {
                    "urls": [
                        {
                            "filename": "example-1.0-py3-none-any.whl",
                            "digests": {"sha256": "0" * 64},
                        }
                    ]
                }
            )

    def test_missing_entry(self):
        self.spec["command"] = "other"
        with self.assertRaisesRegex(packs.PackError, "PACK_ENTRY_NOT_FOUND"):
            self.build()

    def test_sdist_only(self):
        def failure(*args):
            raise subprocess.CalledProcessError(1, "pip")

        with self.assertRaisesRegex(packs.PackError, "PACK_SDIST_ONLY"):
            self.build(
                download=failure, metadata=lambda *_: {"urls": [{"filename": "example.tar.gz"}]}
            )

    def test_size_limit(self):
        with (
            patch.object(packs, "MAX_BYTES", 1),
            self.assertRaisesRegex(packs.PackError, "PACK_TOO_LARGE"),
        ):
            self.build()

    def test_direct_url_dependency(self):
        def download(requirement, destination, python, before=None):
            self.download(requirement, destination, python)
            with zipfile.ZipFile(destination / "example-1.0-py3-none-any.whl", "a") as z:
                z.writestr(
                    "example-1.0.dist-info/METADATA",
                    "Name: example\nRequires-Dist: dep @ https://host.example/dep.whl\n",
                )

        with self.assertRaisesRegex(packs.PackError, "PACK_DIRECT_URL"):
            self.build(download=download)

    def test_marker_alone_is_not_direct_url(self):
        def download(requirement, destination, python, before=None):
            self.download(requirement, destination, python)
            with zipfile.ZipFile(destination / "example-1.0-py3-none-any.whl", "a") as z:
                z.writestr(
                    "example-1.0.dist-info/METADATA",
                    "Name: example\nRequires-Dist: dep>=1; python_version < '3.9'\n",
                )
            self.digest = hashlib.sha256(
                (destination / "example-1.0-py3-none-any.whl").read_bytes()
            ).hexdigest()

        self.assertTrue(self.build(download=download)[0])

    def test_dependencies_are_resolved_as_of_the_pinned_release_time(self):
        seen = []

        def download(requirement, destination, python, before=None):
            seen.append(before)
            self.download(requirement, destination, python)

        def metadata(name, version):
            return {"urls": [{
                "filename": "example-1.0-py3-none-any.whl", "digests": {"sha256": self.digest},
                "upload_time_iso_8601": "2025-04-07T09:11:05.096297Z",
            }]}

        self.build(download=download, metadata=metadata)
        self.assertEqual(seen, ["2025-04-07T09:11:05.096297Z"])

    def test_index_denied(self):
        with self.assertRaisesRegex(packs.PackError, "PACK_INDEX_NOT_ALLOWED"):
            packs.build_pack(self.spec, [], packs_dir=self.temp.name)

def _wheel(directory, name, requires=()):
    path = directory / f"{name}-1.0-py3-none-any.whl"
    lines = ["Metadata-Version: 2.1", f"Name: {name}", "Version: 1.0",
             *(f"Requires-Dist: {r}" for r in requires)]
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{name}-1.0.dist-info/METADATA", "\n".join(lines) + "\n")
        z.writestr(f"{name}-1.0.dist-info/entry_points.txt",
                   "[console_scripts]
example = pkg:main
")
    return path


class WindowsClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_a_windows_only_requirement_is_downloaded_and_a_linux_only_one_is_not(self):
        asked = []

        def download(requirement, destination, python, before=None):
            asked.append((requirement, before))
            if requirement.startswith("example"):
                _wheel(destination, "example", [
                    "mcp>=1", "pywin32>=300; sys_platform == 'win32'",
                    "uvloop; sys_platform != 'win32'", "extra-only; extra == 'cli'"])
            elif requirement.startswith("pywin32"):
                _wheel(destination, "pywin32", ["winhelper; platform_system == 'Windows'"])
            else:
                _wheel(destination, re.split("[>=]", requirement)[0].replace("-", "_"))

        stage = Path(self.temp.name)
        download("example==1.0", stage, "3.12", "T")
        packs._windows_closure(stage, [], "example", "3.12", "T", download)
        self.assertEqual(sorted(p.name.split("-")[0] for p in stage.glob("*.whl")),
                         ["example", "mcp", "pywin32", "winhelper"])
        self.assertTrue(all(before == "T" for _, before in asked))
        joined = " ".join(r for r, _ in asked)
        self.assertNotIn("uvloop", joined)
        self.assertNotIn("extra-only", joined)

    def test_the_windows_manifest_records_the_closure_version(self):
        digests = {}

        def download(requirement, destination, python, before=None):
            if requirement.startswith("example"):
                path = _wheel(destination, "example", ["pywin32; sys_platform == 'win32'"])
            else:
                path = _wheel(destination, "pywin32")
            digests[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()

        def metadata(name, version):
            return {"urls": [{"filename": f, "digests": {"sha256": d}}
                             for f, d in digests.items()]}

        spec = {"index": "pypi", "name": "example", "version": "1.0", "extras": [],
                "command": "example", "argv": []}
        allow = [{"kind": "egress_target", "value": h}
                 for h in ("pypi.org", "files.pythonhosted.org")]
        digest, manifest = packs.build_pack(spec, allow, packs_dir=self.temp.name,
                                            download=download, metadata=metadata, windows=True)
        self.assertEqual(sorted(f["name"].split("-")[0] for f in manifest["files"]),
                         ["example", "pywin32"])
        self.assertEqual(manifest["platform"]["closure"], packs.WINDOWS_CLOSURE)
        self.assertTrue(packs.windows_current(digest, self.temp.name))
        old = Path(self.temp.name) / ("0" * 64)
        old.mkdir()
        (old / "manifest.json").write_text(
            json.dumps({"platform": {"os": "windows", "python": "3.12"}}))
        self.assertFalse(packs.windows_current("0" * 64, self.temp.name))
        self.assertTrue(packs.windows_current("f" * 64, self.temp.name))  # 읽을 수 없으면 그대로
