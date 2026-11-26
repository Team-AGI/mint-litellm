import hashlib
import json
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


if __name__ == "__main__":
    unittest.main()


def test_pip_runs_from_the_bundled_wheel_when_the_image_has_no_pip(tmp_path, monkeypatch):
    from mint_litellm.control import packs

    wheel = tmp_path / "pip.whl"
    monkeypatch.setenv("MINT_PIP_WHEEL", str(wheel))
    assert packs._pip()[1:] == ["-m", "pip"]  # 파일이 없으면 설치된 pip
    wheel.write_bytes(b"zip")
    assert packs._pip()[1:] == [str(wheel) + "/pip"]


class GitPackTests(unittest.TestCase):
    """저장소 커밋 출처: 커밋에서 wheel을 만들고 의존 라이브러리는 PyPI에서 받는다."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.allow = [{"kind": "egress_target", "value": h}
                      for h in ("pypi.org", "files.pythonhosted.org")]
        self.spec = {"index": "git", "name": "example", "version": "a" * 40, "extras": [],
                     "git": "https://github.com/org/example", "command": "example", "argv": []}
        self.allow += [{"kind": "egress_target", "value": h}
                       for h in ("github.com", "codeload.github.com")]
        self.urls = []

    def wheel(self, directory):
        with zipfile.ZipFile(directory / "example-1.0-py3-none-any.whl", "w") as z:
            z.writestr("example-1.0.dist-info/entry_points.txt",
                       "[console_scripts]\nexample = pkg:main\n")

    def pack(self, **kwargs):
        def build(url, directory):
            self.urls.append(url)
            self.wheel(directory)

        return packs.build_pack(
            self.spec, self.allow, packs_dir=self.temp.name, build=build,
            download=lambda *a: None, metadata=lambda *a: self.fail("PyPI 해시 조회 없음"))

    def test_the_commit_wheel_becomes_a_pack_without_a_pypi_digest(self):
        digest, manifest = self.pack()
        self.assertEqual(self.urls, [f"https://github.com/org/example/archive/{'a' * 40}.zip"])
        self.assertEqual(manifest["package"]["index"], "git")
        self.assertEqual(manifest["package"]["version"], "a" * 40)
        self.assertEqual(manifest["entry"], "pkg:main")
        self.assertEqual([f["name"] for f in manifest["files"]], ["example-1.0-py3-none-any.whl"])
        self.assertEqual(sorted(p.name for p in Path(self.temp.name).iterdir()), [digest])

    def test_an_unpinned_or_foreign_source_is_not_built(self):
        for change in ({"version": "main"}, {"git": "https://gitlab.com/org/example"}):
            self.spec = {**self.spec, **change}
            with self.assertRaisesRegex(packs.PackError, "PACK_INDEX_NOT_ALLOWED"):
                self.pack()
        self.assertEqual(self.urls, [])

    def test_github_hosts_must_be_allowed(self):
        self.allow = self.allow[:2]
        with self.assertRaisesRegex(packs.PackError, "PACK_INDEX_NOT_ALLOWED"):
            self.pack()


class WindowsPackTest(unittest.TestCase):
    """Windows 묶음: 같은 요구 사항·같은 시점으로 win_amd64 wheel을 받는다."""

    def run_pip(self, **kwargs):
        from unittest import mock

        with mock.patch.object(packs.subprocess, "run") as run:
            packs._download("example==1.0", Path("."), "3.12", "2026-01-01T00:00:00Z", **kwargs)
        return run.call_args.args[0]

    def test_the_windows_download_asks_for_win_amd64_with_the_same_pins(self):
        linux, windows = self.run_pip(), self.run_pip(windows=True)
        self.assertIn("manylinux2014_x86_64", linux)
        self.assertNotIn("win_amd64", linux)  # Linux 묶음은 그대로
        self.assertEqual(windows[windows.index("--platform") + 1], "win_amd64")
        self.assertNotIn("manylinux2014_x86_64", windows)
        for same in ("--only-binary=:all:", "--uploaded-prior-to", "2026-01-01T00:00:00Z",
                     "--python-version", "3.12", "--abi", "cp312", "example==1.0"):
            self.assertIn(same, windows)

    def test_the_windows_pack_is_its_own_content_addressed_pack(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        spec = {"index": "pypi", "name": "example", "version": "1.0", "extras": [],
                "command": "example", "argv": []}
        allow = [{"kind": "egress_target", "value": h}
                 for h in ("pypi.org", "files.pythonhosted.org")]
        wheels = []

        def download(requirement, destination, python, before=None):
            wheel = destination / "example-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as z:
                z.writestr("example-1.0.dist-info/entry_points.txt",
                           "[console_scripts]\nexample = pkg:main\n")
            wheels.append(hashlib.sha256(wheel.read_bytes()).hexdigest())

        def metadata(name, version):
            return {"urls": [{"filename": "example-1.0-py3-none-any.whl",
                              "digests": {"sha256": wheels[-1]}}]}

        built = [packs.build_pack(spec, allow, packs_dir=temp.name, download=download,
                                  metadata=metadata, windows=win) for win in (False, True)]
        (linux, linux_manifest), (windows, windows_manifest) = built
        self.assertNotEqual(linux, windows)
        self.assertEqual(linux_manifest["platform"]["os"], "linux")
        self.assertEqual(windows_manifest["platform"],
                         {"os": "windows", "arch": "amd64", "python": "3.12"})
        self.assertEqual(sorted(p.name for p in Path(temp.name).iterdir()),
                         sorted([linux, windows]))
