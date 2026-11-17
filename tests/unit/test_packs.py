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

    def download(self, requirement, destination, python):
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

    def test_index_denied(self):
        with self.assertRaisesRegex(packs.PackError, "PACK_INDEX_NOT_ALLOWED"):
            packs.build_pack(self.spec, [], packs_dir=self.temp.name)


if __name__ == "__main__":
    unittest.main()
