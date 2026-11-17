import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mint_litellm.control import inspection

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "inspector" / "inspect.py"
spec = importlib.util.spec_from_file_location("mint_inspector", SCRIPT)
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


class InspectionTests(unittest.TestCase):
    def test_rejects_escaping_wheel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "test.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("../escape", "bad")
            with self.assertRaises(ValueError):
                inspector._extract(wheel, root / "files")
            self.assertFalse((root / "escape").exists())

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wheel = root / "test.whl"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(info, "target")
            with self.assertRaises(ValueError):
                inspector._extract(wheel, root / "files")

    def test_timeout_creates_atomic_request(self):
        with tempfile.TemporaryDirectory() as directory:
            result = inspection.inspect_pack(
                "a" * 64, "pkg:main", [], directory=directory, timeout=0
            )
            self.assertEqual(result["status"], "incomplete")
            requests = list(Path(directory).glob("*/request.json"))
            self.assertEqual(len(requests), 1)
            self.assertEqual(json.loads(requests[0].read_text())["entry"], "pkg:main")
            self.assertFalse(list(Path(directory).glob("*/request.tmp")))

    def test_matching_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def deliver(_):
                request = next(root.glob("*/request.json"))
                request.with_name("result.json").write_text(
                    json.dumps({"pack_sha256": "a" * 64, "status": "ok", "complete": True})
                )

            with patch.object(inspection.time, "sleep", side_effect=deliver):
                result = inspection.inspect_pack("a" * 64, "pkg:main", [], directory=root)
            self.assertEqual(result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
