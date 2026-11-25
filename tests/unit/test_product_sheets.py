"""제품 기준 문서(docs/product)가 서로, 그리고 코드와 맞는지 확인한다."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_product_sheets_have_no_errors():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "product" / "check.py")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout[-3000:]
