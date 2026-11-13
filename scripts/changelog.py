"""변경 조각(changelog.d/*.md)을 CHANGELOG.md의 새 판본 절로 모으고 조각을 지운다.

사용: python scripts/changelog.py 1.2.3
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAGMENTS = ROOT / "changelog.d"


def fragment_files(directory: Path = FRAGMENTS) -> list[Path]:
    return sorted(p for p in directory.glob("*.md") if p.name != "README.md")


def assemble(directory: Path = FRAGMENTS) -> str:
    """조각을 파일 이름 순서로 이어 붙인 글머리 목록을 돌려준다."""
    return "".join(p.read_text(encoding="utf-8").strip() + "\n" for p in fragment_files(directory))


def release(
    version: str, changelog: Path = ROOT / "CHANGELOG.md", directory: Path = FRAGMENTS
) -> None:
    body = assemble(directory)
    if not body:
        raise SystemExit("모을 조각이 없습니다.")
    marker = "## [Unreleased]\n"
    text = changelog.read_text(encoding="utf-8")
    head, sep, rest = text.partition(marker)
    if not sep:
        raise SystemExit("CHANGELOG.md에 Unreleased 절이 없습니다.")
    changelog.write_text(f"{head}{marker}\n## [{version}]\n\n{body}{rest}", encoding="utf-8", newline="\n")
    for p in fragment_files(directory):
        p.unlink()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    release(sys.argv[1])
