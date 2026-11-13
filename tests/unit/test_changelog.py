"""변경 조각 모으기: 조각은 비지 않은 글머리 한 줄이고, 모으기는 이름 순서로 결정적이다."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "changelog_script", ROOT / "scripts" / "changelog.py"
)
changelog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(changelog)


def test_every_fragment_is_a_single_non_empty_bullet():
    files = changelog.fragment_files()
    assert files
    for p in files:
        lines = p.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1 and lines[0].startswith("- ") and lines[0][2:].strip(), p.name


def test_assembly_is_sorted_and_release_consumes_fragments(tmp_path):
    frag = tmp_path / "changelog.d"
    frag.mkdir()
    (frag / "b.md").write_text("- 둘\n", encoding="utf-8")
    (frag / "a.md").write_text("- 하나\n", encoding="utf-8")
    assert changelog.assemble(frag) == "- 하나\n- 둘\n" == changelog.assemble(frag)
    log = tmp_path / "CHANGELOG.md"
    log.write_text("# Changelog\n\n## [Unreleased]\n\n## [1.0.0]\n\n- 옛\n", encoding="utf-8")
    changelog.release("1.1.0", log, frag)
    assert log.read_text(encoding="utf-8") == (
        "# Changelog\n\n## [Unreleased]\n\n## [1.1.0]\n\n- 하나\n- 둘\n\n## [1.0.0]\n\n- 옛\n"
    )
    assert not list(frag.glob("*.md"))
