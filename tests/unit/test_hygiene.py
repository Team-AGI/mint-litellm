"""저장소에 내부 작업 흔적이 들어가지 않도록 텍스트 파일을 검사한다.

금지 문자열이 이 파일에 그대로 남지 않도록 유니코드 이스케이프와 조합으로 패턴을 만들고,
이 파일도 검사 대상에 포함한다.
"""

import re
from pathlib import Path

import pytest

import mint_litellm

ROOT = Path(mint_litellm.__file__).resolve().parents[2]
SUFFIXES = {".py", ".sql", ".md", ".toml", ".yml", ".yaml", ".txt", ".cfg", ".ini", ".json", ".sh"}
SKIP_DIRS = {
    ".git",
    ".venv",
    ".pyhome",
    ".uv-cache",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "tmp",
}


def _text(hex_utf8: str) -> str:
    return bytes.fromhex(hex_utf8).decode("utf-8")


SECTION_SIGN = chr(0xA7)
MEMO_WORDS = [
    _text("ec9dbceb8ba8"),
    _text("eb8298eca491ec9790"),
    "TO" + "DO",
    "FIX" + "ME",
    "X" * 3,
]
INTERNAL_DOCUMENTS = [
    _text("ec9c84ed82a4"),
    "wi" + "ki",
    _text("eca780ec8b9cec849c"),
    _text("ec84a4eab384ec849c"),
]

FORBIDDEN = {
    "section sign": re.compile(SECTION_SIGN),
    "decision or task id": re.compile(r"\b(?:DS|DL|V|P|N)-\d+[a-z]?\b"),
    "work memo words": re.compile("|".join(MEMO_WORDS)),
    "internal documents": re.compile("|".join(INTERNAL_DOCUMENTS), re.IGNORECASE),
    "dated trace": re.compile(r"\b20\d\d-\d\d-\d\d\b|\b1[01]/\d\d\b"),
    "ip address": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
}


# MCP 프로토콜 판본 문자열은 날짜 꼴이지만 작업 흔적이 아니다.
PROTOCOL_VERSIONS = re.compile(r"\b20(?:24-11-05|25-03-26|25-06-18|25-11-25|26-07-28)\b")


def repo_files():
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.is_file() and path.suffix in SUFFIXES:
            yield path


def test_this_file_is_scanned():
    assert Path(__file__).resolve() in {path.resolve() for path in repo_files()}


@pytest.mark.parametrize("label", sorted(FORBIDDEN))
def test_no_internal_traces(label):
    pattern = FORBIDDEN[label]
    hits = [
        f"{path.relative_to(ROOT)}:{n}"
        for path in repo_files()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(PROTOCOL_VERSIONS.sub("", line) if label == "dated trace" else line)
    ]
    assert not hits, hits


def test_patterns_catch_what_they_describe():
    assert FORBIDDEN["section sign"].search("see " + SECTION_SIGN + "5")
    assert FORBIDDEN["decision or task id"].search("see DS" + "-12")
    assert FORBIDDEN["work memo words"].search("TO" + "DO later")
    assert FORBIDDEN["internal documents"].search("the Wi" + "ki page")
    assert FORBIDDEN["dated trace"].search("on 2026" + "-01-02")
    assert FORBIDDEN["ip address"].search("host 10." + "0.0.1")
