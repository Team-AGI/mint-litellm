"""최적화 이전의 지시문 표지 검사 구현(동일성 비교용 기준). 동작을 바꾸지 말 것."""

import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

from legacy_sensitive_scan import safe_key

# 한 번에 정규화·검사하는 조각 크기와 이웃 조각의 겹침(가장 긴 표지 일치는 수십 글자).
CHUNK_CHARS = 256 * 1024
OVERLAP_CHARS = 1024
# 결과 한 건에서 훑는 글자 수의 기본 상한. 넘으면 호출한 쪽이 막거나 기록한다.
DEFAULT_MAX_SCAN_CHARS = 32 * 1024 * 1024

_FLAGS = re.IGNORECASE
_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?:ignore|disregard|forget|override)\s{1,3}(?:all\s|any\s|the\s|your\s|my\s){0,3}"
            r"(?:previous|prior|above|earlier|preceding)\s{1,3}"
            r"(?:instructions?|prompts?|rules?|directions?|context)",
            _FLAGS,
        ),
    ),
    (
        "instruction_override",
        re.compile(r"(?:이전|위의?|앞선|기존)\s{0,3}(?:지시|명령|지침|규칙)\S{0,3}\s{0,3}무시"),
    ),
    (
        "role_marker",
        re.compile(
            r"<\|?(?:im_start|system|assistant)\|?>|\[/?(?:INST|SYS)\]|<<SYS>>"
            r"|(?:^|\n)\s{0,8}(?:system|assistant)\s{0,3}:",
            _FLAGS,
        ),
    ),
    (
        "role_marker",
        re.compile(r"시스템\s{0,3}프롬프트|(?:^|\n)\s{0,8}(?:시스템|어시스턴트)\s{0,3}:"),
    ),
    (
        "concealment",
        re.compile(
            r"(?:do\s{1,3}not|don'?t|never)\s{1,3}(?:tell|inform|mention|reveal|show)\s{1,3}"
            r"(?:this\s{1,3}to\s{1,3})?(?:the\s{1,3})?user",
            _FLAGS,
        ),
    ),
    (
        "concealment",
        re.compile(
            r"사용자(?:에게|한테)\s{0,3}(?:알리지|말하지|보여주지|공개하지)\s{0,3}(?:마|말)"
        ),
    ),
)


def _chunks(text: str, size: int, overlap: int) -> Iterable[str]:
    """겹치는 조각. 첫 조각이 아니면 ``x``를 앞에 붙여 줄 처음으로 오인되지 않게 한다."""
    start = 0
    while True:
        yield text[start : start + size] if start == 0 else "x" + text[start : start + size]
        if start + size >= len(text):
            return
        start += size - overlap


def scan_instructions(
    texts: Iterable[str],
    max_chars: int = DEFAULT_MAX_SCAN_CHARS,
    *,
    chunk_chars: int = CHUNK_CHARS,
    overlap_chars: int = OVERLAP_CHARS,
) -> tuple[str, ...]:
    """걸린 지시문 표지의 종류를 정렬해 돌려준다.

    종류는 ``instruction_override``·``role_marker``·``concealment``이다. ``max_chars``를 넘는
    뒷부분은 보지 않는다.
    """
    found: set[str] = set()
    budget = max_chars
    for text in texts:
        if budget <= 0:
            break
        text = text[:budget]
        budget -= len(text)
        for part in _chunks(text, chunk_chars, overlap_chars):
            # 전각 문자나 호환 문자로 표지를 피하지 못하게 한다.
            normalized = unicodedata.normalize("NFKC", part)
            found.update(kind for kind, pattern in _MARKERS if pattern.search(normalized))
    return tuple(sorted(found))


_MAX_DEPTH = 20


def walk_structured(
    root: Any, max_chars: int = DEFAULT_MAX_SCAN_CHARS, *, depth: int = _MAX_DEPTH
) -> tuple[list[tuple[str, str]], bool]:
    """구조화된 결과의 문자열 값과 키를 ``(JSON 경로, 문자열)``로 모은다.

    키도 값과 같은 경로로 모은다. 경로에는 짧은 식별자 키만 그대로 적고, 그 밖의 키(비밀로
    보이는 것 포함)는 ``[key#순번]``으로 적어 경로가 비밀을 싣지 않게 한다. 글자 수가
    ``max_chars``를 넘거나 ``depth``보다 깊은 부분은 보지 않고 둘째 값(잘림)을 참으로 돌려준다.
    """
    items: list[tuple[str, str]] = []
    stack: list[tuple[str, Any, int]] = [("$", root, 0)]
    budget, truncated = max_chars, False
    while stack:
        path, node, level = stack.pop()
        if isinstance(node, str):
            if len(node) > budget:
                items.append((path, node[:budget]))
                return items, True
            items.append((path, node))
            budget -= len(node)
        elif isinstance(node, Mapping | list | tuple):
            if level >= depth:
                truncated = True
            elif isinstance(node, Mapping):
                children = []
                for n, (key, child) in enumerate(node.items()):
                    key = str(key)
                    sub = f"{path}.{key}" if len(key) < 16 or safe_key(key) else f"{path}[key#{n}]"
                    if len(key) > budget:
                        return items, True
                    budget -= len(key)
                    items.append((sub, key))
                    children.append((sub, child, level + 1))
                stack += reversed(children)
            else:
                stack += reversed([(f"{path}[{n}]", c, level + 1) for n, c in enumerate(node)])
    return items, truncated
