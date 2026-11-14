"""도구 결과 본문에서 지시문 표지를 찾는다.

결과에 심은 지시를 사용자 명령으로 처리하지 않으려는 휴리스틱 검사이며, 탐지를 완전히 보장하지
않는다. 정규식은 모두 반복 횟수를 제한해 결과 길이에 곱으로 늘지 않게 한다. 긴 본문은
서로 겹치는 조각으로 나눠 끝까지 훑는다(겹침이 가장 긴 표지 일치보다 길어서 조각 경계에 걸친
표지도 잡는다). 훑는 글자 수는 합쳐서 ``max_chars``까지이고,
넘는 부분은 보지 않으므로 호출한 쪽이 넘었는지를 따로 판단한다.
"""

import re
import unicodedata
from collections.abc import Iterable, Mapping
from itertools import islice
from typing import Any

from mint_litellm.plugin.policy.sensitive_scan import safe_key

# 한 번에 정규화·검사하는 조각 크기와 이웃 조각의 겹침(가장 긴 표지 일치는 수십 글자).
CHUNK_CHARS = 256 * 1024
OVERLAP_CHARS = 1024
# 결과 한 건에서 훑는 글자 수의 기본 상한. 넘으면 호출한 쪽이 막거나 기록한다.
DEFAULT_MAX_SCAN_CHARS = 32 * 1024 * 1024

# 표지마다 (종류, 정규식, 일치에 반드시 들어 있는 앞부분의 정규식, 앞부분을 소문자 본문에서 찾는가).
# 긴 본문은 대소문자 무시 정규식으로 전체를 훑지 않고, 앞부분이 나온 자리 둘레만 본다.
_FLAGS = re.IGNORECASE
_OVERRIDE_OBJECT = r"\s{1,3}(?:all|any|the|your|my|previous|prior|above|earlier|preceding)"
_CONCEAL_VERB = r"\s{1,3}(?:tell|inform|mention|reveal|show)"
_MARKERS: tuple[tuple[str, re.Pattern[str], tuple[re.Pattern[str], ...], bool], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?:ignore|disregard|forget|override)\s{1,3}(?:all\s|any\s|the\s|your\s|my\s){0,3}"
            r"(?:previous|prior|above|earlier|preceding)\s{1,3}"
            r"(?:instructions?|prompts?|rules?|directions?|context)",
            _FLAGS,
        ),
        tuple(
            re.compile(verb + _OVERRIDE_OBJECT)
            for verb in ("ignore", "disregard", "forget", "override")
        ),
        True,
    ),
    (
        "instruction_override",
        re.compile(r"(?:이전|위의?|앞선|기존)\s{0,3}(?:지시|명령|지침|규칙)\S{0,3}\s{0,3}무시"),
        (re.compile("무시"),),
        False,
    ),
    (
        "role_marker",
        re.compile(
            r"<\|?(?:im_start|system|assistant)\|?>|\[/?(?:INST|SYS)\]|<<SYS>>"
            r"|(?:^|\n)\s{0,8}(?:system|assistant)\s{0,3}:",
            _FLAGS,
        ),
        tuple(
            re.compile(anchor)
            for anchor in (
                r"<\|?im_start",
                r"<\|?system\|?>",
                r"<\|?assistant\|?>",
                r"\[/?inst\]",
                r"\[/?sys\]",
                "<<sys>>",
                r"system\s{0,3}:",
                r"assistant\s{0,3}:",
            )
        ),
        True,
    ),
    (
        "role_marker",
        re.compile(r"시스템\s{0,3}프롬프트|(?:^|\n)\s{0,8}(?:시스템|어시스턴트)\s{0,3}:"),
        tuple(
            re.compile(anchor)
            for anchor in (r"시스템\s{0,3}프롬프트", r"시스템\s{0,3}:", r"어시스턴트\s{0,3}:")
        ),
        False,
    ),
    (
        "concealment",
        re.compile(
            r"(?:do\s{1,3}not|don'?t|never)\s{1,3}(?:tell|inform|mention|reveal|show)\s{1,3}"
            r"(?:this\s{1,3}to\s{1,3})?(?:the\s{1,3})?user",
            _FLAGS,
        ),
        tuple(re.compile(anchor + _CONCEAL_VERB) for anchor in ("not", r"don'?t", "never")),
        True,
    ),
    (
        "concealment",
        re.compile(
            r"사용자(?:에게|한테)\s{0,3}(?:알리지|말하지|보여주지|공개하지)\s{0,3}(?:마|말)"
        ),
        (re.compile("사용자(?:에게|한테)"),),
        False,
    ),
)

# 앞부분이 나온 자리에서 일치가 앞뒤로 뻗을 수 있는 가장 긴 길이보다 넉넉하게 잡은 구간.
_BEFORE, _AFTER = 24, 96
# 앞부분이 이보다 많이 나오면 자리마다 보는 것보다 전체를 훑는 편이 싸다.
_MAX_ANCHORS = 20000
# 이보다 짧은 조각은 바로 정규식으로 본다.
_ANCHOR_MIN = 4096


def _chunks(text: str, size: int, overlap: int) -> Iterable[str]:
    """겹치는 조각. 첫 조각이 아니면 ``x``를 앞에 붙여 줄 처음으로 오인되지 않게 한다."""
    start = 0
    while True:
        yield text[start : start + size] if start == 0 else "x" + text[start : start + size]
        if start + size >= len(text):
            return
        start += size - overlap


def _found_in(part: str) -> set[str]:
    """정규화한 본문 한 조각에 걸린 표지 종류."""
    if len(part) < _ANCHOR_MIN:
        return {kind for kind, pattern, _, _ in _MARKERS if pattern.search(part)}
    ascii_only = part.isascii()
    low = part.lower()
    # ``ı``·``İ``는 대소문자 무시 일치에서 ``i``와 같게 보이지만 소문자로 바꾸면 자리가 어긋난다.
    # 그런 조각은 전체를 훑는다.
    exact = ascii_only or (len(low) == len(part) and "ı" not in part and "İ" not in part)
    found: set[str] = set()
    for kind, pattern, anchors, lowered in _MARKERS:
        if kind in found or (ascii_only and not lowered):  # 한글 표지는 영문·기호 본문에 없다
            continue
        if not exact:
            if pattern.search(part):
                found.add(kind)
            continue
        hay = low if lowered else part
        spots: list[int] = []
        for anchor in anchors:
            spots += [m.start() for m in islice(anchor.finditer(hay), _MAX_ANCHORS + 1)]
        if len(spots) > _MAX_ANCHORS:
            hit = pattern.search(part)
        else:
            hit = any(pattern.search(part, max(0, at - _BEFORE), at + _AFTER) for at in spots)
        if hit:
            found.add(kind)
    return found


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
        # 영문·숫자·기호만이면 정규화해도 그대로이고, 겹치는 조각으로 나눌 때 놓치는 일치가 없으므로
        # 통째로 한 번 본다.
        parts = [text] if text.isascii() else _chunks(text, chunk_chars, overlap_chars)
        for part in parts:
            # 전각 문자나 호환 문자로 표지를 피하지 못하게 한다.
            found |= _found_in(unicodedata.normalize("NFKC", part))
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
