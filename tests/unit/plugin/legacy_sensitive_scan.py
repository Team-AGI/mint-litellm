"""최적화 이전의 도구 결과 검사 구현(동일성 비교용 기준). 동작을 바꾸지 말 것."""

import math
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from datetime import date
from typing import Any

# 이 글자 수를 넘는 결과는 끝까지 볼 수 없으므로 탐지 종류 ``scan_limit``으로 따로 센다.
MAX_SCAN_CHARS = 4 * 1024 * 1024

SCAN_LIMIT = "scan_limit"

# 영문·숫자·밑줄·하이픈에 붙어 있지 않을 때만(UUID·해시 조각 제외). 한글 조사는 붙어 있어도 된다.
_B = r"(?a)(?<![\w-])"
_E = r"(?![\w-])"

_PRIVATE_KEY = re.compile(
    r"(?a)-----BEGIN [A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----\s{0,3}[A-Za-z0-9+/]{40,}"
    r"(?:[A-Za-z0-9+/=\s]{0,16384}?-----END [A-Z ]{0,20}PRIVATE KEY(?: BLOCK)?-----)?"
)
_AWS_KEY = re.compile(r"(?a)\b(?:AKIA|ASIA)[A-Z2-7]{16}\b")
_GOOGLE_KEY = re.compile(r"(?a)\bAIza[0-9A-Za-z_-]{35}\b")
_GITHUB_TOKEN = re.compile(r"(?a)\bgh[pousr]_[A-Za-z0-9]{36,255}\b")
_BEARER = re.compile(r"(?a)\bBearer\s{1,3}([A-Za-z0-9._~+/=-]{20,2048})", re.IGNORECASE)
_JWT = re.compile(r"(?a)\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}")
_RRN = re.compile(_B + r"(\d{6})(-?)([1-8]\d{6})" + _E)
_PHONE = re.compile(
    _B + r"(?:01[016789][-. ]?\d{3,4}[-. ]?\d{4}|(?:02|0[3-6][1-5]|070)[-. ]\d{3,4}[-. ]\d{4})" + _E
)
_EMAIL = re.compile(
    r"(?a)(?<![\w.+%-])[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,4}"
    r"\.[A-Za-z]{2,24})" + _E
)
_CARD = re.compile(
    _B + r"(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{1,7}|\d{4}[- ]\d{6}[- ]\d{5}|\d{15,16})" + _E
)

# 비밀처럼 보이는 긴 문자열(고엔트로피). 이어진 32~256자일 때만 보고, 더 긴 덩어리(이미지·인코딩한
# 파일)는 후보에서 뺀다. 16진수만으로 된 값(UUID·해시)과 이미지 base64는 비밀로 보지 않는다.
HIGH_ENTROPY = "high_entropy_token"
_TOKEN = re.compile(r"(?a)(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{32,256}={0,2}(?![A-Za-z0-9_+/=-])")
_HEX_ONLY = re.compile(r"[0-9a-fA-F-]+")
_IMAGE_MAGIC = ("iVBOR", "/9j/", "R0lGOD", "UklGR")
_MIN_ENTROPY = 4.0
_MIN_PART = 24
# 해시·식별자를 담는 필드 이름(구조화된 결과에서 이 이름의 값은 고엔트로피 검사에서 뺀다).
_HASH_FIELD = re.compile(
    r"(?:sha\d*|md5|hash|digest|checksum|etag|fingerprint|uuid|guid|commit|oid|integrity)(?:\[\d+\])*$",
    re.IGNORECASE,
)

# 문서·시험용으로 예약된 도메인과 공식 예시 키는 비밀·개인정보로 보지 않는다.
_RESERVED_MAIL = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|test|invalid|localhost|example)$", re.IGNORECASE
)
# 신용카드 발급사 식별 번호(붙여 쓴 15~16자리일 때만 확인)
_CARD_PREFIX = re.compile(r"4|5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720)|3[47]|35|6011|65|9")


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _rrn_ok(m: re.Match[str]) -> bool:
    head, dash, tail = m.group(1), m.group(2), m.group(3)
    century = 2000 if tail[0] in "3478" else 1900
    try:
        date(century + int(head[:2]), int(head[2:4]), int(head[4:6]))
    except ValueError:
        return False
    if dash:
        # 2020년 10월 이후 발급분은 검사 숫자가 맞지 않을 수 있어 하이픈 형식은 날짜만 본다.
        return True
    digits = head + tail
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    check = (11 - sum(int(d) * w for d, w in zip(digits, weights, strict=False)) % 11) % 10
    return check == int(digits[12])


def _card_ok(m: re.Match[str]) -> bool:
    raw = m.group(0)
    digits = re.sub(r"\D", "", raw)
    if not 13 <= len(digits) <= 19 or not _luhn(digits):
        return False
    return raw != digits or bool(_CARD_PREFIX.match(digits))


def _bearer_ok(m: re.Match[str]) -> bool:
    # "Bearer authentication"처럼 숫자가 없는 일반 단어와 자리표시자는 토큰으로 보지 않는다.
    return any(c.isdigit() for c in m.group(1))


def _entropy_ok(m: re.Match[str]) -> bool:
    token = m.group(0)
    if _HEX_ONLY.fullmatch(token) or token.startswith(_IMAGE_MAGIC):
        return False
    if m.string.endswith("base64,", 0, m.start()):
        return False
    # ``-``·``_``로 이어 붙인 식별자(경로·배포 이름·접두사 붙은 키)는 가장 긴 조각만 본다.
    part = max(re.split(r"[-_]", token.rstrip("=")), key=len)
    if len(part) < _MIN_PART or _HEX_ONLY.fullmatch(part):
        return False
    # 낱말을 이어 붙인 식별자(CamelCase)와 숫자만의 값은 숫자가 거의 없거나 글자가 없다.
    if sum(c.isdigit() for c in part) < 2 or not any(c.isalpha() for c in part):
        return False
    n = len(part)
    return -sum(c / n * math.log2(c / n) for c in Counter(part).values()) >= _MIN_ENTROPY


# (종류, 정규식, 추가 검증). 앞에 있는 종류가 겹침에서 이긴다.
_DETECTORS: tuple[tuple[str, re.Pattern[str], Callable[[re.Match[str]], bool] | None], ...] = (
    ("private_key", _PRIVATE_KEY, None),
    ("cloud_access_key", _AWS_KEY, lambda m: not m.group(0).endswith("EXAMPLE")),
    ("cloud_access_key", _GOOGLE_KEY, None),
    ("access_token", _GITHUB_TOKEN, None),
    ("jwt", _JWT, None),
    ("bearer_token", _BEARER, _bearer_ok),
    ("resident_registration_number", _RRN, _rrn_ok),
    ("card_number", _CARD, _card_ok),
    ("phone_number", _PHONE, None),
    ("email", _EMAIL, lambda m: not _RESERVED_MAIL.search(m.group(1))),
    (HIGH_ENTROPY, _TOKEN, _entropy_ok),
)


def _spans(text: str, entropy: bool = False) -> list[tuple[int, int, str]]:
    found = [
        (m.start(), m.end(), kind)
        for kind, pattern, check in _DETECTORS
        if entropy or kind != HIGH_ENTROPY
        for m in pattern.finditer(text)
        if check is None or check(m)
    ]
    # 겹치면 먼저 시작하는 것, 같으면 긴 것을 남긴다(Bearer 뒤의 JWT를 두 번 세지 않는다).
    found.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    kept: list[tuple[int, int, str]] = []
    for span in found:
        if not kept or span[0] >= kept[-1][1]:
            kept.append(span)
    return kept


def scan_sensitive(
    texts: Iterable[str], max_chars: int = MAX_SCAN_CHARS, *, entropy: bool = False
) -> dict[str, int]:
    """탐지 종류별 건수. 일치한 값은 돌려주지 않는다. ``entropy``는 고엔트로피 검사를 더한다."""
    counts: Counter[str] = Counter()
    budget = max_chars
    for text in texts:
        if len(text) > budget:
            counts[SCAN_LIMIT] += 1
            break
        budget -= len(text)
        counts.update(kind for _, _, kind in _spans(text, entropy))
    return dict(sorted(counts.items()))


_SAFE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,39}")


def locate_sensitive(items: Iterable[tuple[str, str]]) -> list[tuple[str, Counter[str]]]:
    """구조화된 결과의 ``(JSON 경로, 문자열)``을 고엔트로피 검사까지 더해 본다.

    걸린 경로마다 탐지 종류별 건수를 돌려준다(값은 돌려주지 않는다). 해시·식별자 필드의 값은
    고엔트로피 검사에서 뺀다.
    """
    found: list[tuple[str, Counter[str]]] = []
    for path, text in items:
        entropy = not _HASH_FIELD.search(path)
        kinds = Counter(kind for _, _, kind in _spans(text, entropy))
        if kinds:
            found.append((path, kinds))
    return found


def safe_key(key: str) -> bool:
    """JSON 경로에 그대로 적어도 되는 키인가(짧은 식별자이면서 비밀로 보이지 않는 것)."""
    return bool(_SAFE_KEY.fullmatch(key)) and not _spans(key, True)


def mask_text(text: str) -> str:
    """탐지된 값을 ``[MASKED:종류]``로 바꾼 본문. 고엔트로피 문자열은 가리지 않는다."""
    out, pos = [], 0
    for start, end, kind in _spans(text):
        out += [text[pos:start], f"[MASKED:{kind}]"]
        pos = end
    out.append(text[pos:])
    return "".join(out)


# 도구로 보내는 인자에서 막는 종류. 인증정보와 검증식이 맞는 식별번호만 본다. 이메일·전화번호는
# 수신자 같은 정상 입력이 많아 제외한다. 끝까지 볼 수 없는 인자(scan_limit)는 막는다.
# 알려진 형식의 비밀(키·토큰 패턴). 구조화된 결과에서 이것이 걸리면 가릴 수 없으므로 막는다.
SECRET_KINDS = frozenset({"private_key", "cloud_access_key", "access_token", "jwt", "bearer_token"})
INPUT_SECRET_KINDS = frozenset(
    {
        "private_key",
        "cloud_access_key",
        "access_token",
        "jwt",
        "bearer_token",
        "resident_registration_number",
        "card_number",
        SCAN_LIMIT,
    }
)
_MAX_ARGUMENT_DEPTH = 20


class _TooDeep(Exception):
    pass


def _argument_texts(value: Any) -> Iterable[str]:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > _MAX_ARGUMENT_DEPTH:
            raise _TooDeep
        if isinstance(item, str):
            yield item
        elif isinstance(item, Mapping):
            for key, child in item.items():
                stack += [(str(key), depth + 1), (child, depth + 1)]
        elif isinstance(item, list | tuple):
            stack += [(child, depth + 1) for child in item]
        elif item is not None:
            yield str(item)


def scan_arguments(arguments: Any) -> dict[str, int]:
    """호출 인자(키와 값)의 탐지 종류별 건수. 값은 돌려주지 않는다. 너무 깊으면 ``scan_limit``."""
    try:
        return scan_sensitive(_argument_texts(arguments))
    except _TooDeep:
        return {SCAN_LIMIT: 1}
