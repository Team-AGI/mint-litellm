"""도구 결과 본문에서 비밀과 개인정보를 찾아 가린다.

네트워크 호출 없이 정규식과 검증식(날짜·검사 숫자·Luhn)만 쓰며, 확신이 높은 형식만 잡는다.
정규식은 반복 횟수를 제한해 결과 길이에 곱으로 늘지 않게 한다. 일치한 값은 어디에도 남기지 않고
탐지 종류와 건수만 돌려준다. 변형(공백·분할·인코딩)한 값은 놓칠 수 있다.
"""

import re
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import date

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
)


def _spans(text: str) -> list[tuple[int, int, str]]:
    found = [
        (m.start(), m.end(), kind)
        for kind, pattern, check in _DETECTORS
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


def scan_sensitive(texts: Iterable[str]) -> dict[str, int]:
    """탐지 종류별 건수. 일치한 값은 돌려주지 않는다."""
    counts: Counter[str] = Counter()
    budget = MAX_SCAN_CHARS
    for text in texts:
        if len(text) > budget:
            counts[SCAN_LIMIT] += 1
            break
        budget -= len(text)
        counts.update(kind for _, _, kind in _spans(text))
    return dict(sorted(counts.items()))


def mask_text(text: str) -> str:
    """탐지된 값을 ``[MASKED:종류]``로 바꾼 본문."""
    if len(text) > MAX_SCAN_CHARS:
        return text
    out, pos = [], 0
    for start, end, kind in _spans(text):
        out += [text[pos:start], f"[MASKED:{kind}]"]
        pos = end
    out.append(text[pos:])
    return "".join(out)
