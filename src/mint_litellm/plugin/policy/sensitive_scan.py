"""도구 결과 본문에서 비밀과 개인정보를 찾아 가린다.

네트워크 호출 없이 정규식과 검증식(날짜·검사 숫자·Luhn)만 쓰며, 확신이 높은 형식만 잡는다.
정규식은 반복 횟수를 제한해 결과 길이에 곱으로 늘지 않게 한다. 일치한 값은 어디에도 남기지 않고
탐지 종류와 건수만 돌려준다. 변형(공백·분할·인코딩)한 값은 놓칠 수 있다.
"""

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
# 앞 경계 검사를 첫 숫자 뒤로 옮긴 형태다. 같은 일치를 내고 숫자가 아닌 글자는 건너뛴다.
_RRN = re.compile(r"(?a)(\d(?<![\w-]\d)\d{5})(-?)([1-8]\d{6})" + _E)
# 앞 경계 검사를 첫 글자(0) 뒤로 옮긴 형태다. 같은 일치를 내고 0이 아닌 글자는 건너뛴다.
_PHONE = re.compile(
    r"(?a)0(?<![\w-]0)(?:1[016789][-. ]?\d{3,4}[-. ]?\d{4}"
    r"|(?:2|[3-6][1-5]|70)[-. ]\d{3,4}[-. ]\d{4})" + _E
)
_EMAIL = re.compile(
    r"(?a)(?<![\w.+%-])[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,4}"
    r"\.[A-Za-z]{2,24})" + _E
)
# 주민등록번호와 같이 앞 경계 검사를 첫 숫자 뒤로 옮겼다.
_CARD = re.compile(
    r"(?a)\d(?<![\w-]\d)(?:\d{3}[- ]\d{4}[- ]\d{4}[- ]\d{1,7}|\d{3}[- ]\d{6}[- ]\d{5}|\d{14,15})"
    + _E
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


# 두 배로 한 자리의 숫자 합(5→1, 6→3, …)
_LUHN_DOUBLE = str.maketrans("0123456789", "0246813579")


def _luhn(digits: str) -> bool:
    odd, even = digits[::-1][::2], digits[::-1][1::2]
    return (sum(map(int, odd)) + sum(map(int, even.translate(_LUHN_DOUBLE)))) % 10 == 0


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
    if raw.isdigit():  # 붙여 쓴 번호는 발급사 식별 번호를 먼저 본다(검사 숫자보다 싸다)
        return bool(_CARD_PREFIX.match(raw)) and 13 <= len(raw) <= 19 and _luhn(raw)
    digits = raw.replace("-", "").replace(" ", "")
    return 13 <= len(digits) <= 19 and _luhn(digits)


def _bearer_ok(m: re.Match[str]) -> bool:
    # "Bearer authentication"처럼 숫자가 없는 일반 단어와 자리표시자는 토큰으로 보지 않는다.
    return any(c.isdigit() for c in m.group(1))


_DIGITS_2 = re.compile(r"(?a)\d.*?\d")
_ALPHA = re.compile(r"[A-Za-z]")
_SPLIT = re.compile(r"[-_]")
# n글자에서 서로 다른 글자가 d개일 때 엔트로피가 가장 낮은 분포는 한 글자 n-d+1번, 나머지 한 번씩.
_CLOGC = [0.0] + [c * math.log2(c) for c in range(1, 258)]


def _token_ok(token: str) -> bool:
    if token.startswith(_IMAGE_MAGIC) or _HEX_ONLY.fullmatch(token):
        return False
    # ``-``·``_``로 이어 붙인 식별자(경로·배포 이름·접두사 붙은 키)는 가장 긴 조각만 본다.
    part = token.rstrip("=")
    if "-" in part or "_" in part:
        part = max(_SPLIT.split(part), key=len)
    n = len(part)
    if n < _MIN_PART or (n != len(token) and _HEX_ONLY.fullmatch(part)):
        return False
    # 낱말을 이어 붙인 식별자(CamelCase)와 숫자만의 값은 숫자가 거의 없거나 글자가 없다.
    if not _DIGITS_2.search(part) or not _ALPHA.search(part):
        return False
    distinct = len(set(part))
    if distinct < 16:  # d개 글자의 엔트로피는 log2(d)를 넘지 못한다
        return False
    # H = log2(n) - sum(c*log2(c))/n. 경계 근처만 원래 식으로 다시 계산한다.
    low = math.log2(n) - _CLOGC[n - distinct + 1] / n
    if low >= _MIN_ENTROPY + 1e-9:
        return True
    counts = Counter(part).values()
    entropy = math.log2(n) - sum(map(_CLOGC.__getitem__, counts)) / n
    if abs(entropy - _MIN_ENTROPY) > 1e-9:
        return entropy > _MIN_ENTROPY
    return -sum(c / n * math.log2(c / n) for c in counts) >= _MIN_ENTROPY


def _entropy_ok(m: re.Match[str]) -> bool:
    return not m.string.endswith("base64,", 0, m.start()) and _token_ok(m.group(0))


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


# 긴 본문은 탐지기마다 전체를 훑지 않는다. 일치하려면 반드시 들어 있어야 하는 짧은 글자(키 접두사·
# ``@``·숫자 덩어리)를 먼저 찾고, 없으면 그 탐지기를 건너뛰고, 몇 군데뿐이면 그 둘레만 본다.
# 짧은 본문은 바로 정규식으로 본다.
_FAST_MIN = 16 * 1024
_MAX_HITS = 64
_MAX_WINDOWS = 20000
_MAX_STARTS = 4096


def _mask_table(keep: str, sep: str = "") -> bytes:
    return bytes.maketrans(
        bytes(range(256)),
        bytes(
            ord("1") if chr(i) in keep else ord("s") if chr(i) in sep else ord("0")
            for i in range(256)
        ),
    )


# 글자마다 한 바이트가 되게 바꾼 뒤(자리가 그대로이다) 숫자는 1, 구분자는 s, 나머지는 0으로 둔다.
_DIGIT_MASK = _mask_table("0123456789", "- ")
_TOKEN_MASK = _mask_table("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_+/-")
_TOKEN_RUN = re.compile(rb"1{32,}")
# 일치 하나가 차지할 수 있는 길이(탐지기마다 덮는 범위: 앞, 뒤)
_EMAIL_SPAN = (66, 420)
_ID_SPAN = (26, 60)
_Regions = bool | list[tuple[int, int]] | tuple[int, ...]


def _merged(hits: list[int], before: int, after: int, end: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for hit in sorted(hits):
        start, stop = max(0, hit - before), min(end, hit + after)
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], stop))
        else:
            out.append((start, stop))
    return out


def _find_all(
    hay: str | bytes,
    needles: Iterable[str | bytes],
    limit: int = _MAX_HITS,
    *,
    overlapping: bool = False,
) -> list[int] | None:
    """바늘이 나오는 자리. 너무 많으면 ``None``(전체를 훑는다).

    ``overlapping``이 아니면 앞 자리와 겹치는 자리는 건너뛴다(둘레를 보는 쪽에서는 겹치는 자리가
    같은 구간에 든다).
    """
    hits: list[int] = []
    for needle in needles:
        step = 1 if overlapping else len(needle)
        at = hay.find(needle)
        while at >= 0:
            if len(hits) >= limit:
                return None
            hits.append(at)
            at = hay.find(needle, at + step)
    return sorted(hits)


def _around(hay: str | bytes, needles: tuple[str | bytes, ...], span: tuple[int, int], end: int):
    hits = _find_all(hay, needles, _MAX_WINDOWS)
    return True if hits is None else _merged(hits, span[0], span[1], end)


def _starting(hay: str | bytes, needles: tuple[str | bytes, ...]) -> _Regions:
    """일치가 이 글자로 시작하는 탐지기: 시작 자리 목록(없으면 건너뜀, 너무 많으면 전체)."""
    hits = _find_all(hay, needles, _MAX_STARTS, overlapping=True)
    return True if hits is None else tuple(hits)


def _token_regions(mask: bytes, end: int) -> _Regions:
    """토큰 글자만 이어진 32자 이상 덩어리와 그 뒤 ``=`` 자리까지의 구간."""
    needle, regions, at = b"1" * 32, [], 0
    while (at := mask.find(needle, at)) >= 0:
        if len(regions) >= _MAX_HITS:
            return True
        stop = _TOKEN_RUN.match(mask, at).end()
        regions.append((at, min(end, stop + 4)))
        at = stop
    return regions


def _plan(text: str, entropy: bool) -> dict[re.Pattern[str], _Regions]:
    """탐지기마다 전체(``True``)·건너뜀(``False``나 빈 목록)·훑을 구간·시작 자리 목록."""
    n = len(text)
    raw = text.encode("latin-1", "replace")
    digits = raw.translate(_DIGIT_MASK)
    plan: dict[re.Pattern[str], _Regions] = {
        _PRIVATE_KEY: _starting(text, ("-----BEGIN",)),
        _AWS_KEY: _starting(text, ("AKIA", "ASIA")),
        _GOOGLE_KEY: _starting(text, ("AIza",)),
        _GITHUB_TOKEN: _starting(text, tuple(f"gh{c}_" for c in "pousr")),
        _JWT: _starting(text, ("eyJ",)),
        _BEARER: _starting(raw.lower(), (b"bearer",)),
        _EMAIL: _around(text, ("@",), _EMAIL_SPAN, n),
        _RRN: _around(digits, (b"1" * 13, b"111111s1111111"), _ID_SPAN, n),
        _CARD: _around(digits, (b"1" * 15, b"1111s1111s1111s1", b"1111s111111s11111"), _ID_SPAN, n),
    }
    if entropy:
        plan[_TOKEN] = _token_regions(raw.translate(_TOKEN_MASK), n)
    return plan


def _matches(pattern: re.Pattern[str], text: str, regions: _Regions) -> Iterable[re.Match[str]]:
    if regions is True:
        yield from pattern.finditer(text)
    elif isinstance(regions, tuple):
        end = 0
        for start in regions:
            if start >= end and (m := pattern.match(text, start)):
                end = m.end()
                yield m
    elif regions:
        for start, stop in regions:
            yield from pattern.finditer(text, start, stop)


def _detect(
    text: str, plan: dict[re.Pattern[str], _Regions], entropy_only: bool
) -> list[tuple[int, int, str]]:
    return [
        (m.start(), m.end(), kind)
        for kind, pattern, check in _DETECTORS
        if (kind == HIGH_ENTROPY) == entropy_only
        for m in _matches(pattern, text, plan.get(pattern, True))
        if check is None or check(m)
    ]


def _resolve(found: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    # 겹치면 먼저 시작하는 것, 같으면 긴 것을 남긴다(Bearer 뒤의 JWT를 두 번 세지 않는다).
    found.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    kept: list[tuple[int, int, str]] = []
    for span in found:
        if not kept or span[0] >= kept[-1][1]:
            kept.append(span)
    return kept


def _spans(text: str, entropy: bool = False) -> list[tuple[int, int, str]]:
    plan = _plan(text, entropy) if len(text) >= _FAST_MIN else {}
    found = _detect(text, plan, False)
    if entropy:
        found += _detect(text, plan, True)
    return _resolve(found)


def _kinds(text: str, entropy: bool) -> Counter[str]:
    """``_spans``의 종류별 건수. 다른 탐지가 없으면 고엔트로피 후보의 위치를 모으지 않고 센다."""
    if len(text) < _FAST_MIN:
        return Counter(kind for _, _, kind in _spans(text, entropy))
    plan = _plan(text, entropy)
    found = _detect(text, plan, False)
    # 다른 탐지와 겹치는 후보와 ``base64,`` 바로 뒤의 값은 위치를 알아야 가려낸다.
    if not entropy or found or "base64," in text:
        if entropy:
            found += _detect(text, plan, True)
        return Counter(kind for _, _, kind in _resolve(found))
    regions = plan[_TOKEN]
    if regions is True:
        tokens = _TOKEN.findall(text)
    else:
        tokens = [t for start, stop in regions for t in _TOKEN.findall(text, start, stop)]
    count = sum(map(_token_ok, tokens))
    return Counter({HIGH_ENTROPY: count}) if count else Counter()


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
        counts.update(_kinds(text, entropy))
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
        kinds = _kinds(text, entropy)
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
INPUT_SECRET_KINDS = frozenset({
    "private_key", "cloud_access_key", "access_token", "jwt", "bearer_token",
    "resident_registration_number", "card_number", SCAN_LIMIT,
})
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
