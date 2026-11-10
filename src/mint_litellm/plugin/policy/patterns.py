"""호출 인자에서 정책 입력용 패턴 불리언 4개를 계산한다. 결과 불리언만 정책 엔진에 간다.

정규식은 쓰지 않는다. 인자 전체 64KB·문자열 하나 4KB·중첩 20을 넘으면 네 패턴 모두 참이다
(보수적). 이름 해석(DNS)은 하지 않으므로 호스트 이름이 사설 주소로 풀리는 경우는 보지 못한다.
"""

import ipaddress
import posixpath
import re
import unicodedata
from collections.abc import Collection, Iterable, Mapping
from typing import Any
from urllib.parse import unquote, urlsplit

MAX_TOTAL_BYTES = 64 * 1024
MAX_STRING_BYTES = 4 * 1024
MAX_DEPTH = 20
NAMES = ("url_external", "private_host", "path_traversal", "secret_like")

_DOTS = str.maketrans({"。": ".", "｡": ".", "．": "."})
# 호스트가 들어 있는 권한부는 URL 끝 문자나 경로·질의·조각 구분자에서 끝난다. 역슬래시를 슬래시로
# 읽는 쪽은 역슬래시에서도 끝난다. 본문 끝까지 자르지 않아 호출당 비용이 인자 길이에 곱으로
# 늘지 않는다.
_AUTHORITY_END = re.compile("[ \t\r\n\"'<>/?#]")
_AUTHORITY_END_BS = re.compile("[ \t\r\n\"'<>/\\\\?#]")
# 주소 리터럴(점 표기 10진·8진·16진, IPv6)에 나올 수 없는 문자. 호스트가 이 문자를 하나라도 가지면
# 주소 해석(예외를 던지는 해석기)을 건너뛴다. 해석기가 받는 문자는 모두 이 집합 안에 있다.
_NOT_ADDRESS = re.compile(r"[^0-9a-fxo.:_+\s-]")
_SCHEME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-"


class _Overflow(Exception):
    pass


def _strings(value: Any) -> Iterable[str]:
    """문자열 값을 모은다. 상한을 넘거나 알 수 없는 값이 있으면 ``_Overflow``."""
    total = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise _Overflow
        if isinstance(item, str):
            size = len(item)
            if size <= MAX_STRING_BYTES:
                size = len(item.encode("utf-8", "replace"))
            total += size
            if size > MAX_STRING_BYTES or total > MAX_TOTAL_BYTES:
                raise _Overflow
            yield item
        elif isinstance(item, Mapping):
            for key, child in item.items():
                stack.append((str(key), depth + 1))  # 키도 값처럼 검사한다.
                stack.append((child, depth + 1))
        elif isinstance(item, list | tuple):
            stack.extend((child, depth + 1) for child in item)
        elif item is not None and not isinstance(item, bool | int | float):
            raise _Overflow


def _normalize(text: str) -> str:
    if text.isascii() and "%" not in text:
        return text  # 퍼센트 디코딩·NFKC·전각 점 치환 모두 바꿀 것이 없다.
    text = unicodedata.normalize("NFKC", unquote(text))
    return text.translate(_DOTS)


def _forms(text: str) -> list[str]:
    """원문과, 퍼센트 디코딩·NFKC를 바뀌지 않을 때까지(최대 3회) 거친 형태들."""
    forms = [text]
    for _ in range(3):
        decoded = _normalize(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    return forms


def _urls(text: str) -> Iterable[str]:
    """``scheme:`` 뒤에 슬래시나 역슬래시가 하나 이상 오는 곳마다 호스트를 낸다.

    파싱 실패는 빈 문자열(알 수 없음)이다. 역슬래시는 슬래시로 읽는다. 한 글자 스킴은 드라이브
    문자로 보고 건너뛴다. 호스트는 권한부에서만 정해지므로 권한부까지만 파싱한다.
    """
    start = 0
    while (at := text.find(":", start)) != -1:
        start = at + 1
        end = start
        while end < len(text) and text[end] in "/\\":
            end += 1
        if end == start:
            continue
        i = at
        while i > 0 and text[i - 1] in _SCHEME_CHARS:
            i -= 1
        if at - i < 2 or not text[i].isalpha():
            continue
        seen = None
        for ending in (_AUTHORITY_END, _AUTHORITY_END_BS):
            found = ending.search(text, end)
            authority = text[end : found.start() if found else len(text)]
            if authority == seen:
                continue
            seen = authority
            try:
                yield (urlsplit("//" + authority).hostname or "").lower().rstrip(".")
            except ValueError:
                yield ""


def _loose_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """inet_aton 표기(10진·8진·16진, 1~4개 성분)."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    numbers = []
    for part in parts:
        try:
            if part[:2].lower() == "0x":
                numbers.append(int(part[2:], 16))
            elif len(part) > 1 and part[0] == "0":
                numbers.append(int(part, 8))
            else:
                numbers.append(int(part, 10))
        except ValueError:
            return None
    *head, last = numbers
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(parts)):
        return None
    return ipaddress.IPv4Address(sum(n << (8 * (3 - i)) for i, n in enumerate(head)) + last)


def _private_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return not address.is_global or address.is_multicast


def _private_host(host: str, *, loose: bool) -> bool:
    """``host``가 사설·루프백·링크로컬·멀티캐스트 리터럴 주소이거나 ``localhost``인가."""
    host = host.strip().strip("[]").split("%", 1)[0].lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    if host.isascii() and _NOT_ADDRESS.search(host):
        return False
    try:
        return _private_ip(ipaddress.ip_address(host))
    except ValueError:
        pass
    if loose or host[:2] == "0x":
        address = _loose_ipv4(host)
        if address is not None:
            return _private_ip(address)
    return False


def _bare_host(text: str) -> str:
    text = text.strip()
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    head, sep, tail = text.rpartition(":")
    return head if sep and tail.isdigit() and ":" not in head else text


def _is_absolute(text: str) -> bool:
    return text[:1] in ("/", "\\") or (len(text) > 2 and text[1] == ":" and text[2] in ("/", "\\"))


def _traversal(text: str, allowed_paths: Collection[str]) -> bool:
    for variant in (text,):
        flat = variant.replace("\\", "/")
        if ".." in flat.split("/"):
            return True
        if allowed_paths and _is_absolute(variant) and "://" not in variant:
            path = posixpath.normpath(flat)
            if not any(path == a or path.startswith(a.rstrip("/") + "/") for a in allowed_paths):
                return True
    return False


def host_allowed(host: str, allowed: Collection[str]) -> bool:
    return bool(host) and any(host == a or host.endswith("." + a) for a in allowed)


def compute_patterns(
    arguments: Mapping[str, Any],
    *,
    allowed_hosts: Collection[str] = (),
    allowed_paths: Collection[str] = (),
    secret_markers: Collection[str] = (),
) -> dict[str, bool]:
    """``allowed_hosts``는 소문자 호스트, ``allowed_paths``는 정규화된 절대 경로 접두."""
    result = dict.fromkeys(NAMES, False)
    try:
        # 상한 검사를 모두 끝낸 뒤에 훑는다. 상한을 넘는 인자는 훑어 봐야 결과가 같다(모두 참).
        for raw in list(_strings(arguments)):
            for text in _forms(raw):
                for host in _urls(text):
                    if not host_allowed(host, allowed_hosts):
                        result["url_external"] = True
                    if _private_host(host, loose=True):
                        result["private_host"] = True
                if _private_host(_bare_host(text), loose=False):
                    result["private_host"] = True
                if _traversal(text, allowed_paths):
                    result["path_traversal"] = True
                if any(marker in text for marker in secret_markers):
                    result["secret_like"] = True
    except _Overflow:
        return dict.fromkeys(NAMES, True)
    return result
