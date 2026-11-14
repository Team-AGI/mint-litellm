"""원격 MCP 서버 주소의 이름 조회 결과 재확인(POL-R-12).

호출 직전에 서버 URL의 호스트를 조회해 내부 대역(루프백·사설·링크 로컬·CGNAT·미지정·멀티캐스트·
예약·클라우드 메타데이터)으로 풀리면 막거나 알린다. 조회는 이벤트 루프 밖(``getaddrinfo``)에서
돌고 결과는 호스트별로 짧게 기억하므로 캐시가 맞으면 사전 조회만 한다. 과거에 공개 주소만
받았던 호스트가 내부 주소로 바뀌면 ``rebind``로 따로 가른다.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_TTL_SECONDS = 30.0
DEFAULT_MAX_ENTRIES = 1024

PRIVATE = "private"
REBIND = "rebind"
UNRESOLVED = "unresolved"

# 클라우드 메타데이터 주소: 공용 링크 로컬 주소, 컨테이너 자격 주소, AWS IPv6 주소
_METADATA = frozenset(
    (
        ipaddress.IPv4Address(0xA9FEA9FE),
        ipaddress.IPv4Address(0xA9FEAA02),
        ipaddress.IPv6Address("fd00:ec2::254"),
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_CGNAT = ipaddress.IPv4Network((0x64400000, 10))

Lookup = Callable[[str], Awaitable[list[str]]]


@dataclass(frozen=True)
class Verdict:
    """``kind``는 ``None``(통과)·``private``·``rebind``·``unresolved``, ``label``은 주소 종류."""

    kind: str | None = None
    label: str = ""

    def detail(self) -> str:
        return f"{self.kind} {self.label}".strip() if self.kind else ""


OK = Verdict()


def classify(address: str) -> str | None:
    """내부 대역이면 종류 이름, 공개 주소면 None. 해석할 수 없는 값은 막는 쪽(``unparsable``)."""
    try:
        ip = ipaddress.ip_address(address.partition("%")[0])
    except ValueError:
        return "unparsable"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _METADATA:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 4 and ip in _CGNAT:
        return "cgnat"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "reserved"
    return None


def _first_internal(addresses: list[str]) -> str | None:
    return next((label for a in addresses if (label := classify(a)) is not None), None)


async def system_lookup(host: str) -> list[str]:
    """호스트의 모든 주소. 이벤트 루프 밖에서 조회한다."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


class ResolveGuard:
    """호스트별 판정을 ``ttl`` 초 기억한다. 크기는 ``max_entries``로 제한한다."""

    def __init__(
        self,
        *,
        lookup: Lookup = system_lookup,
        ttl: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._lookup, self._ttl, self._max, self._clock = lookup, ttl, max_entries, clock
        self._cache: dict[str, tuple[float, Verdict]] = {}
        # 공개 주소만 받았던 호스트. 내부 주소로 바뀌면 rebind로 가른다.
        self._was_public: dict[str, None] = {}
        # 기다리다 시간이 다 된 조회. 끝까지 돌게 두고 결과를 캐시에 넣는다(같은 호스트는 하나만).
        self._pending: dict[str, asyncio.Task[list[str]]] = {}

    def cached(self, host: str) -> Verdict | None:
        """캐시가 유효하면 판정, 아니면 None. 조회 없이 마이크로초 단위로 끝난다."""
        entry = self._cache.get(host)
        if entry is not None and entry[0] > self._clock():
            return entry[1]
        return None

    async def check(self, host: str, timeout: float | None = None) -> Verdict:
        hit = self.cached(host)
        if hit is not None:
            return hit
        literal = _literal(host)
        if literal:
            return self._judge(host, [literal])
        task = self._pending.get(host)
        if task is None:
            task = asyncio.ensure_future(self._lookup(host))
            self._pending[host] = task
            task.add_done_callback(lambda t, h=host: self._finish(h, t))
        try:
            addresses = await asyncio.wait_for(asyncio.shield(task), timeout)
        except Exception:
            # 시간 초과면 조회는 뒤에서 계속되고 끝나면 캐시에 들어간다. 실패는 기억하지 않는다.
            return Verdict(UNRESOLVED)
        return self._judge(host, addresses)

    def _finish(self, host: str, task: asyncio.Task[list[str]]) -> None:
        self._pending.pop(host, None)
        if not task.cancelled() and task.exception() is None and self.cached(host) is None:
            self._judge(host, task.result())

    def _judge(self, host: str, addresses: list[str]) -> Verdict:
        if not addresses:
            return Verdict(UNRESOLVED)
        label = _first_internal(addresses)
        if label is None:
            verdict = OK
            self._remember(self._was_public, host)
        elif host in self._was_public:
            verdict = Verdict(REBIND, label)
        else:
            verdict = Verdict(PRIVATE, label)
        self._store(host, verdict)
        return verdict

    def _store(self, host: str, verdict: Verdict) -> None:
        now = self._clock()
        if len(self._cache) >= self._max and host not in self._cache:
            for key in [k for k, (until, _) in self._cache.items() if until <= now]:
                del self._cache[key]
            if len(self._cache) >= self._max:
                del self._cache[next(iter(self._cache))]
        self._cache[host] = (now + self._ttl, verdict)

    def _remember(self, seen: dict[str, None], host: str) -> None:
        seen.pop(host, None)
        seen[host] = None
        if len(seen) > self._max:
            del seen[next(iter(seen))]


def _literal(host: str) -> str | None:
    """호스트가 주소 그대로이면 그 주소(대괄호·영역 표지 제거), 이름이면 None."""
    text = host.strip("[]").partition("%")[0]
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def host_of(url: str | None) -> str | None:
    """서버 URL의 호스트. 없거나 해석할 수 없으면 None."""
    if not url:
        return None
    try:
        return (urlsplit(url).hostname or "").rstrip(".").lower() or None
    except ValueError:
        return None
