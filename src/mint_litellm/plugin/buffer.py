"""로컬 내구 버퍼와 증거 기록 순서.

사건은 같은 ``source_key``로 DB → 버퍼 → 표준 오류 순서의 한 위치에 처음 기록된다. 기록 결과가
불명인 경우(커밋 뒤 응답 유실 등)에는 다음 위치에 다시 쓰므로 같은 사건이 두 위치에 남을 수
있고, 버퍼 재적재가 DB의 ``(instance_id, source_key)`` 유일성으로 한 건에 수렴시킨다.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import itertools
import logging
import os
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, TextIO
from uuid import UUID

from mint_litellm.types.events import Event, EventKind, Evidence, control_source_key
from mint_litellm.types.ids import new_uuid7

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

_OPEN = ".open"
log = logging.getLogger("mint_litellm.buffer")

_CLOSED = ".jsonl"
_REPLAYING = ".replaying"
_LOCKFILE = ".lock"
# 디렉터리 fsync를 지원하지 않는 파일 시스템이 돌려주는 오류. 그 밖의 오류는 실제 입출력 실패다.
_DIRECTORY_FSYNC_UNSUPPORTED = frozenset({errno.EINVAL, errno.ENOTSUP, errno.EBADF})
_SYSTEM_KINDS = frozenset({EventKind.BUFFER_OVERFLOW, EventKind.BUFFER_REPLAYED})


class SystemEventKeys:
    """한 실행이 시스템 사건 키를 1부터 순서대로 발급한다.

    같은 종류의 사건이 한 실행에서 여러 건이어도 키가 겹쳐 한 건으로 합쳐지지 않으며, 실행이 다르면
    순번이 같아도 키가 다르다.
    """

    def __init__(self) -> None:
        self.run_id = new_uuid7()
        self._sequence = itertools.count(1)

    def next(self, kind: EventKind) -> str:
        return control_source_key(kind, str(self.run_id), next(self._sequence))


class BufferWriteError(Exception):
    """버퍼에 쓰지 못했다(읽기 전용 볼륨, 가득 참, 입출력 오류)."""


class ConsumptionLost(Exception):
    """호출별 승인을 소비하지 못했다. 같은 트랜잭션의 사건 기록도 되돌려졌다."""

    def __init__(self, reason: str = "CALL_APPROVAL_REQUIRED") -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ConfirmationConsume:
    id: UUID
    org_id: str
    fp_key_version: int
    state_version: int


@dataclass(frozen=True)
class ConsumeRequest:
    """승인된 호출별 승인을 한 번 소비하는 조건. 모든 항목이 현재 호출과 일치해야 한다."""

    call_approval_id: UUID | None
    invocation_id: UUID
    principal_type: str
    principal_id: str
    server_id: str
    tool: str
    args_fp: str
    policy_version_id: str
    state_version: int
    confirmation: ConfirmationConsume | None = None
    # 계약 관리 서버에서 승인이 묶인 도구 계약. 소비 때 지금도 승인된 계약이어야 한다.
    contract_id: str | None = None
    # 프로필이 있는 서버에서 승인이 묶인 대상·행위. 소비 때 승인 행의 값과 같아야 한다.
    target: str | None = None
    action: str | None = None


class EventStore(Protocol):
    async def insert_event(self, event: Event, consume: ConsumeRequest | None = None) -> bool:
        """사건을 넣는다. 같은 배치에 같은 ``source_key``가 이미 있으면 ``False``."""
        ...


@dataclass
class TakeTicket:
    """재적재 코루틴과 인수 스레드가 한 파일의 소유권을 넘기는 표.

    코루틴이 취소돼 결과를 받지 못해도 스레드가 인수한 파일을 놓치지 않게 한다.
    """

    path: Path | None = None
    abandoned: bool = False


@dataclass(frozen=True)
class Overflow:
    dropped_events: int
    dropped_files: int


class LocalBuffer:
    """JSONL 추가 쓰기 + fsync. 상한을 넘으면 가장 오래된 닫힌 파일부터 지운다."""

    def __init__(self, directory: Path, max_bytes: int) -> None:
        self._dir = directory
        self._max_bytes = max_bytes
        self._segment_bytes = max(1024, min(4 * 1024 * 1024, max_bytes // 4))
        self._owner = new_uuid7().hex
        self._seq = 0
        self._handle: BinaryIO | None = None
        self._path: Path | None = None
        self._size = 0
        self._dropped_events = 0
        self._dropped_files = 0
        self._lock = threading.RLock()
        self._directory_lock_handle: TextIO | None = None
        self._held: dict[Path, TextIO] = {}

    def append(self, event: Event) -> None:
        line = event.to_json_line()
        if "\n" in line:
            raise BufferWriteError("event line contains a line break")
        data = (line + "\n").encode("utf-8")
        # 용량 확인, 회전, 쓰기, fsync, 크기 갱신을 한 잠금으로 묶는다. 다른 스레드의 회전이 끼면
        # 쓴 줄이 이미 닫힌 파일이나 다른 파일에 대한 fsync로 성공 처리될 수 있다.
        # 같은 디렉터리를 쓰는 다른 프로세스도 용량 확인과 쓰기 사이에 끼지 못해야 상한이 지켜진다.
        with self._lock:
            try:
                self._dir.mkdir(parents=True, exist_ok=True)
                with self._directory_lock():
                    self._make_room(len(data))
                    if self._handle is None or self._size + len(data) > self._segment_bytes:
                        self._rotate()
                    assert self._handle is not None
                    self._handle.write(data)
                    self._handle.flush()
                    os.fsync(self._handle.fileno())
                    self._size += len(data)
            except BufferWriteError:
                raise
            except (OSError, ValueError) as exc:
                self._abandon()
                raise BufferWriteError(f"{type(exc).__name__}") from exc

    def peek_overflow(self) -> Overflow | None:
        """아직 보고하지 않은 삭제 건수. 보고를 마친 뒤 ``settle_overflow``로 덜어낸다."""
        with self._lock:
            if not self._dropped_files:
                return None
            return Overflow(self._dropped_events, self._dropped_files)

    def settle_overflow(self, report: Overflow) -> None:
        with self._lock:
            self._dropped_events = max(0, self._dropped_events - report.dropped_events)
            self._dropped_files = max(0, self._dropped_files - report.dropped_files)

    def take_overflow(self) -> Overflow | None:
        report = self.peek_overflow()
        if report is not None:
            self.settle_overflow(report)
        return report

    def close(self) -> None:
        with self._lock:
            self._close_current()

    def has_pending(self) -> bool:
        with self._lock:
            if self._handle is not None and self._size > 0:
                return True
            try:
                return any(self._claimable())
            except OSError:
                return False

    def pending(self) -> list[Path]:
        """다시 적재할 파일의 목록. 지금 쓰고 있는 파일도 닫아서 포함한다.

        닫지 않으면 쓰는 프로세스가 살아 있는 동안 그 파일의 사건은 다시 적재되지 않는다. 주인이
        없어진 열린 파일과, 재적재 중 프로세스가 죽어 남은 파일도 포함한다.
        """
        with self._lock:
            self._close_current()
            try:
                return list(self._claimable())
            except OSError:
                return []

    def take(self, path: Path, ticket: TakeTicket | None = None) -> Path | None:
        """파일 하나를 재적재용으로 인수한다(이름을 바꾸고 잠근다). 이미 다른 쪽이 가져갔으면 None.

        한 번에 한 파일만 인수해야 재적재가 중간에 끝나도 남는 파일이 하나뿐이다. 기다리던 쪽이
        ``abandon``한 표이면 인수하지 않는다.
        """
        with self._lock, self._directory_lock():
            if ticket is not None and ticket.abandoned:
                return None
            # 후보를 모은 뒤에 다른 프로세스가 가져가 잠갔을 수 있다. 닫힌 파일이 아니면 잠금이
            # 풀려 있는지 다시 확인한 뒤에만 이름을 바꾼다.
            name = path.name
            if not name.endswith(_CLOSED) and (
                name.endswith(f"{_REPLAYING}.{self._owner}") or not self._orphaned(path)
            ):
                return None
            base = name.split(_REPLAYING)[0]
            target = path.with_name(f"{base}{_REPLAYING}.{self._owner}")
            try:
                os.rename(path, target)
            except OSError:
                return None
            if fcntl is not None:
                handle: TextIO | None = None
                try:
                    handle = target.open("r")
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    if handle is not None:
                        handle.close()
                    with contextlib.suppress(OSError):
                        os.rename(target, path)
                    return None
                self._held[target] = handle
            if ticket is not None:
                ticket.path = target
            return target

    def abandon(self, ticket: TakeTicket) -> None:
        """인수를 기다리던 쪽이 취소됐다. 인수한 파일은 돌려놓고, 아직이면 인수하지 못하게 한다."""
        with self._lock:
            ticket.abandoned = True
            path, ticket.path = ticket.path, None
        if path is not None:
            self.release(path)

    def release(self, path: Path) -> None:
        """재적재를 마치지 못한 파일을 다시 닫힌 파일로 돌려놓는다."""
        self._drop_hold(path)
        original = path.name.split(_REPLAYING)[0]
        name = original if original.endswith(_CLOSED) else original.removesuffix(_OPEN) + _CLOSED
        with contextlib.suppress(OSError):
            os.rename(path, path.with_name(name))

    def finish(self, path: Path) -> None:
        """재적재를 마친 파일을 지운다."""
        self._drop_hold(path)
        with contextlib.suppress(OSError):
            path.unlink()

    def _drop_hold(self, path: Path) -> None:
        with self._lock:
            handle = self._held.pop(path, None)
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()

    @staticmethod
    def read(path: Path) -> tuple[list[Event], int]:
        events: list[Event] = []
        unreadable = 0
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                if not raw.strip():
                    continue
                try:
                    events.append(Event.from_json_line(raw))
                except ValueError:
                    unreadable += 1
        return events, unreadable

    def _claimable(self):
        if not self._dir.is_dir():
            return
        for entry in sorted(self._dir.iterdir()):
            name = entry.name
            if name.endswith(_CLOSED):
                yield entry
            elif (
                name.endswith(_OPEN) and not name.startswith(self._owner) and self._orphaned(entry)
            ):
                yield entry
            elif (
                _REPLAYING in name
                and not name.endswith(f"{_REPLAYING}.{self._owner}")
                and self._orphaned(entry)
            ):
                yield entry

    @staticmethod
    def _orphaned(path: Path) -> bool:
        """쓰거나 재적재하는 프로세스가 없는 파일. 배타 잠금을 얻을 수 있으면 주인이 없다.

        잠금을 쓸 수 없는 플랫폼(Windows)에서는 판별할 수 없어 항상 거짓이다. 그 플랫폼에서는
        종료한 프로세스가 남긴 열린 파일과 재적재 중인 파일을 자동으로 복구하지 않는다.
        """
        if fcntl is None:
            return False
        try:
            with path.open("r") as handle:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(handle, fcntl.LOCK_UN)
        except OSError:
            return False
        return True

    def _rotate(self) -> None:
        self._close_current()
        self._seq += 1
        path = self._dir / f"{self._owner}-{self._seq:06d}{_OPEN}"
        handle = path.open("ab")
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._handle, self._path, self._size = handle, path, 0
        self._fsync_directory(strict=True)

    def _close_current(self) -> None:
        handle, path = self._handle, self._path
        self._handle = self._path = None
        self._size = 0
        if handle is None or path is None:
            return
        with contextlib.suppress(OSError):
            handle.close()
        with contextlib.suppress(OSError):
            os.rename(path, path.with_name(path.name.removesuffix(_OPEN) + _CLOSED))
            self._fsync_directory()

    def _abandon(self) -> None:
        """쓰기에 실패한 열린 파일을 닫아 다음 호출이 새 파일에서 다시 시도하게 한다."""
        handle = self._handle
        self._handle = self._path = None
        self._size = 0
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()

    def _fsync_directory(self, *, strict: bool = False) -> None:
        """디렉터리 항목을 디스크에 남긴다. ``strict``이면 실제 입출력 실패를 올린다."""
        if os.name != "posix":
            return
        try:
            fd = os.open(self._dir, os.O_RDONLY)
        except OSError:
            if strict:
                raise
            return
        try:
            os.fsync(fd)
        except OSError as exc:
            if strict and exc.errno not in _DIRECTORY_FSYNC_UNSUPPORTED:
                raise
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _directory_lock(self):
        """같은 디렉터리를 쓰는 프로세스 사이에서 용량 계산·삭제·인수를 직렬화한다.

        호출하는 쪽이 ``self._lock``을 쥐고 있어야 같은 프로세스의 스레드끼리도 배제된다.
        """
        if fcntl is None:
            yield
            return
        if self._directory_lock_handle is None:
            self._dir.mkdir(parents=True, exist_ok=True)
            self._directory_lock_handle = (self._dir / _LOCKFILE).open("a")
        fcntl.flock(self._directory_lock_handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(self._directory_lock_handle, fcntl.LOCK_UN)

    def _total_bytes(self) -> int:
        total = 0
        for entry in self._dir.iterdir():
            with contextlib.suppress(FileNotFoundError):
                if entry.is_file():
                    total += entry.stat().st_size
        return total

    def _make_room(self, incoming: int) -> None:
        """호출하는 쪽이 디렉터리 잠금을 쥐고 있어야 한다."""
        while self._total_bytes() + incoming > self._max_bytes:
            closed = sorted(p for p in self._dir.iterdir() if p.name.endswith(_CLOSED))
            if not closed:
                if self._handle is not None and self._size > 0:
                    self._close_current()
                    continue
                raise BufferWriteError("buffer is full")
            victim = closed[0]
            try:
                events, unreadable = self.read(victim)
                victim.unlink()
            except FileNotFoundError:
                continue
            self._dropped_events += len(events) + unreadable
            self._dropped_files += 1


class Recorded(Protocol):
    evidence: Evidence


@dataclass(frozen=True)
class DatabaseResult:
    stored: bool
    consumption_lost: bool = False
    consumption_reason: str = "CALL_APPROVAL_REQUIRED"


class EvidenceRecorder:
    """DB → 버퍼 → 표준 오류 순서로 사건을 남기고, DB가 돌아오면 버퍼를 다시 적재한다."""

    def __init__(
        self,
        store: EventStore | None,
        buffer: LocalBuffer,
        *,
        budget_seconds: float,
        instance_id: str,
        stderr: TextIO | None = None,
        replay_interval_seconds: float = 2.0,
    ) -> None:
        self._store = store
        self._buffer = buffer
        self._budget = budget_seconds
        self._instance_id = instance_id
        self._stderr = stderr
        self._replay_interval = replay_interval_seconds
        self._last_replay = 0.0
        self._replaying: asyncio.Task[None] | None = None
        self._keys = SystemEventKeys()
        self._overflow_lock = asyncio.Lock()
        self._pending_overflow: tuple[Overflow, Event] | None = None

    async def try_database(
        self,
        event: Event,
        consume: ConsumeRequest | None = None,
        *,
        timeout: float | None = None,
    ) -> DatabaseResult:
        """DB에 쓴다. 시간 초과는 커밋 여부가 불명이라 실패로 다루고, 다음 위치에 다시 쓴다."""
        if self._store is None:
            return DatabaseResult(stored=False)
        try:
            async with asyncio.timeout(self._budget if timeout is None else timeout):
                inserted = await self._store.insert_event(event, consume)
        except ConsumptionLost as exc:
            return DatabaseResult(
                stored=False, consumption_lost=True, consumption_reason=exc.reason
            )
        except Exception as exc:
            log.debug(
                "사건 기록 실패: %s sqlstate=%s", type(exc).__name__, getattr(exc, "sqlstate", None)
            )
            return DatabaseResult(stored=False)
        if consume is not None and not inserted:
            return DatabaseResult(stored=False)
        self._schedule_replay()
        return DatabaseResult(stored=True)

    async def fallback(
        self, event: Event, *, on_written: Callable[[], None] | None = None
    ) -> Evidence:
        """DB에 쓰지 못한 사건을 버퍼에, 그것도 안 되면 표준 오류에 남긴다.

        ``on_written``은 사건이 남겨진 직후, 넘침 보고를 기다리기 전에 불린다.
        """
        evidence = await self._write_local(event)
        if on_written is not None:
            on_written()
        if evidence is Evidence.BUFFER:
            await self._report_overflow()
        return evidence

    async def _report_overflow(self) -> None:
        """건수는 보고를 마칠 때까지 남긴다. 보고하다 취소되면 같은 사건을 같은 키로 다시 보낸다."""
        async with self._overflow_lock:
            if self._pending_overflow is None:
                overflow = self._buffer.peek_overflow()
                if overflow is None:
                    return
                event = self._system_event(
                    EventKind.BUFFER_OVERFLOW,
                    {
                        "dropped_events": overflow.dropped_events,
                        "dropped_files": overflow.dropped_files,
                    },
                )
                self._pending_overflow = (overflow, event)
            overflow, event = self._pending_overflow
            await self._store_system(event)
            self._buffer.settle_overflow(overflow)
            self._pending_overflow = None

    async def _write_local(self, event: Event) -> Evidence:
        try:
            await asyncio.to_thread(self._buffer.append, event.with_evidence(Evidence.BUFFER))
        except Exception:
            self._write_stderr(event.with_evidence(Evidence.STDERR))
            return Evidence.STDERR
        return Evidence.BUFFER

    async def record(self, event: Event) -> Evidence:
        if (await self.try_database(event)).stored:
            return Evidence.DB
        return await self.fallback(event)

    async def replay(self) -> None:
        """버퍼에 쌓인 사건을 DB에 적재한다. 중복은 세어 ``buffer_replayed``에 남긴다.

        파일은 하나씩 인수한다. 적재가 실패하거나 취소되면 그 파일을 돌려놓고, 나머지는 건드리지
        않으므로 다음 재적재가 이어받는다.
        """
        store = self._store
        if store is None:
            return
        replayed = duplicates = unreadable = 0
        held: Path | None = None
        try:
            for candidate in await asyncio.to_thread(self._buffer.pending):
                held = await self._take(candidate)
                if held is None:
                    continue
                events, bad = await asyncio.to_thread(self._buffer.read, held)
                for event in events:
                    async with asyncio.timeout(self._budget):
                        inserted = await store.insert_event(event.with_evidence(Evidence.DB))
                    if event.kind in _SYSTEM_KINDS:
                        continue
                    if inserted:
                        replayed += 1
                    else:
                        duplicates += 1
                unreadable += bad
                self._buffer.finish(held)
                held = None
        except Exception:
            pass
        finally:
            if held is not None:
                self._buffer.release(held)
        if replayed or duplicates or unreadable:
            await self._append_system(
                EventKind.BUFFER_REPLAYED,
                {"replayed": replayed, "duplicates": duplicates, "unreadable": unreadable},
            )

    async def _take(self, candidate: Path) -> Path | None:
        """파일을 인수한다. 취소되거나 루프가 곧 끝나도 스레드가 인수한 파일은 돌려놓는다."""
        ticket = TakeTicket()
        task = asyncio.ensure_future(asyncio.to_thread(self._buffer.take, candidate, ticket))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            self._buffer.abandon(ticket)
            raise

    async def replay_pending(self) -> None:
        """호출이 끊겨 쓰기가 없어도 버퍼 사건이 DB에 들어가도록 주기 점검이 부른다.

        버퍼 확인은 잠금·파일 작업이라 이벤트 루프 밖에서 한다.
        """
        if self._replaying is not None and not self._replaying.done():
            return
        if await asyncio.to_thread(self._buffer.has_pending):
            self._last_replay = time.monotonic()
            self._replaying = asyncio.get_running_loop().create_task(self.replay())

    def _schedule_replay(self) -> None:
        now = time.monotonic()
        if (
            self._replaying is not None and not self._replaying.done()
        ) or now - self._last_replay < self._replay_interval:
            return
        self._last_replay = now
        if not self._buffer.has_pending():
            return
        try:
            self._replaying = asyncio.get_running_loop().create_task(self.replay())
        except RuntimeError:
            return

    def _system_event(self, kind: EventKind, payload: dict[str, int]) -> Event:
        return Event(
            instance_id=self._instance_id,
            inserted_at=_utcnow(),
            kind=kind,
            source_key=self._keys.next(kind),
            payload=payload,
        )

    async def _append_system(self, kind: EventKind, payload: dict[str, int]) -> None:
        await self._store_system(self._system_event(kind, payload))

    async def _store_system(self, event: Event) -> None:
        """시스템 사건도 DB → 버퍼 → 표준 오류 순서로 남긴다. 버퍼 넘침을 다시 알리지는 않는다."""
        if self._store is not None:
            try:
                async with asyncio.timeout(self._budget):
                    await self._store.insert_event(event)
                return
            except Exception:
                pass
        await self._write_local(event)

    def _write_stderr(self, event: Event) -> None:
        stream = self._stderr if self._stderr is not None else sys.stderr
        with contextlib.suppress(Exception):
            stream.write(event.to_json_line() + "\n")
            stream.flush()


def _utcnow():
    from datetime import UTC, datetime

    return datetime.now(UTC)


Handler = Callable[[Event], Awaitable[None]]
