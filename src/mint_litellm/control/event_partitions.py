"""사건 원장 월별 분할: 앞선 분할 만들기, 닫힌 달 내보내기, 선택적 보관(분할 지우기).

``mint.events``는 ``inserted_at`` 기준 UTC 월 분할이다. 작업 ``event_partition_maintain``은
이번 달부터 석 달 뒤까지의 분할을 미리 만들고, 달이 끝나 하루가 지났고 모든 사건이 봉인된 분할을
``MINT_EXPORT_DIR/events/``에 gzip JSONL 파일과 서명된 매니페스트로 내보낸다.

작업 ``event_retention``은 ``MINT_EVENT_RETENTION_DAYS``가 있을 때만 일한다(MINT는 기본값을 정하지
않는다). 달 전체가 보관 일수보다 오래되고 내보내기 기록이 있는 분할만, 파일을 다시 읽어 서명·해시·
행 수를 확인한 뒤 지운다. 확인이 하나라도 실패하면 지우지 않고 경보를 연다.
"""

import gzip
import hashlib
import json
import os
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg

from mint_litellm.control import alerts, exports, ledger
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.exports import ExportFailed
from mint_litellm.control.jobs import JobContext
from mint_litellm.restore import files
from mint_litellm.types.events import EventKind

AHEAD_MONTHS = 3
# 달이 끝난 뒤 이만큼 기다린 다음 내보낸다(늦게 들어오는 행과 봉인이 끝나도록).
SETTLE = timedelta(days=1)
_CHUNK = 1 << 20


def month_start(day: date) -> date:
    return day.replace(day=1)


def next_month(day: date) -> date:
    return (day.replace(day=28) + timedelta(days=4)).replace(day=1)


def month_bounds(month: date) -> tuple[datetime, datetime]:
    first = datetime(month.year, month.month, 1, tzinfo=UTC)
    after = next_month(month)
    return first, datetime(after.year, after.month, 1, tzinfo=UTC)


def _tag(month: date) -> str:
    return f"{month.year:04d}{month.month:02d}"


def _paths(export_dir: Path, month: date) -> tuple[Path, Path]:
    base = export_dir / "events"
    return base / f"events-{_tag(month)}.jsonl.gz", base / f"events-{_tag(month)}.manifest.json"


def ensure_partitions(conn: psycopg.Connection, today: date | None = None) -> list[date]:
    """이번 달부터 ``AHEAD_MONTHS``개월 뒤까지 분할을 만든다. 새로 만든 달을 돌려준다."""
    month = month_start(today or datetime.now(UTC).date())
    created: list[date] = []
    blocked: list[str] = []
    for _ in range(AHEAD_MONTHS + 1):
        try:
            if conn.execute("SELECT mint.ensure_event_partition(%s)", (month,)).fetchone()[0]:
                created.append(month)
        except psycopg.errors.CheckViolation:
            # 기본 분할에 이미 그 달의 행이 있다. 나머지 달은 계속 만들고 마지막에 알린다.
            blocked.append(_tag(month))
        month = next_month(month)
    if blocked:
        raise ControlError(
            "이미 기본 분할에 행이 있는 달이라 분할을 만들 수 없습니다: " + ", ".join(blocked)
        )
    return created


def _partition_months(conn: psycopg.Connection) -> list[date]:
    rows = fetchall(
        conn,
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
        " WHERE i.inhparent = 'mint.events'::regclass AND c.relname ~ '^events_[0-9]{6}$'"
        " ORDER BY c.relname",
    )
    return [date(int(r["relname"][7:11]), int(r["relname"][11:13]), 1) for r in rows]


def _sha256_and_lines(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(block)
    lines = 0
    with gzip.open(path, "rb") as handle:
        for _ in handle:
            lines += 1
    return digest.hexdigest(), lines


def verify_export(settings: Any, row: dict[str, Any]) -> None:
    """내보내기 기록과 디스크의 파일·매니페스트가 맞는지 본다. 아니면 ``ExportUnverified``."""
    data_path, manifest_path = _paths(settings.export_dir, row["month"])
    try:
        manifest = files.read_verified(manifest_path, exports.keys(settings))
        sha, lines = _sha256_and_lines(data_path)
    except (OSError, EOFError, gzip.BadGzipFile) as error:
        raise files.ExportUnverified(f"read failed: {type(error).__name__}") from None
    expected = {
        "kind": "event_partition", "month": row["month"].strftime("%Y-%m"),
        "row_count": row["row_count"], "file_sha256": row["file_sha256"],
    }
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise files.ExportUnverified("manifest does not match the export record")
    if sha != row["file_sha256"] or lines != row["row_count"]:
        raise files.ExportUnverified("file does not match the export record")


def _write_month(
    conn: psycopg.Connection, settings: Any, month: date
) -> tuple[int, str, dict[str, list[int]], str]:
    """한 달의 사건을 gzip JSONL로 쓴다. ``(행 수, 파일 SHA-256, 봉인 구간, 상대 경로)``."""
    lo, hi = month_bounds(month)
    data_path, _ = _paths(settings.export_dir, month)
    data_path.parent.mkdir(parents=True, exist_ok=True)
    temp = data_path.with_name(f".{data_path.name}.{os.getpid()}.tmp")
    count = 0
    ranges: dict[str, list[int]] = {}
    try:
        with conn.transaction():
            conn.execute("SELECT set_config('TimeZone', 'UTC', true)")
            with (
                open(temp, "wb") as raw,
                gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as out,
                conn.cursor(name="event_export") as cursor,
            ):
                cursor.execute(
                    "SELECT to_jsonb(e) FROM mint.events e"
                    " WHERE inserted_at >= %s AND inserted_at < %s ORDER BY inserted_at, event_id",
                    (lo, hi),
                )
                for (document,) in cursor:
                    out.write(json.dumps(document, sort_keys=True, ensure_ascii=False).encode())
                    out.write(b"\n")
                    count += 1
                    seq = document.get("seal_seq")
                    if seq is not None:
                        span = ranges.setdefault(document["instance_id"], [seq, seq])
                        span[0], span[1] = min(span[0], seq), max(span[1], seq)
                out.flush()
                raw.flush()
                os.fsync(raw.fileno())
        os.replace(temp, data_path)
    finally:
        temp.unlink(missing_ok=True)
    sha, lines = _sha256_and_lines(data_path)
    if lines != count:
        raise files.ExportUnverified("written file has a different line count")
    return count, sha, ranges, str(data_path.relative_to(settings.export_dir)).replace("\\", "/")


def _export_month(job: JobContext, month: date) -> None:
    conn, settings = job.conn, job.settings
    job.external_write()
    count, sha, ranges, relative = _write_month(conn, settings, month)
    _, manifest_path = _paths(settings.export_dir, month)
    files.atomic_write(manifest_path, files.sign({
        "format": files.FORMAT, "kind": "event_partition", "month": month.strftime("%Y-%m"),
        "row_count": count, "file": relative, "file_sha256": sha, "seal_ranges": ranges,
        "written_at": files.now(),
    }, settings.export_hmac_key))
    row = fetchone(
        conn,
        "INSERT INTO mint.event_exports (month, row_count, file_sha256, path, seal_ranges)"
        " VALUES (%s, %s, %s, %s, %s::jsonb)"
        " ON CONFLICT (month) DO UPDATE SET row_count = EXCLUDED.row_count,"
        " file_sha256 = EXCLUDED.file_sha256, path = EXCLUDED.path,"
        " seal_ranges = EXCLUDED.seal_ranges, revision = mint.event_exports.revision + 1,"
        " written_at = now() WHERE mint.event_exports.dropped_at IS NULL RETURNING *",
        (month, count, sha, relative, json.dumps(ranges)),
    )
    verify_export(settings, row)  # 방금 쓴 파일을 다시 읽어 기록과 대조한다
    ledger.record(
        conn, job.instance_id, EventKind.EVENT_PARTITION_EXPORTED, entity_id=_tag(month),
        state_version=row["revision"], actor="worker",
        payload={"month": month.strftime("%Y-%m"), "row_count": count, "file_sha256": sha,
                 "path": relative},
    )


def _alert(job: JobContext, reason: str, month: date) -> None:
    alerts.raise_alert(
        job.conn, job.instance_id, kind="export_failed", severity="high",
        dedup_key="export_failed:event_partition",
        subject={"kind": "event_partition", "month": month.strftime("%Y-%m"), "reason": reason},
    )


def maintain(job: JobContext) -> None:
    ensure_partitions(job.conn)
    now = datetime.now(UTC)
    for month in _partition_months(job.conn):
        if month_bounds(month)[1] + SETTLE > now:
            continue
        lo, hi = month_bounds(month)
        state = fetchone(
            job.conn,
            "SELECT count(*) AS n, count(*) FILTER (WHERE seal_seq IS NULL) AS unsealed"
            " FROM mint.events WHERE inserted_at >= %s AND inserted_at < %s",
            (lo, hi),
        )
        if state["unsealed"]:
            continue  # 봉인이 끝난 뒤에 내보낸다
        old = fetchone(job.conn, "SELECT * FROM mint.event_exports WHERE month = %s", (month,))
        if old is not None and old["row_count"] == state["n"]:
            try:
                verify_export(job.settings, old)
                continue
            except files.ExportUnverified:
                pass  # 파일이 사라졌거나 달라졌으면 다시 쓴다
        try:
            _export_month(job, month)
        except (OSError, files.ExportUnverified) as error:
            _alert(job, type(error).__name__, month)
            raise ExportFailed(
                f"사건 분할 내보내기에 실패했습니다: {type(error).__name__}"
            ) from None


def retain(job: JobContext) -> None:
    days = job.settings.event_retention_days
    if days is None:
        return
    cutoff = datetime.now(UTC) - timedelta(days=days)
    present = set(_partition_months(job.conn))
    rows = fetchall(
        job.conn,
        "SELECT * FROM mint.event_exports WHERE dropped_at IS NULL ORDER BY month",
    )
    for row in rows:
        month = row["month"]
        if month not in present or month_bounds(month)[1] > cutoff:
            continue
        job.external_write()
        try:
            verify_export(job.settings, row)
        except files.ExportUnverified as error:
            _alert(job, f"unverified:{error}", month)
            raise ExportFailed("내보낸 파일을 확인하지 못해 분할을 지우지 않습니다.") from None
        try:
            with job.conn.transaction():
                job.conn.execute(
                    "SELECT mint.drop_event_partition(%s, %s, %s)",
                    (month, row["row_count"], row["file_sha256"]),
                )
                ledger.record(
                    job.conn, job.instance_id, EventKind.EVENT_PARTITION_DROPPED,
                    entity_id=_tag(month), state_version=row["revision"], actor="worker",
                    payload={"month": month.strftime("%Y-%m"), "row_count": row["row_count"],
                             "file_sha256": row["file_sha256"], "retention_days": days},
                )
        except psycopg.errors.CheckViolation as error:
            # 내보낸 뒤 행이 바뀌었거나 아직 봉인이 끝나지 않았다. 다음 내보내기가 다시 맞춘다.
            _alert(job, "partition_changed", month)
            raise ExportFailed(f"분할을 지우지 않았습니다: {error}") from None
