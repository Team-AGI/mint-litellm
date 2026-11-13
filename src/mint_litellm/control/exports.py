"""부정 상태·체크포인트 파일 내보내기. 작업 실행기의 처리기와 복원 명령이 함께 쓴다.

파일은 ``MINT_EXPORT_DIR``에만 쓴다. 쓰고 나면 다시 읽어 해시·HMAC을 대조(수령)한 뒤에야
``exports`` 행을 ``written``으로 바꾸고 ``latest.json``을 갱신한다. ``latest.json``은 더 낮은
``state_epoch``로 덮지 않는다. 파일을 쓰기 직전에는 외부 쓰기 경계(``guard``)를 부른다.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psycopg

from mint_litellm.control import alerts, ledger
from mint_litellm.control.db.connection import fetchone
from mint_litellm.control.errors import ControlError
from mint_litellm.control.jobs import JobContext, RestoreBlocked
from mint_litellm.control.stage2_config import Stage2Settings
from mint_litellm.restore import files, judge
from mint_litellm.types.events import EventKind

# 부정 상태 항목 여덟 종류(철회·거부·중지·종료·rejected 서버, 종료 관계, 닫힌 조직, 해제된 허용
# 목록, 철회된 동의, 삭제·강등된 운영자). 운영자는 강등을 행만 봐서는 알 수 없으므로 한 번이라도
# 바뀐 행(``state_version`` > 1)을 모두 담는다. ``id``는 서버만 server_id, 운영자는 이름이고
# 나머지는 행 식별자다. 항목마다 행 전체 스냅숏(``row``, 모든 열)을 담아 복원 때 같은 id로
# 되돌릴 수 있게 한다. 운영자 행은 토큰 해시 원문 대신 그 해시의 SHA-256 지문(``token_fp``, 활성
# 운영자만)을 담는다. 파일은 내보내기 키로 서명되고, 지문은 DB가 같은 식으로 계산해 대조한다.
# ponytail: 항목을 전부 한 파일에 담는다(철회가 수만 건이 되면 증분 파일로 나눈다).
SNAPSHOT_SQL = """
WITH items AS (
  SELECT 'approval' AS kind, t.id::text AS id, t.state_version, t.status AS state,
         to_jsonb(t) AS row
    FROM mint.approvals t WHERE t.instance_id = %(i)s AND t.status = 'revoked'
  UNION ALL SELECT 'denial', t.id::text, t.state_version, 'active', to_jsonb(t)
    FROM mint.denials t WHERE t.instance_id = %(i)s AND t.lifted_at IS NULL
  UNION ALL SELECT 'server', t.server_id, t.state_version, t.status, to_jsonb(t)
    FROM mint.servers t WHERE t.instance_id = %(i)s
     AND t.status IN ('rejected', 'suspended', 'terminating', 'terminated')
  UNION ALL SELECT 'relation', t.id::text, t.state_version, t.status, to_jsonb(t)
    FROM mint.usage_relations t WHERE t.instance_id = %(i)s
     AND t.status IN ('terminating', 'terminated')
  UNION ALL SELECT 'org', t.org_id, t.state_version, t.status, to_jsonb(t)
    FROM mint.orgs t WHERE t.instance_id = %(i)s AND t.status = 'closed'
  UNION ALL SELECT 'allowlist', t.id::text, t.state_version, t.status, to_jsonb(t)
    FROM mint.allowlists t WHERE t.instance_id = %(i)s AND t.status = 'lifted'
  UNION ALL SELECT 'consent', t.id::text, t.state_version, 'revoked', to_jsonb(t)
    FROM mint.consents t WHERE t.instance_id = %(i)s AND t.revoked_at IS NOT NULL
  UNION ALL SELECT 'operator', t.name, t.state_version,
      CASE WHEN t.expires_at IS NULL THEN t.role ELSE 'removed' END,
      (to_jsonb(t) - 'token_hash') || jsonb_build_object('token_fp', CASE WHEN t.expires_at IS NULL
        THEN encode(sha256(convert_to(t.token_hash, 'UTF8')), 'hex') END)
    FROM mint.operators t WHERE t.instance_id = %(i)s AND t.state_version > 1
), last AS (
  SELECT to_seal_seq, encode(tail_hash, 'hex') AS tail FROM mint.seal_batches
  WHERE instance_id = %(i)s ORDER BY to_seal_seq DESC LIMIT 1
)
SELECT coalesce((SELECT epoch FROM mint.state_epoch WHERE instance_id = %(i)s), 0) AS epoch,
       (SELECT to_seal_seq FROM last) AS seq, (SELECT tail FROM last) AS tail,
       coalesce((SELECT jsonb_agg(jsonb_build_object('kind', kind, 'id', id,
           'state_version', state_version, 'state', state, 'row', row)
           ORDER BY kind, id) FROM items),
         '[]'::jsonb) AS items
"""


class ExportFailed(ControlError):
    """파일을 쓰지 못했거나 다시 읽은 내용이 맞지 않는다. 작업은 재시도한다."""

    code = "export_failed"


def snapshot(conn: psycopg.Connection, instance_id: str) -> dict[str, Any]:
    """한 문장(한 시점)으로 세대·봉인 끝·부정 상태 항목 전체를 읽는다."""
    # 행 스냅숏의 시각 문자열이 세션 시간대에 따라 달라지지 않게 UTC로 고정한다.
    with conn.transaction():
        conn.execute("SELECT set_config('TimeZone', 'UTC', true)")
        return fetchone(conn, SNAPSHOT_SQL, {"i": instance_id})


def keys(settings: Stage2Settings) -> list[bytes]:
    return [k for k in (settings.export_hmac_key, settings.export_hmac_key_previous) if k]


def _already_written(conn: psycopg.Connection, instance_id: str, epoch: int) -> bool:
    return (
        fetchone(
            conn,
            "SELECT 1 AS x FROM mint.exports WHERE instance_id = %s AND kind = 'negative_state'"
            " AND status = 'written' AND state_epoch >= %s LIMIT 1",
            (instance_id, epoch),
        )
        is not None
    )


def _tail_at(conn: psycopg.Connection, instance_id: str, seq: int | None) -> str | None:
    if seq is None:
        return None
    row = fetchone(
        conn,
        "SELECT encode(tail_hash, 'hex') AS tail FROM mint.seal_batches"
        " WHERE instance_id = %s AND to_seal_seq = %s",
        (instance_id, seq),
    )
    return None if row is None else row["tail"]


def _event(conn, instance_id: str, kind: EventKind, row: dict, payload: dict, actor: str) -> None:
    ledger.record(
        conn, instance_id, kind, entity_id=str(row["id"]), state_version=row["attempts"],
        actor=actor, payload=payload,
    )


def write_export(
    conn: psycopg.Connection,
    instance_id: str,
    settings: Stage2Settings,
    kind: str,
    *,
    min_epoch: int = 0,
    force_latest: bool = False,
    actor: str = "worker",
    guard: Callable[[], None] = lambda: None,
    write_latest: bool = True,
    republish: bool = False,
) -> dict[str, Any] | None:
    """``kind``(``negative_state``|``checkpoint``) 파일을 쓰고 수령을 확인한다.

    이미 ``min_epoch`` 이상의 부정 상태 파일이 쓰였으면 아무것도 하지 않고 None을 돌려준다.
    ``force_latest``는 DB 기준으로 ``latest.json``을 더 낮은 세대로도 덮는다(accept-stale).
    """
    skip_done = kind == "negative_state" and not republish
    if skip_done and min_epoch and _already_written(conn, instance_id, min_epoch):
        return None
    snap = snapshot(conn, instance_id)
    epoch, seq, tail = snap["epoch"], snap["seq"], snap["tail"]
    if skip_done and _already_written(conn, instance_id, epoch):
        return None
    export_dir = settings.export_dir
    row = None
    if kind == "negative_state":
        row = fetchone(
            conn,
            "SELECT * FROM mint.exports WHERE instance_id = %s AND kind = 'negative_state'"
            " AND state_epoch = %s",
            (instance_id, epoch),
        )
        if row is not None and row["to_seal_seq"] != seq:
            # 같은 세대의 재시도: 항목은 세대가 같으면 같으므로 봉인 끝만 처음 값으로 맞춘다
            seq = row["to_seal_seq"]
            tail = _tail_at(conn, instance_id, seq)
        path = files.negative_path(export_dir, instance_id, epoch)
    else:
        path = files.checkpoint_path(export_dir, instance_id, datetime.now(UTC))
    body: dict[str, Any] = {
        "format": files.FORMAT, "kind": kind, "instance_id": instance_id, "state_epoch": epoch,
        "to_seal_seq": seq, "tail_hash": tail, "items": snap["items"],
        "written_at": files.now(),
    }
    sha = files.content_sha256({k: v for k, v in body.items() if k != "written_at"})
    relative = str(path.relative_to(export_dir)).replace("\\", "/")
    if republish and row is not None and row["status"] == "written":
        # 복원 게시: 보관으로 사라진 파일을 다시 쓴다. 봉인 끝은 행에 적힌 값을 그대로 써서 행의
        # 해시·봉인 끝과 파일이 계속 일치한다(같은 세대의 항목은 같다).
        if row["payload_sha256"] != sha:
            raise ExportFailed("같은 세대의 부정 상태 내용이 행과 다릅니다.")
        guard()
        files.atomic_write(path, files.sign(body, settings.export_hmac_key))
        again = files.read_verified(path, keys(settings))
        return {**again, "path": relative, "latest_written": False}
    if row is None:
        row = fetchone(
            conn,
            "INSERT INTO mint.exports (id, instance_id, kind, state_epoch, to_seal_seq,"
            " payload_sha256, path) VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s)"
            " RETURNING *",
            (instance_id, kind, epoch, seq, sha, relative),
        )
    elif row["payload_sha256"] != sha:
        raise ExportFailed("같은 세대의 부정 상태 내용이 처음 시도와 다릅니다.")
    elif row["status"] == "failed":
        conn.execute("UPDATE mint.exports SET status = 'pending' WHERE id = %s", (row["id"],))
    row = fetchone(
        conn, "UPDATE mint.exports SET attempts = attempts + 1 WHERE id = %s RETURNING *",
        (row["id"],),
    )
    try:
        guard()  # 파일 쓰기 직전: 되돌림 상태와 임대 유효성
        signed = files.sign(body, settings.export_hmac_key)
        files.atomic_write(path, signed)
        again = files.read_verified(path, keys(settings))  # 수령: 다시 읽어 해시·HMAC 대조
        again_content = {k: v for k, v in again.items() if k != "written_at"}
        if files.content_sha256(again_content) != row["payload_sha256"]:
            raise files.ExportUnverified("content changed")
        latest_written = (
            _write_latest(settings, instance_id, again, force_latest) if write_latest else False
        )
    except (OSError, files.ExportUnverified) as error:
        conn.execute("UPDATE mint.exports SET status = 'failed' WHERE id = %s", (row["id"],))
        _event(conn, instance_id, EventKind.EXPORT_FAILED, row,
               {"kind": kind, "state_epoch": epoch, "reason": type(error).__name__}, actor)
        alerts.raise_alert(
            conn, instance_id, kind="export_failed", severity="high",
            dedup_key=f"export_failed:{kind}",
            subject={"kind": kind, "state_epoch": epoch, "reason": type(error).__name__},
        )
        raise ExportFailed(f"내보내기 파일을 쓰지 못했습니다: {type(error).__name__}") from None
    conn.execute(
        "UPDATE mint.exports SET status = 'written', written_at = now() WHERE id = %s",
        (row["id"],),
    )
    _event(conn, instance_id, EventKind.EXPORT_WRITTEN, row,
           {"kind": kind, "state_epoch": epoch, "to_seal_seq": seq, "path": relative,
            "payload_sha256": row["payload_sha256"], "latest_written": latest_written}, actor)
    return {**again, "path": relative, "latest_written": latest_written}


def write_latest_file(
    settings: Stage2Settings, instance_id: str, document: dict[str, Any], force: bool
) -> bool:
    """``latest.json``만 쓴다(복원 게시가 마지막에 부른다)."""
    return _write_latest(settings, instance_id, document, force)


def _write_latest(
    settings: Stage2Settings, instance_id: str, document: dict[str, Any], force: bool
) -> bool:
    path = files.latest_path(settings.export_dir, instance_id)
    if not force:
        try:
            existing = files.read_verified(path, keys(settings))
            if int(existing["state_epoch"]) > int(document["state_epoch"]):
                return False  # 더 낮은 세대로 덮지 않는다
        except (FileNotFoundError, files.ExportUnverified, KeyError, ValueError):
            pass  # 읽을 수 없는 옛 파일은 판정이 이미 통과한 뒤이므로 새 값으로 바꾼다
    files.atomic_write(path, latest_document(settings, instance_id, document))
    return True


def latest_document(
    settings: Stage2Settings, instance_id: str, document: dict[str, Any]
) -> dict[str, Any]:
    """체크포인트 문서에서 만든 서명된 ``latest.json`` 내용."""
    return files.sign({
        "format": files.FORMAT, "instance_id": instance_id,
        "state_epoch": document["state_epoch"], "to_seal_seq": document["to_seal_seq"],
        "tail_hash": document["tail_hash"], "written_at": document["written_at"],
    }, settings.export_hmac_key)


def resign_newest_negative(settings: Stage2Settings, instance_id: str) -> bool:
    """가장 최근 부정 상태 파일이 옛 키로 서명되어 있으면 같은 내용을 현재 키로 다시 서명한다."""
    path = files.newest_negative(settings.export_dir, instance_id)
    if path is None:
        return False
    document = files.read_verified(path, keys(settings))
    if document["key_id"] == files.key_id(settings.export_hmac_key):
        return False
    files.atomic_write(path, files.sign(document, settings.export_hmac_key))
    return True


def _epoch_of(job: JobContext) -> int:
    key = job.job.get("idempotency_key") or ""
    prefix, _, number = key.partition(":")
    return int(number) if prefix == "export_negative" and number.isdigit() else 0


def _refuse_when_latest_vanished(job: JobContext) -> None:
    """이미 쓴 내보내기가 있는데 ``latest.json``이 없으면 새로 만들지 않고 멈춘다.

    작업 실행기의 판정은 주기 동안 직전 값을 쓰므로, 파일이 사라진 직후에 도는 내보내기가
    파일을 조용히 되살려 소실 차단을 놓치게 하면 안 된다. 복구는 복원 절차만 한다.
    """
    if files.latest_path(job.settings.export_dir, job.instance_id).exists():
        return
    row = fetchone(
        job.conn,
        "SELECT EXISTS (SELECT 1 FROM mint.exports WHERE instance_id = %s"
        " AND status = 'written') AS written",
        (job.instance_id,),
    )
    if row and row["written"]:
        raise RestoreBlocked(judge.EXPORT_MISSING)


def export_negative_state(job: JobContext) -> None:
    _refuse_when_latest_vanished(job)
    write_export(
        job.conn, job.instance_id, job.settings, "negative_state",
        min_epoch=_epoch_of(job), guard=job.external_write,
    )


def export_checkpoint(job: JobContext) -> None:
    _refuse_when_latest_vanished(job)
    write_export(job.conn, job.instance_id, job.settings, "checkpoint", guard=job.external_write)
    job.external_write()
    try:
        resign_newest_negative(job.settings, job.instance_id)
    except (OSError, files.ExportUnverified):
        raise ExportFailed("옛 키로 서명된 부정 상태 파일을 다시 서명하지 못했습니다.") from None

