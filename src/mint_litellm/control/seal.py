"""원장 봉인: 미봉인 사건을 순서대로 해시 연쇄로 묶고 배치 한 행을 남긴다.

``row_hash = SHA-256(정규 JSON(가변 열 제외 행) ‖ prev)``. 정규 JSON은 키를 정렬하고 공백 없이
UTF-8로 쓴다. 가변 열은 봉인 열 네 개(``seal_seq``·``prev_hash``·``row_hash``·``sealed_at``)다.
최초 ``prev``는 32바이트 0이다. 키가 주어지면 배치 끝 해시를 내보내기 키로 서명해 배치 행에 둔다
(DB를 쓸 수 있는 쪽이 연쇄를 통째로 다시 계산해도 키 없이는 서명을 만들 수 없다). 봉인은 사건을
남기지 않는다(봉인 사건이 다음 봉인 대상을 만들어 매분 반복되는 것을 막는다).
"""

import hashlib
from collections.abc import Sequence
from datetime import UTC
from typing import Any

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.restore import files
from mint_litellm.restore.files import canonical_json

ZERO = bytes(32)
BATCH_LIMIT = 5000
# 늦게 커밋되는 행이 이미 봉인된 순번 뒤로 밀리지 않도록 막 들어온 행은 봉인하지 않는다.
SETTLE_SECONDS = 5

_COLUMNS = (
    "event_id, instance_id, inserted_at, kind, source_key, invocation_id, attempt_id,"
    " actor, subject, payload"
)


def canonical(row: dict[str, Any]) -> bytes:
    body = {
        "event_id": str(row["event_id"]),
        "instance_id": row["instance_id"],
        "inserted_at": row["inserted_at"].astimezone(UTC).isoformat(),
        "kind": row["kind"],
        "source_key": row["source_key"],
        "invocation_id": None if row["invocation_id"] is None else str(row["invocation_id"]),
        "attempt_id": row["attempt_id"],
        "actor": row["actor"],
        "subject": row["subject"],
        "payload": row["payload"],
    }
    return canonical_json(body)


def row_hash(row: dict[str, Any], prev: bytes) -> bytes:
    return hashlib.sha256(canonical(row) + prev).digest()


def _batch_document(
    instance_id: str, first: int, last: int, prev_tail: bytes, tail: bytes
) -> dict[str, Any]:
    return {"format": files.FORMAT, "kind": "seal_batch", "instance_id": instance_id,
            "from_seal_seq": first, "to_seal_seq": last, "prev_tail_hash": prev_tail.hex(),
            "tail_hash": tail.hex()}


def seal_once(
    conn: psycopg.Connection, instance_id: str, key: bytes | None = None
) -> tuple[int, int] | None:
    """미봉인 행이 있으면 배치 하나를 봉인하고 ``(from, to)``를 돌려준다. 없으면 None.

    한 트랜잭션이며 인스턴스별 자문 잠금으로 동시 봉인을 직렬화한다(순번·배치 끝의 유일성이
    두 번째 방어선이다).
    """
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"mint.seal:{instance_id}",))
        last = fetchone(
            conn,
            "SELECT to_seal_seq, tail_hash FROM mint.seal_batches WHERE instance_id = %s"
            " ORDER BY to_seal_seq DESC LIMIT 1",
            (instance_id,),
        )
        first, prev = 1, ZERO
        if last is not None:
            first, prev = last["to_seal_seq"] + 1, bytes(last["tail_hash"])
        rows = fetchall(
            conn,
            f"SELECT {_COLUMNS} FROM mint.events WHERE instance_id = %s AND seal_seq IS NULL"
            " AND inserted_at < now() - make_interval(secs => %s)"
            " ORDER BY inserted_at, event_id LIMIT %s",
            (instance_id, SETTLE_SECONDS, BATCH_LIMIT),
        )
        if not rows:
            return None
        tail_prev, ids, seqs, prevs, hashes = prev, [], [], [], []
        for offset, row in enumerate(rows):
            digest = row_hash(row, prev)
            ids.append(row["event_id"])
            seqs.append(first + offset)
            prevs.append(prev)
            hashes.append(digest)
            prev = digest
        conn.execute(
            "UPDATE mint.events e SET seal_seq = v.s, prev_hash = v.p, row_hash = v.h,"
            " sealed_at = now() FROM unnest(%s::uuid[], %s::bigint[], %s::bytea[], %s::bytea[])"
            " AS v(i, s, p, h) WHERE e.event_id = v.i",
            (ids, seqs, prevs, hashes),
        )
        last_seq = first + len(rows) - 1
        signed = (
            files.sign(_batch_document(instance_id, first, last_seq, tail_prev, prev), key)
            if key else None
        )
        conn.execute(
            "INSERT INTO mint.seal_batches (instance_id, from_seal_seq, to_seal_seq,"
            " prev_tail_hash, tail_hash, tail_sig, sig_key_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (instance_id, first, last_seq, tail_prev, prev,
             signed and bytes.fromhex(signed["hmac"]), signed and signed["key_id"]),
        )
        return first, last_seq


def _signature_problem(
    instance_id: str, batch: dict[str, Any], keys: Sequence[bytes], required: bool
) -> str | None:
    if batch["tail_sig"] is None:
        return "서명이 없습니다." if required else None
    document = _batch_document(
        instance_id, batch["from_seal_seq"], batch["to_seal_seq"],
        bytes(batch["prev_tail_hash"]), bytes(batch["tail_hash"]))
    document["key_id"] = batch["sig_key_id"]
    document["hmac"] = bytes(batch["tail_sig"]).hex()
    try:
        files.verify(document, keys)
    except files.ExportUnverified as error:
        return f"서명이 맞지 않습니다({error})."
    return None


def _dropped_ranges(conn: psycopg.Connection, instance_id: str) -> list[tuple[int, int]]:
    rows = fetchall(
        conn, "SELECT seal_ranges -> %s AS r FROM mint.event_exports WHERE dropped_at IS NOT NULL",
        (instance_id,),
    )
    return [(r["r"][0], r["r"][1]) for r in rows if r["r"]]


def _in_ranges(seq: int, ranges: list[tuple[int, int]]) -> bool:
    return any(lo <= seq <= hi for lo, hi in ranges)


def verify(
    conn: psycopg.Connection,
    instance_id: str,
    from_seq: int | None = None,
    to_seq: int | None = None,
    checkpoint: tuple[int, str] | None = None,
    keys: Sequence[bytes] = (),
) -> dict[str, Any]:
    """연쇄 전체를 처음부터 다시 계산해 배치·행 해시와 맞는지 본다.

    ``from_seq``·``to_seq``는 보고할 구간만 좁힌다(연쇄는 언제나 처음부터 이어 확인한다).
    ``checkpoint``는 마지막 체크포인트 파일의 ``(to_seal_seq, tail_hash 16진)``이며
    ``seal_batches``의 같은 위치와 대조한다(DB 안에서 연쇄 전체를 다시 계산한 변조를 잡는다).
    ``keys``(내보내기 키)가 주어지면 배치 끝 해시의 서명도 확인한다. 서명은 첫 서명 배치부터
    빠짐없이 있어야 한다(서명 없는 옛 배치는 그 앞에서만 허용).
    """
    errors: list[str] = []
    batches = fetchall(
        conn,
        "SELECT from_seal_seq, to_seal_seq, prev_tail_hash, tail_hash, tail_sig, sig_key_id"
        " FROM mint.seal_batches"
        " WHERE instance_id = %s ORDER BY to_seal_seq",
        (instance_id,),
    )
    prev, expected, rows_checked, signing = ZERO, 1, 0, False
    gone = _dropped_ranges(conn, instance_id)
    for batch in batches:
        lo, hi = batch["from_seal_seq"], batch["to_seal_seq"]

        def report(text: str, start: int = lo, end: int = hi) -> None:
            if (from_seq is None or end >= from_seq) and (to_seq is None or start <= to_seq):
                errors.append(text)

        if keys:
            signing = signing or batch["tail_sig"] is not None
            problem = _signature_problem(instance_id, batch, keys, signing)
            if problem:
                report(f"배치 {lo}~{hi}: {problem}")
        if lo != expected:
            report(f"배치 {lo}~{hi}: 앞 배치와 이어지지 않습니다(기대 시작 {expected}).")
        if bytes(batch["prev_tail_hash"]) != prev:
            report(f"배치 {lo}~{hi}: prev_tail_hash가 앞 배치의 끝과 다릅니다.")
        rows = fetchall(
            conn,
            f"SELECT {_COLUMNS}, seal_seq, prev_hash, row_hash FROM mint.events"
            " WHERE instance_id = %s AND seal_seq BETWEEN %s AND %s ORDER BY seal_seq",
            (instance_id, lo, hi),
        )
        have = {row["seal_seq"] for row in rows}
        # 보관 기간이 지나 분할째 지운 달의 순번은 빠져 있어도 된다(내보내기 기록이 구간을 가진다).
        missing = [n for n in range(lo, hi + 1) if n not in have and not _in_ranges(n, gone)]
        if missing:
            report(f"배치 {lo}~{hi}: 봉인된 행이 {len(rows)}건이고 {hi - lo + 1}건이어야 합니다.")
        chain = bytes(batch["prev_tail_hash"])
        last = lo - 1
        for row in rows:
            if row["seal_seq"] != last + 1:
                chain = bytes(row["prev_hash"])  # 지운 구간 뒤에서 행 자신의 prev_hash로 이어 본다
            last = row["seal_seq"]
            digest = row_hash(row, chain)
            if bytes(row["prev_hash"]) != chain or bytes(row["row_hash"]) != digest:
                seq = row["seal_seq"]
                report(f"seal_seq {seq}: 행 해시가 다시 계산한 값과 다릅니다.", seq, seq)
            chain = bytes(row["row_hash"])  # 오류를 그 행에 가둔다
            rows_checked += 1
        if last == hi and chain != bytes(batch["tail_hash"]):
            report(f"배치 {lo}~{hi}: tail_hash가 마지막 행 해시와 다릅니다.")
        prev, expected = bytes(batch["tail_hash"]), hi + 1
    stray = fetchone(
        conn,
        "SELECT count(*) AS n FROM mint.events WHERE instance_id = %s AND seal_seq >= %s",
        (instance_id, expected),
    )["n"]
    if stray:
        errors.append(f"배치에 속하지 않은 봉인 행이 {stray}건 있습니다.")
    checkpoint_ok = None
    if checkpoint is not None:
        seq, tail = checkpoint
        found = fetchone(
            conn,
            "SELECT encode(tail_hash, 'hex') AS tail FROM mint.seal_batches"
            " WHERE instance_id = %s AND to_seal_seq = %s",
            (instance_id, seq),
        )
        checkpoint_ok = found is not None and found["tail"] == tail
        if not checkpoint_ok:
            errors.append(f"체크포인트의 봉인 끝({seq})이 DB의 배치와 다릅니다.")
    return {
        "ok": not errors,
        "batches": len(batches),
        "rows": rows_checked,
        "to_seal_seq": expected - 1,
        "checkpoint_ok": checkpoint_ok,
        "errors": errors,
    }
