"""제어 평면 스키마(``mint``)의 백업과 복원.

백업 파일은 머리 한 줄(JSON)과 본문으로 이루어진다. 본문은 ``pg_dump`` 사용자 지정 형식이거나
(``pg_dump``가 있을 때) 표별 논리 내보내기(JSON)이다. LiteLLM 데이터베이스는 읽지도 쓰지도 않는다.
암호화는 이미 설치된 ``cryptography``의 AES-GCM만 쓰며, 없으면 암호문을 만들지 않고 거부한다.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from graphlib import TopologicalSorter
from importlib import metadata
from pathlib import Path

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError

MAGIC = b"MINTBK1\n"
PASSPHRASE_ENV = "MINT_BACKUP_PASSPHRASE"
RESTORE_URL_ENV = "MINT_RESTORE_DATABASE_URL"


def mint_version() -> str:
    try:
        return metadata.version("mint-litellm")
    except metadata.PackageNotFoundError:
        return "unknown"


def migration_level(conn: psycopg.Connection) -> str:
    row = fetchone(conn, "SELECT max(name) AS last, count(*) AS n FROM mint.schema_migrations")
    return f"{row['last']}#{row['n']}"


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise ControlError(
            f"{PASSPHRASE_ENV}가 설정되어 있지만 암호화 모듈(cryptography)이 없습니다. "
            "암호화 없이 백업하려면 이 환경 변수를 비우십시오."
        ) from None
    return AESGCM, Scrypt


def _key(passphrase: str, salt: bytes) -> bytes:
    _, scrypt = _crypto()
    return scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())


def _tables(conn: psycopg.Connection) -> list[str]:
    """데이터가 있는 표를 외래 키 의존 순서(부모 먼저)로 돌려준다. 파티션 자식은 부모가 포함한다."""
    names = [r["relname"] for r in fetchall(
        conn,
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = 'mint' AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
        " AND c.relname <> 'schema_migrations' ORDER BY 1")]
    edges = fetchall(
        conn,
        "SELECT cc.relname AS child, pc.relname AS parent FROM pg_constraint k"
        " JOIN pg_class cc ON cc.oid = k.conrelid JOIN pg_class pc ON pc.oid = k.confrelid"
        " JOIN pg_namespace n ON n.oid = cc.relnamespace"
        " WHERE k.contype = 'f' AND k.conparentid = 0 AND n.nspname = 'mint'")
    graph: dict[str, set[str]] = {name: set() for name in names}
    for e in edges:
        if e["child"] in graph and e["parent"] in graph and e["child"] != e["parent"]:
            graph[e["child"]].add(e["parent"])
    return list(TopologicalSorter(graph).static_order())


def _columns(conn: psycopg.Connection, table: str) -> list[str]:
    return [r["attname"] for r in fetchall(
        conn,
        "SELECT attname FROM pg_attribute WHERE attrelid = ('mint.' || quote_ident(%s))::regclass"
        " AND attnum > 0 AND NOT attisdropped AND attgenerated = '' ORDER BY attnum", (table,))]


def _json_body(url: str) -> tuple[bytes, str]:
    """한 번의 반복 가능 읽기 스냅숏에서 모든 표를 읽는다. 돌려주는 값: 본문, 마이그레이션 수준."""
    with psycopg.connect(url) as conn:
        conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
        conn.read_only = True
        tables = _tables(conn)
        data = {t: [r["r"] for r in fetchall(conn, f'SELECT to_jsonb(x) AS r FROM mint."{t}" x')]
                for t in tables}
        level = migration_level(conn)
    # ponytail: 전부 메모리에 올린다. 이벤트가 매우 커지면 pg_dump 경로를 쓴다.
    return json.dumps({"order": tables, "tables": data}, ensure_ascii=False).encode(), level


def _pg_dump(url: str) -> tuple[bytes, str]:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "dump"
        done = subprocess.run(
            ["pg_dump", "--format=custom", "--schema=mint", "--no-owner", "--file", str(out),
             "--dbname", url], capture_output=True, text=True)
        if done.returncode:
            raise ControlError(f"pg_dump가 실패했습니다: {done.stderr.strip()[:300]}")
        body = out.read_bytes()
    with psycopg.connect(url) as conn:
        return body, migration_level(conn)


def create(url: str, path: Path, instance_id: str, *, passphrase: str | None,
           mode: str = "auto") -> dict:
    """백업 파일을 만든다. 돌려주는 값은 머리 정보(사건 기록에도 쓴다)."""
    if mode == "auto":
        mode = "pg_dump" if shutil.which("pg_dump") else "json"
    if mode == "pg_dump" and not shutil.which("pg_dump"):
        raise ControlError("pg_dump가 없습니다. --format json을 쓰십시오.")
    target = Path(path)
    if target.exists():
        raise ControlError(f"{target}이(가) 이미 있습니다.")
    if passphrase:
        _crypto()
    body, level = (_pg_dump if mode == "pg_dump" else _json_body)(url)
    head = {"format": "mint-backup-1", "mode": mode, "mint_version": mint_version(),
            "migration_level": level, "instance_id": instance_id,
            "created_at": datetime.now(UTC).isoformat(),
            "body_sha256": hashlib.sha256(body).hexdigest(), "encrypted": bool(passphrase)}
    if passphrase:
        aes, _ = _crypto()
        salt, nonce = os.urandom(16), os.urandom(12)
        head["salt"], head["nonce"] = (base64.b64encode(x).decode() for x in (salt, nonce))
        line = json.dumps(head, sort_keys=True).encode()
        body = aes(_key(passphrase, salt)).encrypt(nonce, body, line)
    else:
        line = json.dumps(head, sort_keys=True).encode()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(MAGIC + line + b"\n" + body)
    return {k: v for k, v in head.items() if k not in ("salt", "nonce")}


def read(path: Path, passphrase: str | None) -> tuple[dict, bytes]:
    """머리 정보와 복호한 본문을 돌려준다. 변조·잘못된 암호는 오류이다."""
    raw = Path(path).read_bytes()
    if not raw.startswith(MAGIC):
        raise ControlError("MINT 백업 파일이 아닙니다.")
    line, _, body = raw[len(MAGIC):].partition(b"\n")
    head = json.loads(line)
    if head.get("encrypted"):
        if not passphrase:
            raise ControlError(f"암호화된 백업입니다. {PASSPHRASE_ENV}를 설정하십시오.")
        aes, _ = _crypto()
        try:
            body = aes(_key(passphrase, base64.b64decode(head["salt"]))).decrypt(
                base64.b64decode(head["nonce"]), body, line)
        except Exception:
            raise ControlError("복호에 실패했습니다. 암호가 틀렸거나 변조되었습니다.") from None
    elif passphrase:
        raise ControlError(f"{PASSPHRASE_ENV}가 설정되어 있지만 이 백업은 암호화되지 않았습니다.")
    if hashlib.sha256(body).hexdigest() != head["body_sha256"]:
        raise ControlError("백업 본문의 해시가 맞지 않습니다. 파일이 손상되었습니다.")
    return head, body


def check_restorable(conn: psycopg.Connection, head: dict, instance_id: str) -> None:
    level = migration_level(conn)
    if head["migration_level"] != level:
        raise ControlError(
            f"마이그레이션 수준이 다릅니다(백업 {head['migration_level']}, 현재 {level}). "
            "같은 판본으로 올린 뒤(./mint.sh upgrade) 다시 실행하십시오.")
    if head["instance_id"] != instance_id:
        raise ControlError(
            f"백업의 인스턴스 {head['instance_id']}이(가) 현재 {instance_id}와 다릅니다.")


def restore(url: str, head: dict, body: bytes) -> None:
    """``url`` 데이터베이스의 ``mint`` 표를 백업 내용으로 바꾼다(한 트랜잭션).

    JSON 경로는 세션 복제 역할로 추가 전용·전이 트리거를 건너뛰므로 슈퍼유저 접속이 필요하다.
    """
    if head["mode"] == "pg_dump":
        if not shutil.which("pg_restore"):
            raise ControlError("pg_restore가 없습니다.")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "dump"
            src.write_bytes(body)
            done = subprocess.run(
                ["pg_restore", "--clean", "--if-exists", "--no-owner", "--single-transaction",
                 "--schema=mint", "--dbname", url, str(src)], capture_output=True, text=True)
        if done.returncode:
            raise ControlError(f"pg_restore가 실패했습니다: {done.stderr.strip()[:300]}")
        return
    doc = json.loads(body)
    with psycopg.connect(url) as conn:
        try:
            conn.execute("SET LOCAL session_replication_role = replica")
        except psycopg.errors.InsufficientPrivilege:
            raise ControlError(
                f"복원에는 데이터베이스 관리 권한이 필요합니다. {RESTORE_URL_ENV}에 관리 계정의 "
                "주소를 주십시오.") from None
        for t in reversed(doc["order"]):
            conn.execute(f'DELETE FROM mint."{t}"')
        for t in doc["order"]:
            rows = doc["tables"][t]
            if not rows:
                continue
            cols = ", ".join(f'"{c}"' for c in _columns(conn, t))
            conn.execute(
                f'INSERT INTO mint."{t}" ({cols}) SELECT {cols}'
                f' FROM jsonb_populate_recordset(NULL::mint."{t}", %s::jsonb)', (json.dumps(rows),))
