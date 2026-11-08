"""되돌림 판정(내용 대조). 플러그인과 작업 실행기가 같은 함수를 쓴다.

판정은 세 단계다. ① 파일을 읽고 서명을 확인한다(``read_files``, 파일 입출력). ② DB에서 사실을
한 문장으로 읽는다(``FACTS_SQL``, 동기·비동기 연결 어느 쪽이든). ③ 순수 함수 ``Judge.decide``가
네 경우(파일 없음·읽기 실패·내용 불일치·정상)를 판정한다.

상태: ``skip``(판정 안 함, 첫 설치), ``ok``, ``hold``(내용 대조가 처음 어긋남: 작업 실행기만
봉인·내보내기를 보류하고 호출은 막지 않는다), ``blocked``(모든 호출 차단).
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from psycopg.types.json import Jsonb

from mint_litellm.control.db.connection import fetchone
from mint_litellm.restore import files

SKIP, OK, HOLD, BLOCKED = "skip", "ok", "hold", "blocked"
RESTORE_PENDING = "restore_pending"
EXPORT_MISSING = "export_missing"
EXPORT_UNVERIFIED = "export_unverified"
EXPORT_CONFIG_MISSING = "export_config_missing"

# 부정 상태 항목 대조. 항목마다 DB 행을 파일의 행 스냅숏과 비교한다.
# - 판본이 파일보다 낮으면 되돌림(``reapply``).
# - 판본이 같으면 행 내용이 파일 스냅숏과 같아야 한다(다르면 ``content``). 두 쪽에 모두 있는
#   열만 비교한다(스키마 변경으로 열이 늘거나 줄어도 오탐하지 않는다). 시각은 UTC 문자열로 맞춘다.
# - 판본이 더 높으면 그 행이 여전히 부정 상태이거나, 원장에 같은 id(사건 키의 개체 id: 서버는
#   ``servers.id``)의 해제 사건(``denial_lifted``·``server_resumed``)이 있어야 한다. 사건의 판본은
#   파일 판본보다 크고 행의 현재 판본 이하여야 한다(파일 이후의 그 전이에 결속). 봉인 여부는
#   묻지 않는다(미봉인 사건 때문에 보류가 풀리지 않는 교착을 없앤다). 아니면 ``reapply``.
#   해제 전이가 있는 것은 거부 해제와 서버 재개뿐이다(나머지 종류의 상태 기계는 종결 상태로만
#   가며 해제 사건이 없다). 판본이 더 높고 아직 부정 상태인 행은 신원 열(범위·서버·도구·조직 등)이
#   파일과 같아야 한다(다르면 ``content``).
# - 운영자(``operator``)는 판본이 같아도 행 전체가 아니라 권한만 비교한다(사용자 결속이 다르면
#   내용 불일치, 역할이 높거나 만료가 늦거나 활성 토큰 지문이 다르면 되돌림). 판본이 더 높아도
#   권한이 파일보다 낮거나 같으면 정상이다. 파일보다 만료가 늦어졌거나 사라졌다면 되돌림이고,
#   역할이 올랐다면 원장에 그 판본 구간의 역할 변경 사건이 있고 그 구간의 마지막 사건이 현재
#   역할로 바꾼 것이어야 한다(정당한 승격). 비교하는 행에는 토큰 해시 대신
#   지문(``token_fp``)이 있어 판본이 같을 때 교체된 토큰이 잡힌다. 지문이 없는(만료된)
#   운영자가 DB에 없으면 문제이고, 활성 운영자가 DB에 없는 것은 문제가 아니다(권한이 없는 쪽이다).
# 값이 안 바뀐 UPDATE도 판본을 올리므로 판본만으로는 되돌림을 가릴 수 있다. 정상 해제·변경은 새
# 부정 상태 파일을 내므로 파일이 따라온다.
ITEM_CHECK_CTE = """
f AS (
  SELECT * FROM jsonb_to_recordset(%(items)s::jsonb)
    AS x(kind text, id text, state_version bigint, state text, row jsonb)
), rows AS (
  SELECT 'approval' AS kind, t.id::text AS id, t.id::text AS ev, t.state_version,
         t.status AS state, t.status = 'revoked' AS neg, mint.row_json(t) AS row
    FROM mint.approvals t
    WHERE t.instance_id = %(i)s AND t.id::text IN (SELECT id FROM f WHERE kind = 'approval')
  UNION ALL SELECT 'denial', t.id::text, t.id::text, t.state_version,
      CASE WHEN t.lifted_at IS NULL THEN 'active' ELSE 'lifted' END,
      t.lifted_at IS NULL, mint.row_json(t)
    FROM mint.denials t
    WHERE t.instance_id = %(i)s AND t.id::text IN (SELECT id FROM f WHERE kind = 'denial')
  UNION ALL SELECT 'server', t.server_id, t.id::text, t.state_version, t.status,
      t.status IN ('rejected', 'suspended', 'terminating', 'terminated'), mint.row_json(t)
    FROM mint.servers t
    WHERE t.instance_id = %(i)s AND t.server_id IN (SELECT id FROM f WHERE kind = 'server')
  UNION ALL SELECT 'relation', t.id::text, t.id::text, t.state_version, t.status,
      t.status IN ('terminating', 'terminated'), mint.row_json(t)
    FROM mint.usage_relations t
    WHERE t.instance_id = %(i)s AND t.id::text IN (SELECT id FROM f WHERE kind = 'relation')
  UNION ALL SELECT 'org', t.org_id, t.org_id, t.state_version, t.status, t.status = 'closed',
      mint.row_json(t)
    FROM mint.orgs t
    WHERE t.instance_id = %(i)s AND t.org_id IN (SELECT id FROM f WHERE kind = 'org')
  UNION ALL SELECT 'allowlist', t.id::text, t.id::text, t.state_version, t.status,
      t.status = 'lifted',
      mint.row_json(t)
    FROM mint.allowlists t
    WHERE t.instance_id = %(i)s AND t.id::text IN (SELECT id FROM f WHERE kind = 'allowlist')
  UNION ALL SELECT 'consent', t.id::text, t.id::text, t.state_version,
      CASE WHEN t.revoked_at IS NULL THEN 'active' ELSE 'revoked' END,
      t.revoked_at IS NOT NULL, mint.row_json(t)
    FROM mint.consents t
    WHERE t.instance_id = %(i)s AND t.id::text IN (SELECT id FROM f WHERE kind = 'consent')
  UNION ALL SELECT 'operator', t.name, t.name, t.state_version,
      CASE WHEN t.expires_at IS NULL THEN t.role ELSE 'removed' END, true, mint.row_json(t)
    FROM mint.operator_state t
    WHERE t.instance_id = %(i)s AND t.name IN (SELECT id FROM f WHERE kind = 'operator')
), checked AS (
  SELECT f.kind, f.id, r.state AS db_state, CASE
    WHEN r.id IS NULL AND (f.kind <> 'operator' OR f.row ->> 'expires_at' IS NOT NULL)
      THEN 'missing_row'
    WHEN r.state_version < f.state_version THEN 'reapply'
    WHEN f.kind = 'operator' AND r.state_version = f.state_version AND f.row IS NOT NULL THEN
      CASE
        WHEN r.row -> 'user_id' IS DISTINCT FROM f.row -> 'user_id' THEN 'content'
        WHEN mint.operator_rank(r.row ->> 'role') > mint.operator_rank(f.row ->> 'role')
          OR (f.row ->> 'expires_at' IS NOT NULL AND (r.row ->> 'expires_at' IS NULL
              OR (r.row ->> 'expires_at')::timestamptz > (f.row ->> 'expires_at')::timestamptz))
          OR (r.row ->> 'expires_at' IS NULL
              AND r.row -> 'token_fp' IS DISTINCT FROM f.row -> 'token_fp') THEN 'reapply'
      END
    WHEN r.state_version = f.state_version AND f.row IS NOT NULL AND
         (r.row - ARRAY(SELECT jsonb_object_keys(r.row) EXCEPT SELECT jsonb_object_keys(f.row)))
         <> (f.row - ARRAY(SELECT jsonb_object_keys(f.row) EXCEPT SELECT jsonb_object_keys(r.row)))
      THEN 'content'
    WHEN r.state_version = f.state_version AND r.state <> f.state THEN 'reapply'
    WHEN f.kind = 'operator' AND r.state_version > f.state_version AND f.row IS NOT NULL AND (
         (f.row ->> 'expires_at' IS NOT NULL AND (r.row ->> 'expires_at' IS NULL
            OR (r.row ->> 'expires_at')::timestamptz > (f.row ->> 'expires_at')::timestamptz))
         OR (mint.operator_rank(r.row ->> 'role') > mint.operator_rank(f.row ->> 'role')
             AND NOT EXISTS (
               SELECT 1 FROM (
                 SELECT e.payload ->> 'to' AS to_role FROM mint.events e
                 WHERE e.instance_id = %(i)s AND e.kind = 'operator_role_changed'
                   AND split_part(e.source_key, ':', 1) = 'operator'
                   AND split_part(e.source_key, ':', 2) = r.ev
                   AND split_part(e.source_key, ':', 3) ~ '^[0-9]{1,18}$'
                   AND split_part(e.source_key, ':', 3)::bigint
                       BETWEEN f.state_version + 1 AND r.state_version
                 ORDER BY split_part(e.source_key, ':', 3)::bigint DESC LIMIT 1) last
               WHERE last.to_role = r.row ->> 'role')))
      THEN 'reapply'
    WHEN r.state_version > f.state_version AND NOT r.neg AND NOT EXISTS (
         SELECT 1 FROM mint.events e
         WHERE e.instance_id = %(i)s
           AND e.kind = CASE f.kind WHEN 'denial' THEN 'denial_lifted'
                                    WHEN 'server' THEN 'server_resumed' END
           AND split_part(e.source_key, ':', 1) = f.kind
           AND split_part(e.source_key, ':', 2) = r.ev
           AND (CASE WHEN split_part(e.source_key, ':', 3) ~ '^[0-9]{1,18}$'
                     THEN split_part(e.source_key, ':', 3)::bigint END)
               BETWEEN f.state_version + 1 AND r.state_version)
      THEN 'reapply'
    WHEN r.state_version > f.state_version AND r.neg AND f.row IS NOT NULL AND EXISTS (
         SELECT 1 FROM unnest(CASE f.kind
           WHEN 'denial' THEN ARRAY['org_id', 'scope_type', 'scope_id', 'server_id', 'tools']
           WHEN 'approval' THEN ARRAY['org_id', 'scope_type', 'scope_id', 'server_id', 'tools',
                                      'relation_id']
           WHEN 'server' THEN ARRAY['server_id']
           WHEN 'relation' THEN ARRAY['org_id', 'team_id', 'server_id', 'purpose']
           WHEN 'org' THEN ARRAY['org_id']
           WHEN 'allowlist' THEN ARRAY['org_id', 'kind', 'value']
           WHEN 'consent' THEN ARRAY['org_id', 'server_id', 'human_user_id', 'purpose']
           WHEN 'operator' THEN ARRAY['name', 'user_id']
         END) AS k
         WHERE r.row -> k IS DISTINCT FROM f.row -> k)
      THEN 'content'
  END AS problem
  FROM f LEFT JOIN rows r ON r.kind = f.kind AND r.id = f.id
)
"""

ITEM_PROBLEMS_SQL = (
    "WITH" + ITEM_CHECK_CTE
    + "SELECT kind, id, problem, db_state FROM checked WHERE problem IS NOT NULL"
)

FACTS_SQL = "WITH" + ITEM_CHECK_CTE + """
SELECT (SELECT epoch FROM mint.state_epoch WHERE instance_id = %(i)s) AS epoch,
  (EXISTS (SELECT 1 FROM mint.exports WHERE instance_id = %(i)s AND status = 'written')
   OR EXISTS (SELECT 1 FROM mint.restore_requests WHERE instance_id = %(i)s
              AND status = 'pending')) AS has_written,
  EXISTS (SELECT 1 FROM mint.exports WHERE instance_id = %(i)s AND status = 'written'
          AND kind = 'negative_state') AS has_negative_written,
  (SELECT count(*) FROM checked WHERE problem IS NOT NULL) AS missing,
  CASE WHEN %(seq)s::bigint IS NULL THEN true ELSE EXISTS (
    SELECT 1 FROM mint.seal_batches WHERE instance_id = %(i)s AND to_seal_seq = %(seq)s::bigint
      AND encode(tail_hash, 'hex') = %(tail)s) END AS anchor_ok
"""


@dataclass(frozen=True)
class Verdict:
    state: str
    cause: str | None = None
    file_epoch: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.state == BLOCKED

    @property
    def held(self) -> bool:
        """봉인·내보내기를 멈춰야 하는가(처음 어긋남 또는 차단)."""
        return self.state in (HOLD, BLOCKED)


@dataclass(frozen=True)
class FileState:
    latest: dict[str, Any] | None = None
    negative: dict[str, Any] | None = None
    error: str | None = None  # None | 'missing' | 'unverified'


def read_files(export_dir: Path, instance_id: str, keys: Sequence[bytes]) -> FileState:
    try:
        latest = files.read_verified(files.latest_path(export_dir, instance_id), keys)
    except FileNotFoundError:
        return FileState(error="missing")
    except files.ExportUnverified:
        return FileState(error="unverified")
    negative = None
    path = files.newest_negative(export_dir, instance_id)
    if path is not None:
        try:
            negative = files.read_verified(path, keys)
        except (FileNotFoundError, files.ExportUnverified):
            return FileState(latest=latest, error="unverified")
    return FileState(latest=latest, negative=negative)


def facts_params(state: FileState, instance_id: str) -> dict[str, Any]:
    latest, negative = state.latest or {}, state.negative or {}
    return {
        "i": instance_id,
        "items": Jsonb(negative.get("items") or []),
        "seq": latest.get("to_seal_seq"),
        "tail": latest.get("tail_hash"),
    }


class Judge:
    """파일 상태와 DB 사실로 판정한다. 내용 불일치 횟수(연속)를 기억한다."""

    def __init__(self) -> None:
        self.misses = 0

    def decide(self, state: FileState, facts: dict[str, Any] | None) -> Verdict:
        if state.error == "unverified":
            self.misses = 0
            return Verdict(BLOCKED, EXPORT_UNVERIFIED)
        assert facts is not None
        if state.error == "missing":
            self.misses = 0
            if facts["has_written"]:
                return Verdict(BLOCKED, EXPORT_MISSING)
            return Verdict(SKIP)
        assert state.latest is not None
        if state.negative is None and facts["has_negative_written"]:
            self.misses = 0  # 부정 상태 파일이 사라졌다(볼륨 누락·디렉터리 교체)
            return Verdict(BLOCKED, EXPORT_MISSING)
        file_epoch = int(state.latest["state_epoch"])
        epoch = facts["epoch"] if facts["epoch"] is not None else 0
        detail = {
            "missing_items": int(facts["missing"]),
            "anchor_ok": bool(facts["anchor_ok"]),
            "db_epoch": epoch,
            "file_epoch": file_epoch,
        }
        # DB 세대가 파일보다 작은 것은 보조 신호다(복구 뒤 소비로 추월하면 보이지 않는다).
        mismatch = detail["missing_items"] > 0 or not detail["anchor_ok"] or epoch < file_epoch
        if not mismatch:
            self.misses = 0
            return Verdict(OK, file_epoch=file_epoch, detail=detail)
        self.misses += 1
        state_name = BLOCKED if self.misses >= 2 else HOLD
        return Verdict(state_name, RESTORE_PENDING, file_epoch, detail)

    def evaluate(self, conn, export_dir: Path, instance_id: str, keys: Sequence[bytes]) -> Verdict:
        """동기 연결용 한 번의 판정."""
        state = read_files(export_dir, instance_id, keys)
        facts = None
        if state.error != "unverified":
            facts = fetchone(conn, FACTS_SQL, facts_params(state, instance_id))
        return self.decide(state, facts)
