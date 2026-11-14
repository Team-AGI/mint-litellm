"""사람이 확인하는 정책의 증빙: 첨부, 필수 증빙 확인, 기한 경보.

증빙 종류마다 대상 구분(신청·서버·이용 관계)과 쓰이는 자리가 정해져 있다. 필수 자리에서는
``require``가 현재 증빙이 없거나 기한이 지났으면 거절하고, 주기 작업은 같은 기준으로 경보를 연다.
증빙의 원문은 저장하지 않는다. 요약과 문서 위치·해시값만 남긴다.
"""

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from mint_litellm.control import alerts
from mint_litellm.control.context import Context
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, conflict, forbidden, not_found
from mint_litellm.control.services.base import enqueue_job, transact
from mint_litellm.types.events import EventKind
from mint_litellm.types.ids import new_uuid7

# 기한이 이 기간 안으로 다가오면 경보를 연다.
WARN_WITHIN = timedelta(days=7)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ROLES = ("admin", "approver")
# 이 종류의 증빙은 관리자만 붙일 수 있다(화면 단추도 같은 값을 따른다).
ADMIN_ONLY_KINDS = frozenset({"instance_exception"})


@dataclass(frozen=True)
class Kind:
    key: str
    policy: str  # 근거 정책 식별자(명령줄 출력에만 쓴다)
    subject: str  # intake | server | relation
    label: str
    days: int | None  # 기본 유효 일수. None이면 기한이 없다.
    gate: str  # approve | reapprove | finish | periodic
    not_applicable_ok: bool = False
    needs_hash: bool = False  # 문서 해시값이 있어야 붙일 수 있다
    when: str | None = None  # 이 조건의 대상에서만 요구한다(None이면 늘 요구)


_KIND_LIST = (
    Kind("trial_call", "POL-I-06", "intake", "시험 호출 결과", 90, "approve"),
    Kind("provider_terms", "POL-I-09", "intake", "제공자 자료 처리 조건 확인", 365, "approve"),
    Kind("least_privilege", "POL-E-19", "intake", "서버 계정 최소 권한 확인", 180, "approve"),
    Kind("prompt_review", "POL-I-07", "intake", "제공 지시문 검토", 90, "approve", True),
    Kind("transfer_approval", "POL-E-11", "intake", "서버 간 전달 승인", 365, "approve", True),
    Kind("version_review", "POL-O-10", "server", "되돌릴 판본의 보안 문제 확인", 30,
         "reapprove"),
    Kind("unpinned_acceptance", "POL-O-06", "server", "버전 미고정 패키지 사용 승인", 30,
         "unpinned"),
    Kind("vuln_exception", "POL-O-08", "server", "취약점 조치 예외", 30, "exception"),
    Kind("instance_exception", "POL-O-09", "server", "인스턴스 간 불일치 예외", 30, "exception"),
    Kind("deletion_proof", "POL-D-07", "relation", "자료 삭제·반환 증빙", None, "finish"),
    Kind("access_recheck", "POL-O-03", "server", "변경된 자료의 접근 권한 재확인", 90,
         "periodic", True),
    Kind("source_review", "POL-O-04", "server", "변경된 자료의 출처 확인", 90, "periodic", True),
    Kind("instruction_review", "POL-O-05", "server", "바뀐 지시문 재심사", 90, "periodic", True),
    Kind("command_input_review", "POL-E-13", "intake", "명령·질의 입력 전달 방식 점검 결과", 180,
         "approve", needs_hash=True, when="runs_commands"),
    Kind("access_revocation", "POL-D-05", "server", "서버 계정·문서 공유 권한 회수 확인", None,
         "retire"),
)
KINDS: dict[str, Kind] = {k.key: k for k in _KIND_LIST}

_SUBJECT_TABLE = {
    "intake": ("intakes", "id::text"),
    "server": ("servers", "server_id"),
    "relation": ("usage_relations", "id::text"),
}


# 명령·질의를 실행하는 서버: 로컬 실행(stdio)이거나 도구 이름에 실행·질의를 뜻하는 말이 있다.
_COMMAND_WORDS = frozenset(
    "exec execute shell command cmd bash eval script query sql search run".split()
)


def applies(conn: Any, instance_id: str, kind: Kind, subject_kind: str, subject_id: str) -> bool:
    """``kind.when`` 조건에 이 대상이 드는지. 조건이 없으면 늘 참이다."""
    if kind.when is None:
        return True
    table, column = _SUBJECT_TABLE[subject_kind]
    server = fetchone(
        conn, f"SELECT server_id FROM mint.{table} WHERE instance_id = %s AND {column} = %s",
        (instance_id, subject_id),
    )
    if server is None:
        return False
    args = (instance_id, server["server_id"])
    local = fetchone(
        conn,
        "SELECT 1 AS x FROM mint.deployment_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status IN ('candidate', 'approved') AND transport = 'stdio' LIMIT 1", args,
    )
    if local is not None:
        return True
    tools = fetchall(
        conn,
        "SELECT tool FROM mint.tool_contracts WHERE instance_id = %s AND server_id = %s"
        " AND status IN ('candidate', 'approved')", args,
    )
    return any(
        _COMMAND_WORDS & set(re.split(r"[^a-z0-9]+", t["tool"].lower())) for t in tools
    )


def kind_of(key: str) -> Kind:
    try:
        return KINDS[key]
    except KeyError:
        raise ControlError(f"알 수 없는 증빙 종류입니다: {key}") from None


def group_key(subject_kind: str, subject_id: str, server_id: str) -> str:
    """경보 묶음 키. 신청·서버 증빙은 서버마다 한 건, 이용 관계는 관계마다 한 건이다."""
    if subject_kind == "relation":
        return f"evidence:relation:{subject_id}"[:512]
    return f"evidence:server:{server_id}"[:512]


def state_of(row: dict | None, now: datetime) -> str:
    """valid | not_applicable | expiring | expired | missing."""
    if row is None:
        return "missing"
    until = row["valid_until"]
    if until is not None and until <= now:
        return "expired"
    if until is not None and until <= now + WARN_WITHIN:
        return "expiring"
    return "not_applicable" if row["result"] == "not_applicable" else "valid"


def current(conn: Any, instance_id: str, subject_kind: str, subject_id: str) -> dict[str, dict]:
    """대상의 증빙 종류별 가장 최근 행."""
    rows = fetchall(
        conn,
        "SELECT DISTINCT ON (kind) * FROM mint.policy_evidence WHERE instance_id = %s"
        " AND subject_kind = %s AND subject_id = %s ORDER BY kind, attached_at DESC, id DESC",
        (instance_id, subject_kind, subject_id),
    )
    return {r["kind"]: r for r in rows}


def show(ctx: Context, subject_kind: str, subject_id: str) -> list[dict]:
    """대상에 붙일 수 있는 증빙 종류마다 현재 상태. 모든 역할이 읽는다."""
    rows = current(ctx.conn, ctx.instance_id, subject_kind, str(subject_id))
    now = datetime.now(UTC)
    return [
        {**k.__dict__,
         "state": state_of(rows.get(k.key), now)
         if applies(ctx.conn, ctx.instance_id, k, subject_kind, str(subject_id))
         else "not_applicable",
         "row": rows.get(k.key)}
        for k in _KIND_LIST
        if k.subject == subject_kind
    ]


def missing(ctx: Context, gate: str, subject_kind: str, subject_id: str) -> list[dict]:
    """``gate`` 자리에서 필요한데 없거나 기한이 지난 증빙."""
    return [
        e for e in show(ctx, subject_kind, subject_id)
        if e["gate"] == gate and e["state"] in ("missing", "expired")
    ]


def require(ctx: Context, gate: str, subject_kind: str, subject_id: str) -> None:
    lacking = missing(ctx, gate, subject_kind, subject_id)
    if lacking:
        names = ", ".join(
            f"{e['label']}({'기한 지남' if e['state'] == 'expired' else '없음'})" for e in lacking
        )
        raise conflict(
            f"필요한 증빙이 없거나 기한이 지났습니다: {names}. 증빙을 첨부한 뒤 진행하십시오."
        )


def _check_subject(ctx: Context, kind: Kind, subject_id: str) -> str:
    """대상이 있는지 확인하고 그 대상의 서버 식별자를 돌려준다."""
    table, column = _SUBJECT_TABLE[kind.subject]
    row = fetchone(
        ctx.conn,
        f"SELECT server_id FROM mint.{table} WHERE instance_id = %s AND {column} = %s",
        (ctx.instance_id, subject_id),
    )
    if row is None:
        raise not_found(f"{subject_id} 대상이 없습니다.")
    return row["server_id"]


def attach(
    ctx: Context,
    kind_key: str,
    subject_id: str,
    *,
    summary: str,
    ref: str | None = None,
    sha256: str | None = None,
    valid_until: datetime | None = None,
    not_applicable: bool = False,
) -> str:
    """증빙 한 건을 붙이고 같은 대상·종류의 열린 경보를 닫는다. 새 증빙 식별자를 돌려준다."""
    if ctx.operator.role not in _ROLES:
        raise forbidden(f"증빙 첨부는 {ctx.operator.role} 역할로 실행할 수 없습니다.", exit_code=4)
    kind = kind_of(kind_key)
    if kind.key in ADMIN_ONLY_KINDS and ctx.operator.role != "admin":
        raise forbidden("인스턴스 간 불일치 예외는 admin만 붙일 수 있습니다.", exit_code=4)
    subject_id = str(subject_id)
    summary = (summary or "").strip()
    if not summary:
        raise ControlError("증빙 요약(해당 없음이면 그 사유)이 필요합니다.")
    if not_applicable and not kind.not_applicable_ok:
        raise ControlError(f"{kind.label}은(는) 해당 없음으로 처리할 수 없습니다.")
    if kind.needs_hash and not not_applicable and sha256 is None:
        raise ControlError(f"{kind.label}은(는) 문서 해시값(소문자 16진 64자)이 필요합니다.")
    if sha256 is not None and not _SHA256.fullmatch(sha256):
        raise ControlError("문서 해시값은 소문자 16진 64자여야 합니다.")
    now = datetime.now(UTC)
    ceiling = None if kind.days is None else now + timedelta(days=kind.days)
    if valid_until is None:
        valid_until = ceiling
    elif valid_until <= now:
        raise ControlError("유효 기한이 이미 지났습니다.")
    elif ceiling is not None and valid_until > ceiling:
        raise ControlError(f"{kind.label}의 유효 기한은 {kind.days}일을 넘을 수 없습니다.")
    row_id = new_uuid7()
    with transact(ctx):
        server_id = _check_subject(ctx, kind, subject_id)
        ctx.conn.execute(
            "INSERT INTO mint.policy_evidence (id, instance_id, kind, subject_kind, subject_id,"
            " result, summary, document_ref, document_sha256, attached_by, valid_until)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (row_id, ctx.instance_id, kind.key, kind.subject, subject_id,
             "not_applicable" if not_applicable else "confirmed", summary, ref, sha256,
             ctx.operator.name, valid_until),
        )
        # 묶음 경보는 닫고, 남은 누락은 다음 확인 작업이 최신 목록으로 다시 연다
        alerts.resolve(ctx.conn, ctx.instance_id, group_key(kind.subject, subject_id, server_id))
        if kind.key == "access_revocation":  # 폐기 마무리가 이 증빙을 기다린다
            enqueue_job(ctx, "server_finalize", subject_id)
        ctx.emit(
            EventKind.EVIDENCE_ATTACHED, row_id, 1,
            {"kind": kind.key, "policy": kind.policy, "subject_kind": kind.subject,
             "subject_id": subject_id,
             "result": "not_applicable" if not_applicable else "confirmed",
             "valid_until": valid_until.isoformat() if valid_until else None,
             "document_sha256": sha256},
        )
    return str(row_id)


# --- 기한 경보 ---------------------------------------------------------------------------


def _subjects(conn: Any, instance_id: str) -> list[tuple[str, str, str, str]]:
    """경보 대상: (대상 구분, 대상, 서버, 자리). 승인된 신청, 승인된 서버, 종료 중 관계."""
    intakes = fetchall(
        conn,
        "SELECT DISTINCT ON (i.server_id) i.id::text AS id, i.server_id FROM mint.intakes i"
        " JOIN mint.servers s ON s.instance_id = i.instance_id AND s.server_id = i.server_id"
        " WHERE i.instance_id = %s AND i.status = 'decided'"
        " AND i.decision IN ('approved', 'exception') AND s.contract_status = 'managed'"
        " AND s.status NOT IN ('rejected', 'terminating', 'terminated')"
        " ORDER BY i.server_id, i.decided_at DESC",
        (instance_id,),
    )
    servers = fetchall(
        conn,
        "SELECT server_id FROM mint.servers WHERE instance_id = %s AND status = 'approved'"
        " AND contract_status = 'managed'",
        (instance_id,),
    )
    relations = fetchall(
        conn,
        "SELECT id::text AS id, server_id FROM mint.usage_relations"
        " WHERE instance_id = %s AND status = 'terminating'",
        (instance_id,),
    )
    retired = fetchall(
        conn,
        "SELECT server_id FROM mint.servers WHERE instance_id = %s"
        " AND status IN ('terminating', 'terminated')",
        (instance_id,),
    )
    return (
        [("intake", r["id"], r["server_id"], "approve") for r in intakes]
        + [("server", r["server_id"], r["server_id"], "retire") for r in retired]
        + [("server", r["server_id"], r["server_id"], "periodic") for r in servers]
        + [("relation", r["id"], r["server_id"], "finish") for r in relations]
    )


def scan_alerts(conn: Any, instance_id: str) -> int:
    """필수 자리의 증빙이 없거나 기한이 지났거나 7일 안에 끝나면 경보를 연다. 새로 연 수를 돌려준다.

    대상은 승인된 신청, 승인된 관리 서버(주기 확인 증빙), 종료 중인 이용 관계다. 경보는 서버마다
    한 건(이용 관계는 관계마다 한 건)이고, 정책별 누락은 경보 본문의 ``items``에 담긴다.
    """
    now = datetime.now(UTC)
    groups: dict[str, dict[str, Any]] = {}
    for subject_kind, subject_id, server_id, gate in _subjects(conn, instance_id):
        rows = current(conn, instance_id, subject_kind, subject_id)
        for kind in _KIND_LIST:
            if kind.subject != subject_kind or kind.gate != gate:
                continue
            state = state_of(rows.get(kind.key), now)
            if not applies(conn, instance_id, kind, subject_kind, subject_id):
                continue
            if state in ("valid", "not_applicable"):
                continue
            until = rows[kind.key]["valid_until"] if kind.key in rows else None
            key = group_key(subject_kind, subject_id, server_id)
            group = groups.setdefault(key, {"server_id": server_id, "items": []})
            group["items"].append(
                {"evidence": kind.key, "label": kind.label, "subject_kind": subject_kind,
                 "subject_id": subject_id, "state": state,
                 "valid_until": until.isoformat() if until else None}
            )
    opened = 0
    for key, group in groups.items():
        missing_any = any(i["state"] == "missing" for i in group["items"])
        with conn.transaction():
            opened += alerts.raise_alert(
                conn, instance_id,
                kind="evidence_missing" if missing_any else "evidence_expiring",
                severity="medium", dedup_key=key, subject=group,
            )
    return opened
