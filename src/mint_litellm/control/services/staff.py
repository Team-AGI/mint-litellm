"""직원 화면 서비스. 데이터베이스의 ``mint.staff_*`` 함수 호출을 감싼다.

직원 화면의 쓰기는 직원 로그인 역할이 함수로만 한다. 함수는 대상 사용자와 배치를 트랜잭션마다 거는
``mint.staff_user_id``·``mint.staff_instance_id`` 설정에서만 읽고 본인 행만 바꾸므로(한계: 그 값은
콘솔의 세션 인증이 보증한다). 이 계층의 선확인 뒤 DB 함수가 같은 쓰기 트랜잭션에서
소속·서버·세션·키 분리·유효 기간을 다시 확인한다.
직원 로그인 역할은 표를 읽지 못하므로 확인용 읽기는 제어 연결로 하고, 쓰기는 직원 연결의 한
트랜잭션에서 한다.
"""

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import psycopg
from psycopg.rows import dict_row

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import (
    ControlError,
    conflict,
    forbidden,
    not_found,
    separation_of_duties,
    stale_evidence,
)
from mint_litellm.types.ids import new_uuid7


@dataclass(frozen=True)
class StaffContext:
    """직원 한 명의 요청 맥락. 두 연결은 같은 프로세스의 서로 다른 풀에서 온다."""

    staff: psycopg.Connection  # 직원 로그인 역할(함수 실행만)
    control: psycopg.Connection  # 제어 로그인 역할(확인용 읽기만)
    instance_id: str
    user_id: str
    # 본인 동의의 유효 기간 상한(일). Stage2Settings.staff_consent_max_days 값을 넘긴다.
    consent_max_days: int = 90
    # 마지막 성공 확인 뒤 직원 세션을 받아 주는 시간(초, session_verify_window_seconds).
    verify_window_seconds: int = 600
    # 인증된 LiteLLM 세션 키 정보에서만 채운다. 화면 입력을 받지 않는다.
    team_ids: tuple[str, ...] = ()
    # 이 세션의 키 토큰(키 범위 승인 조회용).
    key_token: str = ""


@contextmanager
def _staff_transaction(
    sctx: StaffContext, session_id_hash: str = "",
) -> Iterator[psycopg.Connection]:
    """직원 함수가 읽는 설정을 이 트랜잭션에만 걸고 연결을 내준다."""
    # 바깥 트랜잭션 안이면 세이브포인트가 되어 설정이 바깥 끝까지 남는다. 유휴 연결만 받는다.
    if sctx.staff.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
        raise RuntimeError("staff connection must be idle before a staff transaction")
    with sctx.staff.transaction():
        sctx.staff.execute(
            "SELECT set_config('mint.staff_user_id', %s, true),"
            " set_config('mint.staff_instance_id', %s, true),"
            " set_config('mint.staff_session_id_hash', %s, true),"
            " set_config('mint.staff_consent_max_days', %s, true),"
            " set_config('mint.staff_verify_window_seconds', %s, true)",
            (sctx.user_id, sctx.instance_id, session_id_hash,
             str(sctx.consent_max_days), str(sctx.verify_window_seconds)),
        )
        yield sctx.staff


def _active_session(sctx: StaffContext, session_id_hash: str) -> dict:
    """본인 직원 세션이 폐기·만료되지 않았는지 쓰기 앞에서 확인하고 행을 돌려준다."""
    with sctx.control.transaction():
        row = fetchone(
            sctx.control,
            "SELECT key_token FROM mint.console_sessions WHERE instance_id = %s AND id_hash = %s"
            " AND subject = 'staff' AND user_id = %s AND revoked_at IS NULL"
            " AND idle_expiry > now() AND absolute_expiry > now()"
            " AND last_verified_at > now() - make_interval(secs => %s)",
            (sctx.instance_id, session_id_hash, sctx.user_id, sctx.verify_window_seconds),
        )
    if row is None:
        raise forbidden("직원 세션이 없거나 만료되었습니다. 다시 로그인하십시오.")
    return row


# ---------------------------------------------------------------------------
# 세션
# ---------------------------------------------------------------------------


def start_session(
    sctx: StaffContext,
    session_id_hash: str,
    key_token: str,
    idle_expiry: datetime,
    absolute_expiry: datetime,
) -> None:
    now = datetime.now(UTC)
    if not now < idle_expiry <= absolute_expiry:
        raise ControlError("세션 만료 시각이 올바르지 않습니다(현재 < 유휴 만료 <= 절대 만료).")
    with _staff_transaction(sctx) as conn:
        conn.execute(
            "SELECT mint.staff_start_session(%s, %s, %s, %s, %s::jsonb)",
            (session_id_hash, key_token, idle_expiry, absolute_expiry,
             json.dumps(list(sctx.team_ids))),
        )


def touch_session(sctx: StaffContext, session_id_hash: str, idle_expiry: datetime) -> None:
    _active_session(sctx, session_id_hash)
    with _staff_transaction(sctx, session_id_hash) as conn:
        conn.execute("SELECT mint.staff_touch_session(%s, %s)", (session_id_hash, idle_expiry))


def end_session(sctx: StaffContext, session_id_hash: str) -> None:
    with _staff_transaction(sctx, session_id_hash) as conn:
        conn.execute("SELECT mint.staff_end_session(%s)", (session_id_hash,))


# ---------------------------------------------------------------------------
# 본인 확인
# ---------------------------------------------------------------------------


def _confirmation(sctx: StaffContext, confirmation_id: str) -> dict:
    with sctx.control.transaction():
        row = fetchone(
            sctx.control,
            "SELECT status, requested_by_key_token, expires_at <= now() AS expired,"
            " (SELECT require_separate_confirm_key FROM mint.settings WHERE instance_id = %s)"
            " AS separate_key FROM mint.self_confirmations"
            " WHERE instance_id = %s AND id = %s AND principal_id = %s",
            (sctx.instance_id, sctx.instance_id, confirmation_id, sctx.user_id),
        )
    if row is None:
        raise not_found(f"본인 확인 {confirmation_id}이(가) 없습니다.")
    return row


def _decide(
    sctx: StaffContext, session_id_hash: str, confirmation_id: str, target: str
) -> None:
    session = _active_session(sctx, session_id_hash)
    row = _confirmation(sctx, confirmation_id)
    open_states = ("pending", "confirmed") if target == "cancel" else ("pending",)
    if row["status"] not in open_states:
        raise conflict(
            f"본인 확인 {confirmation_id}은(는) 이미 처리되었거나 만료되어 처리할 수 없습니다."
        )
    if target != "cancel" and row["expired"]:
        raise stale_evidence(f"본인 확인 {confirmation_id}은(는) 만료되었습니다.")
    if (
        target == "confirm"
        and row["separate_key"] is not False
        and session["key_token"] == row["requested_by_key_token"]
    ):
        raise separation_of_duties(
            "호출한 키와 같은 키로 로그인한 세션은 확인할 수 없습니다. 다른 키로 로그인하십시오."
        )
    with _staff_transaction(sctx, session_id_hash) as conn:
        if target == "cancel":
            conn.execute("SELECT mint.staff_cancel(%s)", (confirmation_id,))
        else:
            conn.execute(
                f"SELECT mint.staff_{target}(%s, %s)", (confirmation_id, session["key_token"])
            )


def confirm(sctx: StaffContext, session_id_hash: str, confirmation_id: str) -> None:
    """본인 확인을 확정한다. 확정 키(세션의 키)는 요청 키와 달라야 한다."""
    _decide(sctx, session_id_hash, confirmation_id, "confirm")


def reject(sctx: StaffContext, session_id_hash: str, confirmation_id: str) -> None:
    _decide(sctx, session_id_hash, confirmation_id, "reject")


def cancel(sctx: StaffContext, session_id_hash: str, confirmation_id: str) -> None:
    _decide(sctx, session_id_hash, confirmation_id, "cancel")


# ---------------------------------------------------------------------------
# 본인 동의
# ---------------------------------------------------------------------------


def _member_orgs(sctx: StaffContext, team_ids: Sequence[str]) -> set[str]:
    """사용자 바인딩 → 팀 바인딩 → 기본 조직, 처음 맞는 쪽이 소속을 정한다(DB 함수와 같은 순서)."""
    user_orgs = {
        r["org_id"] for r in fetchall(
            sctx.control,
            "SELECT org_id FROM mint.org_bindings WHERE instance_id = %s"
            " AND subject_type = 'user' AND subject_id = %s",
            (sctx.instance_id, sctx.user_id),
        )
    }
    team_orgs = set() if user_orgs else {
        r["org_id"] for r in fetchall(
            sctx.control,
            "SELECT org_id FROM mint.org_bindings WHERE instance_id = %s"
            " AND subject_type = 'team' AND subject_id = ANY(%s)",
            (sctx.instance_id, list(team_ids)),
        )
    }
    orgs = user_orgs or team_orgs
    if not orgs:
        default = fetchone(
            sctx.control,
            "SELECT default_org_id FROM mint.settings WHERE instance_id = %s",
            (sctx.instance_id,),
        )
        orgs = {default["default_org_id"]} if default and default["default_org_id"] else set()
    return orgs


def _check_consent_target(
    sctx: StaffContext, org_id: str, server_id: str, team_ids: Sequence[str]
) -> None:
    with sctx.control.transaction():
        org = fetchone(
            sctx.control,
            "SELECT status FROM mint.orgs WHERE instance_id = %s AND org_id = %s",
            (sctx.instance_id, org_id),
        )
        if org is None or org["status"] != "active":
            raise ControlError(f"활성 상태의 조직 {org_id}이(가) 없습니다.")
        orgs = _member_orgs(sctx, team_ids)
        member = org_id in orgs
        if not member:
            raise forbidden(f"조직 {org_id}에 속한 사용자만 이 조직의 동의를 등록할 수 있습니다.")
        server = fetchone(
            sctx.control,
            "SELECT s.status FROM mint.servers s WHERE s.instance_id = %s AND s.server_id = %s"
            " AND EXISTS (SELECT 1 FROM mint.usage_relations r WHERE r.instance_id = s.instance_id"
            " AND r.server_id = s.server_id AND r.org_id = %s AND r.status = 'active')",
            (sctx.instance_id, server_id, org_id),
        )
        if server is None:
            raise forbidden(f"조직 {org_id}의 이용 관계에 서버 {server_id}가 없습니다.")
        if server["status"] != "approved":
            raise ControlError(
                f"서버 {server_id}는 승인된 서버가 아니어서 동의를 등록할 수 없습니다."
            )


def grant_consent(
    sctx: StaffContext,
    session_id_hash: str,
    *,
    org_id: str,
    server_id: str,
    purpose: str,
    data_scope: str,
    text_version: str,
    valid_until: datetime,
    team_ids: Sequence[str] = (),
) -> str:
    """본인 직접 동의를 등록하고 동의 식별자를 돌려준다.

    유효 기간 상한은 ``sctx.consent_max_days``(설정 MINT_STAFF_CONSENT_MAX_DAYS)이다.
    ``team_ids``는 LiteLLM 세션 키 정보에서 읽은 값이어야 하며 화면 입력을 넘기지 않는다
    (팀 바인딩으로 조직에 속한 사용자를 인정하는 데 쓰인다. 강제는 콘솔 직원 화면이 한다).
    """
    if not 1 <= len(purpose.strip()) <= 128:
        raise ControlError("purpose는 1자 이상 128자 이하여야 합니다.")
    if not data_scope.strip() or not text_version.strip():
        raise ControlError("data_scope와 text_version이 필요합니다.")
    now = datetime.now(UTC)
    if valid_until.tzinfo is None:
        raise ControlError("valid-until에는 시간대가 필요합니다.")
    if valid_until <= now:
        raise ControlError("valid-until이 이미 지났습니다.")
    if valid_until > now + timedelta(days=sctx.consent_max_days):
        raise ControlError(f"동의 유효 기간은 최대 {sctx.consent_max_days}일입니다.")
    _active_session(sctx, session_id_hash)
    _check_consent_target(sctx, org_id, server_id, team_ids)
    if any(
        c["org_id"] == org_id and c["server_id"] == server_id and not c["revoked_at"]
        and c["valid_until"] > now and c["purpose"] == purpose.strip()
        and c["data_scope"] == data_scope
        for c in list_consents(sctx)
    ):
        raise ControlError("같은 목적·범위의 동의가 이미 있습니다.")
    consent_id = new_uuid7()
    with _staff_transaction(sctx, session_id_hash) as conn:
        conn.execute(
            "SELECT mint.staff_grant_consent(%s, %s, %s, %s, %s, %s, %s)",
            (consent_id, org_id, server_id, purpose.strip(), data_scope, text_version, valid_until),
        )
    return str(consent_id)


def revoke_consent(sctx: StaffContext, session_id_hash: str, consent_id: str) -> None:
    _active_session(sctx, session_id_hash)
    with _staff_transaction(sctx, session_id_hash) as conn:
        conn.execute("SELECT mint.staff_revoke_consent(%s)", (consent_id,))


# ---------------------------------------------------------------------------
# 본인 범위 조회
# ---------------------------------------------------------------------------


def _list(sctx: StaffContext, query: str, params: tuple = ()) -> list[dict]:
    with _staff_transaction(sctx) as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(query, params)
        return cur.fetchall()


def list_confirmations(sctx: StaffContext) -> list[dict]:
    return _list(sctx, "SELECT * FROM mint.staff_list_confirmations()")


def list_consents(sctx: StaffContext) -> list[dict]:
    return _list(sctx, "SELECT * FROM mint.staff_list_consents()")


def list_events(sctx: StaffContext, limit: int = 100) -> list[dict]:
    return _list(sctx, "SELECT * FROM mint.staff_list_events(%s)", (limit,))


# ---------------------------------------------------------------------------
# 화면용 읽기(제어 연결)
# ---------------------------------------------------------------------------


def find_session(
    control: psycopg.Connection, instance_id: str, id_hash: str, window_seconds: int = 600
) -> dict | None:
    """유효한 직원 세션의 사용자·키·소속 팀. 없으면 None. 읽기만 한다.

    마지막 성공 확인이 ``window_seconds``를 넘은 세션은 없는 것으로 본다."""
    with control.transaction():
        return fetchone(
            control,
            "SELECT user_id, key_token, team_ids FROM mint.console_sessions"
            " WHERE instance_id = %s AND id_hash = %s AND subject = 'staff'"
            " AND revoked_at IS NULL AND idle_expiry > now() AND absolute_expiry > now()"
            " AND last_verified_at > now() - make_interval(secs => %s)",
            (instance_id, id_hash, window_seconds),
        )


def requires_separate_key(sctx: StaffContext) -> bool:
    with sctx.control.transaction():
        row = fetchone(
            sctx.control,
            "SELECT require_separate_confirm_key AS v FROM mint.settings WHERE instance_id = %s",
            (sctx.instance_id,),
        )
    return row is None or row["v"] is not False


def list_available(sctx: StaffContext) -> list[dict]:
    """이 사용자가 쓸 수 있는 서버와 도구: 소속 조직의 이용 관계가 있는 승인된 서버마다,
    본인·본인 팀·본인 조직·본인 키 범위의 유효한 승인이 허용하는 도구."""
    orgs = sorted(_member_orgs(sctx, sctx.team_ids))
    if not orgs:
        return []
    scope = (
        "((a.scope_type = 'user' AND a.scope_id = %(user)s)"
        " OR (a.scope_type = 'team' AND a.scope_id = ANY(%(teams)s))"
        " OR (a.scope_type = 'org' AND a.scope_id = r.org_id)"
        " OR (a.scope_type = 'key' AND a.scope_id = %(key)s))"
    )
    denied = (
        "EXISTS (SELECT 1 FROM mint.denials d WHERE d.instance_id = s.instance_id"
        " AND d.lifted_at IS NULL AND (d.server_id IS NULL OR d.server_id = s.server_id)"
        " AND (d.org_id IS NULL OR d.org_id = r.org_id)"
        " AND ((d.scope_type = 'user' AND d.scope_id = %(user)s)"
        "   OR (d.scope_type = 'team' AND d.scope_id = ANY(%(teams)s))"
        "   OR (d.scope_type = 'org' AND d.scope_id = r.org_id)"
        "   OR (d.scope_type = 'key' AND d.scope_id = %(key)s)"
        "   OR (d.scope_type = 'server' AND d.scope_id = s.server_id))"
        " AND (d.tools IS NULL OR t = ANY(d.tools)))"
    )
    with sctx.control.transaction():
        return fetchall(
            sctx.control,
            "SELECT s.server_id, r.org_id, o.name AS org_name, s.transport, s.auth_type,"
            " COALESCE((SELECT array_agg(DISTINCT t ORDER BY t) FROM mint.approvals a,"
            "   unnest(a.tools) AS t WHERE a.instance_id = s.instance_id"
            "   AND a.server_id = s.server_id AND a.org_id = r.org_id AND a.status = 'active'"
            f"   AND a.valid_from <= now() AND a.valid_until > now() AND {scope}"
            f"   AND NOT {denied}), '{{}}') AS tools,"
            " (SELECT max(a.valid_until) FROM mint.approvals a WHERE a.instance_id = s.instance_id"
            "   AND a.server_id = s.server_id AND a.org_id = r.org_id AND a.status = 'active'"
            f"   AND a.valid_until > now() AND {scope}) AS valid_until,"
            " (s.data_grade IN ('confidential', 'restricted') OR EXISTS (SELECT 1"
            "   FROM mint.approvals a WHERE a.instance_id = s.instance_id"
            "   AND a.server_id = s.server_id AND a.org_id = r.org_id AND a.status = 'active'"
            "   AND a.valid_from <= now() AND a.valid_until > now()"
            f"   AND a.conditions ->> 'require_consent' IS NOT NULL AND {scope}))"
            " AS consent_required"
            " FROM mint.servers s JOIN mint.usage_relations r ON r.instance_id = s.instance_id"
            " AND r.server_id = s.server_id AND r.status = 'active'"
            " JOIN mint.orgs o ON o.instance_id = r.instance_id AND o.org_id = r.org_id"
            " AND o.status = 'active'"
            " WHERE s.instance_id = %(iid)s AND s.status = 'approved' AND r.org_id = ANY(%(orgs)s)"
            " ORDER BY s.server_id, r.org_id",
            {"user": sctx.user_id, "teams": list(sctx.team_ids), "key": sctx.key_token,
             "iid": sctx.instance_id, "orgs": orgs},
        )
