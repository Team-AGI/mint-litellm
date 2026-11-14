"""작업 ``session_verify``: 활성 콘솔 세션마다 제어 평면 키로 본인 키와 사용자를 다시 확인한다.

키가 활성(삭제된 키의 보관 응답이 아님)이고 차단되지 않았고 만료 전이며 사람 사용자이고 (관리자
세션이면) 그 사용자의 운영자 행이 아직 유효하고 역할이 같을 때만 세션을 유지한다. 직원 세션은
운영자 행을 보지 않고 소속 팀을 새 키 정보로 갱신한다. 그렇지 않으면 폐기한다. LiteLLM에 닿지
못한 경우는 키의 상태를 알 수 없으므로 폐기하지 않고 작업을 실패로 끝내 재시도한다.
"""

from datetime import UTC, datetime

from mint_litellm.control import jobs
from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_admin import LiteLLMError
from mint_litellm.control.operators import HUMAN_ROLES
from mint_litellm.control.services import console_sessions

# LiteLLM에 닿지 못할 때 세션을 유지하는 주기 수. 그 뒤에는 확인하지 못한 세션을 폐기한다.
UNVERIFIED_PERIODS = 2


def _parse(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def verdict(
    session: dict, key: dict | None, user: dict | None, operator: dict | None
) -> str | None:
    """세션을 폐기해야 하면 사유 코드, 유지하면 None. SSO 세션에는 키가 없어 키 검사를 건너뛴다."""
    if not console_sessions.is_sso_session(session["key_token"]):
        if key is None or key.get("deleted_at"):
            return "key_gone"
        if key.get("blocked"):
            return "key_blocked"
        expires = _parse(key.get("expires"))
        if expires is not None and expires <= datetime.now(UTC):
            return "key_expired"
        if key.get("user_id") != session["user_id"]:
            return "key_owner_changed"
    if user is None or user.get("user_role") not in HUMAN_ROLES:
        return "user_not_human"
    if session["subject"] == "admin" and (operator is None or operator["role"] != session["role"]):
        return "operator_changed"
    return None


def run(job: jobs.JobContext) -> None:
    conn, instance = job.conn, job.instance_id
    period = getattr(job.settings, "session_verify_seconds", 300)
    # 제어 평면 키가 없는 것도 확인하지 못함으로 같게 다룬다(키 없는 설치에 세션이 남지 않는다)
    unreachable: Exception | None = None
    if job.litellm is None:
        unreachable = ControlError(
            "session_verify에는 제어 평면 키(MINT_LITELLM_URL·MINT_LITELLM_KEY)가 필요합니다."
        )
    for session in console_sessions.active_sessions(conn, instance):
        job.checkpoint()
        try:
            if job.litellm is None:
                raise unreachable
            sso = console_sessions.is_sso_session(session["key_token"])
            key = None if sso else job.litellm.get_key(session["key_token"])
            user = job.litellm.get_user(session["user_id"])
        except (LiteLLMError, ControlError) as error:
            unreachable = unreachable or error
            if session["unverified_seconds"] > UNVERIFIED_PERIODS * period:
                console_sessions.revoke(
                    conn, instance, session["id_hash"], actor="session_verify", reason="unverified"
                )
            continue
        operator = console_sessions.active_operator(conn, instance, session["user_id"])
        reason = verdict(session, key, user, operator)
        if reason is None:
            if session["subject"] == "staff":
                teams = (
                    console_sessions.teams_of_user(user or {}) if sso
                    else console_sessions.teams_of(key or {})
                )
                console_sessions.set_teams(conn, instance, session["id_hash"], teams)
            console_sessions.mark_verified(conn, instance, session["id_hash"])
        else:
            console_sessions.revoke(
                conn, instance, session["id_hash"], actor="session_verify", reason=reason
            )
    if unreachable is not None:
        raise unreachable
