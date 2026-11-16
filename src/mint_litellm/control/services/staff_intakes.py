"""직원 신청은 세션 신원으로 생성하며, 검증·결정은 기존 도입 절차가 맡는다."""

import json
import re
from urllib.parse import urlsplit
from uuid import UUID

import psycopg

from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import ControlError, conflict, not_found
from mint_litellm.control.services import staff
from mint_litellm.control.services.intakes import _validated_inputs
from mint_litellm.types.canonical import canonical_text


def validate(form: dict) -> tuple[dict, str]:
    sid = str(form.get("server_id", "")).strip()
    url = str(form.get("url", "")).strip()
    transport = form.get("transport", "http")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", sid):
        raise ControlError("서버 식별자는 영문·숫자로 시작하고 "
                           "영문·숫자·점·밑줄·하이픈만 사용합니다.")
    try:
        parts = urlsplit(url)
        if (not 1 <= len(url) <= 2048 or parts.scheme not in ("https", "http")
                or not parts.hostname or parts.port == 0
                or parts.username is not None or parts.password is not None
                or "?" in url or "#" in url or "\\" in url
                or any(c.isspace() or ord(c) < 32 for c in url)):
            raise ValueError
    except ValueError:
        raise ControlError("서버 주소는 자격 정보·쿼리·조각이 없는 "
                           "HTTP 또는 HTTPS 주소여야 합니다.") from None
    if transport not in ("http", "sse"):
        raise ControlError("전송 방식은 HTTP 또는 SSE여야 합니다.")
    resources = str(form.get("resources", ""))
    if len(resources) > 4000:
        raise ControlError("허용 자원은 4,000자 이하여야 합니다.")
    notice = str(form.get("credential_notice", "")).strip()
    revocation = str(form.get("revocation_record", "")).strip()
    terms = str(form.get("data_return_terms", "")).strip()
    try:
        days = int(form.get("audit_access_days", ""))
    except (TypeError, ValueError):
        days = 0
    if (not 1 <= days <= 3650 or not 1 <= len(notice) <= 1000
            or not 1 <= len(revocation) <= 1000 or not 1 <= len(terms) <= 2000):
        raise ControlError("감사 열람 기간과 자격 변경 안내·철회 기록·"
                           "자료 삭제 및 반환 조건을 입력하십시오.")
    payload = _validated_inputs(
        str(form.get("purpose", "")), str(form.get("data_grade", "")),
        [line.strip() for line in resources.splitlines() if line.strip()],
        parts.hostname, "session", {"credential_notice": notice, "revocation_record": revocation,
                                    "audit_access_days": days}, terms,
    )
    payload.pop("owner_user_id")  # DB 함수가 인증된 직원 세션에서만 채운다.
    payload.update(server_id=sid, url=url, transport=transport)
    contract = canonical_text({"url": url, "transport": transport, "auth_type": "none",
                               "issuer": None, "oauth_scopes": [], "allowed_tools": None,
                               "image_digest": None, "source_commit": None})
    return payload, contract


def submit(sctx: staff.StaffContext, session_id_hash: str, request_id: str, form: dict) -> str:
    try:
        identifier = UUID(request_id)
    except (ValueError, TypeError):
        raise ControlError("신청 화면을 다시 열어 제출하십시오.") from None
    payload, contract = validate(form)
    staff._active_session(sctx, session_id_hash)
    try:
        with staff._staff_transaction(sctx, session_id_hash) as conn:
            row = conn.execute("SELECT mint.staff_submit_intake(%s,%s::jsonb,%s)",
                               (identifier, json.dumps(payload), contract)).fetchone()
            return str(row[0])
    except psycopg.errors.UniqueViolation:
        raise conflict("같은 서버의 신청이 이미 진행 중입니다. 관리자에게 확인하십시오.") from None


def listing(sctx: staff.StaffContext) -> list[dict]:
    return fetchall(sctx.control,
                    "SELECT id, server_id, purpose, status, decision, created_at, decided_at"
                    " FROM mint.intakes WHERE instance_id=%s AND requested_by=%s AND source='staff'"
                    " ORDER BY created_at DESC LIMIT 100", (sctx.instance_id, sctx.user_id))


def detail(sctx: staff.StaffContext, identifier: str) -> dict:
    try:
        intake_id = UUID(identifier)
    except (ValueError, TypeError):
        raise not_found("신청을 찾을 수 없습니다.") from None
    row = fetchone(sctx.control,
                   "SELECT id, server_id, purpose, data_grade, allowed_resources, readiness,"
                   " data_return_terms, status, decision, decision_reason, created_at, decided_at"
                   " FROM mint.intakes WHERE instance_id=%s AND requested_by=%s"
                   " AND source='staff' AND id=%s", (sctx.instance_id, sctx.user_id, intake_id))
    if row is None:
        raise not_found("신청을 찾을 수 없습니다.")
    return row
