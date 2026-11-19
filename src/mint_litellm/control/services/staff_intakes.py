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

# 직원은 주소와 목적만 적는다. 나머지는 여기서 채운다(종료 준비 문구는 조직 기본값).
DEFAULTS = {
    "data_grade": "internal",
    "audit_access_days": "90",
    "credential_notice": "자격 증명이 바뀌면 관리자에게 알립니다",
    "revocation_record": "철회는 MINT 기록으로 남깁니다",
    "data_return_terms": "사용을 끝내면 서버에 남은 자료를 삭제합니다",
}


def server_name(url: str) -> str:
    """주소에서 서버 식별자: 맨 앞 mcp·www·api 칸을 빼고 점을 하이픈으로."""
    try:
        labels = (urlsplit(url).hostname or "").split(".")
    except ValueError:
        labels = []
    while len(labels) > 2 and labels[0] in ("mcp", "www", "api"):
        labels.pop(0)
    return re.sub(r"[^A-Za-z0-9._-]", "-", "-".join(labels))[:128]


def validate(form: dict, allowed_ports: tuple[int, ...] = (443, 8443)) -> tuple[dict, str]:
    form = {**DEFAULTS, **{k: v for k, v in form.items() if str(v).strip()}}
    url = str(form.get("url", "")).strip()
    sid = str(form.get("server_id", "")).strip() or server_name(url)
    transport = form.get("transport") or ("sse" if url.rstrip("/").endswith("/sse") else "http")
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
    # 포트는 허용 목록 예외가 없는 검사라, 접수 뒤 자동 거절되기 전에 화면에서 바로 알린다.
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in allowed_ports:
        raise ControlError(
            f"포트 {port}은(는) 쓸 수 없습니다. 허용 포트: {', '.join(map(str, allowed_ports))}."
        )
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


def submit(
    sctx: staff.StaffContext, session_id_hash: str, request_id: str, form: dict,
    allowed_ports: tuple[int, ...] = (443, 8443),
) -> str:
    try:
        identifier = UUID(request_id)
    except (ValueError, TypeError):
        raise ControlError("신청 화면을 다시 열어 제출하십시오.") from None
    payload, contract = validate(form, allowed_ports)
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
                    " FROM mint.intakes WHERE instance_id=%s AND requested_by=%s"
                    " AND source IN ('staff','endpoint') ORDER BY created_at DESC LIMIT 100",
                    (sctx.instance_id, sctx.user_id))


def detail(sctx: staff.StaffContext, identifier: str) -> dict:
    try:
        intake_id = UUID(identifier)
    except (ValueError, TypeError):
        raise not_found("신청을 찾을 수 없습니다.") from None
    row = fetchone(sctx.control,
                   "SELECT id, server_id, purpose, data_grade, allowed_resources, readiness,"
                   " data_return_terms, status, decision, decision_reason, created_at, decided_at,"
                   " state_version"
                   " FROM mint.intakes WHERE instance_id=%s AND requested_by=%s"
                   " AND source IN ('staff','endpoint') AND id=%s",
                   (sctx.instance_id, sctx.user_id, intake_id))
    if row is None:
        raise not_found("신청을 찾을 수 없습니다.")
    return row


def observed(sctx: staff.StaffContext) -> dict:
    """내 단말이 보고한 도구 목록의 마지막 시각(서버별). 관측이 없으면 서버가 빠진다."""
    rows = fetchall(sctx.control,
                    "SELECT t.server_id, max(t.reported_at) AS at FROM mint.endpoint_tool_lists t"
                    " JOIN mint.endpoint_installs i ON i.instance_id = t.instance_id"
                    " AND i.key_token = t.key_token"
                    " WHERE t.instance_id=%s AND i.user_id=%s AND i.revoked_at IS NULL"
                    " GROUP BY t.server_id", (sctx.instance_id, sctx.user_id))
    return {r["server_id"]: r["at"] for r in rows}
