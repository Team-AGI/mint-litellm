"""직원의 가입 요청과 관리자 처리 화면."""

import hashlib
import hmac
import re
import secrets
from urllib.parse import urlencode

import psycopg
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from mint_litellm.console.cookies import is_https
from mint_litellm.console.core import (
    Actor,
    config_of,
    page_actor,
    require_csrf,
    require_origin,
    too_many_attempts,
)
from mint_litellm.console.staff_pages import staff_connection
from mint_litellm.console.templating import render
from mint_litellm.console.ui_launch import ui_origin
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.services.base import enqueue_job
from mint_litellm.types.ids import new_uuid7

public = APIRouter()
admin = APIRouter(dependencies=[Depends(require_csrf)])
COOKIE = "mint_signup_csrf"
DUPLICATE = "이미 가입되었거나 요청 중입니다. 로그인하거나 관리자에게 문의하십시오"


def invitation_url(config, invitation):
    base = ui_origin(config)
    if not base:
        return None
    return f"{base}/ui/onboarding?{urlencode({'invitation_id': invitation})}"


def form(request, error=None, status=200):
    token = secrets.token_urlsafe(32)
    response = render(request, "signup_form.html", {"csrf": token, "error": error}, status=status)
    response.set_cookie(COOKIE, token, httponly=True, secure=is_https(request),
                        samesite="strict", max_age=3600, path="/staff/signup")
    return response


@public.get("/staff/signup")
def signup_form(request: Request):
    return form(request)


@public.post("/staff/signup", dependencies=[Depends(require_origin)])
def signup_submit(request: Request, email: str = Form(""), name: str = Form(""),
                  csrf: str = Form(""), conn: psycopg.Connection = Depends(staff_connection)):
    cookie = request.cookies.get(COOKIE, "")
    if not cookie or not hmac.compare_digest(cookie, csrf):
        raise AdminError(AdminCode.FORBIDDEN, "요청을 확인할 수 없습니다. 다시 시도하십시오.")
    if too_many_attempts(request):
        return form(request, "요청이 너무 많습니다. 잠시 뒤 다시 시도하십시오.", 429)
    email, name = email.strip().lower(), name.strip()
    if (len(email) > 320 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
            or not name or len(name) > 200):
        return form(request, "이메일과 이름을 확인하십시오.", 400)
    instance = config_of(request).instance_id
    token = secrets.token_urlsafe(32)
    result = fetchone(conn, "SELECT mint.staff_signup_submit(%s,%s,%s,%s,%s) AS ok",
                      (instance, new_uuid7(), email, name,
                       hashlib.sha256(token.encode()).hexdigest()))
    if not result["ok"]:
        return form(request, DUPLICATE)
    return RedirectResponse(f"/staff/signup/{token}?received=1", status_code=303)


@public.get("/staff/signup/{token}")
def signup_status(token: str, request: Request,
                  conn: psycopg.Connection = Depends(staff_connection)):
    row = fetchone(conn, "SELECT * FROM mint.staff_signup_status(%s, %s)",
                   (config_of(request).instance_id, hashlib.sha256(token.encode()).hexdigest()))
    if row is None:
        raise AdminError(AdminCode.NOT_FOUND, "가입 요청을 찾을 수 없습니다.")
    url = invitation_url(config_of(request), row["invitation_id"]) if row["invitation_id"] else None
    return render(request, "signup_status.html", {"row": row, "url": url})


def require_admin(actor):
    if actor.role != "admin":
        raise AdminError(AdminCode.FORBIDDEN, "관리자만 가입 요청을 처리할 수 있습니다.")


@admin.get("/signup-requests")
def requests_page(request: Request, actor: Actor = Depends(page_actor)):
    require_admin(actor)
    rows = fetchall(actor.conn, "SELECT * FROM mint.signup_requests WHERE instance_id = %s"
                    " ORDER BY (status = 'pending' AND decided_at IS NULL) DESC, requested_at DESC",
                    (actor.instance,))
    for row in rows:
        row["url"] = (invitation_url(actor.config, row["invitation_id"])
                      if row["invitation_id"] else None)
        code = row["last_error"] or ""
        errors = {
            "litellm_unreachable": "게이트웨이에 연결하지 못했습니다.",
            "litellm_unavailable": "게이트웨이 연결이 설정되지 않았습니다.",
            "litellm_http_401": "게이트웨이 인증에 실패했습니다.",
            "litellm_http_403": "게이트웨이가 요청을 거부했습니다.",
            "duplicate_user": "같은 이메일의 계정이 여러 개입니다.",
            "missing_user_id": "생성된 계정을 확인하지 못했습니다.",
            "missing_invitation_id": "초대 정보를 확인하지 못했습니다.",
        }
        row["error_text"] = (errors.get(code) or "게이트웨이 요청을 처리하지 못했습니다.") \
            if code else None
    return render(request, "signup_requests.html", {"rows": rows}, actor=actor)


@admin.post("/signup-requests/{request_id}/{decision}")
def decide(request_id: str, decision: str, reason: str = Form(""),
           actor: Actor = Depends(page_actor)):
    require_admin(actor)
    if decision not in ("approve", "reject") or len(reason) > 1000:
        raise ValueError("입력 값을 확인하십시오.")
    with actor.conn.transaction():
        row = fetchone(actor.conn, "UPDATE mint.signup_requests SET decided_at = now(),"
                       " decided_by = %s, reason = %s, status = %s"
                       " WHERE instance_id = %s AND id = %s AND status = 'pending'"
                       " AND decided_at IS NULL RETURNING id",
                       (actor.ctx.operator.name, reason.strip() or None,
                        "pending" if decision == "approve" else "rejected", actor.instance,
                        request_id))
        if not row:
            raise AdminError(AdminCode.NOT_FOUND, "처리할 가입 요청이 없습니다.")
        if decision == "approve":
            enqueue_job(actor.ctx, "staff_signup", str(row["id"]), f"staff_signup:{row['id']}")
    return RedirectResponse("/signup-requests", status_code=303)
