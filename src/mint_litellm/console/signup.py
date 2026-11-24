"""직원의 가입 요청과 관리자 처리 화면."""

import hmac
import re
import secrets

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
from mint_litellm.control import signup
from mint_litellm.control.db.connection import fetchall, fetchone
from mint_litellm.control.errors import AdminCode, AdminError
from mint_litellm.control.services.base import enqueue_job
from mint_litellm.types.ids import new_uuid7

public = APIRouter()
admin = APIRouter(dependencies=[Depends(require_csrf)])
COOKIE = "mint_signup_csrf"
DUPLICATE = "이미 가입되었거나 요청 중입니다. 로그인하거나 관리자에게 문의하십시오."
DONE = "가입 요청을 보냈습니다. 관리자가 승인하면 이 이메일과 비밀번호로 로그인할 수 있습니다."


def form(request, error=None, status=200, done=False):
    token = secrets.token_urlsafe(32)
    response = render(request, "signup_form.html",
                      {"csrf": token, "error": error, "done": DONE if done else None},
                      status=status)
    response.set_cookie(COOKIE, token, httponly=True, secure=is_https(request),
                        samesite="strict", max_age=3600, path="/staff/signup")
    return response


@public.get("/staff/signup")
def signup_form(request: Request):
    return form(request)


@public.post("/staff/signup", dependencies=[Depends(require_origin)])
def signup_submit(request: Request, email: str = Form(""), name: str = Form(""),
                  password: str = Form(""), confirm: str = Form(""), csrf: str = Form(""),
                  conn: psycopg.Connection = Depends(staff_connection)):
    cookie = request.cookies.get(COOKIE, "")
    if not cookie or not hmac.compare_digest(cookie, csrf):
        raise AdminError(AdminCode.FORBIDDEN, "요청을 확인할 수 없습니다. 다시 시도하십시오.")
    if too_many_attempts(request):
        return form(request, "요청이 너무 많습니다. 잠시 뒤 다시 시도하십시오.", 429)
    email, name = email.strip().lower(), name.strip()
    if (len(email) > 320 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
            or not name or len(name) > 200):
        return form(request, "이메일과 이름을 확인하십시오.", 400)
    if not 8 <= len(password) <= 256 or password != confirm:
        return form(request, "비밀번호는 8자 이상이고 두 칸이 같아야 합니다.", 400)
    instance, request_id = config_of(request).instance_id, new_uuid7()
    try:
        sealed = signup.seal(instance, str(request_id), password)
    except (signup.SignupError, ImportError):
        return form(request, "지금은 가입 요청을 받을 수 없습니다. 관리자에게 문의하십시오.", 503)
    finally:
        password = confirm = ""  # 평문은 여기서 버린다
    result = fetchone(conn, "SELECT mint.staff_signup_request(%s,%s,%s,%s,%s) AS ok",
                      (instance, request_id, email, name, sealed))
    if not result["ok"]:
        return form(request, DUPLICATE)
    return form(request, done=True)


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
        code = row["last_error"] or ""
        errors = {
            "litellm_unreachable": "게이트웨이에 연결하지 못했습니다.",
            "litellm_unavailable": "게이트웨이 연결이 설정되지 않았습니다.",
            "litellm_http_401": "게이트웨이 인증에 실패했습니다.",
            "litellm_http_403": "게이트웨이가 요청을 거부했습니다.",
            "duplicate_user": "같은 이메일의 계정이 여러 개입니다.",
            "missing_user_id": "생성된 계정을 확인하지 못했습니다.",
            "missing_invitation_id": "초대 정보를 확인하지 못했습니다.",
            "password_policy": "비밀번호가 게이트웨이 규칙에 맞지 않습니다.",
            "seal_unreadable": "가입 정보를 읽지 못했습니다. 다시 가입 요청을 받아야 합니다.",
            "seal_key_missing": "가입 정보를 읽을 키가 없습니다.",
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
                       " decided_by = %s, reason = %s, status = %s,"
                       " password_sealed = CASE WHEN %s = 'reject' THEN NULL"
                       " ELSE password_sealed END"
                       " WHERE instance_id = %s AND id = %s AND status = 'pending'"
                       " AND decided_at IS NULL RETURNING id",
                       (actor.ctx.operator.name, reason.strip() or None,
                        "pending" if decision == "approve" else "rejected", decision,
                        actor.instance,
                        request_id))
        if not row:
            raise AdminError(AdminCode.NOT_FOUND, "처리할 가입 요청이 없습니다.")
        if decision == "approve":
            enqueue_job(actor.ctx, "staff_signup", str(row["id"]), f"staff_signup:{row['id']}")
    return RedirectResponse("/signup-requests", status_code=303)
