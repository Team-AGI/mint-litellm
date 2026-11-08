"""관리자 콘솔 앱: FastAPI + Jinja2(서버 렌더링) + HTMX. 빌드 단계와 외부 자산이 없다."""

import logging
from collections.abc import Mapping
from pathlib import Path

import psycopg
from fastapi import Depends, FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from mint_litellm.console import api, login, pages, staff_pages
from mint_litellm.console.core import (
    COOKIE,
    ConsoleConfig,
    Unauthenticated,
    config_of,
    db,
    error_response,
    login_redirect,
    require_csrf,
    require_origin,
    too_many_attempts,
)
from mint_litellm.console.templating import render
from mint_litellm.control.errors import AdminCode, AdminError, ControlError
from mint_litellm.control.services import console_sessions
from mint_litellm.types.ids import new_uuid7

HERE = Path(__file__).parent
log = logging.getLogger(__name__)

CSP = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def create_app(
    config: ConsoleConfig | None = None, env: Mapping[str, str] | None = None
) -> FastAPI:
    config = config or ConsoleConfig.from_env({} if env is None else env)
    app = FastAPI(title="MINT 관리자 콘솔", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.config = config
    app.state.attempts = {}

    @app.middleware("http")
    async def common(request: Request, call_next):
        request.state.request_id = str(new_uuid7())
        try:
            response = await call_next(request)
        except Exception:  # 처리하지 못한 오류도 보안 헤더와 요청 식별자를 단다
            # 키·쿠키·본문은 남기지 않는다. 경로만 남긴다.
            log.exception(
                "요청 %s 처리 실패: %s %s",
                request.state.request_id, request.method, request.url.path,
            )
            response = JSONResponse(
                {"code": "MINT-ADMIN-UNAVAILABLE", "message": "요청을 처리하지 못했습니다.",
                 "reference": request.state.request_id},
                status_code=500,
            )
        for name, value in HEADERS.items():
            response.headers[name] = value
        response.headers["X-Request-Id"] = request.state.request_id
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(ControlError)
    async def control_error(request: Request, error: ControlError):
        if isinstance(error, Unauthenticated) and not request.url.path.startswith("/api/"):
            return login_redirect(request)
        return error_response(error, request.state.request_id)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError):
        fields = ", ".join(".".join(str(p) for p in e["loc"][1:]) or "본문" for e in error.errors())
        return JSONResponse(
            {
                "code": "MINT-ADMIN-INVALID-INPUT",
                "message": f"요청 값이 올바르지 않습니다: {fields}",
                "reference": request.state.request_id,
            },
            status_code=400,
        )

    @app.exception_handler(ValueError)
    async def bad_value(request: Request, error: ValueError):
        return JSONResponse(
            {"code": "MINT-ADMIN-INVALID-INPUT", "message": "입력 값이 올바르지 않습니다.",
             "reference": request.state.request_id},
            status_code=400,
        )

    @app.exception_handler(psycopg.Error)
    async def database_error(request: Request, error: psycopg.Error):
        return JSONResponse(
            {
                "code": "MINT-ADMIN-UNAVAILABLE",
                "message": "데이터베이스 요청을 처리하지 못했습니다.",
                "reference": request.state.request_id,
            },
            status_code=503,
        )

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    app.include_router(api.router, prefix="/api/v1")
    app.include_router(pages.router)
    app.include_router(staff_pages.public)
    app.include_router(staff_pages.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request) -> Response:
        return render(request, "login.html", {"error": None})

    @app.post("/login", dependencies=[Depends(require_origin)])
    def login_submit(
        request: Request, key: str = Form(""), conn: psycopg.Connection = Depends(db)
    ) -> Response:
        cfg = config_of(request)
        if too_many_attempts(request):
            return render(
                request, "login.html",
                {"error": "로그인 시도가 너무 많습니다. 잠시 뒤 다시 시도하십시오."}, status=429,
            )
        try:
            identity = login.verify(cfg.litellm_url, key)
            key = ""  # 평문 키는 여기서 버린다
            session_id, _ = console_sessions.create(
                conn, cfg.instance_id, cfg.stage2, user_id=identity.user_id,
                key_token=identity.key_token,
            )
        except login.LoginRefused as refused:
            return render(request, "login.html", {"error": str(refused)}, status=401)
        except AdminError as error:
            if error.code != AdminCode.FORBIDDEN:
                raise
            return render(request, "login.html", {"error": error.message}, status=403)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            COOKIE, session_id, httponly=True, secure=True, samesite="strict", path="/"
        )
        return response

    @app.post("/logout", dependencies=[Depends(require_csrf)])
    def logout(request: Request, conn: psycopg.Connection = Depends(db)) -> Response:
        cfg = config_of(request)
        session_id = request.cookies.get(COOKIE)
        if session_id:
            info = console_sessions.lookup(conn, cfg.instance_id, cfg.stage2, session_id)
            if info is not None:
                console_sessions.revoke(
                    conn, cfg.instance_id, info.id_hash, actor=info.operator_name,
                    reason="logout",
                )
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    return app
