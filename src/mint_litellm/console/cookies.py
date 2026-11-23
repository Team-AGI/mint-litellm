"""콘솔 쿠키: HTTPS면 ``__Host-``·Secure, 평문 HTTP면 접두사 없는 이름."""

from typing import Any

from fastapi import Request
from fastapi.responses import Response

COOKIE_OPTIONS = {"httponly": True, "samesite": "strict", "path": "/"}


def is_https(request: Request) -> bool:
    """요청이 HTTPS로 왔는가(앞단 프록시의 ``X-Forwarded-Proto: https`` 포함).

    이 값은 Secure·``__Host-`` 쿠키를 켜는 쪽으로만 쓰이므로 헤더를 위조해도 약해지지 않는다.
    """
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or forwarded == "https"


def cookie_name(request: Request, name: str) -> str:
    """HTTPS면 ``__Host-`` 이름 그대로, 평문 HTTP면 접두사를 뗀 이름.

    브라우저는 HTTP 응답의 Secure 쿠키와 Secure가 없는 ``__Host-`` 쿠키를 버리므로, 평문으로
    운영하는 사내망에서도 로그인이 유지되게 한다. HTTPS 요청은 ``__Host-`` 이름만 읽으므로 HTTP로
    심은 쿠키가 HTTPS 세션으로 쓰이지 않는다.
    """
    return name if is_https(request) else name.removeprefix("__Host-")


def set_cookie(response: Response, request: Request, name: str, value: str, **extra: Any) -> None:
    options = {**COOKIE_OPTIONS, **extra, "secure": is_https(request)}
    response.set_cookie(cookie_name(request, name), value, **options)


def delete_cookie(
    response: Response, request: Request, name: str, samesite: str = "strict"
) -> None:
    response.delete_cookie(
        cookie_name(request, name), path="/", secure=is_https(request), httponly=True,
        samesite=samesite,  # type: ignore[arg-type]
    )


def delete_litellm_token(response: Response, request: Request) -> None:
    """LiteLLM 화면이 로그인 상태로 읽는 ``token`` 쿠키를 지운다(LiteLLM이 심을 때와 같은 속성)."""
    response.delete_cookie(
        "token", path="/", secure=is_https(request), httponly=False, samesite="lax"
    )


def read_cookie(request: Request, name: str) -> str | None:
    return request.cookies.get(cookie_name(request, name))
