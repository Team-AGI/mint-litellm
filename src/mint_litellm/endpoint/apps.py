"""직원이 직접 만든 AI 프로그램(앱)의 자격 발급·조회·회수(단말 설치 키로 부르는 경로).

앱 키는 사람에게 결속된 LiteLLM 키이고 모델 호출과 MCP 경로만 열린다. 서버 권한은 그 사람에게
이미 적용되는 MINT 승인 그대로이며(새 승인 단계는 없다), 설치 묶음 키와 따로 만들고 회수한다.
키 값은 발급 응답에만 있고 어디에도 저장하지 않는다.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from mint_litellm.control.litellm_write import LiteLLMKitKeys
from mint_litellm.endpoint.routes import APPS_PATH

MAX_ACTIVE_APPS = 10
DEFAULT_DAYS = 30
ISSUER_ENV = "MINT_KIT_ISSUER_KEY"
LITELLM_URL_ENV = "MINT_LITELLM_INTERNAL_URL"
PUBLIC_URL_ENV = "MINT_ENDPOINT_PUBLIC_URL"
ACTOR = "mint-endpoint-kit"


class AppRefused(Exception):
    """요청을 받아 줄 수 없다. ``status``는 응답 코드, ``detail``은 사람이 읽는 사유이다."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class AppBody(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,39}$")
    days: StrictInt = Field(default=DEFAULT_DAYS, ge=1, le=90)


def issuer(env: Mapping[str, str] | None = None) -> LiteLLMKitKeys:
    """앱 키를 만들고 지우는 LiteLLM 클라이언트. 발급 키가 없으면 ``AppRefused``(503)."""
    env = os.environ if env is None else env
    key = (env.get(ISSUER_ENV) or "").strip()
    if not key:
        raise AppRefused(503, "앱 자격을 발급할 수 없습니다. 운영자에게 문의하십시오.")
    return LiteLLMKitKeys(env.get(LITELLM_URL_ENV) or "http://localhost:4000", key)


def urls(env: Mapping[str, str] | None = None) -> tuple[str | None, str | None]:
    """프로그램이 부를 주소(모델 호출 기준, MCP). 서버가 공개 주소를 모르면 둘 다 없다."""
    env = os.environ if env is None else env
    base = (env.get(PUBLIC_URL_ENV) or "").strip().rstrip("/")
    return (base, base + "/mcp") if base else (None, None)


def listing(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"apps": [{k: _iso(r[k]) for k in
                      ("id", "name", "key_alias", "created_at", "expires_at", "revoked_at")}
                     for r in rows]}


def _iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return None if value is None else str(value)


__all__ = ["APPS_PATH", "AppBody", "AppRefused", "issuer", "listing", "urls"]
