"""OIDC 로그인(인가 코드 + PKCE): Keycloak·Authentik처럼 표준 OpenID Connect를 따르는 인증 서버.

신원 확인만 인증 서버에 맡긴다. 확인된 클레임 하나(기본 ``email``)를 LiteLLM 사용자 식별자로
삼고, 그 사용자가 LiteLLM에 있는지·사람 역할인지·(관리자 콘솔이면) 운영자 행이 있는지는 기존
로그인과 같은 규칙으로 따로 본다. 팀과 역할은 토큰 클레임이 아니라 LiteLLM 정보에서 읽는다.
"""

import base64
import hashlib
import json
import secrets
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import Request
from fastapi.responses import RedirectResponse, Response

from mint_litellm.console.login import LoginRefused
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import console_sessions

STATE_COOKIE = "__Host-mint_oidc"
CALLBACK_PATH = "/auth/oidc/callback"
STATE_SECONDS = 600
DISCOVERY_TTL = 3600
JWKS_TTL = 3600
JWKS_MIN_REFETCH = 30
LEEWAY = 60
# 비대칭 서명만 받는다. 대칭(HS*)과 none은 허용 목록에 없다.
ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512", "EdDSA"]
USER_CLAIMS = ("email", "preferred_username", "sub")
UNAVAILABLE = "SSO 서버에 연결할 수 없습니다. 잠시 뒤 다시 시도하십시오."


@dataclass(frozen=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str | None = None
    user_claim: str = "email"
    # 비우면 요청 주소로 유도한다. 역방향 프록시 뒤에서는 명시한다.
    redirect_uri: str | None = None
    scopes: str = "openid email profile"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "OidcConfig | None":
        issuer = (env.get("MINT_OIDC_ISSUER") or "").strip().rstrip("/")
        if not issuer:
            return None
        parts = urlsplit(issuer)
        local = parts.hostname == "localhost"
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            raise ControlError("MINT_OIDC_ISSUER는 https 주소여야 합니다.")
        client_id = (env.get("MINT_OIDC_CLIENT_ID") or "").strip()
        if not client_id:
            raise ControlError("MINT_OIDC_CLIENT_ID가 설정되어 있지 않습니다.")
        secret = (env.get("MINT_OIDC_CLIENT_SECRET") or "").strip()
        secret_file = (env.get("MINT_OIDC_CLIENT_SECRET_FILE") or "").strip()
        if secret_file:
            try:
                secret = Path(secret_file).read_text(encoding="utf-8").strip()
            except OSError:
                raise ControlError("MINT_OIDC_CLIENT_SECRET_FILE을 읽을 수 없습니다.") from None
        claim = (env.get("MINT_OIDC_USER_CLAIM") or "email").strip()
        if claim not in USER_CLAIMS:
            raise ControlError(
                f"MINT_OIDC_USER_CLAIM은 {', '.join(USER_CLAIMS)} 중 하나여야 합니다."
            )
        return cls(
            issuer, client_id, secret or None, claim,
            (env.get("MINT_OIDC_REDIRECT_URI") or "").strip() or None,
            (env.get("MINT_OIDC_SCOPES") or "").strip() or "openid email profile",
        )


@dataclass(frozen=True)
class SsoIdentity:
    user_id: str
    subject: str
    issuer: str
    target: str

    @property
    def key_token(self) -> str:
        """세션에 남기는 자리표. 키가 없는 로그인이므로 발급자와 주체의 SHA-256이다."""
        digest = hashlib.sha256(f"{self.issuer}\0{self.subject}".encode()).hexdigest()
        return console_sessions.SSO_PREFIX + digest


def saved_target(request: Request) -> str:
    """로그인을 시작한 화면(admin 또는 staff). 쿠키가 없거나 깨졌으면 admin."""
    try:
        saved = json.loads(base64.urlsafe_b64decode(request.cookies.get(STATE_COOKIE, "") + "=="))
        return "staff" if saved["t"] == "staff" else "admin"
    except (ValueError, KeyError, TypeError):
        return "admin"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class OidcClient:
    def __init__(
        self, config: OidcConfig, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.config = config
        self._transport = transport
        self._lock = threading.Lock()
        self._discovery: tuple[float, dict] | None = None
        self._jwks: tuple[float, list[dict]] | None = None
        self._jwks_tried = -JWKS_MIN_REFETCH

    def _http(self) -> httpx.Client:
        return httpx.Client(timeout=10.0, transport=self._transport)

    def _get_json(self, url: str) -> dict:
        try:
            with self._http() as client:
                response = client.get(url)
            body = response.json()
        except (httpx.HTTPError, ValueError):
            raise LoginRefused(UNAVAILABLE) from None
        if response.status_code != 200 or not isinstance(body, dict):
            raise LoginRefused(UNAVAILABLE)
        return body

    def discovery(self) -> dict:
        with self._lock:
            if self._discovery and time.monotonic() - self._discovery[0] < DISCOVERY_TTL:
                return self._discovery[1]
        doc = self._get_json(f"{self.config.issuer}/.well-known/openid-configuration")
        # 문서가 말하는 발급자가 설정과 다르면 다른 서버의 문서이다.
        if str(doc.get("issuer", "")).rstrip("/") != self.config.issuer:
            raise LoginRefused("SSO 서버의 발급자 값이 설정과 다릅니다.")
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(doc.get(field), str):
                raise LoginRefused("SSO 서버의 설정 문서가 올바르지 않습니다.")
        with self._lock:
            self._discovery = (time.monotonic(), doc)
        return doc

    def _keys(self, kid: str | None) -> list[dict]:
        """서명 키 집합. 모르는 키 식별자가 오면 주기 제한 안에서 다시 읽는다(키 교체 대응)."""
        now = time.monotonic()
        with self._lock:
            cached = self._jwks
            fresh = cached and now - cached[0] < JWKS_TTL
            known = cached and (kid is None or any(k.get("kid") == kid for k in cached[1]))
            if fresh and known:
                return cached[1]
            if cached and now - self._jwks_tried < JWKS_MIN_REFETCH:
                return cached[1]
            self._jwks_tried = now
        body = self._get_json(self.discovery()["jwks_uri"])
        keys = [k for k in body.get("keys", []) if isinstance(k, dict) and k.get("use") != "enc"]
        with self._lock:
            self._jwks = (time.monotonic(), keys)
        return keys

    # --- 흐름 ----------------------------------------------------------------------------

    def redirect_uri(self, request: Request) -> str:
        return self.config.redirect_uri or str(request.url_for("oidc_callback"))

    def begin(self, request: Request, target: str) -> Response:
        doc = self.discovery()
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        query = urlencode({
            "response_type": "code", "client_id": self.config.client_id,
            "redirect_uri": self.redirect_uri(request), "scope": self.config.scopes,
            "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        response = RedirectResponse(f"{doc['authorization_endpoint']}?{query}", status_code=303)
        packed = _b64(json.dumps(
            {"s": state, "n": nonce, "v": verifier, "t": target, "x": time.time() + STATE_SECONDS}
        ).encode())
        # 인증 서버에서 돌아오는 이동은 다른 사이트에서 오므로 이 쿠키만 Lax이다.
        response.set_cookie(
            STATE_COOKIE, packed, max_age=STATE_SECONDS, httponly=True, secure=True,
            samesite="lax", path="/",
        )
        return response

    def finish(self, request: Request, code: str, state: str) -> SsoIdentity:
        """콜백을 검증해 신원을 돌려준다. 어느 단계든 실패하면 ``LoginRefused``."""
        try:
            saved = json.loads(base64.urlsafe_b64decode(
                request.cookies.get(STATE_COOKIE, "") + "=="))
            expected_state, nonce, verifier, target, deadline = (
                saved["s"], saved["n"], saved["v"], saved["t"], saved["x"])
        except (ValueError, KeyError, TypeError):
            raise LoginRefused("로그인 요청이 만료되었습니다. 다시 시도하십시오.") from None
        if (
            time.time() > deadline or not code or not state
            or not secrets.compare_digest(str(state), str(expected_state))
        ):
            raise LoginRefused("로그인 요청이 만료되었거나 올바르지 않습니다.")
        doc = self.discovery()
        form = {
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": self.redirect_uri(request), "code_verifier": verifier,
            "client_id": self.config.client_id,
        }
        auth = None
        methods = doc.get("token_endpoint_auth_methods_supported") or []
        if self.config.client_secret:
            if methods and "client_secret_post" not in methods and "client_secret_basic" in methods:
                auth = httpx.BasicAuth(self.config.client_id, self.config.client_secret)
            else:
                form["client_secret"] = self.config.client_secret
        try:
            with self._http() as client:
                response = client.post(doc["token_endpoint"], data=form, auth=auth)
            token = response.json()
        except (httpx.HTTPError, ValueError):
            raise LoginRefused(UNAVAILABLE) from None
        id_token = token.get("id_token") if isinstance(token, dict) else None
        if response.status_code != 200 or not isinstance(id_token, str):
            raise LoginRefused("SSO 서버가 로그인을 거부했습니다.")
        claims = self.verify_id_token(id_token, nonce)
        return self._identity(claims, target)

    def verify_id_token(self, id_token: str, nonce: str) -> dict:
        try:
            import jwt
        except ImportError:
            raise LoginRefused("SSO에 필요한 모듈(PyJWT)이 설치되어 있지 않습니다.") from None
        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            matches = [k for k in self._keys(kid) if kid is None or k.get("kid") == kid]
            if not matches:
                raise LoginRefused("ID 토큰의 서명 키를 찾을 수 없습니다.")
            claims = jwt.decode(
                id_token, jwt.PyJWK(matches[0]).key, algorithms=ALGORITHMS,
                audience=self.config.client_id, leeway=LEEWAY,
                issuer=[self.config.issuer, self.config.issuer + "/"],
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError:
            raise LoginRefused("ID 토큰을 확인할 수 없습니다.") from None
        if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(
            claims["nonce"], nonce
        ):
            raise LoginRefused("ID 토큰이 이 로그인 요청의 것이 아닙니다.")
        aud = claims["aud"]
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.config.client_id:
            raise LoginRefused("ID 토큰의 대상이 올바르지 않습니다.")
        return claims

    def _identity(self, claims: dict, target: str) -> SsoIdentity:
        claim = self.config.user_claim
        value = claims.get(claim)
        if not isinstance(value, str) or not value.strip():
            raise LoginRefused(f"ID 토큰에 {claim} 값이 없습니다.")
        if claim == "email" and claims.get("email_verified") is False:
            raise LoginRefused("확인되지 않은 이메일로는 로그인할 수 없습니다.")
        return SsoIdentity(value.strip(), str(claims["sub"]), self.config.issuer, target)

    def logout_url(self, request: Request, return_to: str) -> str | None:
        """인증 서버가 종료 주소를 알리면 그 주소를, 아니면 None을 돌려준다."""
        try:
            endpoint = self.discovery().get("end_session_endpoint")
        except LoginRefused:
            return None
        if not isinstance(endpoint, str):
            return None
        parts = urlsplit(self.redirect_uri(request))
        query = urlencode({
            "client_id": self.config.client_id,
            "post_logout_redirect_uri": f"{parts.scheme}://{parts.netloc}{return_to}",
        })
        return f"{endpoint}?{query}"


def login_context(request: Request, error: str | None) -> dict:
    return {
        "error": error, "sso": request.app.state.oidc is not None,
        "key_login": request.app.state.config.key_login,
    }
