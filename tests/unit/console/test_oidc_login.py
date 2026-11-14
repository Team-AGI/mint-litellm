"""OIDC 로그인: 가짜 인증 서버(RSA 키, 설정 문서, 키 집합, 토큰 교환)로 성공과 거부 경우 전부."""

import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from console_fixtures import CONTROL_KEY, user_info

jwt = pytest.importorskip("jwt")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

from mint_litellm.console import oidc  # noqa: E402
from mint_litellm.console.core import COOKIE, STAFF_COOKIE, ConsoleConfig  # noqa: E402
from mint_litellm.control import session_verify  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402

ISSUER = "https://idp.test/realms/mint"
CLIENT = "mint-console"


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeIdp:
    """설정 문서·키 집합·토큰 교환을 돌려주는 가짜 서버. 다음 ID 토큰의 클레임을 시험이 정한다."""

    def __init__(self) -> None:
        self.key = new_key()
        self.kid = "k1"
        self.claims: dict = {}
        self.sign_with = None
        self.algorithm = "RS256"
        self.end_session = True
        self.jwks_hits = 0
        self.last_form: dict = {}
        self.pending: dict = {}

    def jwk(self, key, kid) -> dict:
        data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        return {**data, "kid": kid, "use": "sig", "alg": "RS256"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            doc = {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/auth",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/certs",
            }
            if self.end_session:
                doc["end_session_endpoint"] = f"{ISSUER}/logout"
            return httpx.Response(200, json=doc)
        if path.endswith("/certs"):
            self.jwks_hits += 1
            return httpx.Response(200, json={"keys": [self.jwk(self.key, self.kid)]})
        if path.endswith("/token"):
            self.last_form = dict(parse_qs(request.content.decode()))
            claims = {
                "iss": ISSUER, "aud": CLIENT, "sub": "sub-1", "iat": int(time.time()),
                "exp": int(time.time()) + 300, "nonce": self.pending["nonce"],
                "preferred_username": "human-1", **self.claims,
            }
            claims = {k: v for k, v in claims.items() if v is not None}
            token = jwt.encode(
                claims, self.sign_with or self.key, algorithm=self.algorithm,
                headers={"kid": self.kid},
            )
            return httpx.Response(200, json={"id_token": token, "access_token": "x"})
        return httpx.Response(404)


@pytest.fixture
def idp():
    return FakeIdp()


@pytest.fixture
def sso(world, idp):
    """SSO를 켠 콘솔. 사용자 식별 클레임은 preferred_username이다."""
    config = oidc.OidcConfig(ISSUER, CLIENT, "s3cret", "preferred_username")
    world.app.state.oidc = oidc.OidcClient(config, httpx.MockTransport(idp.handler))
    object.__setattr__(world.config, "oidc", config)
    world.with_control_key()
    return world


def start(world, idp, target="admin"):
    response = world.client.get(f"/auth/oidc/login?target={target}")
    assert response.status_code == 303, response.text
    query = parse_qs(urlsplit(response.headers["location"]).query)
    idp.pending = {"nonce": query["nonce"][0], "state": query["state"][0]}
    return query


def callback(world, idp, state=None, target="admin"):
    query = start(world, idp, target)
    return world.client.get(
        "/auth/oidc/callback", params={"code": "c1", "state": state or query["state"][0]}
    )


def refused(response, status=401):
    assert response.status_code == status, response.text
    assert COOKIE not in response.cookies and STAFF_COOKIE not in response.cookies


def sessions(world):
    return world.query("SELECT user_id, key_token, subject, role, team_ids"
                       " FROM mint.console_sessions")


def test_the_login_redirect_uses_code_flow_with_pkce_state_and_nonce(sso, idp):
    query = start(sso, idp)
    assert query["response_type"] == ["code"] and query["client_id"] == [CLIENT]
    assert query["code_challenge_method"] == ["S256"]
    assert {"state", "nonce", "code_challenge", "redirect_uri"} <= set(query)
    assert query["redirect_uri"][0].endswith("/auth/oidc/callback")
    cookie = sso.client.cookies.jar
    assert any(c.name == oidc.STATE_COOKIE and c.secure for c in cookie)


def test_an_operator_signs_in_through_the_identity_provider(sso, idp):
    response = callback(sso, idp)
    assert response.status_code == 303 and response.headers["location"] == "/"
    assert COOKIE in sso.client.cookies
    [(user_id, key_token, subject, role, _)] = sessions(sso)
    assert (user_id, subject, role) == ("human-1", "admin", "admin")
    assert key_token.startswith("sso:") and len(key_token) == 4 + 64
    assert idp.last_form["code_verifier"] and idp.last_form["client_secret"] == ["s3cret"]
    assert sso.client.get("/").status_code == 200


def test_the_audit_event_names_issuer_and_subject_but_no_token(sso, idp):
    callback(sso, idp)
    [(payload,)] = sso.query(
        "SELECT payload::text FROM mint.events WHERE kind = 'console_session_started'")
    event = json.loads(payload)
    assert event["method"] == "oidc" and event["issuer"] == ISSUER
    assert event["idp_subject"] == "sub-1" and event["user_id"] == "human-1"
    assert event["subject"] == "admin"
    stored = sso.query("SELECT string_agg(e::text, ' ') FROM mint.events e")[0][0]
    assert "id_token" not in stored and "access_token" not in stored


@pytest.mark.parametrize("claims", [
    {"aud": "someone-else"}, {"iss": "https://evil.test/realms/mint"},
    {"exp": int(time.time()) - 3600}, {"nonce": "not-the-nonce"}, {"exp": None},
    {"preferred_username": None},
])
def test_a_bad_id_token_is_refused(sso, idp, claims):
    idp.claims = claims
    refused(callback(sso, idp))
    assert sessions(sso) == []


def test_a_token_signed_by_another_key_is_refused(sso, idp):
    idp.sign_with = new_key()
    refused(callback(sso, idp))
    assert sessions(sso) == []


def test_a_symmetric_algorithm_is_refused(sso, idp):
    idp.sign_with, idp.algorithm = "x" * 64, "HS256"
    refused(callback(sso, idp))


def test_a_state_mismatch_is_refused_and_no_token_is_exchanged(sso, idp):
    refused(callback(sso, idp, state="forged"))
    assert idp.last_form == {}


def test_a_callback_without_the_login_cookie_is_refused(sso, idp):
    start(sso, idp)
    sso.client.cookies.clear()
    refused(sso.client.get("/auth/oidc/callback", params={"code": "c", "state": "s"}))


def test_a_user_unknown_to_litellm_is_refused(sso, idp):
    idp.claims = {"preferred_username": "nobody"}
    response = callback(sso, idp)
    refused(response)
    assert "등록된 사용자가 아닙니다" in response.text


def test_a_non_human_litellm_user_is_refused(sso, idp):
    sso.stub.routes[("/user/info", CONTROL_KEY, "svc")] = (200, user_info("svc", "customer"))
    idp.claims = {"preferred_username": "svc"}
    refused(callback(sso, idp))


def test_a_litellm_user_without_an_operator_row_is_refused_on_the_admin_console(sso, idp):
    idp.claims = {"preferred_username": "human-9"}
    response = callback(sso, idp)
    refused(response, 403)
    assert "운영자" in response.text


def test_the_same_user_can_sign_in_to_the_staff_screens_with_teams_from_litellm(sso, idp):
    body = user_info("human-9")
    body["user_info"]["teams"] = ["team-a", "team-a"]
    sso.stub.routes[("/user/info", CONTROL_KEY, "human-9")] = (200, body)
    idp.claims = {"preferred_username": "human-9", "groups": ["team-claim-only"]}
    response = callback(sso, idp, target="staff")
    assert response.status_code == 303 and response.headers["location"] == "/staff"
    assert STAFF_COOKIE in sso.client.cookies
    [(user_id, key_token, subject, _, teams)] = sessions(sso)
    assert (user_id, subject, teams) == ("human-9", "staff", ["team-a"])
    assert key_token.startswith("sso:")
    assert sso.client.get("/staff").status_code == 200
    [(payload,)] = sso.query(
        "SELECT payload::text FROM mint.events WHERE kind = 'console_session_started'"
        " AND payload->>'method' = 'oidc'")
    assert json.loads(payload)["issuer"] == ISSUER


def test_the_email_claim_requires_a_verified_address(sso, idp):
    config = oidc.OidcConfig(ISSUER, CLIENT, None, "email")
    sso.app.state.oidc = oidc.OidcClient(config, httpx.MockTransport(idp.handler))
    sso.stub.routes[("/user/info", CONTROL_KEY, "a@corp.test")] = (200, user_info("a@corp.test"))
    idp.claims = {"email": "a@corp.test", "email_verified": False}
    refused(callback(sso, idp))


def test_the_signing_key_set_is_cached_and_refetched_on_an_unknown_key_id(sso, idp):
    callback(sso, idp)
    callback(sso, idp)
    assert idp.jwks_hits == 1
    idp.key, idp.kid = new_key(), "k2"
    client = sso.app.state.oidc
    client._jwks_tried = -1000  # 다시 읽기 제한 시간이 지난 것으로 본다
    assert callback(sso, idp).status_code == 303
    assert idp.jwks_hits == 2


def test_the_login_pages_offer_sso_first_and_key_login_second(sso):
    page = sso.client.get("/login").text
    assert "SSO로 로그인" in page and 'name="key"' in page
    assert "target=staff" in sso.client.get("/staff/login").text


def test_key_login_can_be_switched_off(sso):
    object.__setattr__(sso.config, "key_login", False)
    page = sso.client.get("/login").text
    assert "SSO로 로그인" in page and 'name="key"' not in page
    response = sso.client.post("/login", data={"key": "sk-admin"})
    refused(response, 403)
    assert sessions(sso) == []
    refused(sso.client.post("/staff/login", data={"key": "sk-admin"}), 403)


def test_without_sso_the_login_page_is_unchanged_and_the_routes_are_missing(world):
    page = world.client.get("/login").text
    assert "SSO" not in page and 'name="key"' in page
    assert world.client.get("/auth/oidc/login").status_code == 404


def test_logout_goes_through_the_identity_provider_when_it_offers_one(sso, idp):
    callback(sso, idp)
    token = sso.csrf(sso.client)
    response = sso.client.post("/logout", headers={"X-CSRF-Token": token}, data={"csrf": token})
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith(f"{ISSUER}/logout?") and f"client_id={CLIENT}" in location
    assert "post_logout_redirect_uri=" in location


def test_a_key_session_logs_out_locally(sso):
    client = sso.session_client("admin")
    token = sso.csrf(client)
    response = client.post("/logout", headers={"X-CSRF-Token": token}, data={"csrf": token})
    assert response.headers["location"] == "/login"


def test_session_verify_does_not_look_for_a_key_behind_an_sso_session():
    session = {"key_token": "sso:" + "a" * 64, "user_id": "u", "subject": "admin",
               "role": "admin"}
    human = {"user_role": "internal_user"}
    assert session_verify.verdict(session, None, human, {"role": "admin"}) is None
    assert session_verify.verdict(session, None, None, {"role": "admin"}) == "user_not_human"
    assert session_verify.verdict(session, None, human, None) == "operator_changed"
    key_session = {**session, "key_token": "a" * 64}
    assert session_verify.verdict(key_session, None, human, {"role": "admin"}) == "key_gone"


def test_configuration_from_the_environment():
    assert oidc.OidcConfig.from_env({}) is None
    config = oidc.OidcConfig.from_env({
        "MINT_OIDC_ISSUER": ISSUER + "/", "MINT_OIDC_CLIENT_ID": CLIENT})
    assert (config.issuer, config.user_claim, config.client_secret) == (ISSUER, "email", None)
    for env in (
        {"MINT_OIDC_ISSUER": "http://idp.test"},
        {"MINT_OIDC_ISSUER": ISSUER},
        {"MINT_OIDC_ISSUER": ISSUER, "MINT_OIDC_CLIENT_ID": CLIENT,
         "MINT_OIDC_USER_CLAIM": "groups"},
        {"MINT_OIDC_ISSUER": ISSUER, "MINT_OIDC_CLIENT_ID": CLIENT,
         "MINT_OIDC_CLIENT_SECRET_FILE": "/nonexistent/secret"},
    ):
        with pytest.raises(ControlError):
            oidc.OidcConfig.from_env(env)
    assert ConsoleConfig.__dataclass_fields__["key_login"].default is True


def test_the_client_secret_is_read_from_a_file(tmp_path):
    path = tmp_path / "secret"
    path.write_text("from-file\n", encoding="utf-8")
    config = oidc.OidcConfig.from_env({
        "MINT_OIDC_ISSUER": ISSUER, "MINT_OIDC_CLIENT_ID": CLIENT,
        "MINT_OIDC_CLIENT_SECRET_FILE": str(path)})
    assert config.client_secret == "from-file"


def test_an_issuer_with_a_trailing_slash_in_the_token_is_accepted(sso, idp):
    idp.claims = {"iss": ISSUER + "/"}
    assert callback(sso, idp).status_code == 303
