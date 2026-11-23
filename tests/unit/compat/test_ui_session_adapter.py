"""LiteLLM 안의 화면 세션 어댑터: 서명 확인, 코드 거부, 설치 조건, 사용하는 LiteLLM 심볼."""

import json

import httpx
import pytest

pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import Response  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from mint_litellm.compat import ui_session_1_106 as adapter  # noqa: E402
from mint_litellm.types import ui_handoff  # noqa: E402

KEY = b"k" * 32
HASH = "ab" * 32


class Backend:
    def __init__(self, role="internal_user"):
        self.role, self.deleted = role, []

    async def find_user(self, user_id):
        return {"user_id": user_id, "user_email": "e", "user_role": self.role}

    async def open_session(self, request, user, session_hash, seconds):
        return Response(f"{user['user_id']}:{session_hash}:{seconds}")

    async def delete_sessions(self, session_hash):
        self.deleted.append(session_hash)
        return 2


def client(backend, grant=None, status=200):
    def console(request):
        headers = dict(request.headers)
        assert ui_handoff.verify(KEY, ui_handoff.REDEEM_PATH, request.content, headers)
        if grant is None:
            return httpx.Response(404)
        return httpx.Response(status, json=grant)

    app = FastAPI()
    app.include_router(adapter.make_router(
        backend, KEY, "http://console", transport=httpx.MockTransport(console)))
    return TestClient(app)


GRANT = {"user_id": "u1", "session_hash": HASH, "seconds_left": 600}


def test_a_valid_code_opens_the_session_of_the_user_it_names():
    reply = client(Backend(), GRANT).get(f"{ui_handoff.ENTER_PATH}?code=abc")
    assert reply.text == f"u1:{HASH}:600"


@pytest.mark.parametrize("query", ["", "?code="])
def test_a_missing_code_is_refused_without_calling_the_console(query):
    assert client(Backend(), GRANT).get(ui_handoff.ENTER_PATH + query).status_code == 403


def test_an_unknown_or_used_code_and_a_non_person_user_are_refused():
    assert client(Backend(), None).get(f"{ui_handoff.ENTER_PATH}?code=x").status_code == 403
    assert client(Backend("customer"), GRANT).get(
        f"{ui_handoff.ENTER_PATH}?code=x").status_code == 403


def test_an_unreachable_console_is_a_retryable_error_not_a_session():
    assert client(Backend(), GRANT, status=500).get(
        f"{ui_handoff.ENTER_PATH}?code=x").status_code == 503


def test_revoke_needs_the_signature_and_a_session_hash():
    backend = Backend()
    web = client(backend)
    body = json.dumps({"session_hash": HASH}).encode()
    assert web.post(ui_handoff.REVOKE_PATH, content=body).status_code == 403
    bad = ui_handoff.sign(b"z" * 32, ui_handoff.REVOKE_PATH, body)
    assert web.post(ui_handoff.REVOKE_PATH, content=body, headers=bad).status_code == 403
    old = ui_handoff.sign(KEY, ui_handoff.REVOKE_PATH, body, now=1)
    assert web.post(ui_handoff.REVOKE_PATH, content=body, headers=old).status_code == 403
    short = json.dumps({"session_hash": "ab"}).encode()
    headers = ui_handoff.sign(KEY, ui_handoff.REVOKE_PATH, short)
    assert web.post(ui_handoff.REVOKE_PATH, content=short, headers=headers).status_code == 400
    assert backend.deleted == []
    good = ui_handoff.sign(KEY, ui_handoff.REVOKE_PATH, body)
    reply = web.post(ui_handoff.REVOKE_PATH, content=body, headers=good)
    assert reply.json() == {"deleted": 2} and backend.deleted == [HASH]


def test_the_adapter_installs_once_and_only_with_a_signing_key():
    app = FastAPI()
    key = "a" * 43
    assert not adapter.install_from_env(app, {})
    assert not adapter.install_from_env(app, {adapter.ENV_KEY: key, adapter.ENV_SWITCH: "off"})
    assert adapter.install_from_env(app, {adapter.ENV_KEY: key})
    assert not adapter.install_from_env(app, {adapter.ENV_KEY: key})
    web = TestClient(app)
    assert web.post(ui_handoff.REVOKE_PATH, content=b"{}").status_code == 403
    assert web.get(ui_handoff.ENTER_PATH).status_code == 403


def test_the_litellm_symbols_the_backend_uses_exist_in_the_installed_version():
    pytest.importorskip("litellm")
    from litellm.constants import LITELLM_UI_SESSION_DURATION
    from litellm.litellm_core_utils.duration_parser import duration_in_seconds
    from litellm.proxy._types import LitellmUserRoles, UserAPIKeyAuth
    from litellm.proxy.auth.login_utils import (
        LoginResult,
        create_ui_token_object,
        encode_ui_session_jwt,
    )
    from litellm.proxy.management_endpoints.key_management_endpoints import (
        delete_verification_tokens,
        generate_key_helper_fn,
    )
    from litellm.proxy.management_endpoints.sso_helper_utils import (
        check_is_admin_only_access,
        has_admin_ui_access,
    )
    from litellm.proxy.management_endpoints.ui_sso import set_session_token_cookie
    from litellm.proxy.utils import get_custom_url

    assert duration_in_seconds(LITELLM_UI_SESSION_DURATION) > 0 and duration_in_seconds("90s") == 90
    login = LoginResult(user_id="u", key="k", user_email=None, user_role="internal_user",
                        login_method="sso")
    token = create_ui_token_object(login_result=login, general_settings={}, premium_user=False)
    claims = encode_ui_session_jwt(token, "m" * 32)
    assert claims.count(".") == 2
    assert all((LitellmUserRoles, UserAPIKeyAuth, delete_verification_tokens,
                generate_key_helper_fn, check_is_admin_only_access, has_admin_ui_access,
                set_session_token_cookie, get_custom_url))
