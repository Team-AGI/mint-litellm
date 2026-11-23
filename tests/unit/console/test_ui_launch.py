"""「LiteLLM 콘솔」 버튼: 1회용 인계 코드, 만료, 세션 결속, 로그아웃 폐기, 쿠키 이름."""

import hashlib
import json

import httpx
import pytest

from mint_litellm.compat import ui_session_1_106 as adapter
from mint_litellm.console.core import COOKIE, STAFF_COOKIE
from mint_litellm.control import ui_sessions
from mint_litellm.types import ui_handoff

UI = "https://gw.test/ui"
STAFFER = "sk-launch-staff"


@pytest.fixture
def lw(world):
    object.__setattr__(world.config, "litellm_ui_url", UI)
    world.stub.own(STAFFER, "human-9")
    world.stub.control(STAFFER, "human-9")
    return world


def code_of(response) -> str:
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith("https://gw.test/mint-ui/enter?code=")
    return location.split("code=")[1]


def redeem(world, code, *, key=None, path=ui_handoff.REDEEM_PATH):
    body = json.dumps({"code": code}).encode()
    headers = ui_handoff.sign(key or world.config.stage2.export_hmac_key, path, body)
    return world.client.post(path, content=body, headers=headers)


def staff_client(world):
    client = world.client.__class__(world.app, base_url="https://testserver",
                                    follow_redirects=False)
    assert client.post("/staff/login", data={"key": STAFFER}).status_code == 303
    return client


def test_button_opens_the_adapter_with_a_hashed_one_time_code(lw):
    admin = lw.session_client("admin")
    response = admin.get("/litellm/open")
    code = code_of(response)
    assert response.headers["referrer-policy"] == "same-origin"  # 다른 출처에 주소를 알리지 않음
    [(stored, user)] = lw.query("SELECT code_hash, user_id FROM mint.ui_handoffs")
    assert stored == hashlib.sha256(code.encode()).hexdigest() and code not in stored
    assert user == "human-1"


def test_the_code_is_one_time_and_returns_only_its_own_session(lw):
    first = code_of(lw.session_client("admin").get("/litellm/open"))
    second = code_of(lw.session_client("approver").get("/litellm/open"))
    got = redeem(lw, first)
    assert got.status_code == 200 and got.json()["user_id"] == "human-1"
    assert redeem(lw, first).status_code == 404  # 같은 코드 재사용
    other = redeem(lw, second).json()
    assert other["user_id"] == "human-2" and other["session_hash"] != got.json()["session_hash"]


def test_expired_unsigned_and_revoked_session_codes_are_refused(lw):
    admin = lw.session_client("admin")
    code = code_of(admin.get("/litellm/open"))
    assert redeem(lw, code, key=b"x" * 32).status_code == 403  # 서명 불일치
    assert redeem(lw, code, path="/other").status_code in (403, 404, 405)
    lw.query("UPDATE mint.ui_handoffs SET expires_at = now() - interval '1 second'")
    assert redeem(lw, code).status_code == 404  # 만료
    fresh = code_of(admin.get("/litellm/open"))
    lw.query("UPDATE mint.console_sessions SET revoked_at = now()")
    assert redeem(lw, fresh).status_code == 404  # 세션이 이미 끝남


def test_the_staff_button_binds_the_code_to_the_staff_session(lw):
    client = staff_client(lw)
    code = code_of(client.get("/staff/litellm/open"))
    assert redeem(lw, code).json()["user_id"] == "human-9"


def test_a_page_from_another_site_cannot_start_a_handoff_and_no_url_hides_it(lw):
    admin = lw.session_client("admin")
    assert admin.get("/litellm/open", headers={"sec-fetch-site": "cross-site"}).status_code == 403
    assert 'href="/litellm/open"' in admin.get("/").text
    assert 'href="/staff/litellm/open"' in staff_client(lw).get("/staff").text
    object.__setattr__(lw.config, "litellm_ui_url", None)
    assert 'href="/litellm/open"' not in admin.get("/").text
    assert admin.get("/litellm/open").status_code == 404


def test_mint_cookies_never_collide_with_the_litellm_token_cookie(lw):
    admin = lw.session_client("admin")
    staff = staff_client(lw)
    names = {c.name for c in (*admin.cookies.jar, *staff.cookies.jar)}
    assert names == {COOKIE, STAFF_COOKIE} and "token" not in names
    assert COOKIE.startswith("__Host-mint_") and STAFF_COOKIE.startswith("__Host-mint_")


def test_logout_removes_the_litellm_session_and_cancels_unused_codes(lw, monkeypatch):
    calls = []
    monkeypatch.setattr(ui_sessions, "_revoke_remote",
                        lambda url, key, session: calls.append(session) or True)
    admin = lw.session_client("admin")
    used = code_of(admin.get("/litellm/open"))
    unused = code_of(admin.get("/litellm/open"))
    session = redeem(lw, used).json()["session_hash"]
    token = lw.csrf(admin)
    assert admin.post("/logout", headers={"X-CSRF-Token": token}).status_code == 303
    assert calls == [session]
    assert lw.query("SELECT count(*) FROM mint.ui_handoffs WHERE revoked_at IS NULL")[0][0] == 0
    assert redeem(lw, unused).status_code == 404


def test_a_failed_removal_is_retried_by_the_sweep(lw, monkeypatch):
    monkeypatch.setattr(ui_sessions, "_revoke_remote", lambda *a: False)
    admin = lw.session_client("admin")
    redeem(lw, code_of(admin.get("/litellm/open")))
    admin.post("/logout", headers={"X-CSRF-Token": lw.csrf(admin)})
    pending = "SELECT count(*) FROM mint.ui_handoffs WHERE revoked_at IS NULL"
    assert lw.query(pending)[0][0] == 1
    monkeypatch.setattr(ui_sessions, "_revoke_remote", lambda *a: True)
    import psycopg
    with psycopg.connect(lw.url) as conn:
        assert ui_sessions.sweep(conn, "inst1", lw.stub.url, b"k" * 32) == 1
    assert lw.query(pending)[0][0] == 0


def test_console_and_adapter_hand_the_session_over_end_to_end(lw):
    """실제 어댑터 경로가 실제 콘솔 앱에 서명 호출을 보낸다(LiteLLM 쪽 세션 발급만 대역)."""
    opened, deleted = [], []

    class Backend:
        async def find_user(self, user_id):
            return {"user_id": user_id, "user_email": "a@acme.test", "user_role": "proxy_admin"}

        async def open_session(self, request, user, session_hash, seconds):
            opened.append((user["user_id"], user["user_role"], session_hash, seconds))
            from fastapi.responses import Response
            return Response("opened")

        async def delete_sessions(self, session_hash):
            deleted.append(session_hash)
            return 1

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    proxy = FastAPI()
    proxy.include_router(adapter.make_router(
        Backend(), lw.config.stage2.export_hmac_key, "https://console.internal",
        transport=httpx.ASGITransport(app=lw.app),
    ))
    code = code_of(lw.session_client("admin").get("/litellm/open"))
    with TestClient(proxy) as browser:
        entered = browser.get(f"{ui_handoff.ENTER_PATH}?code={code}")
        assert entered.status_code == 200 and entered.text == "opened"
        assert browser.get(f"{ui_handoff.ENTER_PATH}?code={code}").status_code == 403
    user, role, session, seconds = opened[0]
    assert (user, role) == ("human-1", "proxy_admin") and 0 < seconds <= 8 * 3600
