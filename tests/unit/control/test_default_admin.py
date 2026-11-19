"""기본 관리자 root: 만들기, 이미 있으면 그대로 두기, 반쯤 만든 상태 이어 가기."""

import base64
import json

import pytest

from mint_litellm.control import default_admin as da


def _jwt(key: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps({"key": key}).encode()).decode().rstrip("=")
    return f"h.{body}.s"


class FakeLiteLLM:
    def __init__(self, user=None, password=None, reject_update=False):
        self.user, self.password, self.reject_update = user, password, reject_update
        self.calls: list[str] = []

    def __call__(self, base, path, body, key, method="POST"):
        self.calls.append(path.split("?")[0])
        if path.startswith("/user/info"):
            return (200, {"user_info": self.user}) if self.user else (404, {})
        if path == "/user/new":
            self.user = {"user_id": body["user_id"], "user_email": body["user_email"],
                         "user_role": body["user_role"]}
            return 200, {}
        if path == "/user/update":
            if self.reject_update:
                return 400, {}
            self.password = body["password"]
            return 200, {}
        if path == "/v2/login":
            ok = self.user and body["username"] == "root" and body["password"] == self.password
            return (200, {"token": _jwt("session-key")}) if ok else (401, {})
        if path == "/user/password/change":
            assert key == "session-key" and body["current_password"] == self.password
            assert body["new_password"] != body["current_password"]
            self.password = body["new_password"]
            return 200, {}
        raise AssertionError(path)


def test_creates_root_as_proxy_admin_with_the_default_password(monkeypatch):
    fake = FakeLiteLLM()
    monkeypatch.setattr(da, "_call", fake)
    assert da.ensure("http://l", "mk") == "created"
    assert fake.password == "rootrootroot"
    assert fake.user["user_email"] == "root" and fake.user["user_role"] == "proxy_admin"


def test_leaves_an_existing_root_alone_even_with_a_changed_password(monkeypatch):
    fake = FakeLiteLLM(user={"user_id": "root"}, password="changed-by-the-admin")
    monkeypatch.setattr(da, "_call", fake)
    assert da.ensure("http://l", "mk") == "exists"
    assert da.ensure("http://l", "mk") == "exists"  # 재기동·업그레이드마다 다시 실행돼도
    assert fake.password == "changed-by-the-admin"
    assert "/user/new" not in fake.calls and "/user/update" not in fake.calls


def test_finishes_a_half_made_root(monkeypatch):
    fake = FakeLiteLLM(user={"user_id": "root"}, password=da.TEMPORARY)
    monkeypatch.setattr(da, "_call", fake)
    assert da.ensure("http://l", "mk") == "completed"
    assert fake.password == da.PASSWORD


def test_reports_a_refused_password_policy(monkeypatch):
    monkeypatch.setattr(da, "_call", FakeLiteLLM(reject_update=True))
    with pytest.raises(RuntimeError, match="password_policy"):
        da.ensure("http://l", "mk")
