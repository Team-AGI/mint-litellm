"""직원 앱 자격 경로: 설치 키로만 발급·조회·회수하고, 형식과 한도는 서버가 지킨다."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from plugin_helpers import KEY
from test_endpoint_routes import KEY_HEADER, FakeDatabase, body, build, post

from mint_litellm.endpoint.apps import AppRefused

APPS = "/mint/v1/endpoint/apps"
APP_ID = "0197c0de-0000-7000-8000-000000000001"
WHEN = datetime(2026, 12, 24, tzinfo=UTC)


@pytest.fixture
def stored(monkeypatch):
    """앱 저장소 대역. 호출 인자를 기록하고 ``refuse``가 있으면 그 거절을 낸다."""
    monkeypatch.setenv("MINT_KIT_ISSUER_KEY", "sk-issuer")
    monkeypatch.setenv("MINT_ENDPOINT_PUBLIC_URL", "https://mint.example.test/")
    calls = {"create": [], "revoke": [], "refuse": None, "revoked": True}

    async def create(self, instance_id, key_token, name, days, issuer):
        calls["create"].append((key_token, name, days))
        if calls["refuse"]:
            raise calls["refuse"]
        return {"id": APP_ID, "name": name, "key": "sk-app-secret",
                "key_alias": f"mint-kit-app-{name}-aa11bb", "expires_at": WHEN,
                "servers": ["srv-1"], "user_id": "u1"}

    async def listing(self, instance_id, key_token):
        return [{"id": UUID(APP_ID), "name": "bot", "key_alias": "mint-kit-app-bot-aa11bb",
                 "created_at": WHEN, "expires_at": WHEN, "revoked_at": None}]

    async def revoke(self, instance_id, key_token, app_id, issuer):
        calls["revoke"].append((key_token, app_id))
        return calls["revoked"]

    monkeypatch.setattr(FakeDatabase, "endpoint_app_create", create, raising=False)
    monkeypatch.setattr(FakeDatabase, "endpoint_apps_list", listing, raising=False)
    monkeypatch.setattr(FakeDatabase, "endpoint_app_revoke", revoke, raising=False)
    return calls


def test_an_app_is_issued_for_the_calling_install_key_and_the_key_is_in_the_reply_only(
    tmp_path, stored
):
    client, _ = build(tmp_path)
    reply = post(client, APPS, {"name": "bot", "days": 7})
    assert reply.status_code == 201
    assert reply.json() == {
        "id": APP_ID, "name": "bot", "key": "sk-app-secret", "key_alias": "mint-kit-app-bot-aa11bb",
        "expires_at": WHEN.isoformat(), "base_url": "https://mint.example.test",
        "mcp_url": "https://mint.example.test/mcp", "servers": ["srv-1"],
    }
    assert stored["create"] == [(KEY, "bot", 7)]
    assert "sk-app-secret" not in client.get(APPS, headers=KEY_HEADER).text


def test_the_period_defaults_to_thirty_days_and_urls_are_null_when_the_server_does_not_know_them(
    tmp_path, stored, monkeypatch
):
    monkeypatch.delenv("MINT_ENDPOINT_PUBLIC_URL")
    client, _ = build(tmp_path)
    reply = post(client, APPS, {"name": "bot"}).json()
    assert stored["create"][0][2] == 30
    assert reply["base_url"] is None and reply["mcp_url"] is None


@pytest.mark.parametrize("payload", [
    {}, {"name": ""}, {"name": "Bot"}, {"name": "-bot"}, {"name": "a" * 41}, {"name": "a_b"},
    {"name": "bot", "days": 0}, {"name": "bot", "days": 91}, {"name": "bot", "days": "7"},
    {"name": "bot", "user_id": "u2"}, {"name": "bot", "team_id": "t9"},
])
def test_a_malformed_app_request_is_refused_before_anything_is_stored(tmp_path, stored, payload):
    client, _ = build(tmp_path)
    assert post(client, APPS, payload).status_code == 422
    assert stored["create"] == []


@pytest.mark.parametrize(("refusal", "status"), [
    (AppRefused(409, "같은 이름의 앱이 이미 있습니다."), 409),
    (AppRefused(409, "앱은 한 사람당 10개까지 만들 수 있습니다."), 409),
    (AppRefused(404, "no such kit key"), 404),
])
def test_a_refusal_keeps_its_status_and_its_reason(tmp_path, stored, refusal, status):
    stored["refuse"] = refusal
    client, _ = build(tmp_path)
    reply = post(client, APPS, {"name": "bot"})
    assert reply.status_code == status and reply.json() == {"detail": refusal.detail}


def test_without_an_issuer_key_the_server_cannot_issue(tmp_path, stored, monkeypatch):
    monkeypatch.delenv("MINT_KIT_ISSUER_KEY")
    client, _ = build(tmp_path)
    assert post(client, APPS, {"name": "bot"}).status_code == 503
    assert stored["create"] == []


def test_the_list_has_no_key_values_and_a_request_without_a_key_is_unauthorised(tmp_path, stored):
    client, _ = build(tmp_path)
    assert client.get(APPS, headers=KEY_HEADER).json() == {"apps": [{
        "id": APP_ID, "name": "bot", "key_alias": "mint-kit-app-bot-aa11bb",
        "created_at": WHEN.isoformat(), "expires_at": WHEN.isoformat(), "revoked_at": None}]}
    assert client.get(APPS).status_code == 401
    assert client.delete(f"{APPS}/{APP_ID}").status_code == 401


def test_revoking_is_for_the_callers_own_apps_and_repeats_are_fine(tmp_path, stored):
    client, _ = build(tmp_path)
    assert client.delete(f"{APPS}/{APP_ID}", headers=KEY_HEADER).json() == {
        "id": APP_ID, "revoked": True}
    assert client.delete(f"{APPS}/{APP_ID}", headers=KEY_HEADER).status_code == 200
    stored["revoked"] = False  # 다른 사람의 앱이거나 없는 앱
    assert client.delete(f"{APPS}/{APP_ID}", headers=KEY_HEADER).status_code == 404
    assert client.delete(f"{APPS}/not-an-id", headers=KEY_HEADER).status_code == 422


def test_the_client_label_reaches_the_decision_event_and_old_kits_may_omit_it(tmp_path):
    client, h = build(tmp_path)
    assert post(client, "/mint/v1/decide", body(client="app:bot")).json()["decision"] == "allow"
    assert post(client, "/mint/v1/decide", body()).json()["decision"] == "allow"
    first, second = h.store.of_kind("decision_evaluated")
    assert first.payload["client"] == "app:bot" and second.payload.get("client") is None


@pytest.mark.parametrize("label", ["", "app bot", "app:" + "a" * 61, "한글", "a/b"])
def test_a_malformed_client_label_is_refused(tmp_path, label):
    client, _ = build(tmp_path)
    assert post(client, "/mint/v1/decide", body(client=label)).status_code == 422
