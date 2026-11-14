"""LiteLLM 쓰기 클라이언트: 본문 제한, 경로 허용 목록, 응답 처리, 쓰기 직전 훅."""

import socket

import pytest
from fake_litellm import CONTROL_KEY, FakeLiteLLM

from mint_litellm.control.litellm_write import (
    LiteLLMForbidden,
    LiteLLMHttpError,
    LiteLLMKitKeys,
    LiteLLMSync,
    LiteLLMUnreachable,
    WriteRefused,
    check_kit_write,
    check_write,
)
from mint_litellm.endpoint.routes import KIT_KEY_ROUTES

SRV = "srv-1"
FULL = {"mcp_servers": [SRV], "mcp_tool_permissions": {SRV: ["a"]}}


@pytest.fixture
def fake():
    server = FakeLiteLLM()
    yield server
    server._server.shutdown()
    server._server.server_close()


@pytest.fixture
def client(fake):
    return LiteLLMSync(fake.url, CONTROL_KEY)


def test_a_key_update_sends_only_the_key_and_the_two_permission_fields(fake, client):
    fake.add_key("k1")
    client.update_key_permission("k1", [SRV], {SRV: ["a"]})
    (method, path, body), = fake.writes()
    assert (method, path) == ("POST", "/key/update")
    assert body == {"key": "k1", "object_permission": FULL}


def test_a_team_update_sends_only_the_team_and_the_two_permission_fields(fake, client):
    fake.add_team("t1")
    client.update_team_permission("t1", [SRV], {SRV: ["a"]})
    (_, path, body), = fake.writes()
    assert path == "/team/update"
    assert body == {"team_id": "t1", "object_permission": FULL}


@pytest.mark.parametrize(
    "path,body",
    [
        ("/key/update", {"key": "k", "object_permission": FULL, "blocked": True}),
        ("/key/update", {"key": "k", "object_permission": FULL, "models": []}),
        ("/key/update", {"key": "k", "metadata": {}}),
        ("/key/update", {"object_permission": FULL}),
        ("/key/update", {"key": "k", "object_permission": {"mcp_servers": []}}),
        ("/key/update", {"key": "k", "object_permission": {**FULL, "mcp_access_groups": []}}),
        ("/key/update", {"key": "k", "object_permission": {**FULL, "vector_stores": []}}),
        ("/key/update", {"key": "", "object_permission": FULL}),
        ("/key/update", {"key": "k", "object_permission": {"mcp_servers": "srv",
                                                           "mcp_tool_permissions": {}}}),
        ("/key/update", {"key": "k", "object_permission": {"mcp_servers": [],
                                                           "mcp_tool_permissions": {"s": "a"}}}),
        ("/team/update", {"team_id": "t", "object_permission": FULL, "max_budget": 1}),
        ("/team/update", {"key": "t", "object_permission": FULL}),
        ("/team/update", None),
    ],
)
def test_extra_missing_or_mistyped_body_fields_are_refused(path, body):
    with pytest.raises(WriteRefused):
        check_write("POST", path, body)


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/v1/mcp/server"),  # 서버 등록
        ("PUT", "/v1/mcp/server"),  # 서버 수정
        ("DELETE", "/v1/mcp/server/srv-1"),  # 서버 삭제
        ("POST", "/v1/mcp/server/import"),
        ("POST", "/v1/mcp/server/register"),
        ("PUT", "/v1/mcp/server/srv-1"),
        ("POST", "/v1/mcp/server/srv-1/user-credential"),
        ("PUT", "/v1/mcp/server/a/b/approve"),
        ("POST", "/key/generate"),
        ("POST", "/key/delete"),
        ("POST", "/team/delete"),
        ("PUT", "/key/update"),
        ("GET", "/key/update"),
        ("POST", "/user/update"),
    ],
)
def test_only_the_whitelisted_methods_and_paths_can_be_written(method, path):
    with pytest.raises(WriteRefused):
        check_write(method, path, None)


@pytest.mark.parametrize(
    "method,path",
    [
        ("PUT", "/v1/mcp/server/srv-1/approve"),
        ("PUT", "/v1/mcp/server/srv-1/reject"),
        ("POST", "/v1/mcp/server/srv-1/pin"),
        ("DELETE", "/v1/mcp/server/srv-1/pin"),
    ],
)
def test_the_four_server_paths_are_allowed_without_a_body(method, path):
    check_write(method, path, None)
    with pytest.raises(WriteRefused):
        check_write(method, path, {"x": 1})


def test_a_refused_write_never_reaches_the_network_or_the_hook(fake):
    called = []
    client = LiteLLMSync(fake.url, CONTROL_KEY, before_write=lambda: called.append(1))
    with pytest.raises(WriteRefused):
        client._write("POST", "/v1/mcp/server", {"server_name": "x"})
    assert fake.requests == [] and called == []


def test_the_hook_runs_before_every_write_and_can_stop_it(fake):
    fake.add_key("k1")
    order = []
    client = LiteLLMSync(
        fake.url, CONTROL_KEY, before_write=lambda: order.append(len(fake.requests))
    )
    client.update_key_permission("k1", [], {})
    assert order == [0]  # 요청이 나가기 전에 불렸다

    def stop():
        raise RuntimeError("restore")

    blocked = client.with_hook(stop)
    with pytest.raises(RuntimeError):
        blocked.update_key_permission("k1", [SRV], {})
    assert len(fake.writes()) == 1  # 막힌 쓰기는 나가지 않았다
    assert client.before_write is not stop  # 사본만 훅이 바뀐다


def test_reads_do_not_call_the_write_hook(fake):
    fake.add_key("k1")
    called = []
    client = LiteLLMSync(fake.url, CONTROL_KEY, before_write=lambda: called.append(1))
    assert client.get_key("k1")["key"] == "k1"
    assert called == []


def test_a_403_is_reported_as_forbidden_and_other_statuses_with_their_code(fake, client):
    fake.add_team("t1")
    fake.add_key("k1", team_id="t1")
    with pytest.raises(LiteLLMForbidden) as forbidden:
        client.update_key_permission("k1", [SRV], {})  # 팀이 서버를 허용하지 않는다
    assert forbidden.value.status == 403
    with pytest.raises(LiteLLMHttpError) as missing:
        client.update_key_permission("nope", [], {})
    assert (missing.value.status, missing.value.code) == (404, "litellm_http_404")
    fake.fail_writes["/team/update"] = 500
    with pytest.raises(LiteLLMHttpError) as broken:
        client.update_team_permission("t1", [], {})
    assert broken.value.status == 500


def test_an_unreachable_server_is_its_own_error():
    with socket.socket() as probe:  # 닫힌 포트
        probe.bind(("localhost", 0))
        port = probe.getsockname()[1]
    client = LiteLLMSync(f"http://localhost:{port}", CONTROL_KEY, timeout=1)
    with pytest.raises(LiteLLMUnreachable):
        client.get_key("k1")
    with pytest.raises(LiteLLMUnreachable):
        client.update_key_permission("k1", [], {})


def test_server_approval_calls_only_the_approve_path(fake, client):
    fake.add_server("srv-p", "pending_review")
    client.approve_server("srv-p")
    assert fake.writes() == [("PUT", "/v1/mcp/server/srv-p/approve", None)]
    assert fake.servers["srv-p"]["approval_status"] == "active"
    with pytest.raises(LiteLLMHttpError) as again:
        client.approve_server("srv-p")
    assert again.value.status == 400


def test_credential_columns_are_scrubbed_from_reads(fake, client):
    fake.add_server("srv-c")
    assert "credentials" not in client.get_server("srv-c")


def test_server_limits_are_written_alone_and_must_be_positive_integers(fake, client):
    fake.add_server("srv-1")
    client.set_server_limits("srv-1", {"rpm": 600, "max_concurrent_requests": 8})
    assert fake.writes() == [("PUT", "/v1/mcp/server",
                              {"server_id": "srv-1", "rpm": 600, "max_concurrent_requests": 8})]
    check_write("PUT", "/v1/mcp/server", {"server_id": "s", "allow_all_keys": False, "rpm": 1})
    for bad in ({"rpm": 0}, {"rpm": -1}, {"rpm": True}, {"rpm": "600"}, {"timeout": 5}):
        with pytest.raises(WriteRefused):
            check_write("PUT", "/v1/mcp/server", {"server_id": "s", **bad})


def test_the_only_server_update_allowed_closes_allow_all_keys(fake, client):
    fake.add_server("srv-1")
    fake.servers["srv-1"]["allow_all_keys"] = True
    client.disable_allow_all_keys("srv-1")
    assert fake.writes() == [("PUT", "/v1/mcp/server",
                              {"server_id": "srv-1", "allow_all_keys": False})]
    assert fake.servers["srv-1"]["allow_all_keys"] is False


@pytest.mark.parametrize(
    "body",
    [
        {"server_id": "s", "allow_all_keys": True},
        {"server_id": "s", "allow_all_keys": "false"},
        {"server_id": "s", "allow_all_keys": False, "url": "http://x.test"},
        {"server_id": "s", "url": "http://x.test"},
        {"allow_all_keys": False},
        {"server_id": "", "allow_all_keys": False},
        None,
    ],
)
def test_a_server_update_with_anything_else_is_refused(body):
    with pytest.raises(WriteRefused):
        check_write("PUT", "/v1/mcp/server", body)


# --- 단말 설치 묶음 키 -------------------------------------------------------------------------

KIT_KEY = {"user_id": "u1", "team_id": "t1", "key_alias": "mint-kit-ab12",
           "allowed_routes": list(KIT_KEY_ROUTES)}  # fmt: skip


def test_a_kit_key_is_limited_to_the_hook_routes_and_the_workers_client_cannot_make_one(
    fake, client
):
    kit = LiteLLMKitKeys(fake.url, CONTROL_KEY)
    key = kit.generate_kit_key(user_id="u1", team_id="t1", alias="mint-kit-ab12")
    assert key == "sk-generated-1"
    assert fake.generated == [KIT_KEY]
    assert fake.generated[0]["allowed_routes"] == [
        "/mint/v1/decide", "/mint/v1/result", "/mint/v1/endpoint/report"]
    kit.generate_kit_key(user_id="u2", team_id=None, alias="mint-kit-cd34")
    assert "team_id" not in fake.generated[1]
    with pytest.raises(WriteRefused):
        client._write("POST", "/key/generate", KIT_KEY)  # 제어 평면 클라이언트는 만들지 못한다.
    assert len(fake.generated) == 2


@pytest.mark.parametrize("body", [
    {**KIT_KEY, "allowed_routes": ["/mint/v1/decide", "llm_api_routes"]},
    {**KIT_KEY, "allowed_routes": []},
    {**KIT_KEY, "key_alias": "someone-elses"},
    {**KIT_KEY, "models": ["gpt"]},
    {**KIT_KEY, "user_role": "proxy_admin"},
    {**KIT_KEY, "user_id": ""},
    {k: v for k, v in KIT_KEY.items() if k != "user_id"},
    None,
])
def test_a_kit_key_request_that_widens_the_key_is_refused_before_sending(fake, body):
    kit = LiteLLMKitKeys(fake.url, CONTROL_KEY)
    with pytest.raises(WriteRefused):
        kit._write("POST", "/key/generate", body)
    assert fake.requests == []


def test_kit_keys_are_deleted_by_their_own_alias_only(fake):
    kit = LiteLLMKitKeys(fake.url, CONTROL_KEY)
    kit.delete_kit_keys(["mint-kit-ab12"])
    assert fake.writes("/key/delete") == [
        ("POST", "/key/delete", {"key_aliases": ["mint-kit-ab12"]})
    ]
    for body in (None, {"key_aliases": []}, {"key_aliases": ["prod-key"]},
                 {"key_aliases": ["mint-kit-a"], "keys": ["sk-1"]}):  # fmt: skip
        with pytest.raises(WriteRefused):
            check_kit_write("POST", "/key/delete", body)
    for method, path in (("POST", "/key/update"), ("PUT", "/key/generate"),
                         ("POST", "/user/new"), ("POST", "/key/regenerate")):
        with pytest.raises(WriteRefused):
            check_kit_write(method, path, KIT_KEY)


def test_a_key_that_is_already_gone_counts_as_deleted_but_other_failures_do_not(fake):
    kit = LiteLLMKitKeys(fake.url, CONTROL_KEY)
    fake.fail_writes["/key/delete"] = 404
    kit.delete_kit_keys(["mint-kit-ab12"])
    fake.fail_writes["/key/delete"] = 500
    with pytest.raises(LiteLLMHttpError):
        kit.delete_kit_keys(["mint-kit-ab12"])
    fake.fail_writes["/key/delete"] = 403
    with pytest.raises(LiteLLMForbidden):
        kit.delete_kit_keys(["mint-kit-ab12"])


def test_a_user_credential_is_deleted_by_user_id_on_the_two_credential_paths_only(fake, client):
    fake.credentials[SRV] = [{"user_id": "u1", "credential_type": "oauth2"},
                             {"user_id": "u2", "credential_type": "byok"}]
    assert [c["user_id"] for c in client.list_server_credentials(SRV)] == ["u1", "u2"]
    client._send = lambda *a, **k: (_ for _ in ()).throw(AssertionError)  # 훅 앞에서 막힌다
    for path in ("/v1/mcp/server/srv-1/user-credential",
                 "/v1/mcp/server/srv-1/oauth-user-credential"):
        for params in (None, {}, {"user_id": ""}, {"user_id": "u1", "x": "1"}, {"x": "u1"}):
            with pytest.raises(WriteRefused):
                client._write("DELETE", path, params=params)
    with pytest.raises(WriteRefused):
        client._write("DELETE", "/v1/mcp/server/srv-1/pin", params={"user_id": "u1"})
    with pytest.raises(WriteRefused):
        client._write("POST", "/v1/mcp/server/srv-1/user-credential", {"x": 1},
                      params={"user_id": "u1"})


def test_credential_deletes_remove_only_the_named_user_and_type(fake):
    fake.credentials[SRV] = [{"user_id": "u1", "credential_type": "oauth2"},
                             {"user_id": "u2", "credential_type": "byok"}]
    LiteLLMSync(fake.url, CONTROL_KEY).delete_user_credential(SRV, "u1", "oauth2")
    assert [c["user_id"] for c in fake.credentials[SRV]] == ["u2"]
    assert fake.writes() == [("DELETE", "/v1/mcp/server/srv-1/oauth-user-credential", None)]


def test_a_missing_credential_list_route_reads_as_none(fake, client):
    fake.credentials_api = False
    assert client.list_server_credentials(SRV) is None


# --- 차단·해제 ---------------------------------------------------------------------------------


def test_block_routes_carry_only_the_target_id(fake, client):
    fake.add_team("t1")
    fake.add_key("k1")
    client.set_blocked("key", "k1", True)
    client.set_blocked("team", "t1", True)
    client.set_blocked("key", "k1", False)
    assert [w[1:] for w in fake.writes()] == [
        ("/key/block", {"key": "k1"}), ("/team/block", {"team_id": "t1"}),
        ("/key/unblock", {"key": "k1"}),
    ]
    assert fake.keys["k1"]["blocked"] is False and fake.teams["t1"]["blocked"] is True


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/key/block", {"key": "k1", "blocked": False}),
        ("/key/block", {"team_id": "t1"}),
        ("/team/unblock", {"key": "k1"}),
        ("/key/block", {"key": ""}),
        ("/key/unblock", None),
    ],
)
def test_block_with_any_other_body_is_refused(path, body):
    with pytest.raises(WriteRefused):
        check_write("POST", path, body)


def test_block_is_post_only_and_the_kit_client_cannot_use_it():
    with pytest.raises(WriteRefused):
        check_write("PUT", "/key/block", {"key": "k1"})
    with pytest.raises(WriteRefused):
        check_kit_write("POST", "/key/block", {"key": "k1"})
