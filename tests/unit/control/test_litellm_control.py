"""제어 평면 클라이언트: 쓰기 경로·본문 제한, 쓰기 직전 경계, 실측 응답 형태 처리."""

import pytest
from litellm_control_stub import CONTROL_KEY, ControlStub, submission

from mint_litellm.control.errors import ControlError
from mint_litellm.control.litellm_control import (
    STAGE2_ALLOWED_ROUTES,
    LiteLLMControl,
    ResponseTooLarge,
    ResponseTooSlow,
)


@pytest.fixture
def stub():
    server = ControlStub()
    yield server
    server.close()


def client(stub, guard=lambda: None):
    return LiteLLMControl(stub.url, CONTROL_KEY, guard=guard)


def test_submission_list_returns_items(stub):
    stub.submissions = [submission("a"), submission("b", approval_status="rejected")]
    assert [i["server_id"] for i in client(stub).list_submissions()] == ["a", "b"]


def test_submission_credentials_are_dropped_on_receipt(stub):
    stub.submissions = [submission("a", credentials={"auth_value": "secret"})]
    assert "credentials" not in client(stub).list_submissions()[0]


def test_approve_and_reject_report_done_then_already(stub):
    stub.submissions = [submission("a"), submission("b")]
    c = client(stub)
    assert c.approve_submission("a") == "done"
    assert c.approve_submission("a") == "already"
    assert c.reject_submission("b", "policy") == "done"
    assert c.reject_submission("b", "again") == "already"
    assert stub.requests[-1][2] == {"review_notes": "again"}


def test_every_write_calls_the_guard_first_and_a_guard_error_stops_the_write(stub):
    stub.submissions = [submission("a")]
    calls = []
    c = client(stub, guard=lambda: calls.append(len(stub.requests)))
    c.approve_submission("a")
    assert calls == [0]  # 요청이 나가기 전에 불렸다
    c.list_submissions()
    c.test_connection({"url": "http://x"})
    assert len(calls) == 1  # 읽기·시험 경로는 쓰기 경계를 부르지 않는다

    def refuse():
        raise RuntimeError("restore")

    before = len(stub.requests)
    with pytest.raises(RuntimeError):
        client(stub, guard=refuse).reject_submission("a", "x")
    assert len(stub.requests) == before


def test_with_guard_returns_a_copy_with_the_same_connection(stub):
    base = client(stub)
    guarded = base.with_guard(lambda: None)
    assert guarded is not base and guarded._base == base._base and guarded._key == base._key


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1/mcp/server"),  # 서버 등록
        ("DELETE", "/v1/mcp/server/x"),  # 서버 삭제
        ("POST", "/v1/mcp/server/import"),
        ("POST", "/v1/mcp/server/register"),
        ("GET", "/v1/mcp/server/x/approve"),
        ("PUT", "/v1/mcp/server/x/y/approve"),
        ("POST", "/user/update"),
        ("POST", "/key/generate"),
        ("DELETE", "/key/update"),
    ],
)
def test_write_whitelist_refuses_other_methods_and_paths(stub, method, path):
    with pytest.raises(ControlError, match="허용되지 않은"):
        client(stub)._write(method, path, {})
    assert stub.requests == []


def test_probe_bodies_are_limited_to_the_contract_fields(stub):
    c = client(stub)
    with pytest.raises(ControlError, match="허용되지 않은 필드"):
        c.test_connection({"url": "http://x", "credentials": {"auth_value": "x"}})
    with pytest.raises(ControlError, match="허용되지 않은 필드"):
        c.test_tools_list({"url": "http://x", "static_headers": {"a": "b"}})
    assert stub.requests == []
    assert c.test_connection(
        {"url": "http://x", "transport": "http", "auth_type": "none", "server_id": "s"}
    ) == {"status": "ok"}


def test_tools_list_over_the_size_limit_is_refused(stub):
    stub.tools_raw = b'{"tools": [' + b'{"name": "t"},' * 100 + b'{"name": "u"}]}'
    with pytest.raises(ResponseTooLarge):
        client(stub).test_tools_list({"url": "http://x"}, max_bytes=100)
    assert client(stub).test_tools_list({"url": "http://x"})["tools"]


def test_the_probe_routes_extend_the_control_plane_route_list():
    from mint_litellm.types.cli_commands import CONTROL_PLANE_ALLOWED_ROUTES

    assert not set(STAGE2_ALLOWED_ROUTES) & set(CONTROL_PLANE_ALLOWED_ROUTES)
    assert set(STAGE2_ALLOWED_ROUTES) == {
        "/mcp-rest/test/connection",
        "/mcp-rest/test/tools/list",
    }


def test_server_update_is_limited_to_closing_allow_all_keys(stub):
    c = client(stub)
    for bad in (
        {"server_id": "a", "allow_all_keys": True},
        {"server_id": "a", "allow_all_keys": False, "url": "http://other"},
        {"server_id": "a"},
        {"allow_all_keys": False},
        None,
    ):
        with pytest.raises(ControlError, match="allow_all_keys: false"):
            c._write("PUT", "/v1/mcp/server", bad)
    assert stub.requests == []


def test_close_all_keys_updates_then_reads_back_and_reports_the_result(stub):
    stub.submissions = [submission("a", allow_all_keys=True, approval_status="active")]
    calls = []
    c = client(stub, guard=lambda: calls.append(1))
    assert c.close_all_keys("a") is True
    assert calls == [1]  # 쓰기 직전 경계
    assert [(m, p) for m, p, _ in stub.requests] == [
        ("PUT", "/v1/mcp/server"),
        ("GET", "/v1/mcp/server/a"),
    ]
    assert stub.requests[0][2] == {"server_id": "a", "allow_all_keys": False}
    stub.submissions[0]["allow_all_keys"] = True
    stub.close_works = False  # 수정이 반영되지 않으면 읽어 확인한 결과가 거짓이다
    assert c.close_all_keys("a") is False


def test_a_client_without_a_guard_cannot_write(stub):
    stub.submissions = [submission("a")]
    bare = LiteLLMControl(stub.url, CONTROL_KEY)
    for write in (
        lambda: bare.approve_submission("a"),
        lambda: bare.reject_submission("a", "x"),
        lambda: bare.close_all_keys("a"),
        lambda: bare.update_key_permission("k", [], {}),
    ):
        with pytest.raises(ControlError, match="경계"):
            write()
    assert stub.requests == []
    assert bare.list_submissions()  # 읽기는 경계 없이 된다


def test_a_refused_reject_is_reported_and_a_too_deep_response_is_a_limit(stub):
    stub.submissions = [submission("a")]
    stub.reject_refused = True
    assert client(stub).reject_submission("a", "x") == "refused"
    stub.tools_raw = b"[" * 5000 + b"]" * 5000
    with pytest.raises(ResponseTooLarge):
        client(stub).test_tools_list({"url": "http://x"})


def test_tools_list_must_finish_within_the_time_limit(stub):
    stub.tools_delay = 0.4
    assert client(stub).test_tools_list({"url": "http://x"}, seconds=3.0)["tools"]  # 기한 직전
    with pytest.raises(ResponseTooSlow):  # 기한 직후
        client(stub).test_tools_list({"url": "http://x"}, seconds=0.1)
