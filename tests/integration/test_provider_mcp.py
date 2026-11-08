"""공급자 쪽 MCP 차단: 모델 요청이 외부 MCP 서버를 가리키면 공급자에게 나가기 전에 막힌다.

실제 스택의 모델 요청 경로(채팅, 응답, Anthropic 메시지, 패스스루)에 가짜 응답 모델을 두고
외부 주소의 ``tools[]``와 ``mcp_servers``를 보낸다. 막힌 요청은 403과 판정 사건이 남고,
게이트웨이 주소나 MCP가 없는 요청은 이 사유로 막히지 않는다.
"""

import json
import re
import uuid

import httpx
import pytest
import support

LITELLM = support.url(support.LITELLM_PORTS[0])
EXTERNAL = "https://external.example.invalid/mcp"
CODE = "MINT-EXTERNAL-MCP-FORBIDDEN"


def external_tool() -> dict:
    return {"type": "mcp", "server_label": "x", "server_url": EXTERNAL, "require_approval": "never"}


def external_servers() -> list[dict]:
    return [{"type": "url", "url": EXTERNAL, "name": "x"}]


@pytest.fixture(scope="module")
def model(stack):
    name = "it-provider-mock-" + uuid.uuid4().hex[:8]
    created = httpx.post(
        f"{LITELLM}/model/new",
        headers=support.master_headers(),
        json={
            "model_name": name,
            "litellm_params": {
                "model": "openai/gpt-4o",
                "api_key": "sk-not-a-real-key",
                "mock_response": "ok",
            },
        },
        timeout=30,
    )
    created.raise_for_status()
    model_id = created.json()["model_id"]
    support.wait_until(
        lambda: any(
            m["id"] == name
            for m in httpx.get(
                f"{LITELLM}/v1/models", headers=support.master_headers(), timeout=10
            ).json()["data"]
        ),
        30,
        1,
        what="mock model",
    )
    yield name
    httpx.post(
        f"{LITELLM}/model/delete",
        headers=support.master_headers(),
        json={"id": model_id},
        timeout=30,
    )


def send(subject, path, body) -> httpx.Response:
    return httpx.post(
        f"{LITELLM}{path}",
        headers={
            "Authorization": f"Bearer {subject.key}",
            # 패스스루는 자체 Anthropic 자격이 없으면 훅 전에 401로 끝나므로 가짜 자격을 싣는다.
            "x-api-key": "sk-ant-not-a-real-key",
        },
        json=body,
        timeout=60,
    )


def code_of(reply: httpx.Response) -> str | None:
    """응답 어디에 담겼든(detail, error.message의 `403: {...}`) MINT 오류 코드를 찾는다."""
    found = re.search(r'\\?"code\\?":\\?"(MINT-[A-Z0-9-]+)', reply.text)
    return found.group(1) if found else None


def decisions(world, subject, since) -> list[dict]:
    return world.decisions_since(subject, since)


def plain_body(model: str, path: str, **extra) -> dict:
    """채팅 또는 응답 API의 가장 짧은 본문."""
    chat = {"messages": [{"role": "user", "content": "hi"}]}
    prompt = {"input": "hi"} if "responses" in path else chat
    return {"model": model, **prompt, **extra}


CASES = {
    "chat-tools": ("/v1/chat/completions", lambda m: plain_body(
        m, "/v1/chat/completions", tools=[external_tool()]
    )),
    "chat-mcp_servers": ("/v1/chat/completions", lambda m: plain_body(
        m, "/v1/chat/completions", mcp_servers=external_servers()
    )),
    "responses-tools": ("/v1/responses", lambda m: plain_body(
        m, "/v1/responses", tools=[external_tool()]
    )),
    "messages-mcp_servers": ("/v1/messages", lambda m: {
        "model": m, "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}],
        "mcp_servers": external_servers(),
    }),
    "passthrough-mcp_servers": ("/anthropic/v1/messages", lambda m: {
        "model": "claude-sonnet-4-5", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}], "mcp_servers": external_servers(),
    }),
    "passthrough-tools": ("/anthropic/v1/messages", lambda m: {
        "model": "claude-sonnet-4-5", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}], "tools": [external_tool()],
    }),
    "responses-extra_body": ("/v1/responses", lambda m: plain_body(
        m, "/v1/responses", extra_body={"tools": [external_tool()]}
    )),
    "responses-registered-name-on-another-host": ("/v1/responses", lambda m: plain_body(
        m, "/v1/responses", tools=[{"type": "mcp", "server_url": "https://evil.example/mcp/mcp_a"}]
    )),
    "passthrough-gateway-form": ("/anthropic/v1/messages", lambda m: {
        "model": "claude-sonnet-4-5", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"type": "mcp", "server_url": "litellm_proxy/mcp/mcp_a"}],
    }),
}


@pytest.mark.parametrize("case", CASES)
def test_external_mcp_in_a_model_request_is_refused_with_one_event(world, model, case):
    path, make = CASES[case]
    subject = world.subject(("a",))
    since = world.now()
    reply = send(subject, path, make(model))
    assert reply.status_code == 403, reply.text
    assert code_of(reply) == CODE, reply.text
    (event,) = decisions(world, subject, since)
    payload = event["payload"]
    assert payload["operation"] == "llm_request"
    assert (payload["evaluated_decision"], payload["enforced_action"]) == ("block", "block")
    assert payload["stop"]["reason_code"] == "EXTERNAL_MCP_FORBIDDEN"
    assert "external.example" not in json.dumps(payload)


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/responses"])
def test_a_gateway_address_is_not_refused(world, model, path):
    subject = world.subject(("a",))
    since = world.now()
    tool = {"type": "mcp", "server_url": "litellm_proxy/mcp/mcp_a", "require_approval": "never"}
    reply = send(subject, path, plain_body(model, path, tools=[tool]))
    assert code_of(reply) != CODE, reply.text
    assert all(
        (e["payload"].get("stop") or {}).get("reason_code") != "EXTERNAL_MCP_FORBIDDEN"
        for e in decisions(world, subject, since)
    )


@pytest.mark.parametrize("path", ["/v1/chat/completions", "/v1/responses"])
def test_a_request_without_mcp_passes_with_no_decision_event(world, model, path):
    subject = world.subject(("a",))
    since = world.now()
    reply = send(subject, path, plain_body(model, path))
    assert reply.status_code == 200, reply.text
    assert decisions(world, subject, since) == []


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/realtime/client_secrets", {"session": {"type": "realtime"}}),
        ("/v1/realtime/transcription_sessions", {}),
        ("/v1/realtime/client_secrets", {"session": {"tools": [external_tool()]}}),
    ],
    ids=["client-secrets", "transcription-sessions", "client-secrets-with-mcp"],
)
def test_realtime_requests_are_refused_before_a_session_exists(world, model, path, body):
    subject = world.subject(("a",))
    since = world.now()
    reply = send(subject, path, body)
    assert reply.status_code == 403, reply.text
    assert code_of(reply) == "MINT-REALTIME-FORBIDDEN", reply.text
    (event,) = decisions(world, subject, since)
    assert event["payload"]["stop"]["reason_code"] == "REALTIME_FORBIDDEN"
