"""결정 경로와 결과 보고 경로: 신원은 인증 객체에서, 계약 일치는 서버가, 보고는 판정을 만든 키만."""

import json
from types import SimpleNamespace

from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from plugin_helpers import (
    KEY,
    call_approval,
    evaluator,
    harness,
    server_row,
    snapshot,
)

from mint_litellm.compat import litellm_1_106 as compat
from mint_litellm.endpoint.decide import install, make_router, result_context
from mint_litellm.plugin.result import ResultDeps
from mint_litellm.types.exec_contract import ExecContract

CONTRACT = ExecContract(
    executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
)
KEY_HEADER = {"Authorization": "Bearer sk-user"}
REQUIRE = ({"type": "require_call_approval"},)


def local_row(contract=CONTRACT):
    return server_row(
        identity_kind="stdio", url_sha256=None, transport="stdio",
        exec_contract_sha256=contract.sha256(), exec_contract_version=1,
    )


def auth(**override):
    args = {"token": KEY, "api_key": "sk-user", "user_id": "u1", "team_id": "t1",
            "metadata": None, "end_user_id": None}
    return SimpleNamespace(**(args | override))


def principal_of(a, *, instance_id):
    return compat.principal_from_auth(a, instance_id=instance_id, master_alias="master-alias")


class FakeDatabase:
    """판정 사건 조회와 응답 관측이 읽는 상태. 판정 사건은 시험 저장소에서 읽는다."""

    def __init__(self, store):
        self.store = store

    async def read_decision(self, instance_id, invocation_id, attempt_id):
        for event in self.store.of_kind("decision_evaluated"):
            if (event.invocation_id, event.attempt_id) == (invocation_id, attempt_id):
                return event.payload
        return None

    async def read_epoch(self, instance_id):
        return 7

    async def has_negative_state(self, query):
        return False

    async def retired_servers(self, instance_id, reported):
        return []

    outcome_calls: list = []

    async def call_approval_outcomes(self, instance_id, user_id, since):
        self.outcome_calls.append((user_id, since))
        return "2026-01-01T00:00:00+00:00", [
            {"server": "srv-1", "tool": "t", "outcome": "approved", "reason": None, "at": "x"}
        ]


def build(tmp_path, snap=None, **kwargs):
    h = harness(tmp_path, snap or snapshot(server=local_row()), **kwargs)
    database = FakeDatabase(h.store)
    runtime = SimpleNamespace(
        config=h.deps.config,
        verified=kwargs.get("verified", True),
        deps=h.deps,
        database=database,
        result_deps=ResultDeps(config=h.deps.config, database=database, recorder=h.deps.recorder),
    )

    def user_api_key_auth(authorization: str | None = Header(default=None)):
        if authorization == "Bearer sk-user":
            return auth()
        if authorization == "Bearer sk-other":
            return auth(token="other-key", api_key="sk-other", user_id="u2")
        raise HTTPException(status_code=401, detail="invalid key")

    app = FastAPI()
    router = make_router(
        auth_dependency=user_api_key_auth,
        runtime_provider=lambda: runtime,
        principal_factory=principal_of,
    )
    assert install(app, router) is True
    assert install(app, router) is False
    return TestClient(app), h


def body(**override):
    data = {"server": "srv-1", "tool": "search", "arguments": {"q": "x"},
            "contract": CONTRACT.model_dump(mode="json"), "tool_use_id": "toolu_1"}
    return data | override


def post(client, path, payload, headers=KEY_HEADER):
    return client.post(path, content=json.dumps(payload),
                       headers={**headers, "Content-Type": "application/json"})


def test_decision_allows_a_registered_local_server_and_names_the_decision(tmp_path):
    client, h = build(tmp_path)
    answer = post(client, "/mint/v1/decide", body()).json()
    assert answer["decision"] == "allow" and answer["reference"].endswith(":1")
    (event,) = h.store.of_kind("decision_evaluated")
    assert event.payload["resolved_identity_kind"] == "stdio"
    assert event.payload["resolved_exec_contract_sha256"] == CONTRACT.sha256()


def test_decision_denies_a_changed_contract_a_remote_server_and_an_unknown_server(tmp_path):
    client, h = build(tmp_path)
    changed = CONTRACT.model_copy(update={"argv": ("/opt/srv/evil.js",)})
    denied = post(client, "/mint/v1/decide", body(contract=changed.model_dump(mode="json")))
    assert denied.json()["decision"] == "deny"
    assert denied.json()["error"]["code"] == "MINT-SERVER-IDENTITY-MISMATCH"
    remote, _ = build(tmp_path / "r", snapshot(server=server_row()))
    answer = post(remote, "/mint/v1/decide", body()).json()
    assert answer["error"]["code"] == "MINT-SERVER-IDENTITY-MISMATCH"
    unknown, _ = build(tmp_path / "u", snapshot(server=None))
    assert post(unknown, "/mint/v1/decide", body()).json()["decision"] == "deny"


def test_decision_takes_identity_from_the_key_only_and_needs_a_valid_key(tmp_path):
    client, h = build(tmp_path)
    assert post(client, "/mint/v1/decide", body(), headers={}).status_code == 401
    assert post(client, "/mint/v1/decide", body(user_id="u9")).status_code == 422
    dup = '{"server": "srv-1", "server": "srv-2"}'
    assert client.post("/mint/v1/decide", content=dup, headers=KEY_HEADER).status_code == 422
    assert h.store.events == {}


def _allowed_reference(client):
    return post(client, "/mint/v1/decide", body()).json()["reference"]


def test_a_result_report_is_recorded_once_for_the_key_that_made_the_decision(tmp_path):
    client, h = build(tmp_path)
    reference = _allowed_reference(client)
    report = {"reference": reference, "outcome": "success", "size_bytes": 12}
    assert post(client, "/mint/v1/result", report).json() == {"recorded": True}
    assert post(client, "/mint/v1/result", report).json() == {"recorded": True}
    (event,) = h.store.of_kind("call_response_received")
    assert event.payload["is_error"] is False and event.payload["size_bytes"] == 12
    assert event.payload["decision_ref"] == reference


def test_error_and_unknown_reports_are_kept_apart(tmp_path):
    client, h = build(tmp_path)
    errored = _allowed_reference(client)
    post(client, "/mint/v1/result", {"reference": errored, "outcome": "error"})
    assert h.store.of_kind("call_response_received")[0].payload["is_error"] is True
    unknown_client, uh = build(tmp_path / "u")
    reference = _allowed_reference(unknown_client)
    post(unknown_client, "/mint/v1/result", {"reference": reference, "outcome": "unknown"})
    (event,) = uh.store.of_kind("call_outcome_unknown")
    assert event.payload["exception_type"] == "client_report"


def test_only_the_deciding_key_can_report_and_only_for_an_allowed_local_decision(tmp_path):
    client, h = build(tmp_path)
    reference = _allowed_reference(client)
    other = {"Authorization": "Bearer sk-other"}
    report = {"reference": reference, "outcome": "success"}
    assert post(client, "/mint/v1/result", report, headers=other).status_code == 404
    ghost = {"reference": "00000000-0000-7000-8000-000000000000:1", "outcome": "success"}
    assert post(client, "/mint/v1/result", ghost).status_code == 404
    denied = post(client, "/mint/v1/decide", body(tool="other")).json()
    assert denied["decision"] == "deny"
    blocked = {"reference": denied["reference"], "outcome": "success"}
    assert post(client, "/mint/v1/result", blocked).status_code == 404
    assert post(client, "/mint/v1/result", {**report, "outcome": "maybe"}).status_code == 422
    assert h.store.of_kind("call_response_received") == []


def test_the_report_context_comes_from_the_recorded_decision_not_the_terminal(tmp_path):
    client, h = build(tmp_path)
    _allowed_reference(client)
    (event,) = h.store.of_kind("decision_evaluated")
    ctx = result_context(event.payload)
    assert ctx["allowed"] is True and ctx["server_id"] == "srv-1" and ctx["key_id"] == KEY
    assert ctx["user_id"] == "u1" and json.loads(json.dumps(ctx)) == ctx


def test_a_consumed_call_approval_is_not_reusable_after_a_lost_response(tmp_path):
    """소비 직후 응답이 사라져도 승인은 되살아나지 않고, 결과는 보고되지 않은 채로 남는다."""
    approval = call_approval(exec_contract_sha256=CONTRACT.sha256())
    snap = snapshot(server=local_row(), call_approvals=(approval,))
    client, h = build(tmp_path, snap, evaluate=evaluator("RequireApproval", obligations=REQUIRE))
    first = post(client, "/mint/v1/decide", body()).json()
    assert first["decision"] == "allow" and len(h.store.consumed) == 1
    assert h.store.consumed[0].exec_contract_sha256 == CONTRACT.sha256()
    # 응답이 단말에 닿지 않았다: 결과 보고가 없다.
    assert h.store.of_kind("call_response_received") == []
    consumed = h.store.of_kind("decision_evaluated")[0].payload["consumed_call_approval_id"]
    assert consumed == str(approval.id)
    # 승인 소비는 DB가 한 번만 허락한다(여기서는 같은 승인이 스냅숏에서 사라진 상태로 재시도).
    again, _ = build(
        tmp_path / "again", snapshot(server=local_row()),
        evaluate=evaluator("RequireApproval", obligations=REQUIRE),
    )
    retry = post(again, "/mint/v1/decide", body()).json()
    assert retry["decision"] == "deny" and retry["error"]["code"] == "MINT-CALL-APPROVAL-REQUIRED"


def test_both_routes_reject_bodies_over_the_limit(tmp_path):
    client, h = build(tmp_path)
    big = " " * (64 * 1024 + 1)
    for path in ("/mint/v1/decide", "/mint/v1/result"):
        assert client.post(path, content=big, headers=KEY_HEADER).status_code == 413
    assert h.store.events == {}


def test_each_route_has_its_own_limit_checked_from_the_declared_length_first(tmp_path):
    client, h = build(tmp_path)
    result_body = " " * (4 * 1024 + 1)  # 결정 요청에는 들어가지만 결과 보고에는 크다
    url = "/mint/v1/{}".format
    assert client.post(url("result"), content=result_body, headers=KEY_HEADER).status_code == 413
    assert client.post(url("decide"), content=result_body, headers=KEY_HEADER).status_code == 422
    # 본문을 읽기 전에 선언된 길이로 거절한다.
    headers = {**KEY_HEADER, "Content-Length": str(10 * 1024 * 1024)}
    assert client.post("/mint/v1/decide", content=b"{}", headers=headers).status_code in (400, 413)
    assert h.store.events == {}


def test_a_request_before_the_worker_finished_starting_gets_a_coded_refusal(tmp_path):
    client, _ = build(tmp_path, verified=False)
    # 결과 보고는 기동 전에는 받지 않는다(코드가 있는 503).
    res = post(client, "/mint/v1/result", {"reference": f"{'0' * 8}-0000-0000-0000-{'0' * 12}:1",
                                          "outcome": "success"})
    assert res.status_code == 503
    assert json.loads(res.json()["detail"])["error"]["code"] == "MINT-ENDPOINT-NOT-READY"
    # 판정은 파이프라인이 막고 사건을 남긴다(통과하지 않는다).
    res = post(client, "/mint/v1/decide", body())
    assert res.status_code == 200 and res.json()["decision"] == "deny"
    assert res.json()["error"]["code"] == "MINT-ENFORCEMENT-UNVERIFIED"


def test_a_second_guardrail_in_the_same_worker_does_not_attach_the_routes_again(monkeypatch):
    from mint_litellm.endpoint import decide as decide_module

    app = FastAPI()
    monkeypatch.setattr(compat, "proxy_app", lambda: app)
    monkeypatch.setattr(compat, "key_auth_dependency", lambda: (lambda: auth()))
    env = {decide_module.ENABLE_ENV: "true"}
    assert decide_module.install_from_env(env) is True
    count = len(app.router.routes)
    assert decide_module.install_from_env(env) is False
    assert len(app.router.routes) == count



def test_the_routes_fail_closed_when_the_runtime_is_not_ready(tmp_path):
    client, _ = build(tmp_path)
    app = FastAPI()
    router = make_router(
        auth_dependency=lambda: auth(), runtime_provider=lambda: None,
        principal_factory=principal_of,
    )
    install(app, router)
    for path in ("/mint/v1/decide", "/mint/v1/result"):
        assert TestClient(app).post(path, json=body()).status_code == 503


def test_outcomes_are_asked_for_the_user_of_the_key_only(tmp_path):
    client, h = build(tmp_path)
    answer = post(client, "/mint/v1/endpoint/outcomes", {"since": None})
    assert answer.status_code == 200 and answer.json()["items"][0]["tool"] == "t"
    assert post(client, "/mint/v1/endpoint/outcomes", {"since": None},
                headers={"Authorization": "Bearer sk-other"}).status_code == 200
    # 본문에 사용자를 적어도 받지 않고, 인증 없이는 열리지 않는다.
    assert post(client, "/mint/v1/endpoint/outcomes", {"user_id": "u2"}).status_code == 422
    assert post(client, "/mint/v1/endpoint/outcomes", {}, headers={}).status_code == 401
    assert [u for u, _ in FakeDatabase.outcome_calls[-2:]] == ["u1", "u2"]
