import asyncio
import json

import pytest
from endpoint_helpers import (
    SERVER_ID,
    auth,
    body,
    contract,
    local_snapshot,
    principal_of,
    registry,
    runtime,
)
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from plugin_helpers import call_approval, evaluator, harness

from mint_litellm.endpoint.contract import mismatched_fields, strict_json
from mint_litellm.endpoint.decide import DecideBody, install, local_request, make_router
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.types.fingerprint import argument_fingerprint

KEY_HEADER = {"Authorization": "Bearer sk-user"}


def decide_direct(h, payload=None, who=None, reg=None):
    call = local_request(
        DecideBody.model_validate(payload or body()),
        who or auth(),
        registry=reg or registry(),
        instance_id="inst",
        principal_factory=principal_of,
    )
    return asyncio.run(evaluate_request(call, h.deps))


# ---- 실행 계약 -------------------------------------------------------------------------------


def test_identical_contracts_match_and_every_field_is_compared():
    assert mismatched_fields(contract(), contract()) == ()
    assert mismatched_fields(contract(), contract(argv=("/opt/mcp/other.py",))) == ("argv",)
    assert mismatched_fields(contract(), contract(executable_sha256="c" * 64)) == (
        "executable_sha256",
    )
    assert mismatched_fields(contract(), contract(env={"MODE": "prod"})) == ("env",)
    assert mismatched_fields(contract(), contract(cwd="/tmp")) == ("cwd",)
    assert mismatched_fields(contract(), contract(script_sha256=None)) == ("script_sha256",)


def test_argv_order_matters_and_hash_follows_it():
    reordered = contract(argv=("/var/log/count.log", "/opt/mcp/count_mcp.py"))
    assert mismatched_fields(contract(), reordered) == ("argv",)
    assert contract().sha256() != reordered.sha256()
    swapped = contract(env={"B": "2", "A": "1"})
    assert contract(env={"A": "1", "B": "2"}).sha256() == swapped.sha256()


@pytest.mark.parametrize("path", ["relative/bin", "/usr/../bin/python3", "/usr//bin", "/a\0b"])
def test_relative_or_unnormalized_paths_are_rejected(path):
    with pytest.raises(ValueError):
        contract(executable=path)


def test_client_side_match_flag_is_not_accepted():
    data = body()
    data["exec_definition_match"] = True
    with pytest.raises(ValueError):
        DecideBody.model_validate(data)


def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers():
    assert strict_json(b'{"a":1}') == {"a": 1}
    for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
        with pytest.raises(ValueError):
            strict_json(raw)


# ---- 어댑터와 판정 -----------------------------------------------------------------------------


def test_matching_contract_is_judged_by_the_same_pipeline_and_recorded(tmp_path):
    h, _ = runtime(tmp_path)
    outcome = decide_direct(h)
    assert outcome.allowed and outcome.error is None
    assert len(h.store.of_kind("decision_evaluated")) == 1
    snap = outcome.snapshot
    assert snap.resolved_server_id == SERVER_ID and snap.resolved_transport == "stdio"
    assert snap.principal.user_id == "u1" and snap.principal.org_id == "org1"
    assert h.snapshots.queries[0].server_id == SERVER_ID and h.snapshots.queries[0].tool == "echo"


def test_contract_mismatch_blocks_and_never_reads_the_snapshot(tmp_path):
    h, _ = runtime(tmp_path)
    drifted = body(contract=contract(executable_sha256="c" * 64).model_dump(mode="json"))
    outcome = decide_direct(h, drifted)
    assert not outcome.allowed and outcome.error.code == "MINT-SERVER-IDENTITY-MISMATCH"
    assert h.snapshots.queries == []
    assert len(h.store.of_kind("decision_evaluated")) == 1


def test_unknown_server_is_unresolved(tmp_path):
    h, _ = runtime(tmp_path)
    outcome = decide_direct(h, body(server="other"))
    assert not outcome.allowed and outcome.error.code == "MINT-SERVER-UNRESOLVED"


def test_identity_comes_from_the_auth_object_not_the_body(tmp_path):
    h, _ = runtime(tmp_path)
    outcome = decide_direct(h, who=auth(user_id="intruder", team_id="t-other"))
    assert not outcome.allowed
    assert h.snapshots.queries[0].user_id == "intruder"
    assert outcome.snapshot.principal.user_id == "intruder"


def test_master_key_cannot_decide(tmp_path):
    h, _ = runtime(tmp_path)
    outcome = decide_direct(h, who=auth(token="master-alias"))
    assert not outcome.allowed and outcome.error.code == "MINT-MASTER-KEY-FORBIDDEN"


def test_changed_arguments_do_not_consume_a_call_approval(tmp_path):
    fp = argument_fingerprint({"text": "approved"}, bytes(range(32)))
    snap = local_snapshot(
        call_approvals=(call_approval(server_id=SERVER_ID, tool="echo", args_fp=fp),)
    )
    h = harness(tmp_path, snap, evaluate=evaluator("Allow"))
    decide_direct(h, body(arguments={"text": "changed"}))
    assert not h.store.consumed


# ---- 경로 ------------------------------------------------------------------------------------


def build_app(tmp_path, *, ready=True):
    h, rt = runtime(tmp_path)

    def user_api_key_auth(authorization: str | None = Header(default=None)):
        if authorization != "Bearer sk-user":
            raise HTTPException(status_code=401, detail="invalid key")
        return auth()

    app = FastAPI()
    router = make_router(
        auth_dependency=user_api_key_auth,
        runtime_provider=lambda: rt if ready else None,
        registry=registry(),
        principal_factory=principal_of,
    )
    assert install(app, router) is True
    assert install(app, router) is False  # 두 번째 설치는 경로를 늘리지 않는다
    return app, h


def post(client, payload=None, headers=KEY_HEADER, content=None):
    if content is None:
        content = json.dumps(payload or body())
    return client.post(
        "/mint/v1/decide", content=content, headers={**headers, "Content-Type": "application/json"}
    )


def test_route_requires_a_valid_caller_key(tmp_path):
    app, h = build_app(tmp_path)
    client = TestClient(app)
    assert post(client, headers={}).status_code == 401
    assert post(client, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert h.store.events == {}


def test_route_allows_and_denies_with_a_reference(tmp_path):
    app, h = build_app(tmp_path)
    client = TestClient(app)
    ok = post(client).json()
    assert ok["decision"] == "allow" and ok["reference"].endswith(":1")
    drift = body(contract=contract(argv=("/x.py",)).model_dump(mode="json"))
    denied = post(client, drift)
    assert denied.status_code == 200 and denied.json()["decision"] == "deny"
    assert denied.json()["error"]["code"] == "MINT-SERVER-IDENTITY-MISMATCH"
    assert len(h.store.of_kind("decision_evaluated")) == 2


def test_route_rejects_identity_fields_duplicates_and_large_bodies(tmp_path):
    app, h = build_app(tmp_path)
    client = TestClient(app)
    assert post(client, body(user_id="u9")).status_code == 422
    assert post(client, content='{"server":"cnt","server":"cnt"}').status_code == 422
    assert post(client, content="not json").status_code == 422
    assert post(client, content=" " * (64 * 1024 + 1)).status_code == 413
    assert h.store.events == {}


def test_route_fails_closed_when_the_runtime_is_not_ready(tmp_path):
    app, _ = build_app(tmp_path, ready=False)
    assert post(TestClient(app)).status_code == 503


def test_route_denies_when_the_decision_store_is_down(tmp_path):
    app, h = build_app(tmp_path)
    h.store.fail = RuntimeError("down")
    assert post(TestClient(app)).json()["decision"] == "deny"


def test_standin_server_gives_the_row_its_url_hash_and_transport(tmp_path):
    from endpoint_helpers import SERVER_ID, local_snapshot
    from plugin_helpers import server_row

    from mint_litellm.endpoint.decide import ContractRegistry, LocalServer
    from mint_litellm.types.decision import url_sha256

    standin = "https://standin.invalid/mcp"
    snap = local_snapshot(
        server=server_row(server_id=SERVER_ID, url_sha256=url_sha256(standin), transport="http")
    )
    h = harness(tmp_path, snap)
    reg = ContractRegistry({"cnt": LocalServer(SERVER_ID, contract(), standin, "http")})
    assert decide_direct(h, reg=reg).allowed
    # 자리 서버 없이 만든 행(서버 ID 고정 값)과는 맞지 않아 차단된다.
    other = harness(tmp_path / "b", snap)
    assert not decide_direct(other).allowed


def test_registry_file_round_trip(tmp_path):
    from mint_litellm.endpoint.decide import ContractRegistry

    document = {
        "servers": [
            {
                "name": "cnt",
                "server_id": "srv-1",
                "standin_url": "https://standin.invalid/mcp",
                "contract": contract().model_dump(mode="json"),
            }
        ]
    }
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    entry = ContractRegistry.load(path).get("cnt")
    assert entry.transport == "http" and entry.standin_url.endswith("/mcp")
    assert entry.contract == contract()
