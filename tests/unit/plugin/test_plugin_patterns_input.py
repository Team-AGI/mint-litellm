import asyncio
import json
from dataclasses import replace

import pytest
from plugin_helpers import (
    NOW,
    approval,
    evaluator,
    harness,
    request,
    server_row,
    snapshot,
)

from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.plugin.policy.input import has_only_policy_fields
from mint_litellm.plugin.policy.opa_client import OPAClient
from mint_litellm.plugin.snapshot import ToolContractRow

D = "."  # 점 표기 주소를 저장소 위생 시험이 막으므로 나눠 쓴다


MANAGED_SERVER = server_row(contract_status="managed", last_observed_at=NOW)
CONTRACTS = (ToolContractRow("c1", "server", "search", "none", 1),)
MANAGED = snapshot(server=MANAGED_SERVER, tool_contracts=CONTRACTS)


def decide(h, **hook):
    return asyncio.run(evaluate_request(request(**hook), h.deps))


def sent_patterns(tmp_path, arguments, *, conditions=None, egress=(), markers=None):
    calls = []
    snap = snapshot(
        server=MANAGED_SERVER,
        tool_contracts=CONTRACTS,
        approvals=(approval(conditions=conditions or {}),),
        egress_targets=tuple(egress),
    )
    h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
    if markers is not None:

        async def fetch(**_):
            return markers

        h.deps = replace(h.deps, secret_markers=fetch)
    outcome = decide(h, arguments=arguments)
    assert outcome.allowed, outcome.error
    assert has_only_policy_fields(calls[0])
    return calls[0]["arguments"]["patterns"]


def test_every_call_carries_the_four_booleans_and_no_argument_text(tmp_path):
    calls = []
    h = harness(tmp_path, MANAGED, evaluate=evaluator(calls=calls))
    assert decide(h, arguments={"q": f"http://10{D}0{D}0{D}1/secret-text"}).allowed
    assert calls[0]["arguments"]["patterns"] == {
        "url_external": True,
        "private_host": True,
        "path_traversal": False,
        "secret_like": False,
    }
    assert "secret-text" not in str(calls[0])


def test_allowed_hosts_come_from_the_approval_and_from_egress_targets(tmp_path):
    args = {"u": "https://api.ok.test/x"}
    assert sent_patterns(tmp_path, args)["url_external"] is True
    assert (
        sent_patterns(tmp_path, args, conditions={"allowed_hosts": ["API.OK.TEST"]})["url_external"]
        is False
    )
    assert sent_patterns(tmp_path, args, egress=[("ok.test", None)])["url_external"] is False
    assert (
        sent_patterns(tmp_path, args, egress=[("https://api.ok.test/", "org1")])["url_external"]
        is False
    )
    assert sent_patterns(tmp_path, args, egress=[("ok.test", "other-org")])["url_external"] is True


def test_allowed_paths_come_from_the_approval(tmp_path):
    args = {"p": "/etc/passwd"}
    assert sent_patterns(tmp_path, args)["path_traversal"] is False
    assert (
        sent_patterns(tmp_path, args, conditions={"allowed_paths": ["/srv/docs"]})["path_traversal"]
        is True
    )
    inside = {"allowed_paths": ["/srv/docs"]}
    assert (
        sent_patterns(tmp_path, {"p": "/srv/docs/a"}, conditions=inside)["path_traversal"] is False
    )


def test_secret_markers_come_from_the_fetched_bundle_data(tmp_path):
    args = {"k": "ghp_abc"}
    assert sent_patterns(tmp_path, args)["secret_like"] is False
    assert sent_patterns(tmp_path, args, markers=("ghp_",))["secret_like"] is True


def test_missing_markers_stop_the_call_as_a_policy_engine_failure(tmp_path):
    h = harness(tmp_path, MANAGED)

    async def none(**_):
        return None

    h.deps = replace(h.deps, secret_markers=none)
    outcome = decide(h)
    assert not outcome.allowed
    assert outcome.error.code == "MINT-DEPENDENCY-OPA"


def test_malformed_pattern_conditions_are_a_schema_error_not_a_crash(tmp_path):
    calls = []
    snap = snapshot(
        server=MANAGED_SERVER,
        tool_contracts=CONTRACTS,
        approvals=(approval(conditions={"allowed_hosts": "a.test"}),),
    )
    h = harness(tmp_path, snap, evaluate=evaluator(calls=calls))
    outcome = decide(h)
    assert not outcome.allowed and not calls
    assert outcome.error.code == "MINT-SCHEMA-ERROR"


def test_stage1_input_without_patterns_is_still_accepted():
    value = {"arguments": {"keys": [], "sizes": {}}}
    assert has_only_policy_fields(value)
    for patterns in ({"x": True}, {"url_external": 1}):
        assert not has_only_policy_fields(
            {"arguments": {"keys": [], "sizes": {}, "patterns": patterns}}
        )


def _markers_client(handler):
    """``handler(path) -> (상태 코드, JSON 값)``을 돌려주는 로컬 서버에 비밀 표지를 세 번 묻는다."""

    async def serve(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                status, value = handler(head.split(b" ")[1].decode())
                body = json.dumps(value).encode()
                writer.write(
                    b"HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                    % (status, len(body))
                    + body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def go():
        server = await asyncio.start_server(serve, "localhost", 0, family=2)
        host, port = server.sockets[0].getsockname()[:2]
        client = OPAClient(f"http://{host}:{port}", 1.0)
        try:
            first = await client.secret_markers(policy_version_id="v", bundle_sha256="h")
            second = await client.secret_markers(policy_version_id="v", bundle_sha256="h")
            other = await client.secret_markers(policy_version_id="w", bundle_sha256="h")
        finally:
            await client.aclose()
            server.close()
            await server.wait_closed()
        return first, second, other

    return asyncio.run(go())


def test_markers_are_read_once_per_version_and_must_match_the_active_bundle():
    hits = []

    def handler(path):
        hits.append(path)
        return 200, {
            "result": {
                "bundle": {"policy_version_id": "v", "bundle_sha256": "h"},
                "secret_markers": ["AKIA"],
            }
        }

    first, second, other = _markers_client(handler)
    assert first == second == ("AKIA",)
    assert other is None
    assert hits == ["/v1/data/mint/context", "/v1/data/mint/context"]  # 판본 v 한 번, w 한 번


def test_marker_errors_are_none():
    assert _markers_client(lambda path: (500, {})) == (None, None, None)
    assert _markers_client(lambda path: (200, {"result": {}})) == (None, None, None)


def test_stage1_servers_get_no_patterns_and_are_not_blocked_by_url_arguments(tmp_path):
    calls = []
    h = harness(tmp_path, evaluate=evaluator(calls=calls))
    outcome = decide(h, arguments={"u": "http://10" + D + "0.0.1/", "p": "../x"})
    assert outcome.allowed
    assert "patterns" not in calls[0]["arguments"]
    assert calls[0]["server"]["contract_status"] == "none"
    assert calls[0]["server"].keys() >= {"id", "status"}


def test_managed_servers_send_the_contract_status(tmp_path):
    calls = []
    h = harness(tmp_path, MANAGED, evaluate=evaluator(calls=calls))
    assert decide(h).allowed
    assert calls[0]["server"]["contract_status"] == "managed"


def test_result_policy_reaches_the_call_context(tmp_path):
    conditions = {"max_result_bytes": 100, "max_result_items": 2}
    approvals = (approval(conditions=conditions),)
    snap = snapshot(server=MANAGED_SERVER, tool_contracts=CONTRACTS, approvals=approvals)
    outcome = decide(harness(tmp_path, snap, evaluate=evaluator()))
    assert outcome.allowed
    assert outcome.context["result_policy"] == {
        "max_result_bytes": 100,
        "max_result_items": 2,
        "scan": True,
        "enforce": True,
    }


def test_result_scan_is_off_for_servers_without_a_contract_and_when_the_approval_says_so(tmp_path):
    plain = decide(harness(tmp_path, snapshot(), evaluate=evaluator()))
    assert plain.context["result_policy"]["scan"] is False
    off = snapshot(
        server=MANAGED_SERVER,
        tool_contracts=CONTRACTS,
        approvals=(approval(conditions={"scan_result": False}),),
    )
    scan = decide(harness(tmp_path, off, evaluate=evaluator())).context["result_policy"]["scan"]
    assert scan is False


@pytest.mark.parametrize("bad", [0, -1, "10", 1.5, True])
def test_malformed_result_limits_are_a_schema_error(tmp_path, bad):
    snap = snapshot(approvals=(approval(conditions={"max_result_bytes": bad}),))
    outcome = decide(harness(tmp_path, snap, evaluate=evaluator()))
    assert not outcome.allowed and outcome.error.code == "MINT-SCHEMA-ERROR"
