"""기간 승인은 인자 지문을 풀고 나머지 결속은 유지한다. 1회 승인·위험 행위는 정확히 맞아야 한다."""

from datetime import timedelta
from uuid import uuid4

from plugin_helpers import (
    NOW,
    call_approval,
    config,
    resolved_server,
    server_row,
    snapshot,
    user_principal,
)

from mint_litellm.plugin.pipeline import match_call_approval
from mint_litellm.plugin.snapshot import WINDOW_MAX_USES, ToolContractRow, consume_sql
from mint_litellm.types.decision import ResolvedServer
from mint_litellm.types.identity import OrgSource

EXEC = "e" * 64
WINDOW_END = NOW + timedelta(minutes=10)


def resolved(**override):
    args = {
        "server_id": "srv-1", "identity_kind": "stdio", "exec_contract_sha256": EXEC,
        "exec_contract_version": 1, "transport": "stdio", "auth_type": "none",
        "candidates_with_same_name": 1,
    }
    return ResolvedServer(**(args | override))


def local_server(**override):
    args = {
        "identity_kind": "stdio", "url_sha256": None, "exec_contract_sha256": EXEC,
        "exec_contract_version": 1, "transport": "stdio",
    }
    return server_row(**(args | override))


def match(row, arguments, tmp_path, *, snap=None, res=None):
    principal = user_principal().model_copy(update={"org_id": "org1", "org_source": OrgSource.TEAM})
    snap = snap or snapshot(server=local_server(), call_approvals=(row,), now=NOW)
    return match_call_approval(
        snap, principal, res or resolved(), "search", arguments, config(tmp_path), uuid4())


def window(**override):
    return call_approval(**({"exec_contract_sha256": EXEC, "valid_until": WINDOW_END} | override))


def test_a_window_matches_other_arguments_but_a_single_use_does_not(tmp_path):
    failure, consume = match(window(), {"q": "other", "page": 2}, tmp_path)
    assert failure is None and consume.windowed is True
    # 소비 요청은 승인 행의 지문을 쓰므로 사용 표 삽입의 결속 조건이 그대로 맞는다.
    assert consume.args_fp == window().args_fp
    single = call_approval(exec_contract_sha256=EXEC)
    assert match(single, {"q": "x"}, tmp_path)[0] is None
    failure, consume = match(single, {"q": "other"}, tmp_path)
    assert consume is None and failure.reason_code == "CALL_APPROVAL_REQUIRED"


def test_a_window_still_requires_the_other_bindings(tmp_path):
    other = {"q": "other"}
    assert match(window(), other, tmp_path, res=resolved(exec_contract_sha256="f" * 64))[1] is None
    assert match(window(principal_id="u2"), other, tmp_path)[1] is None
    assert match(window(server_id="srv-2"), other, tmp_path)[1] is None
    assert match(window(tool="other-tool"), other, tmp_path)[1] is None
    assert match(window(target="repo-a", action="read"), other, tmp_path)[1] is None
    assert match(window(fp_key_version=2), other, tmp_path)[1] is None
    # 정책 판본이 바뀌면 낡은 승인이다.
    failure, _ = match(window(policy_version_id="pv0"), other, tmp_path)
    assert failure.reason_code == "CALL_APPROVAL_STALE"
    assert match(window(valid_until=NOW - timedelta(seconds=1), expires_at=NOW), other,
                 tmp_path)[1] is None


def test_a_window_stops_at_the_use_limit(tmp_path):
    assert match(window(uses=WINDOW_MAX_USES - 1), {"q": "o"}, tmp_path)[0] is None
    failure, consume = match(window(uses=WINDOW_MAX_USES), {"q": "o"}, tmp_path)
    assert consume is None and failure.reason_code == "CALL_APPROVAL_REQUIRED"
    assert f"< {WINDOW_MAX_USES}" in consume_sql(match(window(), {"q": "o"}, tmp_path)[1])


def test_dangerous_actions_keep_exact_arguments_even_in_a_window(tmp_path):
    def managed(action):
        contract = ToolContractRow(
            id="c1", credential_scope="server", tool="search", drift="none", version=1,
            risk_grade="high", action_type=action)
        return snapshot(
            server=server_row(contract_status="managed"), tool_contracts=(contract,),
            call_approvals=(call_approval(contract_id="c1", valid_until=WINDOW_END),), now=NOW)

    row = managed("read").call_approvals[0]
    res = resolved_server()
    assert match(row, {"q": "o"}, tmp_path, snap=managed("read"), res=res)[0] is None
    for action in ("delete", "external_send", "credential_access"):
        snap = managed(action)
        assert match(row, {"q": "o"}, tmp_path, snap=snap, res=res)[1] is None
        assert match(row, {"q": "x"}, tmp_path, snap=snap, res=res)[0] is None
