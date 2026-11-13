"""승인된 OAuth 범위보다 넓어진 서버 정의는 호출을 막고, 같거나 좁으면 통과시킨다."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from plugin_helpers import NOW, resolved_server, server_row, snapshot

from mint_litellm.compat.litellm_1_106 import _to_resolved
from mint_litellm.control.intake_checks import oauth_scopes_of
from mint_litellm.plugin.pipeline import contract_result
from mint_litellm.plugin.snapshot import ToolContractRow


def managed(approved):
    return snapshot(
        server=server_row(
            contract_status="managed", approved_contracts=1, approved_oauth_scopes=approved,
            last_observed_at=NOW - timedelta(seconds=5),
        ),
        tool_contracts=(ToolContractRow("c1", "server", "read", "none", 1),),
    )


def test_scopes_are_read_from_top_level_and_credentials_and_split():
    entry = {"scopes": ["a b"], "credentials": {"scopes": ["c", "a"], "client_id": "x"}}
    assert oauth_scopes_of(entry) == ["a", "b", "c"]
    assert oauth_scopes_of({"credentials": "masked"}) == []
    assert oauth_scopes_of(None) == []


def test_resolved_server_carries_configured_scopes_only():
    server = SimpleNamespace(
        server_id="s", url="https://x.example/mcp", transport="http", auth_type="oauth2",
        configured_scopes=("read write", "admin"), scopes=["discovered"],
    )
    assert _to_resolved(server, 1).oauth_scopes == ("admin", "read", "write")
    bare = SimpleNamespace(server_id="s", url="https://x.example/mcp", transport="http",
                           auth_type="none")
    assert _to_resolved(bare, 1).oauth_scopes == ()


@pytest.mark.parametrize(
    ("approved", "current", "blocked"),
    [
        (("a", "b"), ("a", "b", "c"), True),   # 넓어짐
        (("a", "b"), ("c",), True),            # 승인에 없는 범위
        (("a", "b"), ("a", "b"), False),       # 같음
        (("a", "b"), ("a",), False),           # 좁아짐
        ((), ("a",), True),                    # 승인된 범위가 없는데 생김
        (("a",), (), False),                   # OAuth 범위가 없는 서버
        (None, ("a",), False),                 # 승인 범위를 알 수 없음(이전 스키마): 건드리지 않음
    ],
)
def test_wider_scope_blocks_the_call(approved, current, blocked):
    result = contract_result(
        managed(approved), "read", 60, resolved_server(oauth_scopes=current)
    )
    assert (result.reason_code == "CONTRACT_DRIFT_oauth_scope") is blocked
    if not blocked:
        assert result.reason_code is None


def test_without_a_resolved_server_the_scope_check_is_skipped():
    assert contract_result(managed(("a",)), "read", 60).reason_code is None

