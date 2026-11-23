"""승인된 서버는 기본 통과: 새 도구 허용, 명시적 사후 차단(서버·도구·사용자·행위), 해제 복귀."""

from dataclasses import replace

from plugin_helpers import approval, denial, request, resolved_server, snapshot, user_principal

from mint_litellm.plugin.pipeline import (
    control_listing_negative,
    denial_and_approval,
    derive_principal,
    tool_traits,
)
from mint_litellm.plugin.snapshot import ToolContractRow
from mint_litellm.types.contracts import ALL_TOOLS, covers, denial_hits_tool

RESOLVED = resolved_server()


def principal(snap, **kw):
    return derive_principal(snap, user_principal(**kw))


def selected(snap, tool, **kw):
    sel = denial_and_approval(snap, principal(snap, **kw), RESOLVED, tool)
    return sel.results, sel.selected


def test_an_intake_approval_covers_tools_that_did_not_exist_at_approval():
    snap = snapshot(approvals=(approval(tools=("search",), all_tools=True),))
    results, chosen = selected(snap, "brand_new_tool")
    assert results == [] and chosen is not None
    # 명시 목록만 있는 승인(관리자가 직접 만든 것)은 목록 밖 도구를 허용하지 않는다
    snap = snapshot(approvals=(approval(tools=("search",)),))
    results, chosen = selected(snap, "brand_new_tool")
    assert chosen is None and results


def test_the_wildcard_covers_every_tool():
    assert covers((ALL_TOOLS,), "anything") and not covers(("a",), "b")
    snap = snapshot(approvals=(approval(tools=(ALL_TOOLS,)),))
    assert selected(snap, "x")[1] is not None


def test_a_tool_denial_blocks_only_that_tool_and_only_that_user():
    deny = denial(scope_type="user", scope_id="u1", server_id="srv-1", tools=("drop",))
    snap = snapshot(approvals=(approval(tools=(ALL_TOOLS,)),), denials=(deny,))
    assert selected(snap, "drop")[0]  # 막힌 도구
    assert selected(snap, "search") == ([], snap.approvals[0])  # 형제 도구는 그대로
    other = selected(snap, "drop", user_id="u2")  # 다른 사용자는 그대로
    assert other[0] == []
    lifted = replace(snap, denials=())  # 해제하면 바로 복귀
    assert selected(lifted, "drop")[0] == []


def test_a_server_denial_blocks_every_tool_of_the_server():
    deny = denial(scope_type="server", scope_id="srv-1", server_id="srv-1", tools=None)
    snap = snapshot(approvals=(approval(tools=(ALL_TOOLS,)),), denials=(deny,))
    assert selected(snap, "a")[0] and selected(snap, "b")[0]


def test_an_action_denial_blocks_the_tools_of_that_action_type():
    assert denial_hits_tool(("action:delete",), "drop", "delete")
    assert not denial_hits_tool(("action:delete",), "drop", "read")
    assert not denial_hits_tool(("action:delete",), "drop", None)
    deny = denial(scope_type="user", scope_id="u1", server_id="srv-1", tools=("action:delete",))
    contracts = (
        ToolContractRow("c1", "server", "drop", "none", 1, action_type="delete",
                        risk_grade="high"),
        ToolContractRow("c2", "server", "search", "none", 1, action_type="read",
                        risk_grade="low"),
    )
    from plugin_helpers import server_row

    snap = snapshot(
        server=server_row(contract_status="managed"), tool_contracts=contracts,
        approvals=(approval(tools=(ALL_TOOLS,)),), denials=(deny,))
    action = tool_traits(snap, "drop", {})[0]
    assert action == "delete"
    blocked = denial_and_approval(snap, principal(snap), RESOLVED, "drop", action)
    assert blocked.results
    sibling = denial_and_approval(
        snap, principal(snap), RESOLVED, "search", tool_traits(snap, "search", {})[0])
    assert sibling.results == [] and sibling.selected is not None
    # 목록 조회에서는 막힌 도구도 남긴다(호출 때 막는다)
    assert control_listing_negative(snap, principal(snap), RESOLVED, "drop", "delete") is None
    assert control_listing_negative(snap, principal(snap), RESOLVED, "search", "read") is None


def test_the_request_helper_is_importable():
    assert request() is not None


def test_a_post_block_stays_listed_blocks_the_call_and_lifts_at_once():
    deny = denial(scope_type="user", scope_id="u1", server_id="srv-1", tools=("drop",))
    snap = snapshot(approvals=(approval(tools=(ALL_TOOLS,)),), denials=(deny,))
    me = principal(snap)
    assert denial_and_approval(snap, me, RESOLVED, "drop", listing=True).results == []
    assert denial_and_approval(snap, me, RESOLVED, "drop").results
    lifted = replace(snap, denials=())
    assert denial_and_approval(lifted, principal(lifted), RESOLVED, "drop").results == []
    # 미승인 서버는 목록에서도 여전히 빠진다
    bare = snapshot(approvals=(), denials=())
    assert denial_and_approval(bare, principal(bare), RESOLVED, "drop", listing=True).results
