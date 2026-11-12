import pytest

from mint_litellm.control.contract_observe import drift_kind, instance_differences, normalize_tools
from mint_litellm.control.contract_pin import verify_pin
from mint_litellm.control.errors import AdminError

TOOL = {"description": "read", "input_schema": {"type": "object"}}


def test_drift_classification():
    assert drift_kind(TOOL, None) == "removed"
    assert drift_kind(TOOL, {**TOOL, "input_schema": {}}) == "input_schema"
    assert drift_kind(TOOL, {**TOOL, "description": "changed"}) == "description"
    assert drift_kind(TOOL, {**TOOL, "annotations": {"readOnlyHint": True}}) == "description"
    assert drift_kind({**TOOL, "output_schema": {}}, TOOL) == "output_schema"
    assert drift_kind(TOOL, {**TOOL, "output_schema": {}}) == "none"


@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"tools": [], "error": True},
        {"status": "error", "message": "unreachable"},
        {"tools": [{"name": "x"}]},
        {"tools": [{"name": "x", "inputSchema": {}}] * 2},
        {"tools": [{"name": "x", "inputSchema": {}}] * 501},
    ],
)
def test_listing_failure_is_not_empty_catalog(body):
    with pytest.raises(ValueError):
        normalize_tools(body)


def test_listing_normalization_and_empty_catalog():
    assert normalize_tools({"tools": []}) == {}
    assert normalize_tools(
        {"tools": [{"name": "read", "description": "read", "inputSchema": {"type": "object"}}]}
    ) == {"read": TOOL}


def test_pin_checks_full_set_and_hash_domain():
    assert verify_pin({"read": TOOL}, {"read": TOOL})
    for response in (
        {},
        {"other": TOOL},
        {"read": TOOL, "extra": TOOL},
        {"read": {**TOOL, "input_schema": {}}},
        {"read": {}},
    ):
        with pytest.raises(AdminError):
            verify_pin({"read": TOOL}, response)


def test_instance_differences_compare_every_item_across_instances():
    same = [("a", "deployment", "", "h1"), ("b", "deployment", "", "h1")]
    assert instance_differences(["a", "b"], same) == []
    changed = [*same[:1], ("b", "deployment", "", "h2")]
    (diff,) = instance_differences(["a", "b"], changed)
    assert diff == {"kind": "deployment", "item": "", "digests": {"a": "h1", "b": "h2"}}


def test_an_item_missing_from_one_instance_is_a_difference_and_unlisted_instances_are_ignored():
    rows = [
        ("a", "tool", "server/read", "h1"),
        ("b", "tool", "server/read", "h1"),
        ("b", "tool", "server/write", "h9"),
        ("c", "tool", "server/read", "hX"),
    ]
    (diff,) = instance_differences(["a", "b"], rows)
    assert diff["item"] == "server/write" and diff["digests"] == {"a": None, "b": "h9"}
