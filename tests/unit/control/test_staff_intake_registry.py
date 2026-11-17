import pytest

from mint_litellm.control.errors import ControlError
from mint_litellm.control.intake_jobs import _staff_registry
from mint_litellm.control.litellm_write import WriteRefused, check_write


class Registry:
    def __init__(self, entry=None):
        self.entry = entry
        self.calls = []

    def get_server(self, identifier):
        return self.entry

    def provision_staff_server(self, sid, url, transport, intake_id, url_hash):
        self.calls.append((sid, url, transport, intake_id, url_hash))
        self.entry = {"allow_all_keys": False, "mcp_info": {
            "mint_intake_id": intake_id, "mint_url_sha256": url_hash}}


def test_only_the_same_intake_may_reuse_its_closed_registry_entry():
    client = Registry()
    row = {"id": "intake-1", "server_id": "docs"}
    contract = {"url": "https://docs.example.com/mcp", "transport": "http", "url_sha256": "a" * 64}
    _staff_registry(client, row, contract)
    _staff_registry(client, row, contract)
    assert len(client.calls) == 1
    with pytest.raises(ControlError):
        _staff_registry(client, {**row, "id": "other-intake"}, contract)
    client.entry["allow_all_keys"] = True
    with pytest.raises(ControlError):
        _staff_registry(client, row, contract)


def test_registry_write_boundary_cannot_accept_commands_credentials_or_open_access():
    body = {"server_id": "docs", "server_name": "docs", "url": "https://example.com/mcp",
            "transport": "http", "auth_type": "none", "allow_all_keys": False,
            "rpm": 600, "max_concurrent_requests": 8, "timeout": 30,
            "mcp_info": {"mint_intake_id": "id", "mint_url_sha256": "a" * 64}}
    check_write("POST", "/v1/mcp/server", body)
    for override in ({"command": "sh"}, {"credentials": {}}, {"allow_all_keys": True},
                     {"transport": "stdio"}, {"auth_type": "oauth2"}):
        with pytest.raises(WriteRefused):
            check_write("POST", "/v1/mcp/server", {**body, **override})
