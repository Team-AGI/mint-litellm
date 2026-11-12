"""로컬 실행 서버의 실행 계약: 정본 해시, 판정 단계가 비교하는 값."""

import json

import pytest
from pydantic import ValidationError

from mint_litellm.types.exec_contract import ExecContract

HEX = "ab" * 32


def contract(**override):
    args = {"executable": "/usr/bin/node", "argv": ["/opt/srv/index.js"], "executable_sha256": HEX}
    return ExecContract(**(args | override))


def test_the_hash_follows_every_field_and_ignores_key_order():
    base = contract()
    reordered = {"executable_sha256": HEX, "argv": ["/opt/srv/index.js"],
                 "executable": "/usr/bin/node"}
    assert ExecContract.model_validate_json(json.dumps(reordered)).sha256() == base.sha256()
    for change in (
        {"executable": "/usr/bin/deno"}, {"argv": ["/opt/srv/other.js"]}, {"cwd": "/work"},
        {"executable_sha256": "cd" * 32}, {"script_sha256": HEX}, {"env": {"A": "1"}},
        {"secret_refs": {"TOKEN": "ref-1"}},
    ):
        assert contract(**change).sha256() != base.sha256(), change


@pytest.mark.parametrize(
    "bad",
    [{"executable": "node"}, {"executable": "/usr/../bin/node"}, {"cwd": "work"},
     {"executable_sha256": "XYZ"}, {"argv": ["a\0b"]}, {"schema_version": 2}, {"unknown": 1}],
)
def test_a_contract_must_be_absolute_normalized_and_closed(bad):
    with pytest.raises(ValidationError):
        contract(**bad)


def test_a_windows_path_is_accepted_only_when_absolute_and_normalized():
    ok = contract(executable=r"C:\Tools\node.exe", cwd=r"D:\work")
    assert ok.executable == r"C:\Tools\node.exe"
    for bad in (r"C:Tools\node.exe", r"C:\Tools\..\node.exe", "C:/Tools/node.exe", r"\\srv\a"):
        with pytest.raises(ValidationError):
            contract(executable=bad)


def test_the_resolved_server_carries_the_hash_and_no_url_hash():
    resolved = contract().resolved("local-1")
    assert resolved.identity_kind == "stdio" and resolved.url_sha256 is None
    assert resolved.exec_contract_sha256 == contract().sha256()
    assert resolved.exec_contract_version == 1
    assert resolved.matches_contract(
        identity_kind="stdio", exec_contract_sha256=contract().sha256(),
        exec_contract_version=1, transport="stdio", auth_type="none",
    )
    assert not contract(argv=["/opt/srv/other.js"]).resolved("local-1").matches_contract(
        identity_kind="stdio", exec_contract_sha256=contract().sha256(),
        exec_contract_version=1, transport="stdio", auth_type="none",
    )
