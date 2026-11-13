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


def test_declared_file_access_changes_the_hash_but_an_empty_one_does_not():
    base = contract()
    assert "file_access" not in base.document()
    assert contract(file_access=[]).sha256() == base.sha256()
    read = contract(file_access=[{"path": "/data", "mode": "ro"}])
    write = contract(file_access=[{"path": "/data", "mode": "rw"}])
    assert len({base.sha256(), read.sha256(), write.sha256()}) == 3
    assert read.document()["file_access"] == [{"path": "/data", "mode": "ro"}]


def test_file_access_is_ordered_by_path_and_the_mode_defaults_to_read():
    a = contract(file_access=[{"path": "/b"}, {"path": "/a", "mode": "rw"}])
    b = contract(file_access=[{"path": "/a", "mode": "rw"}, {"path": "/b", "mode": "ro"}])
    assert a.sha256() == b.sha256()
    assert [f.path for f in a.file_access] == ["/a", "/b"]


@pytest.mark.parametrize(
    "bad",
    [[{"path": "data"}], [{"path": "/a/../b"}], [{"path": "/a", "mode": "x"}],
     [{"path": "/a"}, {"path": "/a", "mode": "rw"}], [{"path": "/a", "extra": 1}]],
)
def test_file_access_must_be_absolute_normalized_unique_and_closed(bad):
    with pytest.raises(ValidationError):
        contract(file_access=bad)
