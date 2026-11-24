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


def test_a_network_declaration_changes_the_hash_but_a_missing_one_does_not():
    base = contract()
    assert "network" not in base.document()
    none, any_ = contract(network="none"), contract(network="any")
    assert len({base.sha256(), none.sha256(), any_.sha256()}) == 3
    assert none.document()["network"] == "none"
    with pytest.raises(ValidationError):
        contract(network="some")


def test_registration_hints_tell_what_the_network_declaration_means():
    from mint_litellm.types.exec_contract import network_hints

    assert network_hints(contract(network="none")) == []
    plain = network_hints(contract())
    assert len(plain) == 1 and "네트워크 미제한" in plain[0]
    runner = network_hints(contract(executable="/usr/bin/npx", network="any"))
    assert runner == ["이 계약은 네트워크를 쓸 것으로 보입니다."]


def test_host_allowlist_is_hashed_sorted_and_validated():
    base = {"executable": "/usr/bin/x", "executable_sha256": "0" * 64}
    a = ExecContract(**base, network="hosts", allowed_hosts=("b.io:443", "*.a.com"))
    b = ExecContract(**base, network="hosts", allowed_hosts=("*.a.com", "b.io:443"))
    assert a.allowed_hosts == ("*.a.com", "b.io:443") and a.sha256() == b.sha256()
    assert a.sha256() != ExecContract(**base, network="any").sha256()
    assert "allowed_hosts" not in ExecContract(**base).document()  # 이전 계약의 해시는 그대로
    for bad in (("A.com",), ("a.com:0",), ("a.com:70000",), ("a..com",), ("a.com", "a.com"), ()):
        with pytest.raises(ValueError):
            ExecContract(**base, network="hosts", allowed_hosts=bad)
    with pytest.raises(ValueError):  # 목록은 hosts 선언과 함께만
        ExecContract(**base, network="any", allowed_hosts=("a.com",))


V1_PLAIN = (
    '{"argv":["/opt/srv/index.js"],"cwd":null,"env":{},"executable":"/usr/bin/node",'
    '"executable_sha256":"' + HEX + '","identity_kind":"stdio","schema_version":1,'
    '"script_sha256":null,"secret_refs":{}}'
)
V1_FULL = (
    '{"allowed_hosts":["api.example.com:443"],"argv":["a","b"],"cwd":"/work","env":{"A":"1"},'
    '"executable":"/usr/bin/node","executable_sha256":"' + HEX + '",'
    '"file_access":[{"mode":"rw","path":"/data"}],"identity_kind":"stdio","network":"hosts",'
    '"schema_version":1,"script_sha256":"' + "cd" * 32 + '","secret_refs":{"T":"r"}}'
)


def test_the_first_version_serializes_and_hashes_byte_for_byte_as_before():
    plain = contract()
    assert plain.canonical() == V1_PLAIN
    assert plain.sha256() == "3c9484f97df991d11c27a924a30e204cbd99e5814126134562648cbd9a562fb6"
    full = contract(argv=["a", "b"], cwd="/work", script_sha256="cd" * 32, env={"A": "1"},
                    secret_refs={"T": "r"}, file_access=[{"path": "/data", "mode": "rw"}],
                    network="hosts", allowed_hosts=["api.example.com:443"])
    assert full.canonical() == V1_FULL
    assert full.sha256() == "1f7fe1809f536d0cc800454633554bafdcaae40deacae1fa4f1fbc6c086ca6f3"
    assert "pack" not in plain.document()


def pack_contract(**override):
    args = {
        "schema_version": 2, "executable": "/usr/bin/python3", "argv": ["--stdio"],
        "pack": {"sha256": HEX, "runtime": "python3", "python": "3.12",
                 "entry": "pyghidra_mcp.server:main"},
    }
    return ExecContract(**(args | override))


def test_a_pack_contract_needs_no_executable_hash_and_follows_the_pack():
    c = pack_contract()
    assert c.executable_sha256 is None and "executable_sha256" not in c.document()
    assert c.document()["pack"]["sha256"] == HEX
    assert c.resolved("local-1").exec_contract_version == 2
    assert ExecContract.model_validate_json(c.canonical().replace('"identity_kind":"stdio",', "")
                                            ).sha256() == c.sha256()
    other = pack_contract(pack={"sha256": "cd" * 32, "runtime": "python3", "python": "3.12",
                                "entry": "pyghidra_mcp.server:main"})
    assert other.sha256() != c.sha256()


@pytest.mark.parametrize(
    "bad",
    [{"schema_version": 1},  # 묶음은 2판에서만
     {"pack": None},  # 2판은 묶음이 있어야 한다
     {"pack": {"sha256": "xyz", "runtime": "python3", "python": "3.12", "entry": "a.b:c"}},
     {"pack": {"sha256": HEX, "runtime": "node", "python": "3.12", "entry": "a.b:c"}},
     {"pack": {"sha256": HEX, "runtime": "python3", "python": "3", "entry": "a.b:c"}},
     {"pack": {"sha256": HEX, "runtime": "python3", "python": "3.12", "entry": "a b"}},
     {"pack": {"sha256": HEX, "runtime": "python3", "python": "3.12", "entry": "a.b:c",
               "extra": 1}}],
)
def test_a_pack_contract_is_closed_and_tied_to_version_two(bad):
    with pytest.raises(ValidationError):
        pack_contract(**bad)


def test_the_first_version_still_needs_the_executable_hash():
    with pytest.raises(ValidationError):
        ExecContract(executable="/usr/bin/node")


NPM_INTEGRITY = "sha512-" + "A" * 86 + "=="


def npm_contract(**override):
    args = {"schema_version": 3, "executable": "npx", "argv": ["-y", "@o/srv@1.2.3", "/data"],
            "npm": {"name": "@o/srv", "version": "1.2.3", "integrity": NPM_INTEGRITY,
                    "bin": "srv"}}
    return ExecContract(**(args | override))


def test_an_npm_contract_runs_the_exact_pinned_package_without_a_path_or_file_hash():
    base = npm_contract()
    assert base.document()["npm"]["integrity"] == NPM_INTEGRITY and base.resolved("s").server_id
    for change in (
        {"npm": {**base.npm.model_dump(), "integrity": "sha512-" + "B" * 86 + "=="}},
        {"npm": {**base.npm.model_dump(), "bin": "other"}},
    ):
        assert npm_contract(**change).sha256() != base.sha256()
    bad = ({"argv": ["-y", "@o/srv@1.2.4"]}, {"argv": ["@o/srv@1.2.3"]},
           {"executable": "/usr/bin/npx"}, {"npm": None}, {"schema_version": 1},
           {"npm": {"name": "@o/srv", "version": "^1.2.3", "integrity": NPM_INTEGRITY,
                    "bin": "srv"}})
    for change in bad:
        with pytest.raises(ValidationError):
            npm_contract(**change)
    with pytest.raises(ValidationError):  # npx는 3판에서만 경로 없이 받는다
        contract(executable="npx")
