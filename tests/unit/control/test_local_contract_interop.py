"""묶음 검사가 저장한 실행 계약(판 2)을 승인·단말 목록이 같은 형식으로 읽는다."""

from mint_litellm.control.intake_checks import local_exec_contract
from mint_litellm.endpoint.refresh import scoped_desired
from mint_litellm.types.exec_contract import ExecContract

DIGEST = "d" * 64
MANIFEST = {"platform": {"python": "3.12"}, "entry": "demo.server:main"}
SPEC = {"argv": ["--x"], "network": "hosts", "allowed_hosts": ["pypi.org"],
        "file_access": [{"path": "/data", "mode": "rw"}]}


def test_the_stored_contract_is_read_back_the_way_approval_reads_it():
    stored = local_exec_contract(SPEC, DIGEST, MANIFEST, "/usr/bin/python3")
    assert stored["identity_kind"] == "stdio" and "executable_sha256" not in stored
    contract = ExecContract.model_validate(
        {k: v for k, v in stored.items() if k != "identity_kind"})
    assert contract.schema_version == 2 and contract.pack.sha256 == DIGEST
    assert contract.pack.entry == "demo.server:main" and contract.network == "hosts"
    assert contract.file_access[0].mode == "rw"
    assert {k: v for k, v in stored.items() if k != "identity_kind"} == contract.model_dump(
        mode="json")


def test_the_scope_list_carries_the_stored_pack_contract_for_the_kit():
    stored = local_exec_contract({"network": "none"}, DIGEST, MANIFEST, "/usr/bin/python3")
    row = {"server_id": "demo", "pack_sha256": DIGEST, "permit_until": "2030-01-01T00:00:00",
           "exec_contract": stored}
    item = scoped_desired([row])[0]
    assert item["contract"]["pack"] == {"sha256": DIGEST, "runtime": "python3", "python": "3.12",
                                        "entry": "demo.server:main"}
    assert "executable_sha256" not in item["contract"] and item["pack_sha256"] == DIGEST
