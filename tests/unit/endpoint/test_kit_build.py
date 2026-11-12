"""설치 묶음 만들기: 같은 입력이면 같은 바이트, 사용자 키는 묶음 안에만, 계약 해시는 서버와 같게."""

import gzip
import hashlib
import io
import json
import sys
import tarfile

import pytest
from kit_loader import load

from mint_litellm.endpoint.decide import DecideBody
from mint_litellm.endpoint.kit_build import approved_contracts, build_kit, kit_version
from mint_litellm.types.exec_contract import ExecContract

agent = load("mint_agent")
DOC = ExecContract(
    executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
).document()


def members(data: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as bundle:
        return {m.name: (m.mode, bundle.extractfile(m).read()) for m in bundle.getmembers()}


def test_the_same_input_gives_the_same_bytes_and_the_key_stays_inside_the_kit_file():
    first = build_kit({"srv": DOC}, decide_url="https://mint.test", key="sk-a")
    assert first == build_kit({"srv": DOC}, decide_url="https://mint.test", key="sk-a")
    other = build_kit({"srv": DOC}, decide_url="https://mint.test", key="sk-b")
    assert first != other
    files = members(first)
    assert sorted(files) == [
        "mint-kit/install.sh", "mint-kit/kit.json", "mint-kit/mint_agent.py",
        "mint-kit/mint_kit.py",
    ]  # fmt: skip
    assert files["mint-kit/kit.json"][0] == 0o600 and files["mint-kit/install.sh"][0] == 0o755
    assert [name for name, (_, body) in files.items() if b"sk-a" in body] == ["mint-kit/kit.json"]
    config = json.loads(files["mint-kit/kit.json"][1])
    assert config["kit_version"] == kit_version() and config["decide_url"] == "https://mint.test"
    assert set(config["servers"]) == {"srv"} and "identity_kind" not in config["servers"]["srv"]


def test_the_version_follows_the_program_files_not_the_user():
    def version(servers, url, key):
        config = members(build_kit(servers, decide_url=url, key=key))["mint-kit/kit.json"][1]
        return json.loads(config)["kit_version"]

    assert version({}, "https://a.test", "k1") == version({"s": DOC}, "https://b.test", "k2")


def test_a_contract_that_does_not_fit_the_schema_is_not_packed():
    with pytest.raises(ValueError):
        approved_contracts({"srv": {**DOC, "executable": "relative/node"}})


@pytest.mark.skipif(sys.platform == "win32", reason="posix paths")
def test_what_the_hook_reports_hashes_to_what_was_approved(tmp_path):
    """생산자(설치 묶음의 계약 파일과 훅)가 만든 값을 소비자(서버의 계약 해시)가 같게 계산한다."""
    exe, script = tmp_path / "srv-bin", tmp_path / "index.js"
    exe.write_bytes(b"binary")
    script.write_bytes(b"script")
    approved = ExecContract(
        executable=str(exe), argv=[str(script)], env={"MODE": "ro"},
        executable_sha256=hashlib.sha256(b"binary").hexdigest(),
        script_sha256=hashlib.sha256(b"script").hexdigest(),
    )  # fmt: skip
    kit = build_kit({"srv": approved.document()}, decide_url="https://mint.test", key="k")
    packed = json.loads(members(kit)["mint-kit/kit.json"][1])["servers"]["srv"]
    reported = agent.observed_contract(packed)
    body = DecideBody.model_validate(
        {"server": "srv", "tool": "t", "arguments": {}, "contract": reported}
    )
    assert body.contract.sha256() == approved.sha256()
    script.write_bytes(b"script-changed")
    changed = agent.observed_contract(packed)
    assert DecideBody.model_validate(
        {"server": "srv", "tool": "t", "arguments": {}, "contract": changed}
    ).contract.sha256() != approved.sha256()
