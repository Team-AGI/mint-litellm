"""단말 키트 서명 자동 갱신: 서명 검증, 같은 판본은 그대로, 교체 원자성, 실패 시 옛 코드 유지."""

import base64
import json
import zlib

import pytest
from test_kit_install import kit_module, make_kit, managed_files, unpack

from mint_litellm.endpoint import kit_sign
from mint_litellm.endpoint.decide import ReportBody
from mint_litellm.endpoint.kit_build import kit_version

SEED = bytes(range(32))
ENV = {kit_sign.ENV: base64.urlsafe_b64encode(SEED).decode().rstrip("=")}
NEW_VERSION = "v-new"
SERIAL = 4_000_000_000  # 설치된 묶음의 파일 시각 번호보다 크다
NEW_AGENT = b"# new agent\nVALUE = 1\n"


def make_bundle(seed=SEED, version=NEW_VERSION, serial=SERIAL, announce=None, **replace):
    files = {"mint_agent.py": NEW_AGENT, "mint_kit.py": b"# new kit\nVALUE = 2\n"}
    files.update(replace)
    digests = {n: kit_module.sha256_bytes(d) for n, d in files.items()}
    bundle = {
        "version": version,
        "serial": serial,
        "files": {n: base64.b64encode(zlib.compress(d)).decode() for n, d in files.items()},
        "sig": kit_sign.sign(seed, kit_sign.manifest(version, digests)).hex(),
        "sig2": kit_sign.sign(seed, kit_sign.manifest_v2(version, serial, digests)).hex(),
    }
    if announce:  # (옛 키 씨앗) 새 키가 서명한 묶음에 옛 키의 공지를 싣는다
        new = kit_sign.public_from_seed(seed)
        notice = kit_sign.sign(announce, kit_sign.key_notice(new)).hex()
        bundle["keys"] = [{"pub": new.hex(), "sig": notice}]
    return bundle


def run_now(fn):
    return fn()


@pytest.fixture
def installed(tmp_path, monkeypatch):
    monkeypatch.setenv(kit_sign.ENV, ENV[kit_sign.ENV])
    make_kit(unpack(tmp_path), tmp_path, managed=True).install()
    programs = managed_files(tmp_path)[1]
    live = make_kit(programs, tmp_path, managed=True)
    return live, programs, live.load_state()


def snapshot(programs):
    return {
        p.name: p.read_bytes()
        for p in sorted(programs.iterdir())
        if p.is_file() and p.name != kit_module.UPDATE_NOTE
    }


def test_the_rfc_8032_vector_and_both_implementations_agree():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = kit_sign.sign(seed, b"")
    assert kit_sign.public_from_seed(seed) == public and signature.hex().startswith("e5564300")
    assert kit_module.ed25519_verify(public, b"", signature)
    assert not kit_module.ed25519_verify(public, b"x", signature)
    assert not kit_module.ed25519_verify(public, b"", signature[:-1] + bytes(1))
    ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    assert ed.Ed25519PrivateKey.from_private_bytes(SEED).sign(b"m") == kit_sign.sign(SEED, b"m")


def test_the_kit_carries_the_public_key_only_when_the_server_has_a_signing_key(
    tmp_path, monkeypatch
):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    monkeypatch.delenv(kit_sign.ENV, raising=False)
    assert "update_key" not in json.loads((unpack(tmp_path / "a") / "kit.json").read_text())
    monkeypatch.setenv(kit_sign.ENV, ENV[kit_sign.ENV])
    config = json.loads((unpack(tmp_path / "b") / "kit.json").read_text())
    assert config["update_key"] == kit_sign.public_from_seed(SEED).hex()


def test_the_server_signs_the_real_programs_once_per_version():
    bundle = kit_sign.update_bundle(ENV)
    assert bundle["version"] == kit_version() and kit_sign.update_bundle(ENV) is bundle
    assert kit_sign.update_bundle({}) is None
    public = kit_sign.public_from_seed(SEED).hex()
    version, files, serial, _ = kit_module.verify_update(public, bundle)
    assert serial == bundle["serial"] > 0
    assert version == kit_version() and set(files) == {"mint_agent.py", "mint_kit.py"}


def test_verification_rejects_a_wrong_key_a_tampered_file_and_broken_code():
    public = kit_sign.public_from_seed(SEED).hex()
    assert kit_module.verify_update(public, make_bundle())[0] == NEW_VERSION
    other = kit_sign.public_from_seed(bytes(32)).hex()
    assert kit_module.verify_update(other, make_bundle()) == "bad_signature"
    tampered = make_bundle()
    evil = make_bundle(**{"mint_agent.py": b"evil = 1"})
    tampered["files"]["mint_agent.py"] = evil["files"]["mint_agent.py"]
    assert kit_module.verify_update(public, tampered) == "bad_signature"
    renamed = {**make_bundle(version="other"), "version": NEW_VERSION}
    assert kit_module.verify_update(public, renamed) == "bad_signature"
    broken = make_bundle(**{"mint_kit.py": b"def ("})
    assert kit_module.verify_update(public, broken) == "bad_code"
    assert kit_module.verify_update(public, None) == "bad_bundle"
    empty = {"version": "v", "files": {}, "sig2": ""}
    assert kit_module.verify_update(public, empty) == "bad_bundle"


def test_a_lower_serial_is_refused_and_an_equal_or_higher_one_is_taken():
    public = kit_sign.public_from_seed(SEED).hex()
    assert kit_module.verify_update(public, make_bundle(serial=999), 1000) == "rollback"
    assert kit_module.verify_update(public, make_bundle(serial=1000), 1000)[2] == 1000
    forged = {**make_bundle(serial=999), "serial": 5000}  # 번호만 올리면 서명이 깨진다
    assert kit_module.verify_update(public, forged, 1000) == "bad_signature"


def test_a_rotated_key_is_accepted_only_when_the_old_key_announced_it():
    old_public = kit_sign.public_from_seed(SEED).hex()
    new_seed = bytes(range(1, 33))
    new_public = kit_sign.public_from_seed(new_seed).hex()
    assert kit_module.verify_update(old_public, make_bundle(seed=new_seed)) == "bad_signature"
    stranger = make_bundle(seed=new_seed, announce=bytes(32))
    assert kit_module.verify_update([old_public], stranger) == "bad_signature"
    good = make_bundle(seed=new_seed, announce=SEED)
    *_, keys = kit_module.verify_update([old_public], good)
    assert keys == [old_public, new_public]
    assert kit_module.verify_update(keys, make_bundle(seed=new_seed))[0] == NEW_VERSION


def test_the_server_bundle_during_rotation_works_for_old_and_new_devices():
    new_seed = bytes(range(1, 33))
    env = {kit_sign.ENV: base64.urlsafe_b64encode(new_seed).decode(),
           kit_sign.ENV_PREVIOUS: ENV[kit_sign.ENV]}
    bundle = kit_sign.update_bundle(env)
    old = kit_sign.public_from_seed(SEED).hex()
    *_, keys = kit_module.verify_update([old], bundle)
    assert keys[-1] == kit_sign.public_from_seed(new_seed).hex()
    raw = {n: zlib.decompress(base64.b64decode(f)) for n, f in bundle["files"].items()}
    digests = {n: kit_module.sha256_bytes(d) for n, d in raw.items()}
    assert kit_module.ed25519_verify(  # 새 규칙을 모르는 옛 단말은 옛 키의 sig로 받는다
        bytes.fromhex(old), kit_module.update_manifest(bundle["version"], digests),
        bytes.fromhex(bundle["sig"]))


def test_a_good_update_replaces_the_programs_and_the_version_and_leaves_no_temp_files(installed):
    kit, programs, state = installed
    assert kit.apply_update(programs, state, make_bundle()) is None
    assert (programs / "mint_agent.py").read_bytes() == NEW_AGENT
    assert (programs / "mint_kit.py").read_bytes() == b"# new kit\nVALUE = 2\n"
    config = json.loads((programs / "kit.json").read_text())
    assert config["kit_version"] == NEW_VERSION and config["update_key"]
    assert config["kit_serial"] == SERIAL and config["update_keys"] == [config["update_key"]]
    assert all(not p.name.startswith(".mint-upd-") for p in programs.iterdir())
    saved = kit.load_state()
    assert saved["kit_version"] == NEW_VERSION
    assert saved["files"][f"{kit.logical_programs}/mint_agent.py"] == kit_module.sha256_bytes(
        NEW_AGENT
    )


def test_an_installed_kit_refuses_an_older_bundle(installed):
    kit, programs, state = installed
    kit.config["kit_serial"] = 3000
    before = snapshot(programs)
    assert kit.apply_update(programs, state, make_bundle(serial=2999)) == "rollback"
    assert snapshot(programs) == before


def test_a_failed_check_keeps_every_old_file_byte_for_byte(installed):
    kit, programs, state = installed
    before = snapshot(programs)
    assert kit.apply_update(programs, state, make_bundle(seed=bytes(32))) == "bad_signature"
    assert kit.apply_update(programs, state, None) == "bad_bundle"
    assert snapshot(programs) == before


def test_a_write_failure_midway_changes_nothing(installed, monkeypatch):
    kit, programs, state = installed
    before = snapshot(programs)
    real, calls = kit_module.Kit.stage, []

    def flaky(folder, data, mode):
        calls.append(1)
        if len(calls) == 3:  # kit.json을 쓰는 차례
            raise OSError("disk full")
        return real(folder, data, mode)

    monkeypatch.setattr(kit_module.Kit, "stage", staticmethod(flaky))
    assert kit.apply_update(programs, state, make_bundle()) == "write_failed"
    assert snapshot(programs) == before


def test_without_a_pinned_key_nothing_is_replaced(installed):
    kit, programs, state = installed
    del kit.config["update_key"]
    assert kit.apply_update(programs, state, make_bundle()) == "no_key"


def test_the_reporter_updates_only_when_the_server_version_differs(installed):
    kit, programs, state = installed
    note = programs / kit_module.UPDATE_NOTE
    kit.answer = {"kit_version": kit.config["kit_version"], "kit_update": make_bundle()}
    before = snapshot(programs)
    assert kit_module.self_update(kit, programs, state, note, run_now) == "current"
    assert snapshot(programs) == before and not note.exists()
    kit.answer = {"kit_version": NEW_VERSION, "kit_update": make_bundle(seed=bytes(32))}
    assert kit_module.self_update(kit, programs, state, note, run_now) == "failed"
    assert note.read_text() == "bad_signature" and snapshot(programs) == before
    kit.answer = {"kit_version": NEW_VERSION, "kit_update": make_bundle()}
    assert kit_module.self_update(kit, programs, state, note, run_now) == "updated"
    assert not note.exists() and kit.config["kit_version"] == NEW_VERSION


def test_an_old_install_without_the_key_gets_the_reinstall_note(tmp_path, reports, monkeypatch):
    monkeypatch.delenv(kit_sign.ENV, raising=False)
    kit = make_kit(unpack(tmp_path), tmp_path, managed=True)
    state = kit.install()
    note = kit.programs / kit_module.UPDATE_NOTE
    kit.answer = {"kit_version": "something-newer"}
    assert kit_module.self_update(kit, kit.programs, state, note, run_now) == "failed"
    assert note.read_text() == "needed"
    _, problems = kit.check(state)
    assert kit_module.UPDATE_NEEDED_TEXT in problems


def test_the_report_asks_for_updates_and_carries_the_last_failure(installed, reports):
    kit, _, state = installed
    kit.update_error = "bad_signature"
    kit.config["key"] = "sk-user"
    kit.report(state, "installed")
    payload = reports[-1][2]
    assert payload["kit_update"] is True and payload["update_error"] == "bad_signature"
    ReportBody.model_validate(payload)
