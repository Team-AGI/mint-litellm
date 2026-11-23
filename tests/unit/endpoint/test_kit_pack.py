"""묶음 서버: 신청 명령 해석, 받기·검증·풀기, 준비 상태, 실행기의 묶음 경로, 화면, 호스트 제한."""

import argparse
import hashlib
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest
from kit_loader import load
from test_kit_install import make_kit

kit_module = load("mint_kit")
agent = load("mint_agent")
PYTHON = f"{sys.version_info[0]}.{sys.version_info[1]}"
LATER = "2999-01-01T00:00:00Z"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wheel(files: dict, extra=()) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        for info, data in extra:
            archive.writestr(info, data)
    return buffer.getvalue()


def pack_of(wheels: dict, mutate=None):
    """(해시, 받은 파일들). ``mutate``로 manifest를 틀어 볼 수 있다."""
    manifest = {
        "schema": 1, "package": {"index": "pypi", "name": "demo", "version": "1.0", "extras": []},
        "entry": "demo:main",
        "files": [{"name": n, "sha256": sha(b), "size": len(b)} for n, b in wheels.items()],
    }  # fmt: skip
    if mutate:
        mutate(manifest)
    digest = kit_module.manifest_digest(manifest)
    blobs = {"manifest.json": io.BytesIO(json.dumps(manifest).encode())}
    blobs.update({n: io.BytesIO(b) for n, b in wheels.items()})
    return digest, blobs


GOOD = {
    "demo-1.0-py3-none-any.whl": wheel(
        {
            "demo/__init__.py": b"def main():\n    return 0\n",
            "demo-1.0.dist-info/RECORD": b"",
            "demo-1.0.data/purelib/extra.py": b"X = 1\n",
            "demo-1.0.data/scripts/run": b"#!x\n",
        }
    )
}


def test_a_pack_unpacks_into_a_ready_folder_and_moves_data_dirs_up(tmp_path):
    digest, blobs = pack_of(GOOD)
    final = kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    assert final == tmp_path / "packs" / digest[:16]
    assert (final / "demo/__init__.py").is_file() and (final / "extra.py").is_file()
    assert not (final / "run").exists() and not list(final.glob("*.data"))
    assert kit_module.ready_status(final, digest) == "ok"
    assert sorted(p.name for p in (tmp_path / "packs").iterdir()) == [digest[:16]]


def test_a_changed_or_added_file_makes_the_ready_folder_mismatch(tmp_path):
    digest, blobs = pack_of(GOOD)
    final = kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    (final / "extra.py").write_text("X = 2\n")
    assert kit_module.ready_status(final, digest) == "bad"
    (final / "extra.py").write_text("X = 1\n")
    (final / "new.py").write_text("")
    assert kit_module.ready_status(final, digest) == "bad"


def bad_cases():
    escape = zipfile.ZipInfo("../evil.py")
    link = zipfile.ZipInfo("demo/link.py")
    link.external_attr = 0o120777 << 16
    return {
        "traversal": wheel({"ok.py": b"1"}, [(escape, b"x")]),
        "absolute": wheel({"/etc/x": b"1"}),
        "backslash": wheel({"a\\b.py": b"1"}),
        "link": wheel({"ok.py": b"1"}, [(link, b"/etc/passwd")]),
        "case": wheel({"Demo/a.py": b"1", "demo/a.py": b"2"}),
    }


@pytest.mark.parametrize("case", ["traversal", "absolute", "backslash", "link", "case"])
def test_unsafe_wheel_members_fail_without_leaving_anything_behind(tmp_path, case):
    if case == "backslash" and os.sep == chr(92):
        pytest.skip("zipfile rewrites backslashes on Windows")
    digest, blobs = pack_of({"bad-1.0-py3-none-any.whl": bad_cases()[case]})
    with pytest.raises(kit_module.PackError):
        kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    assert not (tmp_path / "packs").exists() or list((tmp_path / "packs").iterdir()) == []
    assert kit_module.ready_status(tmp_path / "packs" / digest[:16], digest) == "missing"


def test_hash_size_and_manifest_mismatches_are_refused(tmp_path):
    digest, blobs = pack_of(GOOD)
    name = next(iter(GOOD))
    blobs[name] = io.BytesIO(GOOD[name] + b"x")  # 내려받은 바이트가 manifest와 다르다
    with pytest.raises(kit_module.PackError):
        kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    digest, blobs = pack_of(GOOD)
    with pytest.raises(kit_module.PackError):  # 승인된 해시와 다른 manifest
        kit_module.install_blobs("0" * 64, blobs, tmp_path / "packs")
    digest, blobs = pack_of(GOOD, lambda m: m["files"][0].update(sha256="1" * 64))
    with pytest.raises(kit_module.PackError):
        kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    digest, blobs = pack_of(GOOD, lambda m: m["files"][0].update(name="../x.whl"))
    with pytest.raises(kit_module.PackError):
        kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    assert not (tmp_path / "packs").exists() or list((tmp_path / "packs").iterdir()) == []


def test_file_count_and_size_limits_stop_the_unpack(tmp_path, monkeypatch):
    many = wheel({f"p/f{i}.py": b"1" for i in range(5)})
    digest, blobs = pack_of({"m-1.0-py3-none-any.whl": many})
    monkeypatch.setattr(kit_module, "PACK_MAX_FILES", 3)
    with pytest.raises(kit_module.PackError):
        kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    monkeypatch.setattr(kit_module, "PACK_MAX_FILES", 10)
    monkeypatch.setattr(kit_module, "PACK_MAX_BYTES", 3)
    digest, blobs = pack_of({"m-1.0-py3-none-any.whl": many})
    with pytest.raises(kit_module.PackError):
        kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    assert not (tmp_path / "packs").exists() or list((tmp_path / "packs").iterdir()) == []


def test_a_folder_without_the_ready_marker_is_never_usable(tmp_path):
    digest, _ = pack_of(GOOD)
    half = tmp_path / "packs" / digest[:16]
    half.mkdir(parents=True)
    (half / "demo.py").write_text("x")
    assert kit_module.ready_status(half, digest) == "missing"
    contract = {"executable": sys.executable, "pack": {"sha256": digest}}
    state = kit_module.pack_state("s", contract, tmp_path, tmp_path / "staged", {}, time.time())
    assert state == kit_module.S_NEED
    (tmp_path / "staged" / digest[:16]).mkdir(parents=True)
    state = kit_module.pack_state("s", contract, tmp_path, tmp_path / "staged", {}, time.time())
    assert state == kit_module.S_WORK


def test_screen_states_follow_the_runtime_the_pack_the_permit_and_the_clock(tmp_path):
    digest, blobs = pack_of(GOOD)
    kit_module.install_blobs(digest, blobs, tmp_path / "packs")
    now = time.time()
    contract = {"executable": sys.executable, "pack": {"sha256": digest}}
    permit = {"s": {"pack_sha256": digest, "permit_until": LATER}}
    staged = tmp_path / "staged"

    def state(contract=contract, permits=permit):
        return kit_module.pack_state("s", contract, tmp_path, staged, permits, now)

    assert state() == "사용 가능"
    assert state(permits={}) == "실행 허가 만료"
    old = {"s": {"pack_sha256": digest, "permit_until": "2000-01-01T00:00:00Z"}}
    assert state(permits=old) == "실행 허가 만료"
    assert state({**contract, "executable": str(tmp_path / "none")}) == "필요한 프로그램 없음"
    (tmp_path / "packs" / digest[:16] / "x.py").write_text("")
    assert state() == "묶음 불일치"
    assert (
        kit_module.pack_state("v1", {"executable": "/x"}, tmp_path, staged, {}, now) == "사용 가능"
    )


# --- 실행기 ------------------------------------------------------------------------------------


def prepared(tmp_path, monkeypatch, python=PYTHON, until=LATER):
    monkeypatch.setattr(agent, "PACK_PLATFORM", True)
    digest, blobs = pack_of(GOOD)
    packs = tmp_path / "packs"
    folder = kit_module.install_blobs(digest, blobs, packs)
    contract = {
        "executable": sys.executable, "argv": ["--flag"], "pack": {
            "sha256": digest, "runtime": "python3", "python": python, "entry": "demo:main"},
    }  # fmt: skip
    listing = tmp_path / "contracts.json"
    listing.write_text(json.dumps({"servers": {"s": contract}}))
    permits = tmp_path / "permits.json"
    permits.write_text(
        json.dumps({"permits": {"s": {"pack_sha256": digest, "permit_until": until}}})
    )
    return digest, folder, contract, str(packs), str(permits), str(listing)


def verify(tmp_path, monkeypatch, **kw):
    digest, folder, contract, packs, permits, _ = prepared(tmp_path, monkeypatch, **kw)
    return agent.verify_pack("s", contract, packs_dir=packs, permits_path=permits, managed=False)


def test_a_pack_server_starts_the_org_runtime_isolated_with_the_ready_folder(tmp_path, monkeypatch):
    launch = verify(tmp_path, monkeypatch)
    assert launch["argv"][:3] == ["-I", "-B", "-c"] and launch["argv"][-1] == "--flag"
    code = launch["argv"][3]
    assert "from demo import main" in code and "sys.exit(main())" in code
    assert repr(launch["_pack_dir"]) in code and launch["executable"] == os.path.realpath(
        sys.executable
    )


def test_python_dash_m_entries_run_the_module_as_main(tmp_path, monkeypatch):
    digest, folder, contract, packs, permits, _ = prepared(tmp_path, monkeypatch)
    contract["pack"]["entry"] = "demo.tool:__main__"
    launch = agent.verify_pack("s", contract, packs_dir=packs, permits_path=permits, managed=False)
    assert "runpy.run_module('demo.tool'" in launch["argv"][3]


@pytest.mark.parametrize(
    "what", ["runtime", "permit", "content", "extra", "link", "unprepared", "other_pack", "entry"]
)
def test_pack_start_is_refused_when_anything_differs(tmp_path, monkeypatch, what):
    digest, folder, contract, packs, permits, _ = prepared(
        tmp_path, monkeypatch, python="2.7" if what == "runtime" else PYTHON,
        until="2000-01-01T00:00:00Z" if what == "permit" else LATER,
    )  # fmt: skip
    if what == "content":
        (folder / "extra.py").write_text("X = 3\n")
    elif what == "extra":
        (folder / "evil.py").write_text("")
    elif what == "link":
        try:
            os.symlink(folder / "extra.py", folder / "alias.py")
        except OSError:
            pytest.skip("symlinks need privileges")
    elif what == "unprepared":
        (folder / ".ready.json").unlink()
    elif what == "other_pack":
        contract["pack"]["sha256"] = "a" * 64
    elif what == "entry":
        contract["pack"]["entry"] = "demo:main; import os"
    with pytest.raises(agent.Refuse):
        agent.verify_pack("s", contract, packs_dir=packs, permits_path=permits, managed=False)


def test_a_missing_permit_file_or_a_permit_for_another_pack_refuses(tmp_path, monkeypatch):
    digest, folder, contract, packs, permits, _ = prepared(tmp_path, monkeypatch)
    other = {"permits": {"s": {"pack_sha256": "b" * 64, "permit_until": LATER}}}
    Path(permits).write_text(json.dumps(other))
    with pytest.raises(agent.Refuse):
        agent.verify_pack("s", contract, packs_dir=packs, permits_path=permits, managed=False)
    Path(permits).unlink()
    with pytest.raises(agent.Refuse):
        agent.verify_pack("s", contract, packs_dir=packs, permits_path=permits, managed=False)


@pytest.mark.skipif(
    os.name != "posix" or hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="needs a non-root posix user",
)
def test_a_managed_start_needs_root_owned_files(tmp_path, monkeypatch):
    digest, folder, contract, packs, permits, _ = prepared(tmp_path, monkeypatch)
    with pytest.raises(agent.Refuse):
        agent.verify_pack("s", contract, packs_dir=packs, permits_path=permits, managed=True)


def test_run_server_execs_the_verified_pack_launch_and_never_the_contract_argv(
    tmp_path, monkeypatch
):
    digest, folder, contract, packs, permits, listing = prepared(tmp_path, monkeypatch)
    started = []
    agent.run_server(
        "s", listing, {}, execve=lambda fd, argv, env: started.append(argv), packs_dir=packs
    )
    (argv,) = started
    assert argv[1:4] == ["-I", "-B", "-c"] and repr(str(folder)) in argv[4]
    Path(permits).write_text(json.dumps({"permits": {}}))
    with pytest.raises(agent.Refuse):
        agent.run_server("s", listing, {}, execve=lambda *a: None, packs_dir=packs)


def test_pack_servers_are_refused_where_they_are_not_supported(tmp_path, monkeypatch):
    digest, folder, contract, packs, permits, listing = prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(agent, "PACK_PLATFORM", False)
    with pytest.raises(agent.Refuse):
        agent.run_server("s", listing, {}, execve=lambda *a: None, packs_dir=packs)


def test_hosts_without_isolation_refuses_instead_of_opening_the_network(tmp_path, monkeypatch):
    exe = tmp_path / "srv.bin"
    exe.write_bytes(b"x")
    doc = {
        "executable": str(exe), "executable_sha256": agent.sha256_file(str(exe)), "argv": [],
        "network": "hosts", "allowed_hosts": ["a.example"],
    }  # fmt: skip
    listing = tmp_path / "c.json"
    listing.write_text(json.dumps({"servers": {"s": doc}}))
    monkeypatch.setattr(agent, "plan_sandbox", lambda *a, **k: (None, "none"))
    started = []
    with pytest.raises(agent.Refuse):
        agent.run_server("s", str(listing), {}, execve=lambda *a: started.append(1),
                         sandbox=agent.Sandbox(False))  # fmt: skip
    assert started == []


def test_the_pack_folder_is_mounted_read_only_in_the_sandbox(tmp_path, monkeypatch):
    launch = {"executable": "/usr/bin/python3", "argv": [], "_pack_dir": "/opt/mint/packs/ab"}
    assert ("/opt/mint/packs/ab", "ro") in agent.sandbox_mounts(launch, "/home/u")


def test_permit_times_parse_with_or_without_zone_and_fraction():
    assert agent.parse_time("2026-11-17T09:00:00Z") == agent.parse_time("2026-11-17T09:00:00+00:00")
    assert agent.parse_time("2026-11-17T09:00:00.5Z") > agent.parse_time("2026-11-17T09:00:00Z")
    assert agent.parse_time("2026-11-17T09:00:00.123456789+00:00") is not None
    assert agent.parse_time("soon") is None and agent.parse_time(None) is None


# --- 신청 명령 ---------------------------------------------------------------------------------


def parse(*tokens, home=Path("/nonexistent-home")):
    return kit_module.parse_command(list(tokens), home)


def test_uvx_commands_become_pinned_pypi_specs():
    spec = parse("uvx", "pyghidra-mcp==0.3.1", "--port", "1")
    assert spec == {"index": "pypi", "name": "pyghidra-mcp", "version": "0.3.1", "extras": [],
                    "command": "pyghidra-mcp", "argv": ["--port", "1"]}  # fmt: skip
    assert parse("uvx", "demo@2.0")["version"] == "2.0"
    spec = parse("uvx", "--from", "demo[a,b]==1.2", "demo-cli", "x")
    assert (spec["name"], spec["extras"], spec["command"], spec["argv"]) == (
        "demo",
        ["a", "b"],
        "demo-cli",
        ["x"],
    )
    assert parse("pipx", "run", "--spec", "demo==3", "cli")["command"] == "cli"
    assert parse("uv", "tool", "run", "demo==3")["name"] == "demo"


def test_python_dash_m_uses_the_module_as_the_command(monkeypatch):
    monkeypatch.setattr(kit_module, "dist_for_module", lambda m: "demo-dist")
    monkeypatch.setattr(kit_module, "installed_version", lambda n, h: "4.5")
    spec = parse("python3", "-m", "demo.tool", "--x")
    assert (spec["name"], spec["version"], spec["command"], spec["argv"]) == (
        "demo-dist",
        "4.5",
        "demo.tool",
        ["--x"],
    )


def test_a_missing_version_is_found_on_the_machine_or_asked_for(tmp_path, monkeypatch):
    info = tmp_path / ".local/share/uv/tools/demo/lib/python3.12/site-packages/demo-7.1.dist-info"
    info.mkdir(parents=True)
    assert parse("uvx", "demo", home=tmp_path)["version"] == "7.1"
    monkeypatch.setattr(kit_module, "installed_version", lambda n, h: None)
    with pytest.raises(kit_module.AddError, match="판본을 지정"):
        parse("uvx", "demo")


@pytest.mark.parametrize(
    "tokens",
    [
        ("npx", "-y", "x"),
        ("docker", "run", "x"),
        ("uvx", "--with", "y", "x==1"),
        ("uvx",),
        ("uvx", "x>=1"),
        (),
    ],
)
def test_other_runners_and_loose_specs_are_refused_with_a_reason(tokens):
    with pytest.raises(kit_module.AddError):
        parse(*tokens)


def test_absolute_arguments_are_the_file_access_candidates():
    assert kit_module.path_candidates(["--root", "/data/x", "rel", "C:\\w\\f", "/data/x"]) == [
        "/data/x",
        "C:\\w\\f",
    ]


class FakeGateway:
    def __init__(self, status=201, doc=None, me=None, packs=None):
        self.status, self.doc, self.me, self.packs, self.sent = status, doc, me, packs or {}, []

    def json(self, method, path, body=None):
        if method == "POST":
            self.sent.append(body)
            return self.status, self.doc if self.doc is not None else {"id": "i-1"}
        return (200, self.me) if self.me is not None else (0, None)

    def download(self, path, cap):
        data = self.packs.get(path.rsplit("/", 1)[-1])
        return (200, io.BytesIO(data)) if data is not None else (404, None)


def add_args(**kw):
    base = dict(
        source=None,
        name="demo",
        command=["uvx", "demo==1.0", "/data/in"],
        purpose="p",
        grade=None,
        network=None,
        host=[],
        env=[],
        ro=[],
        rw=[],
        yes=True,
        request_id="r-1",
    )
    return argparse.Namespace(**{**base, **kw})  # fmt: skip


def test_add_submits_the_spec_without_running_anything(tmp_path):
    gateway, lines = FakeGateway(), []
    assert kit_module.run_add(add_args(env=["API_TOKEN"]), tmp_path, gateway, out=lines.append) == 0
    (body,) = gateway.sent
    assert body["request_id"] == "r-1" and body["server_id"] == "demo"
    assert body["spec"]["argv"] == ["/data/in"] and body["file_access"] == [
        {"path": "/data/in", "mode": "ro"}
    ]
    assert body["network"] is None and body["env_names"] == ["API_TOKEN"]
    assert body["data_grade"] == "internal" and body["allowed_hosts"] == []
    assert any("비밀" in line for line in lines) and "신청했습니다" in lines


@pytest.mark.parametrize(
    ("status", "text"),
    [
        (409, "진행 중"),
        (429, "한도"),
        (400, "맞지 않습니다"),
        (422, "맞지 않습니다"),
        (404, "키"),
        (0, "닿지 못함"),
    ],
)
def test_add_explains_each_refusal_in_words(tmp_path, status, text):
    lines = []
    code = kit_module.run_add(add_args(), tmp_path, FakeGateway(status=status), out=lines.append)
    assert code == 1 and any(text in line for line in lines)


def test_add_needs_a_purpose_and_hosts_for_hosts(tmp_path):
    gateway, lines = FakeGateway(), []
    assert kit_module.run_add(add_args(purpose=None), tmp_path, gateway, out=lines.append) == 2
    assert kit_module.run_add(add_args(network="hosts"), tmp_path, gateway, out=lines.append) == 2
    assert (
        kit_module.run_add(add_args(host=["a.example:443"]), tmp_path, gateway, out=lambda t: 0)
        == 0
    )
    assert gateway.sent[0]["network"] == "hosts" and gateway.sent[0]["allowed_hosts"] == [
        "a.example:443"
    ]


def test_add_from_a_harness_entry_reuses_its_command_and_env_names(tmp_path):
    (tmp_path / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "gh": {
                        "command": "uvx",
                        "args": ["demo==2.0", "/x"],
                        "env": {"GH_TOKEN": "secret-value"},
                    }
                }
            }
        )
    )
    gateway = FakeGateway()
    args = add_args(source="claude:gh", name=None, command=[])
    assert kit_module.run_add(args, tmp_path, gateway, out=lambda t: 0) == 0
    (body,) = gateway.sent
    assert body["server_id"] == "gh" and body["env_names"] == ["GH_TOKEN"]
    assert "secret-value" not in json.dumps(body)


# --- get ---------------------------------------------------------------------------------------


def served(digest_and_blobs, mutate=None):
    digest, blobs = digest_and_blobs
    data = {name: handle.getvalue() for name, handle in blobs.items()}
    return digest, data


def me_for(digest):
    return {"user": "u", "servers": [{"server_id": "s", "pack_sha256": digest}], "intakes": []}


def test_get_downloads_verifies_unpacks_and_reports(tmp_path, folder):
    kit = make_kit(folder, tmp_path, managed=False)
    digest, data = served(pack_of(GOOD))
    lines = []
    code = kit_module.run_get(
        kit, FakeGateway(me=me_for(digest), packs=data), "s", out=lines.append
    )
    assert (
        code == 0 and kit_module.ready_status(kit.programs / "packs" / digest[:16], digest) == "ok"
    )
    again = kit_module.run_get(
        kit, FakeGateway(me=me_for(digest), packs=data), "s", out=lines.append
    )
    assert again == 0 and "이미" in lines[-1]


def test_get_refuses_tampered_downloads_and_unapproved_servers(tmp_path, folder):
    kit = make_kit(folder, tmp_path, managed=False)
    digest, data = served(pack_of(GOOD))
    name = next(iter(GOOD))
    flipped = bytearray(data[name])
    flipped[10] ^= 1
    data[name] = bytes(flipped)
    lines = []
    assert (
        kit_module.run_get(kit, FakeGateway(me=me_for(digest), packs=data), "s", out=lines.append)
        == 1
    )
    assert not (kit.programs / "packs" / digest[:16]).exists()
    assert kit_module.run_get(kit, FakeGateway(me=me_for(digest)), "other", out=lines.append) == 1
    assert kit_module.run_get(kit, FakeGateway(me={"servers": []}), "s", out=lines.append) == 1
    assert kit_module.run_get(kit, FakeGateway(), "s", out=lines.append) == 1
    assert "닿지 못함" in lines[-1]


def test_a_user_without_write_access_stages_the_download_for_the_admin_step(
    tmp_path, folder, monkeypatch
):
    kit = make_kit(folder, tmp_path, managed=True)
    kit.programs.mkdir(parents=True, exist_ok=True)
    digest, data = served(pack_of(GOOD))
    monkeypatch.setattr(kit_module.os, "access", lambda *a, **k: False)
    assert (
        kit_module.run_get(kit, FakeGateway(me=me_for(digest), packs=data), "s", out=lambda t: 0)
        == 0
    )
    staged = kit.home / ".cache/mint/packs" / digest[:16]
    assert (staged / "manifest.json").is_file()
    assert not (kit.programs / "packs" / digest[:16]).exists()
    monkeypatch.undo()
    contract = {"executable": sys.executable, "pack": {"sha256": digest}}
    assert (
        kit_module.pack_state("s", contract, kit.programs, kit.home / ".cache/mint/packs", {}, 0)
        == "준비 중"
    )


# --- 보고 응답 처리 ----------------------------------------------------------------------------


def pack_contract(digest):
    return {
        "schema_version": 2, "identity_kind": "stdio", "executable": sys.executable, "argv": [],
        "cwd": None, "executable_sha256": None, "script_sha256": None, "env": {},
        "secret_refs": {}, "pack": {"sha256": digest, "runtime": "python3", "python": PYTHON,
                                    "entry": "demo:main"},
    }  # fmt: skip


def desired_item(name, digest, until=LATER):
    contract = pack_contract(digest)
    return {"name": name, "version": kit_module.contract_version(contract), "contract": contract,
            "pack_sha256": digest, "permit_until": until}  # fmt: skip


def test_a_desired_pack_server_is_configured_permitted_promoted_and_then_revoked(
    tmp_path, folder, reports
):
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    digest, blobs = pack_of(GOOD)
    item = desired_item("s", digest)
    assert kit.refresh(state, [item]) == ["s"]
    assert kit.apply_permits(state, [item], set()) is True
    assert kit.local_permits() == {"s": {"pack_sha256": digest, "permit_until": LATER}}
    assert kit.local_contracts()["s"]["pack"]["sha256"] == digest
    # 사용자가 받아 둔 묶음을 관리자 단계가 다시 검증해 푼다.
    kit_module.stage_blobs(blobs, kit.home / ".cache/mint/packs" / digest[:16])
    assert kit.promote_packs() == ["s"]
    assert kit_module.ready_status(kit.programs / "packs" / digest[:16], digest) == "ok"
    assert kit.drop_contracts(state, ["s"]) == ["s"]
    assert "s" not in kit.local_contracts() and kit.local_permits() == {}


def test_a_staged_pack_changed_after_download_is_not_promoted(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    digest, blobs = pack_of(GOOD)
    kit.refresh(state, [desired_item("s", digest)])
    staged = kit.home / ".cache/mint/packs" / digest[:16]
    kit_module.stage_blobs(blobs, staged)
    wheel_path = staged / next(iter(GOOD))
    wheel_path.write_bytes(wheel_path.read_bytes() + b"x")
    assert kit.promote_packs() == []
    assert not (kit.programs / "packs" / digest[:16]).exists()


def test_a_pack_item_whose_hash_disagrees_with_its_contract_is_ignored(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    item = {**desired_item("s", "c" * 64), "pack_sha256": "d" * 64}
    assert kit.refresh(state, [item]) == []
    version1 = {"name": "v1", "contract": {**pack_contract("e" * 64), "pack": None}}
    version1["contract"].pop("pack")
    version1["version"] = kit_module.contract_version(version1["contract"])
    assert kit.refresh(state, [version1]) == ["v1"]  # 판 1 항목은 그대로 처리한다.


def test_the_report_sends_at_most_256_servers(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    state = kit.install()
    state["mcp_servers"] = [f"s{i}" for i in range(300)]
    kit.report(state, "installed")
    assert len(reports[-1][2]["mcp_servers"]) == 256


# --- 화면·표 -----------------------------------------------------------------------------------


def model(**kw):
    base = {
        "connected": True, "user": "홍길동", "key": "ok", "mode": "관리형", "harnesses": ["claude"],
        "server_count": 2, "problems": ["bubblewrap이 없어 서버를 격리하지 못합니다."],
        "servers": [
            {"name": "pyghidra-mcp", "kind": "묶음", "state": "받기 필요", "pack_sha256": "a" * 64,
             "permit_until": LATER},
            {"name": "files", "kind": "로컬", "state": "사용 가능", "pack_sha256": None,
             "permit_until": None},
        ],
        "intakes": [{"server_id": "한글서버", "status": "indeterminate", "decision": None,
                     "reason": "도구 목록 없음", "next": "관리자 확인을 기다리십시오"}],
        "found": [{"harness": "claude", "name": "gh"}],
    }  # fmt: skip
    return {**base, **kw}


def ui(**kw):
    return {"tab": 0, "cursor": 0, "detail": False, "message": "", **kw}


@pytest.mark.parametrize("tab", [0, 1, 2])
def test_every_tab_fits_eighty_columns_with_korean_text(tab):
    for detail in (False, True):
        lines = kit_module.render_screen(model(), ui(tab=tab, detail=detail), 80, 24)
        assert len(lines) == 24
        assert all(kit_module.cell_width(line) <= 80 for line in lines)
    assert any(f"[{tab + 1}" in line for line in lines)


def test_the_screen_shows_local_facts_when_the_gateway_is_unreachable():
    lines = kit_module.render_screen(model(connected=False, key="unknown"), ui(), 80, 24)
    assert "게이트웨이에 닿지 못함" in lines[0] and any("관리형" in line for line in lines)


def test_keys_switch_tabs_move_the_cursor_and_ask_for_actions():
    state, data = ui(), model()
    assert kit_module.handle_key("2", state, data) is None and state["tab"] == 1
    kit_module.handle_key("down", state, data)
    kit_module.handle_key("down", state, data)  # 끝에서 멈춘다
    assert state["cursor"] == 1
    assert kit_module.handle_key("s", state, data) == "get"
    kit_module.handle_key("enter", state, data)
    assert state["detail"] is True
    kit_module.handle_key("esc", state, data)
    assert state["detail"] is False
    kit_module.handle_key("right", state, data)
    assert state["tab"] == 2 and state["cursor"] == 0
    kit_module.handle_key("down", state, data)  # 신청 한 건 아래 이 PC의 항목
    assert kit_module.handle_key("enter", state, data) == "add_found"
    kit_module.handle_key("left", state, data)
    kit_module.handle_key("left", state, data)
    kit_module.handle_key("left", state, data)
    assert state["tab"] == 2  # 순환
    assert [kit_module.handle_key(k, ui(), data) for k in "ncroq"] == [
        "new",
        "check",
        "report",
        "web",
        "quit",
    ]
    assert kit_module.handle_key("s", ui(tab=0), data) is None


def test_a_scripted_session_draws_and_quits(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    state = kit.install()
    keys = iter(["2", "down", "enter", "3", "q"])
    out = io.StringIO()
    gateway = FakeGateway(me={"user": "u", "servers": [], "intakes": []})
    assert kit_module.run_screen(kit, state, gateway, {}, read=lambda: next(keys), out=out) == 0
    assert "내 서버" in out.getvalue() and "도입 신청" in out.getvalue()


def test_check_prints_a_table_with_the_problems_listed():
    lines = kit_module.check_lines({"mode": "managed", "mcp_servers": ["a"]}, ["문제 하나"])
    assert lines[0].startswith("설치 방식") and "관리형" in lines[0]
    assert any("문제 1건" in line for line in lines) and lines[-1] == "  - 문제 하나"


def test_the_installed_shim_opens_the_screen_only_on_a_terminal(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=False)
    kit.install()
    shim = (kit.home / ".local/bin/mint").read_text()
    assert "set -- screen" in shim and "set -- status" in shim and "[ -t 0 ]" in shim


# --- 신청 입력·단계 표시 --------------------------------------------------------------------


def test_the_purpose_prompt_names_the_option_only_for_scripts(tmp_path):
    lines = []
    args = add_args(purpose=None, yes=False)
    assert kit_module.run_add(args, tmp_path, FakeGateway(), out=lines.append) == 2
    assert lines[-1] == "목적(--purpose)을 적으십시오"
    lines.clear()
    kit_module.run_add(args, tmp_path, FakeGateway(), out=lines.append, read=lambda q: "", tty=True)
    assert lines[-1] == "목적을 적으십시오"


def test_the_grade_is_never_asked_and_an_option_is_sent_as_the_internal_value(tmp_path):
    asked, lines, gateway = [], [], FakeGateway()

    def read(question):
        asked.append(question)
        return "목적" if "목적" in question else ""

    code = kit_module.run_add(
        add_args(yes=False, grade=None, purpose=None), tmp_path, gateway, out=lines.append,
        read=read, tty=True, key=lambda: "enter")
    assert code == 0 and gateway.sent[0]["data_grade"] == "internal"
    assert asked == ["목적 "] and not any(line.startswith("자료 등급") for line in lines)
    lines.clear()
    assert kit_module.run_add(add_args(grade="기밀"), tmp_path, gateway, out=lines.append) == 0
    assert gateway.sent[1]["data_grade"] == "confidential"
    assert any(line.startswith("자료 등급") and "기밀" in line for line in lines)
    assert not any("confidential" in line or "internal" in line for line in lines)
    assert kit_module.parse_grade("제한") == "restricted"
    assert kit_module.parse_grade("public") == "public" and kit_module.parse_grade("x") is None
    lines.clear()
    assert kit_module.run_add(add_args(grade="가나"), tmp_path, gateway, out=lines.append) == 2
    assert lines[-1] == "자료 등급은 공개·내부·기밀·제한 중 하나입니다"


def test_add_asks_only_the_purpose_and_stops_at_once_when_the_key_is_refused(tmp_path):
    asked, quiet = [], lambda t: 0  # noqa: E731
    gateway = FakeGateway()

    def read(question):
        asked.append(question)
        return "문서 조회"

    args = add_args(yes=False, purpose=None)
    assert kit_module.run_add(args, tmp_path, gateway, out=quiet, read=read, tty=True) == 0
    assert asked == ["목적 "] and len(gateway.sent) == 1
    refused, lines = FakeGateway(), []
    refused.json = lambda method, path, body=None: (401, None)
    assert kit_module.run_add(args, tmp_path, refused, out=lines.append, read=read, tty=True) == 1
    assert lines == [kit_module.KEY_REJECTED_TEXT] and asked == ["목적 "]


def test_tab_three_shows_the_stage_and_never_an_english_next_step():
    steps = [("received", "접수"), ("pack", "접수 > 묶음 준비"),
             ("inspect", "접수 > 묶음 준비 > 검사 중"),
             ("indeterminate", "접수 > 묶음 준비 > 검사 중 > 판별 불가"),
             ("approved", "접수 > 묶음 준비 > 검사 중 > 승인")]
    for stage, path in steps:
        assert kit_module.stage_path(stage) == path
    rows = [{"server_id": "a", "status": "checking", "decision": None, "stage": "pack",
             "next": "wait"},
            {"server_id": "b", "status": "decided", "decision": "approved", "stage": "approved",
             "next": "none", "reason": None}]
    lines = kit_module.render_screen(model(intakes=rows), ui(tab=2, detail=True), 80, 24)
    text = "\n".join(lines)
    assert "묶음 준비" in text and "승인" in text and "진행  접수 > 묶음 준비" in text
    assert "wait" not in text and "none" not in text
    out = []
    kit_module.run_requests(FakeGateway(me={"intakes": rows}), out=out.append)
    assert not any("wait" in line or "none" in line for line in out)
    assert kit_module.row_label({"status": "checking", "decision": None}) == "검사 중"


def test_found_items_with_a_request_are_left_out_and_managed_codex_items_are_marked(tmp_path):
    (tmp_path / ".claude.json").write_text(json.dumps({"mcpServers": {
        "gh": {"command": "uvx", "args": ["demo==2.0"]},
        "again": {"command": "uvx", "args": ["demo==2.0"]}}}))
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex/config.toml").write_text('[mcp_servers.tool]\ncommand = "uvx"\n')

    class Kit:
        home, programs, harnesses = tmp_path, None, []

        def check(self, state):
            return {}, []

        def local_contracts(self):
            return {}

        def local_permits(self):
            return {}

    intakes = [{"server_id": "gh", "status": "checking", "decision": None, "stage": "pack"},
               {"server_id": "again", "status": "decided", "decision": "rejected",
                "stage": "rejected"}]
    me = {"user": "u", "servers": [], "intakes": intakes}
    built = kit_module.build_model(Kit(), {"mode": "managed"}, FakeGateway(me=me))
    found = {(i["harness"], i["name"]): i["blocked"] for i in built["found"]}
    assert found == {("claude", "again"): False, ("codex", "tool"): True}
    text = "\n".join(kit_module.render_screen(built, ui(tab=2), 80, 24))
    assert "codex:tool  관리 정책으로 막힘 · 신청 필요" in text
    user_level = kit_module.build_model(Kit(), {"mode": "user"}, FakeGateway(me=me))
    assert not any(i["blocked"] for i in user_level["found"])


def test_the_decision_version_is_kept_and_sent_back_in_the_report(tmp_path, folder, reports):
    kit = make_kit(folder, tmp_path, managed=True)
    state = kit.install()
    kit.config.update(decide_url="https://gw.example.com", key="k")
    item = {**desired_item("s", pack_of(GOOD)[0]), "decision_version": 4}
    old = {**desired_item("t", pack_of(GOOD)[0])}  # 옛 서버: 버전 없음
    assert kit.apply_versions(state, [item, old], set()) is True
    assert kit.apply_versions(state, [item, old], set()) is False
    assert kit.stored_versions() == {"s": 4}
    assert kit.apply_versions(state, [item], {"s"}) is True  # 빠진 서버는 지운다
    assert kit.stored_versions() == {}
