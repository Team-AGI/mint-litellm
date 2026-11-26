"""묶음 서버의 Windows 경로: 묶음 고르기, 화면 상태, 시작 검증, 격리 시작 명령(어디서나 돈다)."""

import json
import os
import sys
import time
from pathlib import Path

import pytest
from kit_loader import load
from test_kit_pack import GOOD, LATER, PYTHON, pack_of

kit_module = load("mint_kit")
agent = load("mint_agent")
LINUX_RUNTIME = "/usr/bin/python3"
IDENTITY = "a" * 64


@pytest.fixture(autouse=True)
def on_windows(monkeypatch):
    monkeypatch.setattr(kit_module, "WINDOWS", True)
    monkeypatch.setattr(agent, "WINDOWS", True)


def contract(windows, python=PYTHON):
    pack = {"sha256": IDENTITY, "runtime": "python3", "python": python, "entry": "demo:main"}
    if windows is not None:
        pack["windows"] = windows
    return {"executable": LINUX_RUNTIME, "argv": ["--flag"], "pack": pack}


def windows_pack(tmp_path):
    digest, blobs = pack_of(GOOD, lambda m: m.update(platform={"os": "windows"}))
    return digest, kit_module.install_blobs(digest, blobs, tmp_path / "packs")


def test_the_pack_to_fetch_follows_the_os(monkeypatch):
    pack = contract({"sha256": "b" * 64})["pack"]
    assert kit_module.pack_digest(pack) == "b" * 64
    assert kit_module.pack_digest(contract(None)["pack"]) is None  # Windows용이 아직 없다
    assert kit_module.pack_digest(contract({"unavailable": True})["pack"]) is None
    assert kit_module.pack_digest(contract({"sha256": "zz"})["pack"]) is None
    monkeypatch.setattr(kit_module, "WINDOWS", False)
    assert kit_module.pack_digest(pack) == IDENTITY  # Linux는 옛 계약 그대로


def test_screen_state_names_the_windows_pack_problem_not_a_missing_runtime(tmp_path):
    now, staged = time.time(), tmp_path / "staged"

    def state(doc):
        return kit_module.pack_state("s", doc, tmp_path, staged, {}, now)

    assert state(contract(None)) == kit_module.S_NOWIN  # 이전 승인: Windows용 묶음 만들기 필요
    assert state(contract({"unavailable": True})) == kit_module.S_NOBUILD
    texts = kit_module.NEXT_BY_STATE
    assert "재검사" in texts[kit_module.S_NOWIN]
    assert "Windows용 빌드" in texts[kit_module.S_NOBUILD]
    assert texts[kit_module.S_NOWIN] != texts[kit_module.S_NOPROG]


def test_a_ready_windows_pack_is_usable_with_this_pcs_python_and_the_identity_permit(tmp_path):
    win, _ = windows_pack(tmp_path)
    doc = contract({"sha256": win})  # 계약의 실행 경로(/usr/bin/python3)는 이 PC에 없다
    now, staged = time.time(), tmp_path / "staged"
    permit = {"s": {"pack_sha256": IDENTITY, "permit_until": LATER}}  # 허가는 정체성(Linux 해시)

    def state(doc, permits):
        return kit_module.pack_state("s", doc, tmp_path, staged, permits, now)

    assert state(doc, permit) == kit_module.S_READY
    assert state(doc, {}) == kit_module.S_EXPIRED
    assert state(contract({"sha256": win}, python="2.7"), permit) == kit_module.S_PYVER
    assert state(contract({"sha256": "c" * 64}), permit) == kit_module.S_NEED  # 준비 안 된 묶음


def prepared(tmp_path, windows=True, until=LATER):
    win, folder = windows_pack(tmp_path)
    permits = tmp_path / "permits.json"
    permit = {"s": {"pack_sha256": IDENTITY, "permit_until": until}}
    permits.write_text(json.dumps({"permits": permit}))
    doc = contract({"sha256": win} if windows else None)
    return folder, doc, str(tmp_path / "packs"), str(permits)


def test_a_windows_start_uses_the_windows_pack_folder_and_this_pcs_python(tmp_path):
    folder, doc, packs, permits = prepared(tmp_path)
    launch = agent.verify_pack("s", doc, packs_dir=packs, permits_path=permits, managed=False)
    assert launch["executable"] == os.path.realpath(sys.executable)
    assert launch["argv"][:3] == ["-I", "-B", "-c"] and launch["argv"][-1] == "--flag"
    assert repr(str(folder)) in launch["argv"][3] and launch["_pack_dir"] == str(folder)
    assert launch["_pack_exec"] is True


def test_a_windows_start_without_a_windows_pack_says_why(tmp_path):
    _, doc, packs, permits = prepared(tmp_path, windows=False)
    with pytest.raises(agent.Refuse, match="재검사"):
        agent.verify_pack("s", doc, packs_dir=packs, permits_path=permits, managed=False)
    doc["pack"]["windows"] = {"unavailable": True}
    with pytest.raises(agent.Refuse, match="Windows용 빌드가 없어"):
        agent.verify_pack("s", doc, packs_dir=packs, permits_path=permits, managed=False)


@pytest.mark.parametrize("what", ["content", "extra", "unprepared", "permit", "expired", "python"])
def test_the_integrity_checks_still_apply_on_windows(tmp_path, what):
    until = "2000-01-01T00:00:00Z" if what == "expired" else LATER
    folder, doc, packs, permits = prepared(tmp_path, until=until)
    if what == "content":
        (folder / "extra.py").write_text("X = 3\n")
    elif what == "extra":
        (folder / "evil.py").write_text("")
    elif what == "unprepared":
        (folder / ".ready.json").unlink()
    elif what == "permit":
        Path(permits).write_text(json.dumps({"permits": {}}))
    elif what == "python":
        doc["pack"]["python"] = "2.7"
    with pytest.raises((agent.Refuse, agent.NoPermit)):
        agent.verify_pack("s", doc, packs_dir=packs, permits_path=permits, managed=False)


def no_file(_path):
    raise OSError


def test_the_pack_folder_is_granted_read_and_execute_to_the_container():
    approved = {"executable": r"C:\Program Files\Python312\python.exe", "argv": ["-I"],
                "_pack_dir": r"C:\ProgramData\mint\packs\abcd", "_pack_exec": True}
    env = {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"}

    def grants(doc):
        return agent.win_grants(doc, r"C:\Users\alice", env, exists=lambda p: True,
                                real=lambda p: p, read_text=no_file)

    # Python은 시스템 폴더(이미 읽을 수 있다)라 묶음 폴더만 준다.
    assert {(g[0], g[1]) for g in grants(approved)} == {(r"C:\ProgramData\mint\packs\abcd", "RX")}
    assert {g[1] for g in grants({**approved, "_pack_exec": False})} == {"R"}


def test_run_server_starts_the_pack_inside_the_appcontainer(tmp_path, monkeypatch):
    folder, doc, packs, permits = prepared(tmp_path)
    listing = tmp_path / "contracts.json"
    listing.write_text(json.dumps({"servers": {"s": doc}}))
    seen = {}

    class Box:
        def run(self):
            return 0

        def close(self):
            pass

    def prepare(server, approved, argv, env, home, state_dir, tap):
        seen.update(approved=approved, argv=argv)
        return Box()

    monkeypatch.setattr(agent, "plan_sandbox", lambda *a, **k: (None, "appcontainer"))
    monkeypatch.setattr(agent.AppContainerRun, "prepare", staticmethod(prepare))
    with pytest.raises(SystemExit) as done:
        agent.run_server("s", str(listing), {}, packs_dir=packs, state_dir=str(tmp_path / "st"),
                         sandbox=agent.Sandbox(False))  # 소유자 점검은 POSIX 전용
    assert done.value.code == 0
    assert seen["approved"]["executable"] == os.path.realpath(sys.executable)
    assert seen["argv"][1:4] == ["-I", "-B", "-c"] and seen["approved"]["_pack_dir"] == str(folder)


class FakeKit:
    programs = Path(".")


def gateway_with(extra):
    class Gateway:
        def json(self, method, path):
            return 200, {"servers": [{"server_id": "s", "pack_sha256": IDENTITY, **extra}]}

    return Gateway()


def test_mint_get_on_windows_fetches_the_windows_pack_or_says_why_not(monkeypatch):
    out = []
    assert kit_module.run_get(FakeKit(), gateway_with({}), "s", out=out.append) == 1
    unavailable = gateway_with({"pack_windows": {"unavailable": True}})
    assert kit_module.run_get(FakeKit(), unavailable, "s", out=out.append) == 1
    assert out == [kit_module.NEXT_NOWIN, kit_module.NEXT_NOBUILD]
    asked = []

    def fetch(gateway, server, digest, progress=None):
        asked.append(digest)
        raise kit_module.PackError("stop")

    monkeypatch.setattr(kit_module, "fetch_pack", fetch)
    ready = gateway_with({"pack_windows": {"sha256": "b" * 64}})
    kit_module.run_get(FakeKit(), ready, "s", out=out.append)
    assert asked == ["b" * 64]
