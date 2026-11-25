"""관리자 권한 설치기가 만든 사용자 상태 폴더의 소유자."""

import importlib.util
import sys
from pathlib import Path

KIT = Path(__file__).resolve().parents[3] / "src/mint_litellm/endpoint/kit/mint_kit.py"


def load_kit():
    spec = importlib.util.spec_from_file_location("mint_kit_owner", KIT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["mint_kit_owner"] = module
    spec.loader.exec_module(module)
    return module


def test_new_parent_folders_get_the_owner_too(tmp_path, monkeypatch):
    kit = load_kit()
    chowned = []
    monkeypatch.setattr(kit.os, "chown", lambda path, uid, gid: chowned.append((Path(path), uid)))
    target = tmp_path / ".cache" / "mint" / "clients.json"
    kit.write_atomic(target, b"{}", 0o600, (1000, 1000))
    folders = [p for p, _ in chowned if p.is_dir()]
    assert folders == [tmp_path / ".cache", tmp_path / ".cache" / "mint"]
    assert target.read_bytes() == b"{}"


def test_existing_folders_are_left_alone(tmp_path, monkeypatch):
    kit = load_kit()
    chowned = []
    monkeypatch.setattr(kit.os, "chown", lambda path, uid, gid: chowned.append(Path(path)))
    (tmp_path / "state").mkdir()
    kit.write_atomic(tmp_path / "state" / "a.json", b"1", 0o600, (1000, 1000))
    assert not [p for p in chowned if p.is_dir()]
