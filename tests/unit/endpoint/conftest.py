"""단말 키트 시험이 함께 쓰는 고정물."""

import pytest
from test_kit_install import kit_module, unpack


@pytest.fixture
def folder(tmp_path):
    return unpack(tmp_path)


@pytest.fixture
def reports(monkeypatch):
    sent = []

    def post(url, key, payload, ca_file):
        sent.append((url, key, payload))
        return True

    monkeypatch.setattr(kit_module, "post", post)
    monkeypatch.setattr(kit_module, "claude_version", lambda home: None)
    monkeypatch.setattr(kit_module, "codex_version", lambda home: None)
    monkeypatch.setattr(kit_module, "find_claude", lambda home: None)
    monkeypatch.setattr(kit_module, "scan_processes", lambda windows: [])
    monkeypatch.setattr(kit_module, "scan_autostart", lambda home, windows, user: [])
    return sent
