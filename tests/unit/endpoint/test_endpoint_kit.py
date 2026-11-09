import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from endpoint_helpers import auth, contract, principal_of, registry, runtime
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient

import mint_litellm
from mint_litellm.endpoint.contract import mismatched_fields
from mint_litellm.endpoint.decide import KitSettings, install, make_router
from mint_litellm.endpoint.kit_build import build_kit, kit_version

KIT_DIR = Path(mint_litellm.__file__).parent / "endpoint" / "kit"
spec = importlib.util.spec_from_file_location("mint_kit", KIT_DIR / "mint_kit.py")
mint_kit = importlib.util.module_from_spec(spec)
sys.modules["mint_kit"] = mint_kit
spec.loader.exec_module(mint_kit)

POSIX = os.name == "posix"


def unpack(data: bytes, folder: Path) -> Path:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(folder, filter="data")
    return folder / "mint-kit"


def make_kit(tmp_path, key="sk-user", ca_pem=None) -> Path:
    data = build_kit(registry().servers(), decide_url="https://mint.test", key=key, ca_pem=ca_pem)
    return unpack(data, tmp_path / "kit")


def account(tmp_path):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return mint_kit.Account("emp", home, 1000, 1000)


def kit_of(tmp_path, managed, **kw):
    return mint_kit.Kit(
        make_kit(tmp_path, **kw), tmp_path / "root", managed, account(tmp_path), chown=False
    )


# ---- 키트 묶음 ----


def test_bundle_is_reproducible_and_carries_the_callers_key_and_approved_servers(tmp_path):
    a = build_kit(registry().servers(), decide_url="https://mint.test", key="sk-user")
    assert a == build_kit(registry().servers(), decide_url="https://mint.test", key="sk-user")
    folder = unpack(a, tmp_path)
    config = json.loads((folder / "kit.json").read_text(encoding="utf-8"))
    assert config["key"] == "sk-user" and config["kit_version"] == kit_version()
    (server,) = config["servers"]
    approved = contract()
    assert server == {
        "name": "cnt",
        "command": approved.executable,
        "args": list(approved.argv),
        "env": approved.env,
    }
    assert {p.name for p in folder.iterdir()} == {
        "install.sh",
        "mint_kit.py",
        "hook.py",
        "kit.json",
    }
    assert (folder / "hook.py").read_bytes().count(b"\r") == 0


def test_kit_version_does_not_depend_on_key_or_servers():
    other = build_kit({}, decide_url="https://other.test", key="sk-other")
    assert json.loads(_config(other))["kit_version"] == kit_version()


def _config(data: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        return archive.extractfile("mint-kit/kit.json").read()


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_install_script_parses():
    done = subprocess.run(
        ["bash", "-n", (KIT_DIR / "install.sh").as_posix()], capture_output=True, timeout=30
    )
    assert done.returncode == 0, done.stderr


def test_unset_cwd_in_the_approved_contract_is_not_compared():
    assert mismatched_fields(contract(cwd=None), contract(cwd="/anywhere")) == ()
    assert mismatched_fields(contract(cwd="/work"), contract(cwd="/anywhere")) == ("cwd",)


# ---- 관리형 설치 ----


def managed_files(tmp_path):
    root = tmp_path / "root"
    return (
        root / "etc/claude-code/managed-settings.json",
        root / "etc/claude-code/managed-mcp.json",
        root / "usr/local/lib/mint-endpoint/hook.py",
    )


def test_managed_install_writes_settings_hook_server_list_and_user_key(tmp_path):
    kit = kit_of(tmp_path, True)
    state = kit.install()
    settings_path, mcp_path, hook_path = managed_files(tmp_path)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert settings["allowManagedHooksOnly"] is True
    (entry,) = settings["hooks"]["PreToolUse"]
    (hook,) = entry["hooks"]
    assert entry["matcher"] == "mcp__.*" and hook["onFailure"] == "block" and hook["timeout"] == 3
    assert hook["args"][0] == "/usr/local/lib/mint-endpoint/hook.py"
    assert "/etc/claude-code/managed-mcp.json" in hook["args"]
    assert "~/.config/mint/key" in hook["args"] and "https://mint.test" in hook["args"]
    assert json.loads(mcp_path.read_text(encoding="utf-8"))["mcpServers"]["cnt"]["command"] == (
        contract().executable
    )
    assert hook_path.read_bytes() == (kit.folder / "hook.py").read_bytes()
    key = kit.home / ".config/mint/key"
    assert key.read_text(encoding="utf-8") == "sk-user\n"
    if POSIX:
        assert key.stat().st_mode & 0o777 == 0o600
    assert state["mode"] == "managed" and state["mcp_servers"] == ["cnt"]


def test_managed_install_is_idempotent_and_uninstall_restores_the_start(tmp_path):
    kit = kit_of(tmp_path, True)
    first = kit.install()
    second = kit.install()
    assert first["files"] == second["files"] and second["backups"] == {}
    result = kit.uninstall()
    assert result["kept"] == []
    assert not any(p.exists() for p in managed_files(tmp_path))
    assert not (tmp_path / "root/etc/claude-code").exists()
    assert not (kit.home / ".config/mint/key").exists()


def test_existing_foreign_settings_are_backed_up_and_restored(tmp_path):
    settings_path, _, _ = managed_files(tmp_path)
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"model": "x"}', encoding="utf-8")
    kit = kit_of(tmp_path, True)
    state = kit.install()
    assert "/etc/claude-code/managed-settings.json" in state["backups"]
    assert json.loads(settings_path.read_text(encoding="utf-8"))["allowManagedHooksOnly"] is True
    kit.uninstall()
    assert settings_path.read_text(encoding="utf-8") == '{"model": "x"}'


def test_files_changed_after_install_are_left_alone(tmp_path):
    kit = kit_of(tmp_path, True)
    kit.install()
    settings_path, _, _ = managed_files(tmp_path)
    settings_path.write_text('{"edited": true}', encoding="utf-8")
    result = kit.uninstall()
    assert result["kept"] == ["/etc/claude-code/managed-settings.json"]
    assert settings_path.read_text(encoding="utf-8") == '{"edited": true}'


def test_ca_certificate_is_installed_and_passed_to_the_hook(tmp_path):
    kit = kit_of(tmp_path, True, ca_pem="PEM\n")
    kit.install()
    settings = json.loads(managed_files(tmp_path)[0].read_text(encoding="utf-8"))
    args = settings["hooks"]["PreToolUse"][0]["hooks"][0]["args"]
    assert args[args.index("--ca-file") + 1] == "/usr/local/lib/mint-endpoint/ca.pem"


# ---- 사용자 수준 설치 ----


@pytest.fixture
def fake_claude(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(mint_kit.shutil, "which", lambda name: "/fake/" + name)

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="9.9.9 (Claude Code)\n", stderr="")

    monkeypatch.setattr(mint_kit.subprocess, "run", run)
    return calls


def test_user_level_install_merges_settings_and_removal_restores_them(tmp_path, fake_claude):
    kit = kit_of(tmp_path, False)
    settings_path = kit.home / ".claude/settings.json"
    settings_path.parent.mkdir(parents=True)
    original = {"model": "sonnet", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": []}]}}
    settings_path.write_text(json.dumps(original), encoding="utf-8")
    state = kit.install()
    merged = json.loads(settings_path.read_text(encoding="utf-8"))
    assert merged["model"] == "sonnet" and "allowManagedHooksOnly" not in merged
    assert len(merged["hooks"]["PreToolUse"]) == 2
    assert state["mode"] == "user" and not (kit.managed_dir / "managed-settings.json").exists()
    add = [c for c in fake_claude if c[1:3] == ["mcp", "add-json"]]
    assert add and add[0][3:5] == ["-s", "user"]
    kit.install()  # 다시 설치해도 우리 항목은 하나
    assert len(json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]) == 2
    kit.uninstall()
    assert json.loads(settings_path.read_text(encoding="utf-8")) == original
    assert any(c[1:3] == ["mcp", "remove"] for c in fake_claude)
    assert not (kit.home / ".local/lib/mint-endpoint").exists()


def test_user_level_install_without_prior_settings_leaves_no_file_behind(tmp_path, fake_claude):
    kit = kit_of(tmp_path, False)
    kit.install()
    kit.uninstall()
    assert not (kit.home / ".claude/settings.json").exists()


# ---- 보고 ----


def test_report_marks_user_level_as_unmanaged_and_leaves_the_key_out(
    tmp_path, fake_claude, monkeypatch
):
    sent: list[dict] = []
    monkeypatch.setattr(
        mint_kit, "post", lambda url, key, payload, ca: sent.append(payload) or True
    )
    user = kit_of(tmp_path / "u", False)
    assert user.report(user.install(), "installed") is True
    assert sent[-1]["managed"] is False and sent[-1]["mode"] == "user"
    managed = kit_of(tmp_path / "m", True)
    managed.report(managed.install(), "installed")
    assert sent[-1]["managed"] is True and sent[-1]["claude_version"] == "9.9.9 (Claude Code)"
    assert not any(path.endswith(".config/mint/key") for path in sent[-1]["files"])


# ---- 서버 쪽 경로 ----


def build_app(tmp_path):
    h, rt = runtime(tmp_path)

    def user_api_key_auth(authorization: str | None = Header(default=None)):
        if authorization != "Bearer sk-user":
            raise HTTPException(status_code=401, detail="invalid key")
        return auth()

    reports = tmp_path / "reports.jsonl"
    app = FastAPI()
    router = make_router(
        auth_dependency=user_api_key_auth,
        runtime_provider=lambda: rt,
        registry=registry(),
        principal_factory=principal_of,
        kit=KitSettings(public_url="https://mint.test", reports_path=reports),
    )
    install(app, router)
    return TestClient(app), reports


def test_logged_in_user_downloads_a_kit_bound_to_their_key(tmp_path):
    client, _ = build_app(tmp_path)
    assert client.get("/mint/v1/kit").status_code == 401
    answer = client.get("/mint/v1/kit", headers={"Authorization": "Bearer sk-user"})
    assert answer.status_code == 200 and answer.headers["content-type"] == "application/gzip"
    assert json.loads(_config(answer.content))["key"] == "sk-user"


def test_report_takes_identity_from_the_key_and_rejects_extra_fields(tmp_path):
    client, reports = build_app(tmp_path)
    headers = {"Authorization": "Bearer sk-user"}
    report = {
        "kit_version": kit_version(),
        "action": "installed",
        "mode": "user",
        "managed": False,
        "files": {},
        "mcp_servers": ["cnt"],
        "claude_version": "2.1.312 (Claude Code)",
    }
    assert client.post("/mint/v1/endpoint/report", json=report).status_code == 401
    answer = client.post("/mint/v1/endpoint/report", json=report, headers=headers)
    assert answer.json() == {"ok": True, "managed": False}
    (line,) = reports.read_text(encoding="utf-8").splitlines()
    saved = json.loads(line)
    assert saved["user_id"] == "u1" and saved["mode"] == "user" and saved["managed"] is False
    assert (
        client.post(
            "/mint/v1/endpoint/report", json={**report, "user_id": "u9"}, headers=headers
        ).status_code
        == 422
    )
    assert len(reports.read_text(encoding="utf-8").splitlines()) == 1
