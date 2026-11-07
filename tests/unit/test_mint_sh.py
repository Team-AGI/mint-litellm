"""배포 스크립트의 환경 파일 처리. docker는 호출 인자만 기록하는 대역으로 바꾼다."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

import mint_litellm

SCRIPT = Path(mint_litellm.__file__).resolve().parents[2] / "deploy" / "mint.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash가 필요하다")


def run(tmp_path: Path, env_text: str, *args: str):
    deploy = tmp_path / "deploy"
    deploy.mkdir(exist_ok=True)
    shutil.copy(SCRIPT, deploy / "mint.sh")
    (deploy / ".env").write_text(env_text, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "docker"
    fake.write_text('#!/bin/sh\necho "$@" >> "$FAKE_DOCKER_LOG"\n', encoding="utf-8")
    fake.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "FAKE_DOCKER_LOG": str(tmp_path / "docker.log"),
    }
    result = subprocess.run(
        [BASH, "mint.sh", *args],
        cwd=deploy,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result, deploy / ".env", home


def test_an_env_file_without_the_secrets_directory_key_still_works(tmp_path):
    result, env_file, home = run(tmp_path, "POSTGRES_PASSWORD=x\n", "cli", "status")
    assert result.returncode == 0, result.stderr
    lines = env_file.read_text(encoding="utf-8").splitlines()
    configured = [ln for ln in lines if ln.startswith("MINT_SECRETS_DIR=")]
    assert len(configured) == 1 and configured[0].endswith("/home/.config/mint")
    assert (home / ".config" / "mint").is_dir()
    if os.name != "nt":
        assert stat.S_IMODE((home / ".config" / "mint").stat().st_mode) == 0o700
    again, _, _ = run(tmp_path, env_file.read_text(encoding="utf-8"), "cli", "status")
    assert again.returncode == 0
    assert env_file.read_text(encoding="utf-8").count("MINT_SECRETS_DIR=") == 1


def test_an_empty_secrets_directory_setting_is_replaced_not_duplicated(tmp_path):
    result, env_file, _ = run(tmp_path, "MINT_SECRETS_DIR=\nOTHER=1\n", "cli", "status")
    assert result.returncode == 0, result.stderr
    text = env_file.read_text(encoding="utf-8")
    assert text.count("MINT_SECRETS_DIR=") == 1 and "OTHER=1" in text


def test_a_configured_secrets_directory_is_used_and_no_secret_file_is_created(tmp_path):
    target = tmp_path / "outside"
    result, _, _ = run(tmp_path, f"MINT_SECRETS_DIR={target}\n", "cli", "status")
    assert result.returncode == 0, result.stderr
    assert target.is_dir() and not (target / "secrets.env").exists()


def test_missing_env_file_and_unknown_commands_fail_clearly(tmp_path):
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    shutil.copy(SCRIPT, deploy / "mint.sh")
    missing = subprocess.run([BASH, "mint.sh", "status"], cwd=deploy, capture_output=True,
                             text=True, encoding="utf-8")
    assert missing.returncode != 0 and ".env" in missing.stderr
    unknown = subprocess.run([BASH, "mint.sh", "restore"], cwd=deploy, capture_output=True,
                             text=True, encoding="utf-8")
    assert unknown.returncode != 0 and "restore" not in unknown.stdout


def test_first_run_generates_export_key_and_worker_passwords_once_with_private_env(tmp_path):
    result, env_file, _ = run(tmp_path, "POSTGRES_PASSWORD=x\nMINT_STAFF_DB_PASSWORD=keep-me\n",
                              "cli", "status")
    assert result.returncode == 0, result.stderr
    values = dict(ln.split("=", 1) for ln in env_file.read_text(encoding="utf-8").splitlines())
    import base64
    key = values["MINT_EXPORT_HMAC_KEY"]
    assert len(base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))) >= 32
    assert len(values["MINT_WORKER_DB_PASSWORD"]) >= 32
    assert values["MINT_STAFF_DB_PASSWORD"] == "keep-me"
    if os.name != "nt":
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    run(tmp_path, env_file.read_text(encoding="utf-8"), "cli", "status")
    again = dict(ln.split("=", 1) for ln in env_file.read_text(encoding="utf-8").splitlines())
    assert again["MINT_EXPORT_HMAC_KEY"] == key


def test_up_hands_worker_and_staff_passwords_to_init_and_starts_the_worker(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    result, env_file, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "up")
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "-e MINT_WORKER_DB_PASSWORD" in log and "-e MINT_STAFF_DB_PASSWORD" in log
    values = dict(ln.split("=", 1) for ln in env_file.read_text(encoding="utf-8").splitlines())
    assert values["MINT_WORKER_DB_PASSWORD"] not in log  # 값은 인자가 아니라 환경으로 간다
    assert "--profile worker up -d worker" in log
    assert "--user 0 --entrypoint chown control -R 65532:65532 /var/lib/mint/export /bundles" in log
    assert "--user 0 --entrypoint chown litellm -R 65532:65532 /var/lib/mint/buffer" in log


def test_compose_refuses_to_start_litellm_without_an_export_key():
    text = (SCRIPT.parent / "compose.yaml").read_text(encoding="utf-8")
    litellm = text.split("\n  litellm:\n", 1)[1].split("\n  control:\n", 1)[0]
    assert "MINT_EXPORT_HMAC_KEY: ${MINT_EXPORT_HMAC_KEY:?" in litellm
    assert "export:/var/lib/mint/export:ro" in litellm


def test_compose_gives_the_worker_the_policy_engine_and_the_observe_period():
    text = (SCRIPT.parent / "compose.yaml").read_text(encoding="utf-8")
    worker = text.split("\n  worker:\n", 1)[1].split("\n  console:\n", 1)[0]
    assert "MINT_OPA_URL: http://opa:8181" in worker
    assert "MINT_OBSERVE_SECONDS: ${MINT_OBSERVE_SECONDS:-3600}" in worker
    litellm = text.split("\n  litellm:\n", 1)[1].split("\n  control:\n", 1)[0]
    assert "MINT_OBSERVE_SECONDS: ${MINT_OBSERVE_SECONDS:-3600}" in litellm


def test_values_are_appended_on_their_own_line_when_env_lacks_a_trailing_newline(tmp_path):
    result, env_file, _ = run(tmp_path, "POSTGRES_PASSWORD=x", "cli", "status")
    assert result.returncode == 0, result.stderr
    lines = env_file.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "POSTGRES_PASSWORD=x"
    assert any(ln.startswith("MINT_SECRETS_DIR=") for ln in lines)
    assert any(ln.startswith("MINT_EXPORT_HMAC_KEY=") for ln in lines)
