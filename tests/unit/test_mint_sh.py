"""배포 스크립트의 환경 파일 처리. docker는 호출 인자만 기록하는 대역으로 바꾼다."""

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import mint_litellm

SCRIPT = Path(mint_litellm.__file__).resolve().parents[2] / "deploy" / "mint.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash가 필요하다")


def run(tmp_path: Path, env_text: str, *args: str, docker_tail: str = "", extra_env=None):
    extra_env = extra_env or {}
    deploy = tmp_path / "deploy"
    deploy.mkdir(exist_ok=True)
    shutil.copy(SCRIPT, deploy / "mint.sh")
    (deploy / ".env").write_text(env_text, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "docker"
    fake.write_text(
        '#!/bin/sh\necho "$@" >> "$FAKE_DOCKER_LOG"\n'
        'case "$*" in *pg_dump*|*"--entrypoint cat"*) echo dump;; esac\n' + docker_tail,
        encoding="utf-8",
    )
    if args[:1] == ("upgrade",):  # 백업이 설정 파일을 복사한다
        (deploy / "config").mkdir(exist_ok=True)
        (deploy / "config" / "litellm.config.yaml").write_text("{}\n", encoding="utf-8")
    fake.chmod(0o755)
    fakes = {  # 호스트 주기 실행 등록이 시험 기기를 건드리지 않게 대역으로 바꾼다
        "systemctl": 'echo "$@" >> "$FAKE_HOST_LOG"\n[ -z "$FAKE_NO_SYSTEMD" ]\n',
        "crontab": 'f="$HOME/cron.txt"\n'
        'if [ "$1" = -l ]; then cat "$f" 2>/dev/null; else cat > "$f"; fi\n',
    }
    for name, body in fakes.items():
        (bin_dir / name).write_text("#!/bin/sh\n" + body, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "FAKE_DOCKER_LOG": str(tmp_path / "docker.log"),
        "MINT_UPGRADE_WAIT": "0",
        "FAKE_HOST_LOG": str(tmp_path / "host.log"),
        **extra_env,
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
    assert len(values["MINT_REDIS_PASSWORD"]) >= 32
    assert values["MINT_STAFF_DB_PASSWORD"] == "keep-me"
    signing = values["MINT_KIT_SIGNING_KEY"]
    assert len(base64.urlsafe_b64decode(signing + "=" * (-len(signing) % 4))) == 32
    if os.name != "nt":
        assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    run(tmp_path, env_file.read_text(encoding="utf-8"), "cli", "status")
    again = dict(ln.split("=", 1) for ln in env_file.read_text(encoding="utf-8").splitlines())
    assert again["MINT_EXPORT_HMAC_KEY"] == key and again["MINT_KIT_SIGNING_KEY"] == signing


def test_up_hands_worker_and_staff_passwords_to_init_and_starts_the_worker(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    result, env_file, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "up")
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "-e MINT_WORKER_DB_PASSWORD" in log and "-e MINT_STAFF_DB_PASSWORD" in log
    values = dict(ln.split("=", 1) for ln in env_file.read_text(encoding="utf-8").splitlines())
    assert values["MINT_WORKER_DB_PASSWORD"] not in log  # 값은 인자가 아니라 환경으로 간다
    assert "--profile worker up -d worker inspector" in log
    assert "--profile console up -d console" in log
    assert "--user 0 --entrypoint chown control -R 65532:65532 /var/lib/mint/export /bundles" in log
    assert "--user 0 --entrypoint chown litellm -R 65532:65532 /var/lib/mint/buffer" in log
    assert "chgrp -R 65532 /app/config && chmod -R g+rX /app/config" in log


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


FIX_FLAG = "--fix-config /app/config/litellm.config.yaml"


def test_upgrade_and_up_ask_init_to_add_missing_guardrail_modes_to_the_operator_config(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    for command in ("up", "upgrade"):
        (tmp_path / "docker.log").unlink(missing_ok=True)
        result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", command)
        assert result.returncode == 0, result.stderr
        log = (tmp_path / "docker.log").read_text(encoding="utf-8")
        assert f"init --out /app/config/litellm.mint.yaml {FIX_FLAG}" in log


def test_upgrade_stops_before_starting_litellm_when_init_cannot_fix_the_config(tmp_path):
    (tmp_path / "deploy").mkdir()
    result, _, _ = run(
        tmp_path,
        "POSTGRES_PASSWORD=x\n",
        "upgrade",
        docker_tail='case "$*" in *--fix-config*) exit 1;; esac\n',
    )
    assert result.returncode != 0
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "up -d litellm" not in log


ISSUER_DOCKER = (
    'case "$*" in\n'
    '  *"key/generate"*) echo "noise"; echo sk-issued-1;;\n'
    '  *"up -d console"*) echo "console-sees:$MINT_KIT_ISSUER_KEY" >> "$FAKE_DOCKER_LOG";;\n'
    "esac\n"
)


def up_with_issuer(
    tmp_path, command="up", docker_tail=ISSUER_DOCKER, existing=None, existing_control=None
):
    deploy = tmp_path / "deploy"
    deploy.mkdir(parents=True, exist_ok=True)
    (deploy / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    secrets = tmp_path / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    if existing:
        (secrets / "kit_issuer.key").write_text(existing + "\n", encoding="utf-8")
    if existing_control:
        (secrets / "control.key").write_text(existing_control + "\n", encoding="utf-8")
    env = f"POSTGRES_PASSWORD=x\nLITELLM_MASTER_KEY=sk-master\nMINT_SECRETS_DIR={secrets}\n"
    result, _, _ = run(tmp_path, env, command, docker_tail=docker_tail)
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    return result, log, secrets / "kit_issuer.key"


@pytest.mark.parametrize("command", ["up", "upgrade"])
def test_up_and_upgrade_make_the_kit_issuer_key_once_and_hand_it_to_the_console(
    tmp_path, command
):
    result, log, key_file = up_with_issuer(tmp_path, command)
    assert result.returncode == 0, result.stderr
    assert key_file.read_text(encoding="utf-8") == "sk-issued-1\n"
    if os.name != "nt":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert "console-sees:sk-issued-1" in log
    # 마스터 키는 인자가 아니라 환경으로 가고, 만드는 키는 두 경로만 연다.
    assert "sk-master" not in log and "-e LITELLM_MASTER_KEY" in log
    script = SCRIPT.read_text(encoding="utf-8")
    assert 'routes = ["/key/generate", "/key/delete"]' in script
    # 이미 있으면 다시 만들지 않고 그대로 넘긴다.
    again, second_log, _ = up_with_issuer(
        tmp_path / "again", command, existing="sk-existing", existing_control="sk-control"
    )
    assert again.returncode == 0, again.stderr
    # 이미 있으면 새로 만들지 않는다(제어 키 허용 경로 갱신 실행은 있어도 된다).
    assert not re.search(r"KEY_KIND=(kit|control)(?!-refresh)", second_log)
    assert "console-sees:sk-existing" in second_log


def test_a_failed_issuer_key_does_not_stop_the_stack_and_leaves_no_file(tmp_path):
    result, log, key_file = up_with_issuer(tmp_path, docker_tail="")
    assert result.returncode == 0, result.stderr
    assert not key_file.exists() and "다시 시도합니다" in result.stderr
    assert "--profile console up -d console" in log


CONTROL_DOCKER = (
    'case "$*" in\n'
    '  *"key/generate"*) all="$*"; rest="${all#*KEY_KIND=}"; echo "sk-issued-${rest%% *}";;\n'
    '  *"up -d worker"*) echo "worker-sees:$MINT_LITELLM_KEY" >> "$FAKE_DOCKER_LOG";;\n'
    "esac\n"
)


def test_keys_missing_from_a_reset_litellm_are_reissued(tmp_path):
    # DB를 비우면 LiteLLM의 키도 사라진다. 없다고 확인된 옛 키는 치우고 새로 발급한다.
    stale = 'case "$*" in *"CHECK_KEY"*) echo missing;; esac\n'
    result, log, _ = up_with_issuer(
        tmp_path, "up", docker_tail=stale + CONTROL_DOCKER,
        existing="sk-old-kit", existing_control="sk-old-control",
    )
    assert result.returncode == 0, result.stderr
    secrets = tmp_path / "secrets"
    assert (secrets / "control.key").read_text(encoding="utf-8") == "sk-issued-control\n"
    assert (secrets / "kit_issuer.key").read_text(encoding="utf-8") == "sk-issued-kit\n"
    assert any(p.name.startswith("control.key.stale-") for p in secrets.iterdir())
    assert "-e CHECK_KEY" in log and "sk-old-control" not in log


@pytest.mark.parametrize("command", ["up", "upgrade"])
def test_up_and_upgrade_make_the_control_key_once_store_it_and_hand_it_to_the_worker(
    tmp_path, command
):
    result, log, _ = up_with_issuer(tmp_path, command, docker_tail=CONTROL_DOCKER)
    assert result.returncode == 0, result.stderr
    key_file = tmp_path / "secrets" / "control.key"
    assert key_file.read_text(encoding="utf-8") == "sk-issued-control\n"
    if os.name != "nt":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert "worker-sees:sk-issued-control" in log
    assert "KEY_KIND=control" in log and "KEY_KIND=kit" in log
    # 콘솔·작업 실행기가 compose env_file로 받는 파일에도 같은 키가 들어간다.
    service_env = tmp_path / "secrets" / "services.env"
    lines = service_env.read_text(encoding="utf-8").splitlines()
    assert "MINT_LITELLM_KEY=sk-issued-control" in lines
    assert any(ln.startswith("MINT_KIT_ISSUER_KEY=sk-") for ln in lines)
    if os.name != "nt":
        assert stat.S_IMODE(service_env.stat().st_mode) == 0o600
    assert "sk-issued-control" not in log.replace("worker-sees:sk-issued-control", "")
    # 키를 만든 뒤 init을 다시 실행해 면제 키로 저장하고, 키 값은 인자가 아니라 환경으로 간다.
    assert log.count("init --out") == 2 and "-e MINT_LITELLM_KEY" in log
    # 이미 있으면 다시 만들지 않는다.
    again, second, _ = up_with_issuer(
        tmp_path / "again", command, docker_tail=CONTROL_DOCKER,
        existing="sk-kit", existing_control="sk-existing-control",
    )
    assert again.returncode == 0, again.stderr
    assert not re.search(r"KEY_KIND=(kit|control)(?!-refresh)", second)
    assert second.count("init --out") == 1
    # 이미 있는 제어 키는 허용 경로만 다시 맞추고, 키 값은 인자가 아니라 환경으로 넘긴다.
    assert "KEY_KIND=control-refresh" in second and "-e EXISTING_KEY" in second
    assert "sk-existing-control" not in second.replace("worker-sees:sk-existing-control", "")
    assert "worker-sees:sk-existing-control" in second


def test_a_key_in_the_env_file_wins_over_the_stored_control_key(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "control.key").write_text("sk-stored\n", encoding="utf-8")
    (secrets / "kit_issuer.key").write_text("sk-kit\n", encoding="utf-8")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    env = (f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\nMINT_LITELLM_KEY=sk-from-env\n"
           "MINT_APPROVAL_HOLD_SECONDS=200\nMINT_SLACK_SIGNING_SECRET=s3\nMINT_STAFF_DB_PASSWORD=w\nMINT_REDIS_PASSWORD=rp\n")
    result, _, _ = run(tmp_path, env, "up", docker_tail=CONTROL_DOCKER)
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "worker-sees:sk-stored" not in log
    assert "KEY_KIND" not in log
    lines = (secrets / "services.env").read_text(encoding="utf-8").splitlines()
    assert "MINT_LITELLM_KEY=sk-from-env" in lines and "MINT_KIT_ISSUER_KEY=sk-kit" in lines
    # .env 운영 설정도 컨테이너로 간다(DB 비밀번호 제외, 플러그인용 파일에는 비밀 없음).
    assert "MINT_APPROVAL_HOLD_SECONDS=200" in lines and "MINT_SLACK_SIGNING_SECRET=s3" in lines
    assert not any(ln.startswith(("MINT_STAFF_DB_PASSWORD", "MINT_REDIS_PASSWORD")) for ln in lines)
    settings = (secrets / "settings.env").read_text(encoding="utf-8").splitlines()
    assert "MINT_APPROVAL_HOLD_SECONDS=200" in settings
    names = {ln.split("=", 1)[0] for ln in settings}
    assert not names & {"MINT_SLACK_SIGNING_SECRET", "MINT_LITELLM_KEY", "MINT_STAFF_DB_PASSWORD"}


def test_compose_hands_the_service_keys_to_the_console_and_worker_through_the_env_file():
    text = (SCRIPT.parent / "compose.yaml").read_text(encoding="utf-8")
    for name, following in (("worker", "console"), ("console", None)):
        block = text.split(f"\n  {name}:\n", 1)[1]
        if following:
            block = block.split(f"\n  {following}:\n", 1)[0]
        block = block.split("\nvolumes:\n", 1)[0]
        assert "path: ${MINT_SECRETS_DIR}/services.env" in block and "required: false" in block
        # environment의 빈 값이 env_file을 덮어쓰지 않도록 두 키는 environment에 두지 않는다.
        assert "MINT_LITELLM_KEY:" not in block and "MINT_KIT_ISSUER_KEY:" not in block


BOOTSTRAP_DOCKER = (
    'case "$*" in\n'
    '  *"operator bootstrap"*) echo \'{"ok": true, "token": "mint_op-1_x", "id": "boss"}\';;\n'
    '  *"user password-reset"*) echo \'{"ok": true, "login": "boss@x.test", '
    '"password": "Pw1abc-DEF2gh.iJKL"}\';;\n'
    '  *"cli-token-sees"*) ;;\n'
    '  *" status"*) echo "status-token:$MINT_OPERATOR_TOKEN" >> "$FAKE_DOCKER_LOG";;\n'
    '  *" doctor"*) echo "doctor-ran" >> "$FAKE_DOCKER_LOG";;\n'
    "esac\n"
)


def test_bootstrap_stores_the_first_admin_token_and_later_commands_use_it(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    before, _, _ = run(tmp_path, env, "status", docker_tail=BOOTSTRAP_DOCKER)
    assert before.returncode == 0, before.stderr
    assert "doctor-ran" in (tmp_path / "docker.log").read_text(encoding="utf-8")
    result, _, _ = run(tmp_path, env, "bootstrap", "boss", "human-1", docker_tail=BOOTSTRAP_DOCKER)
    assert result.returncode == 0, result.stderr
    token_file = secrets / "operator.token"
    assert token_file.read_text(encoding="utf-8") == "mint_op-1_x\n"
    if os.name != "nt":
        assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert "mint_op-1_x" not in result.stdout + result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "--json operator bootstrap --name boss --user-id human-1" in log
    assert "policy activate initial" in log
    assert "user password-reset human-1" in log
    ui_login = secrets / "ui-login-human-1.txt"
    assert ui_login.read_text(encoding="utf-8") == "boss@x.test Pw1abc-DEF2gh.iJKL\n"
    if os.name != "nt":
        assert stat.S_IMODE(ui_login.stat().st_mode) == 0o600
    assert "Pw1abc-DEF2gh.iJKL" not in result.stdout + result.stderr
    assert "boss@x.test" in result.stdout
    run(tmp_path, env, "status", docker_tail=BOOTSTRAP_DOCKER)
    assert "status-token:mint_op-1_x" in (tmp_path / "docker.log").read_text(encoding="utf-8")


ROOT_DOCKER = BOOTSTRAP_DOCKER.replace(
    'case "$*" in\n',
    'case "$*" in\n  *default_admin*) echo "default-admin-ran" >> "$FAKE_DOCKER_LOG";;\n',
    1,
)


NO_OPERATORS = (
    'case "$*" in *"control --json status"*) echo "운영자가 아직 없습니다";;\n'
    '  *"exec -T postgres psql"*) echo 0;; esac\n'
)


def test_up_creates_the_default_root_admin_on_a_fresh_install(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    result, _, _ = run(tmp_path, env, "up", docker_tail=NO_OPERATORS + ROOT_DOCKER)
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "default-admin-ran" in log
    assert "ensure_password_policy" in log
    assert log.index("ensure_password_policy") < log.index("up -d opa litellm")
    assert "operator bootstrap --name root --user-id root" in log
    assert "policy activate initial" in log
    assert (secrets / "operator.token").read_text(encoding="utf-8") == "mint_op-1_x\n"
    assert "root / 비밀번호 rootrootroot" in result.stdout
    assert "rootrootroot" not in log and not list(secrets.glob("ui-login-*"))


def test_up_recreates_root_after_a_database_reset_even_with_an_old_token_file(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "operator.token").write_text("mint_op-9_old\n", encoding="utf-8")
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    result, _, _ = run(tmp_path, env, "up", docker_tail=NO_OPERATORS + ROOT_DOCKER)
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "default-admin-ran" in log and "operator bootstrap --name root" in log
    assert (secrets / "operator.token").read_text(encoding="utf-8") == "mint_op-1_x\n"


def test_up_does_not_touch_an_install_that_already_has_an_operator(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "operator.token").write_text("mint_op-9_old\n", encoding="utf-8")
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    result, _, _ = run(tmp_path, env, "up", docker_tail=ROOT_DOCKER)
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "default-admin-ran" not in log and "operator bootstrap" not in log
    assert "ensure_password_policy" not in log
    assert (secrets / "operator.token").read_text(encoding="utf-8") == "mint_op-9_old\n"


def test_bootstrap_refuses_a_second_time_and_without_arguments(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "operator.token").write_text("mint_old\n", encoding="utf-8")
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    again, _, _ = run(tmp_path, env, "bootstrap", "boss", "human-1")
    assert again.returncode != 0 and "이미 있습니다" in again.stderr
    assert (secrets / "operator.token").read_text(encoding="utf-8") == "mint_old\n"
    (tmp_path / "other").mkdir()
    usage, _, _ = run(tmp_path / "other", env, "bootstrap")
    assert usage.returncode != 0 and "사용법" in usage.stderr


def test_up_tells_the_next_step_for_a_first_install(tmp_path):
    result, _, _ = up_with_issuer(tmp_path, docker_tail="")
    assert result.returncode == 0, result.stderr
    assert "./mint.sh bootstrap <이름>" in result.stdout


def positions(log: str, *needles: str) -> list[int]:
    """각 문구가 처음 나온 줄 번호. 문구가 없으면 시험이 실패한다."""
    lines = log.splitlines()
    return [next(i for i, ln in enumerate(lines) if needle in ln) for needle in needles]


def upgrade_with_token(tmp_path, docker_tail=""):
    (tmp_path / "deploy").mkdir(exist_ok=True)
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / "operator.token").write_text("tok\n", encoding="utf-8")
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    return run(tmp_path, env, "upgrade", docker_tail=docker_tail)[0]


def test_upgrade_runs_every_mechanical_step_in_order(tmp_path):
    result = upgrade_with_token(tmp_path)
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    order = positions(
        log, " build litellm", "pg_dump", "stop litellm worker inspector console", "init --out",
        "upgrade policy", "up -d litellm", "up -d console", " check", " doctor", "upgrade report",
    )
    assert order == sorted(order)
    assert list((tmp_path / "deploy" / "backups").glob("*/mint.sql"))
    assert "백업:" in result.stdout and "] 사람이 정할 일을 계산해" in result.stdout


def test_upgrade_dry_run_prints_the_plan_and_touches_nothing(tmp_path):
    (tmp_path / "deploy").mkdir()
    result, env_file, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "upgrade", "--dry-run")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert "아무것도 바꾸지 않았습니다" in lines[0]
    assert [ln.split(".")[0].strip() for ln in lines[1:]] == [str(n) for n in range(1, 11)]
    assert not (tmp_path / "docker.log").exists()
    assert env_file.read_text(encoding="utf-8") == "POSTGRES_PASSWORD=x\n"
    assert not (tmp_path / "deploy" / "backups").exists()


def test_upgrade_with_an_unknown_option_is_refused(tmp_path):
    (tmp_path / "deploy").mkdir()
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "upgrade", "--now")
    assert result.returncode != 0 and "사용법" in result.stderr
    assert not (tmp_path / "docker.log").exists()


def test_a_failed_build_leaves_the_previous_version_running(tmp_path):
    (tmp_path / "deploy").mkdir()
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "upgrade",
                       docker_tail='case "$*" in *" build "*) exit 1;; esac\n')
    assert result.returncode != 0
    assert "[1/10]" in result.stderr and "이전 판본이 그대로 실행 중" in result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert " stop " not in log and "init --out" not in log


def test_a_failed_check_stops_with_the_step_and_the_backup_location(tmp_path):
    result = upgrade_with_token(tmp_path, 'case "$*" in *" check"*) exit 1;; esac\n')
    assert result.returncode != 0
    assert "[9/10] 점검합니다" in result.stderr and "백업:" in result.stderr
    assert "업그레이드했습니다" not in result.stdout
    assert "upgrade report" not in (tmp_path / "docker.log").read_text(encoding="utf-8")


def test_a_failed_migration_stops_before_the_policy_and_litellm_steps(tmp_path):
    (tmp_path / "deploy").mkdir()
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "upgrade",
                       docker_tail='case "$*" in *"init --out"*) exit 1;; esac\n')
    assert result.returncode != 0 and "[5/10]" in result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "up -d opa" not in log and "up -d litellm" not in log


ADD_DOCKER = BOOTSTRAP_DOCKER.replace('*"operator bootstrap"*', '*"operator add"*')


def test_cli_save_token_writes_the_file_on_the_host_not_inside_the_container(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    env = f"POSTGRES_PASSWORD=x\nMINT_SECRETS_DIR={secrets}\n"
    target = tmp_path / "viewer.token"
    result, _, _ = run(
        tmp_path, env, "cli", "operator", "add", "--name", "v1", "--role", "viewer",
        "--save-token", str(target), docker_tail=ADD_DOCKER,
    )
    assert result.returncode == 0, result.stderr
    assert target.read_text(encoding="utf-8") == "mint_op-1_x\n"
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert "mint_op-1_x" not in result.stdout + result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "--save-token" not in log and "--json operator add --name v1 --role viewer" in log
    again, _, _ = run(
        tmp_path, env, "cli", "operator", "add", "--name", "v2", "--role", "viewer",
        "--save-token", str(target), docker_tail=ADD_DOCKER,
    )
    assert again.returncode != 0 and "덮어쓰지 않습니다" in again.stderr


def test_the_compose_file_turns_the_endpoint_routes_on_for_the_gateway_and_the_console():
    compose = (SCRIPT.parent / "compose.yaml").read_text(encoding="utf-8")
    # 콘솔이 발급한 단말 묶음의 판정·보고 경로가 404가 되지 않게 기본으로 켠다.
    assert compose.count("MINT_ENDPOINT_ROUTES: ${MINT_ENDPOINT_ROUTES:-true}") == 2


def test_cli_key_file_is_streamed_from_the_host_file_and_never_put_on_the_command_line(tmp_path):
    key = tmp_path / "verify.key"
    key.write_text("sk-verify\n", encoding="utf-8")
    tail = ('case "$*" in *"--key-file /dev/stdin"*) '
            'echo "stdin:$(cat)" >> "$FAKE_DOCKER_LOG";; esac\n')
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "cli", "verify", "run", "--server", "s1",
                       "--key-file", str(key), docker_tail=tail)
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "verify run --server s1 --key-file /dev/stdin" in log and "stdin:sk-verify" in log
    assert str(key) not in log
    missing, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "cli", "verify", "run",
                        "--key-file", str(tmp_path / "none"))
    assert missing.returncode != 0 and "읽을 수 없습니다" in missing.stderr


def test_a_malformed_signing_key_stops_before_anything_starts(tmp_path):
    env = "POSTGRES_PASSWORD=x\nMINT_WEBHOOK_HMAC_KEY=short\n"
    result, _, _ = run(tmp_path, env, "cli", "status")
    assert result.returncode != 0 and "MINT_WEBHOOK_HMAC_KEY 형식" in result.stderr
    assert not (tmp_path / "docker.log").exists()


def test_backup_says_the_env_file_and_secrets_folder_are_not_included(tmp_path):
    (tmp_path / "deploy" / "config").mkdir(parents=True)
    (tmp_path / "deploy" / "config" / "litellm.config.yaml").write_text("{}\n", encoding="utf-8")
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "backup")
    assert result.returncode == 0, result.stderr
    assert ".env와 비밀 폴더" in result.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX 권한")
def test_backup_takes_back_a_backups_folder_the_backup_container_created(tmp_path):
    # 예약 백업 컨테이너가 backups를 root 소유로 먼저 만들면 운영자 계정으로 돌려놓는다.
    (tmp_path / "deploy" / "backups").mkdir(parents=True)
    (tmp_path / "deploy" / "backups").chmod(0o555)
    try:
        run(tmp_path, "POSTGRES_PASSWORD=x\n", "backup")
    finally:
        (tmp_path / "deploy" / "backups").chmod(0o755)
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "--entrypoint chown backup" in log and "/backups" in log


def test_up_waits_for_litellm_and_shows_its_log_tail_when_it_never_gets_ready(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "litellm.config.example.yaml").write_text("{}\n", encoding="utf-8")
    tail = 'case "$*" in *"up -d --wait litellm"*) exit 1;; esac\n'
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "up", docker_tail=tail)
    assert result.returncode != 0 and "40~60초" in result.stdout
    assert "logs --tail 20 litellm" in (tmp_path / "docker.log").read_text(encoding="utf-8")


def test_restore_replaces_both_databases_from_the_folder_and_starts_again(tmp_path):
    backup = tmp_path / "bk"
    backup.mkdir()
    (backup / "mint.sql").write_text("select 1;\n", encoding="utf-8")
    (backup / "litellm.sql").write_text("select 2;\n", encoding="utf-8")
    (tmp_path / "deploy" / "config").mkdir(parents=True)
    (tmp_path / "deploy" / "config" / "litellm.config.yaml").write_text("{}\n", encoding="utf-8")
    result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "restore", str(backup))
    assert result.returncode == 0, result.stderr
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "DROP DATABASE IF EXISTS mint" in log and "DROP DATABASE IF EXISTS litellm" in log
    assert log.index("stop litellm") < log.index("DROP DATABASE IF EXISTS mint")
    assert "up -d backup" in log


def test_restore_without_a_complete_folder_touches_nothing(tmp_path):
    (tmp_path / "empty").mkdir()
    for args in ((), (str(tmp_path / "empty"),)):
        result, _, _ = run(tmp_path, "POSTGRES_PASSWORD=x\n", "restore", *args)
        assert result.returncode != 0 and "restore" in result.stderr
    assert not (tmp_path / "docker.log").exists()


def test_the_daily_backup_keeps_the_newest_seven_and_drops_a_failed_dump(tmp_path):
    root = tmp_path / "backups"
    root.mkdir()
    for day in range(1, 9):
        (root / f"2000010{day}T000000Z").mkdir()
    # 가장 새 폴더도 하루보다 오래된 것으로 만들어 새 백업이 돌게 한다
    old = 1_000_000_000
    for d in root.iterdir():
        os.utime(d, (old, old))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    dump = bin_dir / "pg_dump"
    dump.write_text('#!/bin/sh\n[ "$FAIL" = 1 ] && exit 1\necho dump\n', encoding="utf-8")
    dump.chmod(0o755)
    (bin_dir / "sleep").write_text("#!/bin/sh\nkill $PPID\n", encoding="utf-8")
    (bin_dir / "sleep").chmod(0o755)
    script = SCRIPT.parent / "backup-schedule.sh"

    def once(fail: str):
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
               "BACKUP_DIR": root.as_posix(), "FAIL": fail}
        subprocess.run([BASH, str(script)], env=env, capture_output=True, timeout=30)

    once("1")
    assert len(list(root.iterdir())) == 8  # 실패한 덤프 폴더는 남지 않는다
    once("0")
    names = sorted(p.name for p in root.iterdir())
    assert len(names) == 7 and names[0] == "20000103T000000Z"
    assert (root / names[-1] / "mint.sql").read_text(encoding="utf-8") == "dump\n"


def test_the_compose_file_runs_the_daily_backup_with_a_restart_policy():
    text = (SCRIPT.parent / "compose.yaml").read_text(encoding="utf-8")
    block = text.split("  backup:\n", 1)[1].split("\n\n", 1)[0]
    assert "backup-schedule.sh" in block and "restart: unless-stopped" in block
    # 작업 실행기와 콘솔은 죽어도 다시 뜬다
    for name in ("worker", "console"):
        assert "restart: unless-stopped" in text.split(f"\n  {name}:\n", 1)[1].split("\n\n", 1)[0]


HEAL_ENV = "POSTGRES_PASSWORD=x\nLITELLM_MASTER_KEY=sk-master\nMINT_SECRETS_DIR={s}\n"
STALE = 'case "$*" in *"CHECK_KEY"*) echo missing;; esac\n'


def heal(tmp_path, docker_tail):
    secrets = tmp_path / "secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / "kit_issuer.key").write_text("sk-old-kit\n", encoding="utf-8")
    (secrets / "control.key").write_text("sk-old-control\n", encoding="utf-8")
    result, _, _ = run(tmp_path, HEAL_ENV.format(s=secrets), "heal", docker_tail=docker_tail)
    log = (tmp_path / "docker.log").read_text(encoding="utf-8")
    return result, log, secrets


def test_heal_does_nothing_when_no_key_is_rejected(tmp_path):
    result, log, secrets = heal(tmp_path, 'case "$*" in *CHECK_KEY*) echo present;; esac\n')
    assert result.returncode == 0, result.stderr
    assert "거부된 키 없음" in result.stdout
    assert "key/generate" not in log and " up -d" not in log
    assert (secrets / "control.key").read_text(encoding="utf-8") == "sk-old-control\n"


def test_heal_leaves_keys_alone_when_litellm_is_unreachable(tmp_path):
    result, log, _ = heal(tmp_path, 'case "$*" in *CHECK_KEY*) echo unknown;; esac\n')
    assert result.returncode == 0 and "key/generate" not in log and " up -d" not in log


def test_heal_reissues_rejected_keys_and_restarts_their_containers(tmp_path):
    result, log, secrets = heal(tmp_path, STALE + CONTROL_DOCKER)
    assert result.returncode == 0, result.stderr
    assert (secrets / "control.key").read_text(encoding="utf-8") == "sk-issued-control\n"
    assert (secrets / "kit_issuer.key").read_text(encoding="utf-8") == "sk-issued-kit\n"
    assert "up -d --force-recreate worker inspector" in log
    assert "up -d --force-recreate console" in log


def test_upgrade_registers_one_systemd_user_timer_and_a_rerun_adds_no_second(tmp_path):
    env = HEAL_ENV.format(s=tmp_path / "secrets")
    result, _, home = run(tmp_path, env, "upgrade")
    assert result.returncode == 0, result.stderr
    units = sorted((home / ".config/systemd/user").iterdir())
    assert [u.suffix for u in units] == [".service", ".timer"]
    assert "OnUnitActiveSec=10min" in units[1].read_text(encoding="utf-8")
    assert "mint.sh heal" in units[0].read_text(encoding="utf-8")
    run(tmp_path, env, "upgrade")
    host = (tmp_path / "host.log").read_text(encoding="utf-8")
    assert host.count("enable --now") == 1
    assert len(list((home / ".config/systemd/user").iterdir())) == 2


def test_without_systemd_a_single_crontab_line_is_kept_and_replaced(tmp_path):
    env = HEAL_ENV.format(s=tmp_path / "secrets")
    for _ in range(2):
        result, _, home = run(tmp_path, env, "upgrade", extra_env={"FAKE_NO_SYSTEMD": "1"})
        assert result.returncode == 0, result.stderr
    lines = (home / "cron.txt").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and lines[0].startswith("*/10 * * * * ")
    assert "mint.sh heal" in lines[0]


def test_auto_heal_off_registers_nothing_and_removes_what_exists(tmp_path):
    env = HEAL_ENV.format(s=tmp_path / "secrets")
    run(tmp_path, env, "upgrade")
    run(tmp_path, env, "upgrade", extra_env={"FAKE_NO_SYSTEMD": "1"})
    off = env + "MINT_AUTO_HEAL=0\n"
    _, _, home = run(tmp_path, off, "upgrade")
    assert list((home / ".config/systemd/user").iterdir()) == []
    assert "disable --now" in (tmp_path / "host.log").read_text(encoding="utf-8")
    _, _, home = run(tmp_path, off, "upgrade", extra_env={"FAKE_NO_SYSTEMD": "1"})
    assert (home / "cron.txt").read_text(encoding="utf-8").strip() == ""


def test_compose_redis_is_private_and_litellm_uses_it_without_depending_on_health():
    import yaml
    text = (SCRIPT.parent / "compose.yaml").read_text(encoding="utf-8")
    services = yaml.safe_load(text)["services"]
    redis = services["redis"]
    assert "@sha256:" in redis["image"] and "ports" not in redis
    assert redis["restart"] == "unless-stopped" and "healthcheck" in redis
    env = services["litellm"]["environment"]
    assert env["REDIS_HOST"] == "redis" and "MINT_REDIS_PASSWORD" in env["REDIS_PASSWORD"]
    dep = services["litellm"]["depends_on"]["redis"]
    assert dep == {"condition": "service_started", "required": False}
