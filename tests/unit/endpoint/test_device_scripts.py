import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import uvicorn
from endpoint_helpers import auth, principal_of, registry, runtime
from fastapi import FastAPI, Header, HTTPException

import mint_litellm
from mint_litellm.endpoint.decide import ContractRegistry, install, make_router

ROOT = Path(mint_litellm.__file__).resolve().parents[2]
DEVICE = ROOT / "tests" / "endpoint" / "device"


def load(name):
    spec = importlib.util.spec_from_file_location(name, DEVICE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", ["up.sh", "down.sh"])
@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_stack_scripts_parse(name):
    done = subprocess.run(
        ["bash", "-n", (DEVICE / name).as_posix()], capture_output=True, timeout=30
    )
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("name", ["accept", "bootstrap", "ep_client", "make_registry"])
def test_device_scripts_compile(name):
    compile((DEVICE / f"{name}.py").read_text(encoding="utf-8"), name, "exec")


def test_stack_scripts_use_their_own_project_name_and_refuse_the_others():
    for name in ("up.sh", "down.sh"):
        text = (DEVICE / name).read_text(encoding="utf-8")
        assert "COMPOSE_PROJECT_NAME:-mintep" in text
        refusal = next(line for line in text.splitlines() if "mints2" in line)
        assert "mints3" in refusal and "mint-manual" in refusal and "mint-g10" in refusal


def test_percentiles():
    client = load("ep_client")
    stats = client.percentiles([float(n) for n in range(1, 101)])
    assert stats == {"n": 100, "p50": 50.5, "p95": 96.0, "max": 100.0}


def test_acceptance_runner_dry_run_writes_a_report(tmp_path, monkeypatch):
    monkeypatch.setenv("EP_SSH_DEVICE", "ssh dev")
    monkeypatch.setenv("EP_SSH_PJ1", "ssh pj")
    accept = load("accept")
    accept.LOG.clear()
    assert accept.main(["--out", str(tmp_path), "--dry"]) in (0, 1)
    names = [
        item["name"] for item in json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    ]
    assert "ghidra-readonly-query" in names and (tmp_path / "results.md").exists()
    accept.DRY = False


@pytest.mark.skipif(os.name != "posix", reason="contract paths are posix")
def test_make_registry_matches_the_hooks_own_contract(tmp_path):
    script = tmp_path / "server.py"
    script.write_text("print(1)\n", encoding="utf-8")
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"cnt": {"command": sys.executable, "args": [str(script)]}}}),
        encoding="utf-8",
    )
    hook = ROOT / "src" / "mint_litellm" / "endpoint" / "hook.py"
    done = subprocess.run(
        [
            sys.executable,
            str(DEVICE / "make_registry.py"),
            "--hook",
            str(hook),
            "--mcp-config",
            str(config),
            "--name",
            "cnt",
            "--server-id",
            "srv-1",
            "--standin-url",
            "https://s.invalid/mcp",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert done.returncode == 0, done.stderr
    path = tmp_path / "registry.json"
    path.write_text(done.stdout, encoding="utf-8")
    entry = ContractRegistry.load(path).get("cnt")
    assert entry.contract.cwd is None and entry.transport == "http"


# ---- ep_client를 실제 서버에 대고(기기에서 처음 돌리기 전에 클라이언트 오류를 거른다) ----


@pytest.fixture
def live(tmp_path):
    h, rt = runtime(tmp_path)
    document = {
        "servers": [
            {
                "name": "cnt",
                "server_id": "srv-local",
                "contract": registry().get("cnt").contract.model_dump(mode="json") | {"cwd": None},
            }
        ]
    }
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    def user_api_key_auth(authorization: str | None = Header(default=None)):
        if authorization != "Bearer sk-user":
            raise HTTPException(status_code=401, detail="invalid key")
        return auth()

    app = FastAPI()
    install(
        app,
        make_router(
            auth_dependency=user_api_key_auth,
            runtime_provider=lambda: rt,
            registry=ContractRegistry.load(path),
            principal_factory=principal_of,
        ),
    )
    server = uvicorn.Server(uvicorn.Config(app, host="localhost", port=0, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        thread.join(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://localhost:{port}", path
    server.should_exit = True
    thread.join(5)


def test_ep_client_against_a_live_decision_path(live):
    base, registry_file = live
    client = load("ep_client")
    common = ["--base", base, "--key", "sk-user", "--registry", str(registry_file)]
    args = client.parser().parse_args(["decide", *common])
    assert client.cmd_decide(args)["verdict"] == "allow"
    bad = client.parser().parse_args(
        ["decide", "--base", base, "--key", "wrong", "--registry", str(registry_file)]
    )
    assert client.cmd_decide(bad)["verdict"] == "http-401"
    race = client.parser().parse_args(["race", *common, "--n", "4"])
    assert client.cmd_race(race)["n"] == 4
    lost = client.parser().parse_args(["lost-response", *common])
    assert client.cmd_lost_response(lost) == {"sent": True}
