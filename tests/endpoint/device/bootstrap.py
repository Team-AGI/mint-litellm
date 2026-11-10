# ruff: noqa: E501, UP017
"""기기에서 실행: 탐색 스택에 사용자·키·조직·운영자·자리 서버·승인을 만들고 ep.json(0600)에 쓴다.

표준 라이브러리만 쓴다. 사용: python3 bootstrap.py (deploy/.env가 있는 복제본에서, up.sh 뒤).
마스터 키는 사용자·키를 만드는 데만 쓴다. 값은 출력하지 않고 ep.json에만 둔다.
환경: EP_HOME(기본 ~/mint-ep), EP_PORT(기본 4500), EP_TOOLS(승인 도구, 기본 echo,slow), EP_HIGH_RISK(기본 slow).
"""

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
# mint.sh가 docker compose를 부르므로 프로젝트 이름을 이 스택으로 고정한다(기본값 mint는 다른 스택의 이름이다).
os.environ["COMPOSE_PROJECT_NAME"] = "mintep"
STATE = Path(os.environ.get("EP_HOME", Path.home() / "mint-ep"))
PORT = os.environ.get("EP_PORT", "4500")
BASE = f"http://localhost:{PORT}"
TOOLS = os.environ.get("EP_TOOLS", "echo,slow")
HIGH_RISK = os.environ.get("EP_HIGH_RISK", "slow")
ROUTES = [
    "/v1/mcp/server",
    "/key/info",
    "/team/info",
    "/user/info",
    "/key/list",
    "/team/list",
    "/guardrails/list",
    "/key/update",
    "/team/update",
]
ENV = {}
for line in (REPO / "deploy" / ".env").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        name, value = line.split("=", 1)
        ENV[name] = value
MASTER = ENV["LITELLM_MASTER_KEY"]


def lite(path, body):
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + MASTER, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as reply:
            return json.loads(reply.read() or b"{}")
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        if "already exists" in text or "Duplicate" in text:
            return {}
        sys.exit(f"{path} {exc.code} {text[:300]}")


def info(path, query):
    from urllib.parse import urlencode

    request = urllib.request.Request(
        BASE + path + "?" + urlencode(query), headers={"Authorization": "Bearer " + MASTER}
    )
    with urllib.request.urlopen(request, timeout=60) as reply:
        return json.loads(reply.read())


def user(user_id, role="internal_user"):
    lite("/user/new", {"user_id": user_id, "user_role": role, "auto_create_key": False})


def key(**body):
    body["key_alias"] = (
        f"{body['key_alias']}-{int(time.time())}"  # 다시 실행해도 별칭이 겹치지 않게
    )
    return lite("/key/generate", body)["key"]


def cli(*args, token=None):
    env = {**os.environ, **({"MINT_OPERATOR_TOKEN": token} if token else {})}
    done = subprocess.run(
        ["./mint.sh", "cli", *args, "--json"],
        cwd=REPO / "deploy",
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    if done.returncode:
        sys.exit(f"{args[:2]} rc={done.returncode} {done.stderr[-400:]}")
    return json.loads(done.stdout) if done.stdout.strip() else {}


def when(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    servers = json.loads((STATE / "endpoint" / "registry.json").read_text())["servers"]
    out = {"MASTER": MASTER, "BASE": BASE, "SERVER_ID": servers[0]["server_id"]}
    for name in ("ep-admin", "ep-approver", "ep-owner", "ep-user1", "ep-user2"):
        user(name)
    user("ep-control", "proxy_admin")
    ids = [item["server_id"] for item in servers]
    for item in servers:
        lite(
            "/v1/mcp/server",
            {
                "server_id": item["server_id"],
                "alias": item["server_id"],
                "server_name": item["server_id"],
                "transport": "http",
                "url": item["standin_url"],
                "auth_type": "none",
                "allow_all_keys": False,
                "description": "endpoint standin",
            },
        )
    access = {"mcp_servers": ids}
    out["CONTROL_KEY"] = key(user_id="ep-control", key_alias="ep-control", allowed_routes=ROUTES)
    out["USER1_KEY"] = key(
        user_id="ep-user1",
        key_alias="ep-user1",
        allowed_routes=["/mint/v1"],
        object_permission=access,
    )
    out["USER1_KEY_ID"] = hashlib.sha256(out["USER1_KEY"].encode()).hexdigest()  # LiteLLM이 인증 객체의 token으로 쓰는 값
    out["USER1_NOROUTE_KEY"] = key(
        user_id="ep-user1", key_alias="ep-user1-noroute", object_permission=access
    )
    out["USER2_KEY"] = key(
        user_id="ep-user2",
        key_alias="ep-user2",
        allowed_routes=["/mint/v1"],
        object_permission=access,
    )
    # 제어 평면 키는 .env에 넣고 CLI가 읽게 한다.
    lines = [
        x
        for x in (REPO / "deploy" / ".env").read_text().splitlines()
        if not x.startswith("MINT_LITELLM_KEY=")
    ]
    (REPO / "deploy" / ".env").write_text(
        chr(10).join([*lines, "MINT_LITELLM_KEY=" + out["CONTROL_KEY"]]) + chr(10)
    )
    os.chmod(REPO / "deploy" / ".env", 0o600)

    out["ADMIN_TOKEN"] = cli("operator", "bootstrap", "--name", "admin1", "--user-id", "ep-admin")[
        "token"
    ]
    out["APPROVER_TOKEN"] = cli(
        "operator",
        "add",
        "approver1",
        "--role",
        "approver",
        "--user-id",
        "ep-approver",
        token=out["ADMIN_TOKEN"],
    )["token"]
    admin = out["ADMIN_TOKEN"]
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "ep.json").write_text(json.dumps(out))  # 중간에 멈춰도 발급한 토큰은 남긴다.
    os.chmod(STATE / "ep.json", 0o600)
    cli("policy", "activate", "initial", token=admin)
    cli("settings", "control-key", token=admin)
    for org, name in (("org1", "조직 하나"), ("org2", "조직 둘")):
        cli("org", "add", org, "--name", name, token=admin)
    cli("org", "bind", "--org", "org1", "--user", "ep-user1", token=admin)
    cli("org", "bind", "--org", "org2", "--user", "ep-user2", token=admin)
    out["RELATIONS"], out["APPROVALS"] = {}, {}
    for item in servers:
        sid = item["server_id"]
        cli("server", "register", sid, "--url", item["standin_url"], token=admin)
        relation = cli(
            "relation", "add", "--org", "org1", "--server", sid, "--purpose", "support", token=admin
        )
        out["RELATIONS"][sid] = relation.get("id")
        args = [
            "approve",
            "--relation",
            out["RELATIONS"][sid],
            "--scope",
            "key",
            "--scope-id",
            out["USER1_KEY_ID"],
            "--tools",
            item.get("tools", TOOLS),
            "--valid-until",
            when(30),
            "--basis",
            "endpoint exploration",
            "--requested-by",
            "ep-owner",
        ]
        if item.get("high_risk", HIGH_RISK):
            args += ["--high-risk-tools", item.get("high_risk", HIGH_RISK)]
        out["APPROVALS"][sid] = cli(*args, token=out["APPROVER_TOKEN"]).get("id")
    out["RELATION"] = out["RELATIONS"][servers[0]["server_id"]]
    out["APPROVAL"] = out["APPROVALS"][servers[0]["server_id"]]
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "ep.json").write_text(json.dumps(out))
    os.chmod(STATE / "ep.json", 0o600)
    print("bootstrap-ok", sorted(out))


main()
