# ruff: noqa: E501
"""장비에서 실행: LiteLLM 사용자·키·팀과 운영자 토큰을 만들어 ~/mint-s2/acc.env(0600)에만 쓴다.

마스터 키는 사용자·키를 만드는 데만 쓰고, 제어 평면 키는 proxy_admin 사용자 키에 allowed_routes를 제한해 발급한다.
사용: python bootstrap.py  (deploy/.env가 있는 장비 복제본에서)
"""
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[4]
STATE = Path(os.environ.get("ACC_HOME", Path.home() / "mint-s2"))
ENV = {}
for line in (REPO / "deploy" / ".env").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        ENV[k] = v
MASTER = ENV["LITELLM_MASTER_KEY"]
BASES = {"mint": "http://127.0.0.1:4300", "plain": "http://127.0.0.1:4310"}
ROUTES = ["/v1/mcp/server", "/key/info", "/team/info", "/user/info", "/key/list", "/team/list",
          "/guardrails/list", "/key/update", "/team/update",
          "/mcp-rest/test/connection", "/mcp-rest/test/tools/list"]


def lite(base, path, body):
    r = httpx.post(BASES[base] + path, headers={"Authorization": "Bearer " + MASTER}, json=body, timeout=60)
    if r.status_code >= 400 and "already exists" not in r.text and "Duplicate" not in r.text:
        sys.exit(f"{path} {r.status_code} {r.text[:300]}")
    return r


def user(user_id, role="internal_user"):
    lite("mint", "/user/new", {"user_id": user_id, "user_role": role, "auto_create_key": False})


def key(base, **body):
    return lite(base, "/key/generate", body).json()["key"]


def main():
    out = {}
    for u in ("acc-admin", "acc-approver", "acc-admin2", "acc-owner", "acc-caller", "acc-submitter", "acc-consent"):
        user(u)
    user("acc-control", "proxy_admin")
    out["ACC_CONTROL_KEY"] = key("mint", user_id="acc-control", key_alias="acc-control", allowed_routes=ROUTES)
    out["ACC_CALLER_KEY"] = "sk-acc-caller-" + secrets.token_urlsafe(24)
    # 호출 키는 사람(관리자)이 미리 서버 접근을 준 상태로 둔다. LiteLLM 접근 검사를 지나야 MINT 판정(미승인 차단)에 닿는다.
    key("mint", user_id="acc-caller", key_alias="acc-caller", key=out["ACC_CALLER_KEY"],
        object_permission={"mcp_servers": ["playwright", "context7", "grafana", "synthetic"]})
    # 대조(plain) 구성에도 같은 호출 키를 만든다(지연 RTT 비교용)
    lite("plain", "/user/new", {"user_id": "acc-caller", "user_role": "internal_user", "auto_create_key": False})
    key("plain", user_id="acc-caller", key_alias="acc-caller", key=out["ACC_CALLER_KEY"],
        object_permission={"mcp_servers": ["playwright", "context7", "grafana", "synthetic"]})
    team = lite("mint", "/team/new", {"team_alias": "acc-submit", "members_with_roles": [
        {"user_id": "acc-submitter", "role": "user"}]}).json()["team_id"]
    out["ACC_SUBMIT_KEY"] = key("mint", user_id="acc-submitter", team_id=team, key_alias="acc-submit")
    out["ACC_LITELLM_ADMIN_KEY"] = MASTER
    # .env에 제어 평면 키를 넣고 작업 실행기·콘솔·CLI가 쓰게 한다.
    text = (REPO / "deploy" / ".env").read_text().splitlines()
    text = [x for x in text if not x.startswith("MINT_LITELLM_KEY=")] + ["MINT_LITELLM_KEY=" + out["ACC_CONTROL_KEY"]]
    (REPO / "deploy" / ".env").write_text("\n".join(text) + "\n")
    os.chmod(REPO / "deploy" / ".env", 0o600)
    (STATE / "acc.json").write_text(json.dumps(out))
    os.chmod(STATE / "acc.json", 0o600)
    print("bootstrap-ok", sorted(out))


def operators():
    """운영자 토큰 발급(제어 평면 키가 .env에 들어간 뒤). admin 둘·approver 하나는 서로 다른 LiteLLM 사용자에 결속한다."""
    state = json.loads((STATE / "acc.json").read_text())

    def cli(*args):
        done = subprocess.run(["./mint.sh", "cli", *args, "--json"], cwd=REPO / "deploy",
                              capture_output=True, text=True, timeout=180)
        if done.returncode:
            sys.exit(f"{args[:2]} rc={done.returncode} {done.stderr[-300:]}")
        return json.loads(done.stdout)

    state["ACC_ADMIN_TOKEN"] = cli("operator", "bootstrap", "--name", "admin1", "--user-id", "acc-admin")["token"]
    env = {**os.environ, "MINT_OPERATOR_TOKEN": state["ACC_ADMIN_TOKEN"]}
    for key, name, role, uid in (("ACC_APPROVER_TOKEN", "approver1", "approver", "acc-approver"),
                                 ("ACC_ADMIN2_TOKEN", "admin2", "admin", "acc-admin2")):
        done = subprocess.run(["./mint.sh", "cli", "operator", "add", name, "--role", role, "--user-id", uid, "--json"],
                              cwd=REPO / "deploy", capture_output=True, text=True, timeout=180, env=env)
        if done.returncode:
            sys.exit(f"operator add {name} rc={done.returncode} {done.stderr[-300:]}")
        state[key] = json.loads(done.stdout)["token"]
    (STATE / "acc.json").write_text(json.dumps(state))
    print("operators-ok")


def servers():
    """공개 MCP 3종과 합성 서버를 LiteLLM 레지스트리(DB)에 서버 식별자를 이름으로 지정해 등록한다.
    pin·승인 경로는 DB에 있는 서버에만 동작한다. 호출 키에는 접근을 미리 준다(사람이 준 항목)."""
    names = ["playwright", "context7", "grafana", "synthetic"]
    state = json.loads((STATE / "acc.json").read_text())
    for base in ("mint", "plain"):
        for name in names:
            r = lite(base, "/v1/mcp/server", {
                "server_id": name, "alias": name, "server_name": name, "transport": "http",
                "url": f"https://cnt:8443/{name}/mcp", "auth_type": "none", "allow_all_keys": False,
                "description": "acceptance"})
            print(base, name, r.status_code)
        r = lite(base, "/key/update", {"key": state["ACC_CALLER_KEY"],
                                       "object_permission": {"mcp_servers": names}})
        print(base, "caller-access", r.status_code)


{"operators": operators, "servers": servers}.get(sys.argv[1] if len(sys.argv) > 1 else "", main)()
