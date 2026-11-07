"""이행 시험의 호출 측정 도구(ACC_V001_PROBE). 장비에서 `v001_probe.py <사례 이름>`으로 실행해 측정 JSON 한 개를 낸다.

migration_v001 시나리오가 v001만 적용한 DB(mint_v001_*)에 1단계 데이터(서버 legacy-server·승인)를 넣고
v002까지 올린 뒤 부른다. 이 도구는 별도 compose 프로젝트 `mint-v001`(독립 네트워크·LiteLLM 한 개)에서
그 DB를 쓰는 LiteLLM을 띄우고 같은 승인으로 호출해 판정이 1단계 규칙대로인지 잰다.
"""
# ruff: noqa: E501
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

PROJECT = "mint-v001"
NET = "mints2_default"   # 정책 엔진·계수 프록시·DB에 닿기 위해 시험 스택의 네트워크에 붙는다
IMAGE = "mint-litellm:local"
STATE = Path(os.environ["ACC_STATE_DIR"])
ENV = {}
for line in (Path(__file__).resolve().parents[4] / "deploy" / ".env").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        ENV[k] = v
MASTER = ENV["LITELLM_MASTER_KEY"]
PORT = 4361


def sh(*argv, check=True, stdin=None):
    done = subprocess.run(argv, capture_output=True, text=True, input=stdin)
    if check and done.returncode:
        sys.exit(f"{argv[:3]} rc={done.returncode} {done.stderr[-300:]}")
    return done.stdout.strip()


def psql(db, sql):
    return sh("docker", "exec", "mints2-postgres-1", "psql", "-U", "postgres", "-d", db, "-At", "-c", sql)


def http(method, path, body=None, key=MASTER):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method, headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json"},
        data=None if body is None else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def counter():
    with urllib.request.urlopen("http://127.0.0.1:4350/synthetic", timeout=10) as r:
        return json.load(r)["tools/call"]


def call(key, tool):
    before = counter()
    status, text = http("POST", "/mcp-rest/tools/call", {"server_id": "legacy-server", "name": tool, "arguments": {}}, key)
    time.sleep(2)
    return status, counter() - before, text


def start(database):
    sh("docker", "rm", "-f", PROJECT + "-litellm", check=False)
    psql("postgres", "SELECT 1")
    if not psql("postgres", "SELECT 1 FROM pg_database WHERE datname='litellm_v001'"):
        psql("postgres", "CREATE DATABASE litellm_v001")
    cfg = STATE / "v001.config.yaml"
    cfg.write_text(Path(__file__).with_name("litellm.config.yaml").read_text())
    pw = ENV["POSTGRES_PASSWORD"]
    sh("docker", "run", "-d", "--name", PROJECT + "-litellm", "--network", NET, "-p", f"127.0.0.1:{PORT}:4000",
       "-e", f"DATABASE_URL=postgresql://postgres:{pw}@postgres:5432/litellm_v001", "-e", f"LITELLM_MASTER_KEY={MASTER}",
       "-e", "STORE_MODEL_IN_DB=True", "-e", f"MINT_DATABASE_URL=postgresql://mint_plugin_app:{ENV['MINT_PLUGIN_DB_PASSWORD']}@postgres:5432/{database}",
       "-e", "MINT_OPA_URL=http://opa:8181", "-e", "MINT_INSTANCE_ID=acceptance", "-e", "MINT_MODE=enforce",
       "-e", "MINT_BUFFER_DIR=/tmp/buf", "-e", "MINT_READINESS_URL=http://localhost:4000/health/readiness",
       "-e", "MINT_SELFCHECK_GRACE_SECONDS=30", "-e", "MINT_EXPORT_DIR=/var/lib/mint/export", "-e", f"MINT_EXPORT_HMAC_KEY={ENV['MINT_EXPORT_HMAC_KEY']}",
       "-e", "SSL_CERT_FILE=/certs/ca.pem", "-v", f"{cfg}:/app/config/litellm.config.yaml:ro",
       "-v", f"{os.environ['ACC_CERT_DIR']}:/certs:ro", IMAGE, "--config", "/app/config/litellm.config.yaml", "--port", "4000")
    for _ in range(90):
        try:
            if http("GET", "/health/readiness")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(5)
    sys.exit("v001 LiteLLM 준비 안 됨")


def main():
    name = sys.argv[1]
    database = (STATE / "migration-db").read_text().strip()
    start(database)
    # 레지스트리에 legacy-server를 합성 서버로 두고, 승인 주체 legacy-user의 키를 만든다.
    reg = http("POST", "/v1/mcp/server", {"server_id": "legacy-server", "alias": "legacy_server", "server_name": "legacy_server",
                                    "url": "https://cnt:8443/synthetic/mcp", "transport": "http", "auth_type": "none", "allow_all_keys": False})
    http("POST", "/user/new", {"user_id": "legacy-user", "user_role": "internal_user", "auto_create_key": False})
    key = json.loads(http("POST", "/key/generate", {"user_id": "legacy-user", "object_permission": {"mcp_servers": ["legacy-server"]}})[1])["key"]
    time.sleep(15)
    allow_status, allow_up, allow_text = call(key, "stable")      # 1단계 승인이 허용하는 도구
    deny_status, deny_up, _ = call(key, "mutable")       # 승인에 없는 도구
    again_status, _, _ = call(key, "stable")[0], 0, 0     # 전면 차단 여부: 같은 허용 도구를 한 번 더
    seen = psql(database, "SELECT count(*) FROM mint.self_confirmations")
    consumed = psql(database, "SELECT count(*) FROM mint.self_confirmations WHERE status='consumed'")
    ca = psql(database, "SELECT count(*) FROM mint.call_approvals WHERE status='consumed'")
    sh("docker", "rm", "-f", PROJECT + "-litellm", check=False)
    out = {
        "migration_v001": {"legacy_allow_calls": allow_up, "legacy_deny_calls": deny_up,
                           "blanket_blocks": int(again_status != 200) + int(allow_status != 200)},
        "confirmation_v001_isolation": {"confirmation_rows_seen": int(seen), "confirmation_rows_consumed": int(consumed),
                                        "stage1_call_approval_consumed": int(ca)},
    }[name]
    out["probe_statuses"] = {"allow": allow_status, "deny": deny_status, "register": reg[0], "detail": (reg[1] if reg[0] >= 400 else allow_text)[:200]}
    print(json.dumps(out))


main()
