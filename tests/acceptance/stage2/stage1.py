"""항목 12: 1단계 완료 SHA로 별도 프로젝트 스택을 만들고 1단계 데이터를 넣은 뒤 `mint.sh upgrade`로 올려 잰다.

스택 하나(`mints1`)가 같은 기기의 시험 스택(`mints2`)·수동 시험 스택과 이름·포트·볼륨을 나누어 쓴다.
1단계 SHA의 `deploy/`를 그대로 쓰며 시험이 바꾸는 것은 `.env`, 저장소 밖 비밀 파일, `deploy/config`뿐이다
(이 셋은 추적되지 않는 파일이라 `git checkout`으로 새 SHA로 옮겨도 남는다). 기기 주소·자격은 쓰지 않는다.
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

STAGE1_SHA = "6b4912c"
PROJECT = "mints1"
PORT = 4361
CONSOLE_PORT = 4362
SERVER = "legacy-server"
TABLES = ("orgs", "servers", "usage_relations", "approvals", "call_approvals")


class Stage1Failure(Exception):
    pass


def clean_env():
    """시험 스택(mints2)의 MINT_*·ACC_* 환경이 compose 보간을 덮어쓰지 않게 거른다."""
    return {k: v for k, v in os.environ.items()
            if not k.startswith(("MINT_", "ACC_", "COMPOSE_", "LITELLM_"))}


def sh(*argv, cwd=None, env=None, check=True, timeout=1500, stdin=None):
    done = subprocess.run(argv, cwd=cwd, env={**clean_env(), "COMPOSE_PROJECT_NAME": PROJECT,
                                              **(env or {})},
                          text=True, encoding="utf-8", capture_output=True, timeout=timeout,
                          input=stdin, check=False)
    if check and done.returncode:
        raise Stage1Failure(f"{' '.join(map(str, argv[:3]))} rc={done.returncode} "
                            f"{(done.stderr or done.stdout)[-400:]}")
    return done


def http(method, path, body=None, key=None, timeout=60):
    request = urllib.request.Request(
        f"http://127.0.0.1:{PORT}{path}", method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Bearer " + key} if key else {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except OSError as error:
        return 0, str(error)


class Stack:
    def __init__(self, root, repo, cert_dir, counter_url, main_project):
        self.root = Path(root)          # 이 스택의 작업 폴더(복제본·비밀 파일)
        self.repo = Path(repo)          # 새 SHA를 가진 저장소(시험 복제본)
        self.cert_dir = Path(cert_dir)
        self.counter_url = counter_url
        self.main_project = main_project
        self.clone = self.root / "repo"
        self.deploy = self.clone / "deploy"
        self.secrets_dir = self.root / "secrets"
        self.master = "sk-s1-" + secrets.token_urlsafe(24)
        self.token = None
        self.key = None

    # ---- 정리와 준비

    def cnt_container(self):
        done = sh("docker", "ps", "-q", "--filter",
                  f"label=com.docker.compose.project={self.main_project}", "--filter",
                  "label=com.docker.compose.service=cnt", check=False)
        return done.stdout.split()[0] if done.stdout.split() else None

    def teardown(self):
        """이 스택(프로젝트 mints1)의 컨테이너·볼륨·네트워크·작업 폴더만 지운다."""
        cnt = self.cnt_container()
        if cnt:
            sh("docker", "network", "disconnect", "-f", f"{PROJECT}_default", cnt, check=False)
        label = f"label=com.docker.compose.project={PROJECT}"
        ids = sh("docker", "ps", "-aq", "--filter", label, check=False).stdout.split()
        if ids:
            sh("docker", "rm", "-f", *ids, check=False)
        volumes = sh("docker", "volume", "ls", "-q", "--filter", label, check=False).stdout.split()
        if volumes:
            sh("docker", "volume", "rm", "-f", *volumes, check=False)
        sh("docker", "network", "rm", f"{PROJECT}_default", check=False)
        shutil.rmtree(self.root, ignore_errors=True)

    def prepare(self):
        self.teardown()
        self.root.mkdir(parents=True)
        sh("git", "clone", "-q", "--no-checkout", str(self.repo), str(self.clone), timeout=300)
        sh("git", "-C", str(self.clone), "checkout", "-q", STAGE1_SHA)
        env = {}
        for line in (self.deploy / ".env.example").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                name, value = line.split("=", 1)
                env[name] = value
        env.update(
            POSTGRES_PASSWORD=secrets.token_urlsafe(18), MINT_PLUGIN_DB_PASSWORD=secrets.token_urlsafe(18),
            MINT_CONTROL_DB_PASSWORD=secrets.token_urlsafe(18), LITELLM_MASTER_KEY=self.master,
            MINT_INSTANCE_ID="acceptance", MINT_LITELLM_PORT=str(PORT),
            MINT_LITELLM_KEY=self.master, MINT_SECRETS_DIR=str(self.secrets_dir),
            MINT_SELFCHECK_GRACE_SECONDS="30")
        env.setdefault("MINT_CONSOLE_PORT", str(CONSOLE_PORT))
        env["MINT_CONSOLE_PORT"] = str(CONSOLE_PORT)  # 이후 판본의 콘솔이 쓴다(1단계는 읽지 않는다)
        path = self.deploy / ".env"
        path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
        path.chmod(0o600)
        # 비밀 파일: 지문 키와, 시험 CA를 신뢰하게 하는 환경(설정 폴더는 litellm·control이 읽는다).
        self.secrets_dir.mkdir(mode=0o700)
        (self.secrets_dir / "secrets.env").write_text(
            f"MINT_FINGERPRINT_KEY={secrets.token_urlsafe(32)}\nMINT_FINGERPRINT_KEY_VERSION=1\n"
            "SSL_CERT_FILE=/app/config/ca.pem\n", encoding="utf-8")
        (self.secrets_dir / "secrets.env").chmod(0o600)
        (self.deploy / "config").mkdir()
        shutil.copy(self.cert_dir / "ca.pem", self.deploy / "config" / "ca.pem")

    def mint(self, *args, token=None, check=True, timeout=900):
        env = {"MINT_OPERATOR_TOKEN": token} if token else {}
        return sh("./mint.sh", *args, cwd=self.deploy, env=env, check=check, timeout=timeout)

    def cli(self, *args, token=None):
        done = self.mint("cli", *args, "--json", token=token or self.token)
        return json.loads(done.stdout)

    def wait_ready(self, seconds=450):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if http("GET", "/health/readiness", timeout=5)[0] == 200:
                return
            time.sleep(5)
        raise Stage1Failure("LiteLLM 준비 시간 초과")

    def psql(self, sql, check=True):
        done = sh("docker", "compose", "--env-file", ".env", "-f", "compose.yaml", "exec", "-T",
                  "postgres", "psql", "-U", "postgres", "-d", "mint", "-X", "-A", "-t",
                  "-v", "ON_ERROR_STOP=1", "-c", sql, cwd=self.deploy, check=check, timeout=120)
        return done

    def scalar(self, sql):
        return self.psql(sql).stdout.strip()

    def schema(self):
        has = self.scalar("SELECT count(*) FROM information_schema.columns WHERE "
                          "table_schema='mint' AND table_name='servers' "
                          "AND column_name='contract_status'")
        return "v002" if has != "0" else "v001"

    def rows(self):
        return sum(int(self.scalar(f"SELECT count(*) FROM mint.{t}")) for t in TABLES)

    def counter(self):
        with urllib.request.urlopen(self.counter_url, timeout=10) as response:
            return json.load(response)["tools/call"]

    # ---- 1단계 설치와 데이터

    def install_stage1(self):
        self.prepare()
        self.mint("up")
        cnt = self.cnt_container()
        if not cnt:
            raise Stage1Failure("계수 역프록시 컨테이너를 찾지 못함")
        sh("docker", "network", "connect", "--alias", "cnt", f"{PROJECT}_default", cnt)
        self.wait_ready()

    def seed_stage1(self):
        for user in ("legacy-admin", "legacy-req", "legacy-user"):
            status, text = http("POST", "/user/new", {"user_id": user, "user_role": "internal_user",
                                                      "auto_create_key": False}, self.master)
            if status >= 400:
                raise Stage1Failure(f"/user/new {user} {status} {text[:200]}")
        url = "https://cnt:8443/synthetic/mcp"
        status, text = http("POST", "/v1/mcp/server", {
            "server_id": SERVER, "alias": "legacy_server", "server_name": "legacy_server",
            "url": url, "transport": "http", "auth_type": "none", "allow_all_keys": False,
        }, self.master)
        if status >= 400:
            raise Stage1Failure(f"서버 등록 {status} {text[:200]}")
        status, text = http("POST", "/key/generate", {
            "user_id": "legacy-user", "object_permission": {"mcp_servers": [SERVER]},
        }, self.master)
        if status >= 400:
            raise Stage1Failure(f"키 발급 {status} {text[:200]}")
        self.key = json.loads(text)["key"]
        self.token = json.loads(self.mint(
            "cli", "operator", "bootstrap", "--name", "v1admin", "--user-id", "legacy-admin",
            "--json").stdout)["token"]
        self.cli("policy", "activate", "initial")
        self.cli("server", "register", SERVER, "--url", url)
        self.cli("org", "bind", "--org", "default", "--user", "legacy-user")
        relation = self.cli("relation", "add", "--org", "default", "--server", SERVER,
                            "--purpose", "legacy")["id"]
        valid_until = (datetime.now(UTC) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        self.cli("approve", "--relation", relation, "--scope", "key", "--scope-id",
                 hashlib.sha256(self.key.encode()).hexdigest(), "--tools", "stable,large",
                 "--valid-until", valid_until, "--basis", "legacy", "--requested-by", "legacy-req",
                 "--high-risk-tools", "large")
        request = self.cli("call-approval", "request", "--org", "default", "--principal-type",
                           "user", "--principal-id", "legacy-user", "--server", SERVER, "--tool",
                           "large", "--arguments", "{}", "--requested-by", "legacy-req")["id"]
        self.cli("call-approval", "approve", request)

    def call(self, tool):
        before = self.counter()
        status, text = http("POST", "/mcp-rest/tools/call", {
            "server_id": SERVER, "name": tool, "arguments": {}}, self.key)
        time.sleep(2)
        return status, self.counter() - before, text

    # ---- 올리기와 측정

    def upgrade(self, sha):
        sh("git", "-C", str(self.clone), "checkout", "-q", sha)
        self.mint("upgrade")
        self.wait_ready()

    def measure(self):
        started = time.monotonic()
        # 업그레이드 직후에는 부정 상태 파일이 아직 없어 집행 미확인으로 막힌다. 풀릴 때까지 센다.
        while True:
            status, upstream, text = self.call("stable")
            if status == 200:
                break
            if time.monotonic() - started > 420:
                raise Stage1Failure(f"올린 뒤 허용 호출이 성립하지 않음: {status} {text[:160]}")
            time.sleep(5)
        ready = time.monotonic() - started
        deny_status, deny_upstream, _ = self.call("mutable")
        again_status, again_upstream, _ = self.call("stable")
        large_status, large_upstream, large_text = self.call("large")
        intake = self.psql(
            "INSERT INTO mint.servers (id, instance_id, server_id, status, url_sha256, transport, "
            "auth_type, registered_by) VALUES (gen_random_uuid(), 'acceptance', 'intake-server', "
            f"'awaiting_approval', '{hashlib.sha256(b'https://intake.invalid').hexdigest()}', "
            "'http', 'none', 'acc');"
            "INSERT INTO mint.intakes (id, instance_id, org_id, server_id, source) VALUES "
            "(gen_random_uuid(), 'acceptance', 'default', 'intake-server', 'operator');")
        refused = self.psql(
            "UPDATE mint.servers SET status='approved' WHERE server_id='intake-server'",
            check=False)
        return {
            "legacy_allow_calls": upstream, "legacy_deny_calls": deny_upstream,
            "blanket_blocks": int(again_status != 200) + int(status != 200),
            "pending_intake_server_approve_exit": int(refused.returncode != 0),
            "stage1_call_approval_consumed": int(self.scalar(
                "SELECT count(*) FROM mint.call_approvals WHERE status='consumed'")),
            "confirmation_rows_seen": int(self.scalar(
                "SELECT count(*) FROM mint.self_confirmations")),
            "confirmation_rows_consumed": int(self.scalar(
                "SELECT count(*) FROM mint.self_confirmations WHERE status='consumed'")),
            "legacy_contract_status": self.scalar(
                f"SELECT string_agg(DISTINCT contract_status, ',') FROM mint.servers "
                f"WHERE server_id='{SERVER}'"),
            "statuses": {"allow": status, "deny": deny_status, "again": again_status,
                         "guarded": large_status},
            "guarded_upstream_calls": large_upstream, "again_upstream_calls": again_upstream,
            "ready_seconds_after_upgrade": round(ready, 1),
            "intake_insert_rc": intake.returncode,
        }

    def run(self, new_sha):
        """1단계 설치 → 데이터 → 올리기 → 측정. 측정값 한 묶음을 돌려준다."""
        self.install_stage1()
        before_schema = self.schema()
        self.seed_stage1()
        pre_status, pre_upstream, pre_text = self.call("stable")  # 1단계 판본에서의 호출
        rows_before = self.rows()
        self.upgrade(new_sha)
        after_schema = self.schema()
        rows_after = self.rows()
        measured = self.measure()
        return {"before_schema": before_schema, "after_schema": after_schema,
                "stage1_rows_before": rows_before, "stage1_rows_after": rows_after,
                "stage1_sha": STAGE1_SHA, "stage1_call_status": pre_status,
                "stage1_call_upstream": pre_upstream, **measured}
