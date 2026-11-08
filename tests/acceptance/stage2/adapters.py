"""장비 장애 주입 어댑터. 이름 있는 함수 하나가 사례 하나이며 argv로만 호출된다.

    python -m tests.acceptance.stage2.adapters <이름> apply|undo [--observation 경로] [--run-id ID]
    python -m tests.acceptance.stage2.adapters case_setup <사례>
    python -m tests.acceptance.stage2.adapters snapshot | list | emit-site [--ssh 별칭 --repo 경로]

종료 코드: 0 성공, 70 어댑터 본문 미작성(실패로 센다),
78 「미구현으로 건너뜀」(제품 명령·처리기 부재).
비밀은 환경변수에서만 읽는다. 기기 주소·계정은 이 파일과 저장소에 없다.
"""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml

from . import scenarios

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STATE = Path(os.environ.get("ACC_STATE_DIR", HERE / ".runtime" / "state"))
SKIPPED, UNWRITTEN = 78, 70
SWAPS = {"playwright": ("0.0.84", "0.0.83"), "context7": ("2.2.2", "2.2.1"),
         "grafana": ("1.4.1", "1.4.0")}
# 사례 이름 머리말 → 그 사례를 돌리는 시험 파일(명령·처리기는 expected_events.yaml에서 읽는다)
GATE_FILE = {"sync_": "test_04_sync.py", "restore_": "test_06_restore.py",
             "intake_": "test_07_intake_negative.py", "confirmation_": "test_08_confirmation.py",
             "auth_": "test_09_auth_ui.py", "migration_": "test_12_migration.py",
             "contract_": "test_02_contracts.py"}


class Skip(Exception):
    """제품 쪽 명령·처리기가 아직 없다."""


class Unwritten(Exception):
    """제품 기능은 있지만 어댑터 본문은 아직 없다."""


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        raise SystemExit(f"환경변수 {name} 없음")
    return value


def run(argv, *, check=True, timeout=120, stdin=None):
    done = subprocess.run(argv, cwd=ROOT, text=True, encoding="utf-8", capture_output=True,
                          timeout=timeout, input=stdin, check=False)
    if check and done.returncode:
        raise SystemExit(f"명령 실패({done.returncode}): "
                         + " ".join(argv[:2]) + " " + done.stderr[-400:])
    return done


def compose(*args, **kw):
    base = shlex.split(os.environ.get("ACC_COMPOSE") or
                       f"docker compose -p {env('COMPOSE_PROJECT_NAME', 'mint-acc')} "
                       "-f deploy/compose.yaml")
    return run([*base, *args], **kw)


def psql(sql, database, *, json_out=False):
    """postgres 컨테이너 안의 슈퍼유저로 한 문장을 실행한다."""
    service = env("ACC_PG_SERVICE", "postgres")
    done = compose("exec", "-T", service, "psql", "-U", env("ACC_PG_SUPERUSER", "postgres"),
                   "-d", database, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql)
    return json.loads(done.stdout) if json_out else done.stdout.strip()


def http(method, url, body=None, key=None):
    request = urllib.request.Request(
        url, method=method, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {key}"} if key else {})})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    return json.loads(raw) if raw else {}


def litellm(method, path, body=None):
    return http(method, env("ACC_LITELLM_ADMIN_URL").rstrip("/") + path, body,
                env("MINT_LITELLM_KEY"))


def instance():
    return env("MINT_INSTANCE_ID", "acceptance")


def export_dir():
    return Path(env("ACC_EXPORT_HOST_DIR")) / instance()


def state_file(name):
    STATE.mkdir(parents=True, exist_ok=True)
    return STATE / name


def gate(name):
    """아직 main에 없는 명령·처리기를 쓰는 사례는 건너뜀으로 끝낸다(rig.require와 같은 기준)."""
    from mint_litellm.cli import build_parser
    from mint_litellm.control import jobs

    for prefix, filename in GATE_FILE.items():
        if not name.startswith(prefix):
            continue
        wanted = yaml.safe_load((HERE / "expected_events.yaml").read_text(
            encoding="utf-8"))["capabilities"].get(filename, {})
        parser = build_parser()
        for command in wanted.get("commands", []):
            try:
                parser.parse_args([*command.split(), "--help"])
            except SystemExit as error:
                if error.code == 2:
                    raise Skip(f"명령 {command}") from None
        missing = sorted(set(wanted.get("handlers", [])) - jobs.HANDLERS.keys())
        if missing:
            raise Skip("작업 처리기 " + ", ".join(missing))


ADAPTERS = {}


def adapter(name=None, *, undo=None):
    def register(fn):
        ADAPTERS[name or fn.__name__] = (fn, undo)
        return fn
    return register


def write_observation(ctx, events=None, **fields):
    """실측 JSON. 기대값 복사본이 아니라 이 함수의 호출자가 측정한 값만 받는다."""
    path = Path(ctx.observation)
    path.parent.mkdir(parents=True, exist_ok=True)
    sha = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    body = {"run_id": ctx.run_id, "sha": sha, "events": events or {}, **fields}
    raw = json.dumps(body, ensure_ascii=False, indent=2) + "\n"
    path.write_text(raw, encoding="utf-8", newline="\n")
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------- 인프라 기본 동작

@adapter("db_backup")
def db_backup(ctx):
    """mint·litellm 두 DB를 postgres 컨테이너 안의 덤프로 보관한다(시험 스택 한정)."""
    service = env("ACC_PG_SERVICE", "postgres")
    for database in ("mint", "litellm"):
        compose("exec", "-T", service, "pg_dump", "-U", env("ACC_PG_SUPERUSER", "postgres"),
                "-Fc", "-f", f"/tmp/{ctx.run_id}-{database}.dump", database)
    state_file("last-backup").write_text(ctx.run_id, encoding="utf-8")


@adapter("db_restore")
def db_restore(ctx, restart=True):
    """직전 db_backup(없으면 snapshot)으로 되돌린다. 복제본·작업 실행기는 멈춘 상태에서 복원한다."""
    marker = state_file("last-backup")
    source = marker.read_text(encoding="utf-8") if marker.exists() else "baseline"
    pg = env("ACC_PG_SERVICE", "postgres")
    user = env("ACC_PG_SUPERUSER", "postgres")
    # 덤프가 없으면 아무것도 멈추거나 지우기 전에 중단한다(지운 뒤 복원이 실패하면 빈 DB가 남는다).
    for database in ("mint", "litellm"):
        compose("exec", "-T", pg, "test", "-s", f"/tmp/{source}-{database}.dump")
    services = [s for s in restore_services() if running(s)]
    if services:
        compose("stop", *services)
    try:
        for database in ("mint", "litellm"):
            # 새로 만든 표까지 지우려고 DB째 다시 만든다(역할은 클러스터 전역이라 남는다).
            for statement in (f"DROP DATABASE IF EXISTS {database} WITH (FORCE)",
                              f"CREATE DATABASE {database}"):
                compose("exec", "-T", pg, "psql", "-U", user, "-d", "postgres", "-X", "-q",
                        "-v", "ON_ERROR_STOP=1", "-c", statement)
            compose("exec", "-T", pg, "pg_restore", "-U", user, "--single-transaction",
                    "--exit-on-error", "-d", database, f"/tmp/{source}-{database}.dump")
    finally:
        if services and restart:
            compose("start", *services)
            wait_ready()
    return services


@adapter("snapshot")
def snapshot(ctx):
    """DB 덤프와 내보내기 파일을 한 쌍으로 보관한다.

    DB만 되돌리면 파일 세대와 어긋나 되돌림 차단이 걸린다.
    """
    ctx.run_id = "baseline"
    host = os.environ.get("ACC_EXPORT_HOST_DIR")
    if host:
        deadline = time.monotonic() + 180
        while not (export_dir() / "latest.json").is_file():
            if time.monotonic() > deadline:
                raise SystemExit("기준 내보내기 체크포인트(latest.json)가 없습니다")
            time.sleep(2)
    db_backup(ctx)
    if host:
        saved = state_file("baseline-export")
        shutil.rmtree(saved, ignore_errors=True)
        shutil.copytree(export_dir(), saved)
    state_file("last-backup").unlink(missing_ok=True)


def restore_services():
    """DB를 쓰는 프로세스. 복제본이 둘이면 둘 다 멈춰야 한다(ACC_RESTORE_SERVICES로 바꾼다)."""
    return (os.environ.get("ACC_RESTORE_SERVICES") or "litellm litellm2 worker console").split()


def export_root(script, *mounts):
    """내보내기 볼륨은 비루트(65532) 소유라 호스트 사용자는 쓸 수 없다. 루트 컨테이너로 처리한다."""
    vol = env("COMPOSE_PROJECT_NAME", "mints2") + "_export"
    args = [a for m in mounts for a in ("-v", m)]
    run(["docker", "run", "--rm", "--user", "0", "-v", f"{vol}:/x", *args,
         "--entrypoint", "sh", "mint-litellm:local", "-c", script])


def export_unlink(path):
    """내보내기 안의 파일 하나를 지운다(호스트 권한이 모자라면 루트 컨테이너로)."""
    try:
        Path(path).unlink()
    except PermissionError:
        rel = Path(path).relative_to(export_dir().parent)
        export_root(f"rm -f /x/{rel.as_posix()}")


def wait_ready(seconds=300):
    """복제본이 요청을 받을 때까지 기다린다. 주소는 ACC_READY_URLS(쉼표), 없으면 관리 주소."""
    raw = os.environ.get("ACC_READY_URLS") or env("ACC_LITELLM_ADMIN_URL", "")
    urls = [u for u in raw.split(",") if u]
    deadline = time.monotonic() + seconds
    for url in urls:
        while True:
            try:
                with urllib.request.urlopen(url.rstrip("/") + "/health/readiness", timeout=5):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise SystemExit(f"준비 시간 초과: {url}") from None
                time.sleep(3)


def running(service):
    done = compose("ps", "--status", "running", "--services", check=False)
    return service in done.stdout.split()


def stop_start(service):
    def apply(ctx):
        was = running(service)
        state_file(f"{service}-was-running").write_text("1" if was else "0")
        if was:
            compose("stop", service)

    def undo(ctx):
        if state_file(f"{service}-was-running").read_text() == "1":
            compose("start", service)
    return apply, undo


for _service, _name in (("worker", "worker_stop"), ("console", "console_stop")):
    ADAPTERS[_name] = stop_start(_service)


def pick_server(ctx=None):
    return os.environ.get("ACC_SERVER_ID") or psql(
        "SELECT server_id FROM mint.litellm_grants WHERE item='mcp_server' AND NOT preexisting "
        "ORDER BY last_applied_at DESC NULLS LAST LIMIT 1", "mint")


def grant_row(server):
    return json.loads(psql(
        "SELECT row_to_json(g) FROM (SELECT target_type, target_id FROM mint.litellm_grants "
        f"WHERE item='mcp_server' AND NOT preexisting AND server_id='{server}' "
        "ORDER BY last_applied_at DESC NULLS LAST LIMIT 1) g", "mint"))


def _permission(grant):
    if grant["target_type"] == "key":
        info = litellm("GET", "/key/info?key=" + grant["target_id"])["info"]
        return "/key/update", {"key": grant["target_id"]}, info.get("object_permission") or {}
    info = litellm("GET", "/team/info?team_id=" + grant["target_id"])["team_info"]
    return "/team/update", {"team_id": grant["target_id"]}, info.get("object_permission") or {}


@adapter("delete_owned_grant")
def delete_owned_grant(ctx):
    """MINT이 소유한 MCP 서버 권한 하나를 LiteLLM에서 직접 지운다(MINT을 거치지 않는 외부 삭제)."""
    server = pick_server()
    grant = grant_row(server)
    path, who, permission = _permission(grant)
    servers = [s for s in permission.get("mcp_servers") or [] if s != server]
    litellm("POST", path, {**who, "object_permission": {**permission, "mcp_servers": servers}})
    state_file("deleted-grant.json").write_text(json.dumps(
        {"server": server, **grant}), encoding="utf-8")


def delete_owned_grant_undo(ctx):
    saved = json.loads(state_file("deleted-grant.json").read_text(encoding="utf-8"))
    path, who, permission = _permission(saved)
    servers = sorted({*(permission.get("mcp_servers") or []), saved["server"]})
    litellm("POST", path, {**who, "object_permission": {**permission, "mcp_servers": servers}})


ADAPTERS["delete_owned_grant"] = (delete_owned_grant, delete_owned_grant_undo)


@adapter("export_unwritable")
def export_unwritable(ctx):
    """작업 실행기가 쓰는 내보내기 디렉터리를 읽기 전용으로 만든다(작업 실행기는 비루트)."""
    inside = env("ACC_EXPORT_CONTAINER_DIR", "/var/lib/mint/export") + "/" + instance()
    compose("exec", "-T", "-u", "root", "worker", "chmod", "-R", "a-w", inside)


def export_unwritable_undo(ctx):
    inside = env("ACC_EXPORT_CONTAINER_DIR", "/var/lib/mint/export") + "/" + instance()
    compose("exec", "-T", "-u", "root", "worker", "chmod", "-R", "u+w", inside)


ADAPTERS["export_unwritable"] = (export_unwritable, export_unwritable_undo)


@adapter("trigger_negative_state")
def trigger_negative_state(ctx):
    """활성 승인 하나를 철회해 부정 상태 세대를 올린다. 되돌리지 않는다(case_setup이 복구)."""
    token = {**os.environ, "MINT_OPERATOR_TOKEN": env("ACC_ADMIN_TOKEN")}
    approval = psql("SELECT id FROM mint.approvals WHERE status='active' ORDER BY id "
                    "DESC LIMIT 1", "mint")
    if not approval:
        raise SystemExit("철회할 활성 승인이 없음")
    cli = shlex.split(os.environ.get("ACC_CLI", f"{sys.executable} -m mint_litellm.cli"))
    done = subprocess.run(cli + ["revoke", approval, "--reason", "acceptance"],
                          cwd=ROOT, env=token, text=True, capture_output=True, timeout=60)
    if done.returncode:
        raise SystemExit(done.stderr[-400:])


@adapter("seal_tamper")
def seal_tamper(ctx):
    """봉인 묶음 하나의 꼬리 해시를 바꾼다. 원래 값은 보관하고 undo가 되돌린다."""
    row = json.loads(psql(
        "SELECT row_to_json(b) FROM (SELECT to_seal_seq, encode(tail_hash,'hex') AS h "
        f"FROM mint.seal_batches WHERE instance_id='{instance()}' ORDER BY to_seal_seq DESC "
        "LIMIT 1) b", "mint"))
    state_file("seal-tamper.json").write_text(json.dumps(row), encoding="utf-8")
    # 추가 전용 트리거는 슈퍼유저 세션의 복제 역할로만 우회한다(시험 스택 한정).
    psql(f"SET session_replication_role=replica; "
         f"UPDATE mint.seal_batches SET tail_hash=decode(repeat('00',32),'hex') "
         f"WHERE instance_id='{instance()}' AND to_seal_seq={row['to_seal_seq']}", "mint")


def seal_tamper_undo(ctx):
    row = json.loads(state_file("seal-tamper.json").read_text(encoding="utf-8"))
    psql(f"SET session_replication_role=replica; "
         f"UPDATE mint.seal_batches SET tail_hash=decode('{row['h']}','hex') "
         f"WHERE instance_id='{instance()}' AND to_seal_seq={row['to_seal_seq']}", "mint")


ADAPTERS["seal_tamper"] = (seal_tamper, seal_tamper_undo)


def fixture_mode(mode, back="base"):
    def apply(ctx):
        http("POST", env("ACC_FIXTURE_URL").rstrip("/") + "/control", {"mode": mode})

    def undo(ctx):
        http("POST", env("ACC_FIXTURE_URL").rstrip("/") + "/control", {"mode": back})
    return apply, undo


for _mutation in ("description", "added", "removed"):
    ADAPTERS["contract_" + _mutation] = fixture_mode(_mutation)


def contract_deployment(ctx):
    """합성 서버의 LiteLLM 등록 allowed_tools만 바꿔 배포 계약만 어긋나게 한다."""
    server = env("ACC_SERVER_ID")
    original = litellm("GET", f"/v1/mcp/server/{server}").get("allowed_tools")
    state_file("deployment.json").write_text(json.dumps(original), encoding="utf-8")
    litellm("PUT", "/v1/mcp/server", {"server_id": server, "allowed_tools": ["stable"]})


def contract_deployment_undo(ctx):
    original = json.loads(state_file("deployment.json").read_text(encoding="utf-8"))
    litellm("PUT", "/v1/mcp/server", {"server_id": env("ACC_SERVER_ID"), "allowed_tools": original})


ADAPTERS["contract_deployment"] = (contract_deployment, contract_deployment_undo)


def swap(server, new, old):
    def run_swap(version):
        run(["bash", "tests/oss/stack.sh", "swap", server, version], timeout=600)

    def apply(ctx):
        run_swap(new)
        state_file(server + "-swapped").write_text(old)

    def undo(ctx):
        run_swap(old)
        state_file(server + "-swapped").unlink(missing_ok=True)
    return apply, undo


for _server, (_new, _old) in SWAPS.items():
    ADAPTERS[_server + "_upgrade"] = swap(_server, _new, _old)


# ---------------------------------------------------------------- 역할 경계(DB만 필요)

def as_role(env_name, sql):
    import psycopg

    try:
        with psycopg.connect(env(env_name), autocommit=True) as conn:
            conn.execute("SET statement_timeout = '10s'")
            return conn.execute(sql).rowcount, None
    except psycopg.Error as error:
        return 0, error.sqlstate


def count(sql):
    return int(psql(sql, "mint") or 0)


@adapter("confirmation_plugin_insert")
def confirmation_plugin_insert(ctx):
    """플러그인 역할은 대기 행만 추가한다. 확인자 열을 채우면 열 권한 부족이어야 한다."""
    gate("confirmation_plugin_insert")
    where = "SELECT count(*) FROM mint.self_confirmations WHERE confirmed_by_user_id IS NOT NULL"
    before = count(where)
    _, sqlstate = as_role("ACC_PLUGIN_DATABASE_URL",
                          "INSERT INTO mint.self_confirmations (id, confirmed_by_user_id) "
                          "VALUES (gen_random_uuid(), 'acceptance')")
    write_observation(ctx, sqlstate=sqlstate, inserted=count(where) - before)


@adapter("confirmation_plugin_confirm")
def confirmation_plugin_confirm(ctx):
    """플러그인 로그인 역할은 확인자 열을 바꿀 수 없다(열 권한)."""
    gate("confirmation_plugin_confirm")
    where = "SELECT count(*) FROM mint.self_confirmations WHERE confirmed_by_user_id IS NOT NULL"
    before = count(where)
    _, sqlstate = as_role("ACC_PLUGIN_DATABASE_URL",
                          "UPDATE mint.self_confirmations SET confirmed_by_user_id = 'acceptance', "
                          "confirmed_by_key_token = 'acceptance', confirmed_at = now() "
                          "WHERE false")
    write_observation(ctx, sqlstate=sqlstate, confirmed=count(where) - before)


@adapter("auth_plugin_control_event")
def auth_plugin_control_event(ctx):
    """플러그인 역할로 제어 평면 사건의 삽입을 시도하고 실제 삽입 여부를 조회한다."""
    import psycopg

    from mint_litellm.types.ids import new_uuid7

    event_id = new_uuid7()
    source = f"approval:{event_id}:1:approval_granted"
    try:
        with psycopg.connect(env("ACC_PLUGIN_DATABASE_URL"), autocommit=True) as conn:
            conn.execute(
                "INSERT INTO mint.events (event_id, instance_id, kind, source_key, payload) "
                "VALUES (%s, %s, 'approval_granted', %s, '{}'::jsonb)",
                (event_id, instance(), source),
            )
        sqlstate = None
    except psycopg.Error as error:
        sqlstate = error.sqlstate
    inserted = count(f"SELECT count(*) FROM mint.events WHERE event_id='{event_id}'")
    write_observation(ctx, sqlstate=sqlstate, inserted=inserted)


# ---------------------------------------------------------------- 시나리오 어댑터

SCENARIOS = sorted(
    name for name in yaml.safe_load((HERE / "expected_events.yaml").read_text(
        encoding="utf-8"))["observations"] if name != "client_flow"
)


def pending(name):
    """본문이 없는 시나리오의 자리표시. `scenarios.py`에 본문이 생기면 쓰이지 않는다."""
    def apply(ctx):
        gate(name)
        raise Unwritten(f"어댑터 본문 미작성: {name}")
    apply.pending = True
    return apply


scenarios.bind(sys.modules[__name__])
ADAPTERS.update(scenarios.BODIES)
for _name in SCENARIOS:
    ADAPTERS.setdefault(_name, (pending(_name), None))


# ---------------------------------------------------------------- 진입점

def case_setup(case):
    """시험 사례 직전의 깨끗한 상태: 기준 스냅숏 복원, 내보내기 비움, 합성 서버·공개 판본 원복.

    프로세스는 멈춘 채로 복원하고 내보내기를 되돌린 뒤 한꺼번에 올린다
    (작업 실행기가 살아 있을 때 파일을 지우면 `export_missing` 차단이 걸린다).
    """
    class Ctx:
        run_id = "baseline"
    state_file("last-backup").unlink(missing_ok=True)
    present = set(compose("ps", "-a", "--services", check=False).stdout.split())
    db_restore(Ctx, restart=False)
    fixture = os.environ.get("ACC_FIXTURE_URL")
    if fixture:
        http("POST", fixture.rstrip("/") + "/control", {"mode": "base"})
    if os.environ.get("ACC_EXPORT_HOST_DIR"):
        saved = state_file("baseline-export")
        # 기준 DB와 같은 세대의 파일로 되돌린다(비우고 기준 사본을 덮고 소유자를 65532로)
        script = "find /x -mindepth 1 -delete; cp -a /b/. /x/ 2>/dev/null; chown -R 65532:65532 /x"
        export_root(script, f"{saved}:/b:ro" if saved.is_dir() else "/tmp:/b:ro")
    for server, (new, old) in SWAPS.items():
        if state_file(server + "-swapped").exists():
            swap(server, new, old)[1](None)
    # 키 교체 시험(hmac_changed 등)이 남긴 환경이 기준과 다를 수 있으므로 기준 환경으로 다시 만든다.
    compose("up", "-d", "--no-deps", "--force-recreate",
            *[s for s in restore_services() if s in present])
    wait_ready()
    if os.environ.get("ACC_EXPORT_HOST_DIR"):  # 작업 실행기의 첫 체크포인트까지
        deadline = time.monotonic() + 120
        while not (export_dir() / "latest.json").is_file():
            if time.monotonic() > deadline:
                raise SystemExit("작업 실행기가 첫 체크포인트를 쓰지 않았습니다")
            time.sleep(2)


def emit_site(ssh=None, repo="."):
    """site.json의 faults·case_setup 조각. 각 항목은 argv 배열이며 ssh를 주면 한 인자로 감싼다."""
    def wrap(*words):
        line = f"cd {shlex.quote(repo)} && .venv/bin/python -m tests.acceptance.stage2.adapters "
        line += " ".join(w if w in {"{observation}", "{run_id}", "{case}"}
                         else shlex.quote(w) for w in words)
        if ssh:
            return ["ssh", ssh, line]
        return ["bash", "-c", line]

    faults = {}
    for name in sorted(ADAPTERS):
        if name in ("db_backup", "db_restore", "snapshot"):
            continue
        faults[name] = {
            "apply": wrap(name, "apply", "--observation", "{observation}", "--run-id", "{run_id}"),
            "undo": wrap(name, "undo"), "timeout": scenarios.TIMEOUTS.get(name, 600)}
    return {"faults": faults, "case_setup": wrap("case_setup", "{case}")}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    parser.add_argument("action", nargs="?", default="apply")
    parser.add_argument("--observation", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--ssh")
    parser.add_argument("--repo", default=".")
    args = parser.parse_args(argv)
    if args.name == "list":
        print("\n".join(sorted(ADAPTERS)))
        return 0
    if args.name == "emit-site":
        print(json.dumps(emit_site(args.ssh, args.repo), ensure_ascii=False, indent=2))
        return 0
    if args.name == "case_setup":
        case_setup(args.action)
        return 0
    entry = ADAPTERS.get(args.name)
    if entry is None:
        print("알 수 없는 어댑터: " + args.name, file=sys.stderr)
        return 2
    fn = entry[0] if args.action == "apply" else entry[1]
    ctx = argparse.Namespace(observation=args.observation,
                             run_id=args.run_id or str(time.time_ns()))
    try:
        if fn is not None:
            fn(ctx)
    except Skip as skip:
        print("미구현으로 건너뜀: " + str(skip))
        return SKIPPED
    except Unwritten as error:
        print(str(error), file=sys.stderr)
        return UNWRITTEN
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
