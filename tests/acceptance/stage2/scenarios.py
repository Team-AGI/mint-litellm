"""시나리오 어댑터 본문 46종. `adapters.py`가 `bind()`로 자기 도구(psql·compose·http 등)를 넘긴다.

각 함수는 실제 CLI·LiteLLM 관리 API·DB 질의로 준비 → 행동 → 실측을 하고 `write_observation`으로
측정값만 남긴다. 기대값은 `expected_events.yaml`이 정본이며 여기서 복사하지 않는다.
설정은 `site.json`(환경변수 ACC_SITE 또는 MINT_ACC_SITE, 없으면 `.runtime/site.json`)과
환경변수에서 읽는다.
기기 주소·계정·비밀은 이 파일에 없다.
"""

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

A = None  # adapters 모듈(순환 import를 피하려고 bind로 받는다)
BODIES = {}
TIMEOUTS = {"restore_steady_24h": 86460, "confirmation_expiry_10m": 1500, "sync_race_30": 1200,
            "auth_blocked_key": 900, "auth_deleted_key": 900, "restore_backup_before_revoke": 900,
            "restore_epoch_caught_up": 900, "restore_consent": 900, "sync_revoke_race": 900,
            "intake_private_literal": 1500, "intake_definitions_limit": 1500}
ROLE_ENV = {"admin": "ACC_ADMIN_TOKEN", "approver": "ACC_APPROVER_TOKEN",
            "admin2": "ACC_ADMIN2_TOKEN"}
CAUSES = ("restore_pending", "export_missing", "export_unverified")


def bind(module):
    global A
    A = module


def scenario(name, undo=None):
    def register(fn):
        def body(ctx):
            A.gate(name)
            fn(ctx)
        BODIES[name] = (body, undo)
        return fn
    return register


# ---------------------------------------------------------------- 공통 도구

def site():
    path = Path(os.environ.get("ACC_SITE") or os.environ.get("MINT_ACC_SITE")
                or A.HERE / ".runtime" / "site.json")
    return json.loads(path.read_text(encoding="utf-8"))


def sec(role):
    return os.environ[site()["secret_env"][role]]


def lit(value):
    return "'" + str(value).replace("'", "''") + "'"


def iid():
    return A.instance()


def q(sql):
    out = A.psql(f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({sql}) t", "mint")
    return json.loads(out)


def q1(sql):
    rows = q(sql)
    return rows[0] if rows else None


def n(sql):
    return int(A.psql(sql, "mint") or 0)


def db_now():
    return A.psql("SELECT clock_timestamp()", "mint")


def wait(predicate, seconds, label, step=1.0):
    deadline = time.monotonic() + seconds
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise SystemExit(f"시간 상한 초과: {label} ({seconds}s)")
        time.sleep(step)


def limit(name):
    return A.yaml.safe_load((A.HERE / "expected_events.yaml").read_text(
        encoding="utf-8"))["limits"][name]


def sv():
    return os.environ.get("ACC_SERVER_ID") or site()["servers"]["synthetic"]["server_id"]


def synthetic():
    return site()["servers"]["synthetic"]


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def raw(method, url, body=None, key=None, headers=None):
    """(상태, 본문 문자열). HTTP 오류도 값으로 돌려준다."""
    request = urllib.request.Request(
        url, method=method, data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {}),
                 **({"Authorization": f"Bearer {key}"} if key else {})})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def admin_key():
    return A.env("ACC_LITELLM_ADMIN_KEY", os.environ.get("MINT_LITELLM_KEY"))


def lite(method, path, body=None, key=None):
    return A.http(method, A.env("ACC_LITELLM_ADMIN_URL").rstrip("/") + path, body,
                  key or admin_key())


def lite_raw(method, path, body=None, key=None):
    return raw(method, A.env("ACC_LITELLM_ADMIN_URL").rstrip("/") + path, body,
               key or admin_key())


def cli(*args, role="admin", token=None, check=True, env_over=None, stack=False):
    """운영자 CLI 한 번. (종료 코드, JSON 또는 None, 표준 오류).

    ``stack``이면 호스트 CLI 대신 ``deploy/mint.sh cli``(스택 안의 CLI)로 돌린다. 호스트에 없는
    도구(``opa`` 바이너리)가 필요한 명령용이다.
    """
    env = {**os.environ, "MINT_OPERATOR_TOKEN": token or A.env(ROLE_ENV[role]),
           **(env_over or {})}
    command = ["./mint.sh", "cli"] if stack else shlex.split(
        os.environ.get("ACC_CLI", f"{sys.executable} -m mint_litellm.cli"))
    done = subprocess.run([*command, *map(str, args), "--json"],
                          cwd=A.ROOT / "deploy" if stack else A.ROOT, env=env, text=True,
                          encoding="utf-8", capture_output=True, timeout=180,
                          stdin=subprocess.DEVNULL if stack else None)
    try:
        data = json.loads(done.stdout) if done.stdout.strip() else None
    except ValueError:
        data = None
    if check and done.returncode:
        raise SystemExit(f"CLI 실패({done.returncode}): {' '.join(map(str, args[:3]))} "
                         + done.stderr[-300:])
    return done.returncode, data, done.stderr


def iso(delta):
    return (datetime.now(UTC) + delta).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def code_of(text):
    found = re.search(r"MINT-[A-Z0-9-]+", text)
    return found.group(0) if found else None


def cause_of(text):
    return next((c for c in CAUSES if c in text), None)


def rest_call(key, tool, arguments, server=None, mark=None):
    """호출 키로 LiteLLM REST 호출. (상태, 본문, 호출 표식)."""
    mark = mark or "acc-" + uuid.uuid4().hex
    status, text = raw("POST", site()["litellm"][0].rstrip("/") + "/mcp-rest/tools/call",
                       {"server_id": server or sv(), "name": tool, "arguments": arguments}, key,
                       {"x-litellm-call-id": mark})
    return status, text, mark


def upstream(server=None):
    status, text = raw("GET", site()["counters"][server or sv()])
    return json.loads(text)["tools/call"]


def log_count(pattern, since):
    """LiteLLM 접근 로그(site.decision_logs)에서 `since`(UTC datetime) 이후 패턴 줄 수."""
    total = 0
    for argv in site().get("decision_logs", []):
        argv = list(argv)
        if argv[:2] == ["docker", "logs"]:
            argv[2:2] = ["--since", since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")]
        done = subprocess.run(argv, text=True, encoding="utf-8", errors="replace",
                              capture_output=True, timeout=120)
        total += len(re.findall(pattern, done.stdout + done.stderr))
    return total


def probe_checks(since):
    """수용검증이 서버를 직접 두드린 검사(connection·definitions) 수. LiteLLM 시험 경로 접근 로그에는
    계약 관측 작업(contract_observe)의 주기 조회도 섞이므로, 신청 검사 기록으로 센다."""
    return n(f"SELECT count(*) FROM mint.intake_checks WHERE instance_id={lit(iid())} "
             "AND \"check\" IN ('connection', 'definitions') "
             f"AND ran_at >= {lit(since.isoformat())}")


def observer_runs(since):
    return n(f"SELECT count(*) FROM mint.jobs WHERE instance_id={lit(iid())} "
             f"AND kind='contract_observe' AND updated_at >= {lit(since.isoformat())}")


def event_count(kind, since):
    return n(f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} "
             f"AND kind={lit(kind)} AND inserted_at >= {lit(since)}")


def epoch():
    return n(f"SELECT coalesce(max(epoch),0) FROM mint.state_epoch WHERE instance_id={lit(iid())}")


@contextmanager
def paused(service):
    """서비스를 멈춰 두고(작업이 쌓이게) 나올 때 원래대로 되돌린다."""
    was = A.running(service)
    if was:
        A.compose("stop", service)
    try:
        yield
    finally:
        if was:
            A.compose("start", service)


def observe(ctx, **fields):
    A.write_observation(ctx, **fields)


# ---- LiteLLM 시험 주체와 정리

def track(kind, ident):
    path = A.state_file("litellm-objects.json")
    items = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    items.append([kind, ident])
    path.write_text(json.dumps(items), encoding="utf-8")


def cleanup(ctx=None):
    path = A.state_file("litellm-objects.json")
    if not path.exists():
        return
    bodies = {"key": ("/key/delete", "keys"), "team": ("/team/delete", "team_ids"),
              "user": ("/user/delete", "user_ids")}
    for kind, ident in reversed(json.loads(path.read_text(encoding="utf-8"))):
        try:
            if kind == "server":
                lite_raw("DELETE", f"/v1/mcp/server/{ident}")
            else:
                route, field = bodies[kind]
                lite_raw("POST", route, {field: [ident]})
        except Exception:  # 이미 지워졌거나 닿지 않아도 정리는 계속한다
            continue
    path.unlink(missing_ok=True)


def new_user():
    user = "acc-" + uuid.uuid4().hex[:10]
    lite("POST", "/user/new", {"user_id": user, "user_role": "internal_user"})
    track("user", user)
    return user


def new_team(servers=()):
    body = {"team_alias": "acc-team-" + uuid.uuid4().hex[:8]}
    if servers:
        body["object_permission"] = {"mcp_servers": list(servers)}
    team = lite("POST", "/team/new", body)["team_id"]
    track("team", team)
    return team


def new_key(user, team=None, servers=(), **extra):
    """호출 키 발급. ``user``가 None이면 ``user_id`` 없이 팀 범위 키로 만든다."""
    body = {**({"user_id": user} if user else {}), **extra}
    if team:
        body["team_id"] = team
    if servers:
        body["object_permission"] = {"mcp_servers": list(servers)}
    key = lite("POST", "/key/generate", body)["key"]
    track("key", key)
    return key, sha(key)


# ---- MINT 쪽 준비(소유 권한용 승인은 intake approve가 만드는 pending 행과 같은 모양을 쓴다)

def relation(server):
    row = q1(f"SELECT id, org_id FROM mint.usage_relations WHERE instance_id={lit(iid())} "
             f"AND server_id={lit(server)} AND status='active' ORDER BY id LIMIT 1")
    if row is None:
        raise SystemExit("활성 이용 관계 없음: 서버가 먼저 활성화되어야 합니다")
    return row


def tool_names(server):
    rows = q(f"SELECT DISTINCT tool FROM mint.tool_contracts WHERE instance_id={lit(iid())} "
             f"AND server_id={lit(server)} AND status='approved' ORDER BY tool")
    if not rows:
        raise SystemExit("승인된 도구 계약 없음")
    return [r["tool"] for r in rows]


def add_pending_approval(scope_type, scope_id, server, tools=None, conditions=None):
    """approve CLI는 LiteLLM에 사전 권한을 요구해 MINT 소유 항목을 못 만든다. intake approve가 쓰는
    것과 같은 `pending` 승인 행을 넣고 동기화 작업을 등록한다(승인 완결은 작업 실행기의 몫)."""
    rel = relation(server)
    approval = str(uuid.uuid4())
    names = "ARRAY[" + ",".join(lit(t) for t in (tools or tool_names(server))) + "]::text[]"
    A.psql(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id, tools,"
        " scope_type, scope_id, valid_from, valid_until, conditions, basis, granted_by,"
        " requested_by, status) VALUES ("
        f"{lit(approval)}, {lit(iid())}, {lit(rel['org_id'])}, {lit(rel['id'])}, 'standard', "
        f"{lit(server)}, {names}, {lit(scope_type)}, {lit(scope_id)}, now(), "
        "now() + interval '1 day', "
        f"{lit(json.dumps(conditions or {}))}::jsonb, '{{\"text\":\"acceptance\"}}'::jsonb, "
        "'acceptance', 'acceptance', 'pending')", "mint")
    enqueue("sync_server", server)
    enqueue("sync_target", f"{scope_type}:{scope_id}")
    return approval


def enqueue(kind, ref):
    A.psql("INSERT INTO mint.jobs (id, instance_id, kind, target_ref) VALUES ("
           f"gen_random_uuid(), {lit(iid())}, {lit(kind)}, {lit(ref)}) ON CONFLICT "
           "(instance_id, kind, target_ref) WHERE status = 'pending' AND idempotency_key IS NULL "
           "DO NOTHING", "mint")


def grant_row(target_type, target_id, server=None, item="mcp_server"):
    return q1("SELECT id, observed, preexisting, held, missing_count, last_applied_at "
              f"FROM mint.litellm_grants WHERE instance_id={lit(iid())} "
              f"AND target_type={lit(target_type)} AND target_id={lit(target_id)} "
              f"AND item={lit(item)} AND server_id={lit(server or sv())}")


def converged(target_type, target_id, server=None):
    row = grant_row(target_type, target_id, server)
    return row is not None and row["observed"] is True


def permission(target_type, target_id):
    """LiteLLM에서 읽은 object_permission(키는 토큰 해시로 조회한다)."""
    if target_type == "key":
        return lite("GET", "/key/info?key=" + target_id)["info"].get("object_permission") or {}
    return lite("GET", "/team/info?team_id=" + target_id)["team_info"].get(
        "object_permission") or {}


def has_server(target_type, target_id, server=None):
    return (server or sv()) in (permission(target_type, target_id).get("mcp_servers") or [])


def active_approval(server=None):
    return A.psql("SELECT id FROM mint.approvals WHERE instance_id=" + lit(iid())
                  + " AND server_id=" + lit(server or sv())
                  + " AND status='active' ORDER BY valid_from DESC LIMIT 1", "mint")


# ================================================================ 동기화 7종

@scenario("sync_team_order", undo=cleanup)
def sync_team_order(ctx):
    server = sv()
    team, user = new_team(), new_user()
    _, kid = new_key(user, team)
    with paused("worker"):  # 키 작업이 팀 작업보다 먼저 임대되도록 쌓아 둔다
        add_pending_approval("key", kid, server)
        add_pending_approval("team", team, server)
    wait(lambda: converged("key", kid) and converged("team", team), limit("sync_seconds"),
         "팀 → 키 수렴")
    order = q1("SELECT t.last_applied_at < k.last_applied_at AS team_first FROM "
               f"mint.litellm_grants t, mint.litellm_grants k WHERE t.instance_id={lit(iid())} "
               f"AND k.instance_id=t.instance_id AND t.target_type='team' "
               f"AND t.target_id={lit(team)} "
               f"AND t.item='mcp_server' AND k.target_type='key' AND k.target_id={lit(kid)} "
               "AND k.item='mcp_server'")
    forbidden = n(f"SELECT count(*) FROM mint.alerts WHERE instance_id={lit(iid())} "
                  f"AND dedup_key LIKE {lit('sync_divergence:forbidden:key:' + kid)}")
    observe(ctx, server_id=server, team_before_key=bool(order and order["team_first"]),
            key_first_status=403 if forbidden else None,
            converged=converged("key", kid) and has_server("key", kid))


@scenario("sync_preexisting", undo=cleanup)
def sync_preexisting(ctx):
    server = sv()
    user = new_user()
    _, kid = new_key(user, servers=[server])  # 사람이 미리 넣은 항목
    approval = add_pending_approval("key", kid, server)
    wait(lambda: A.psql(f"SELECT status FROM mint.approvals WHERE id={lit(approval)}",
                        "mint") == "active", limit("sync_seconds"), "승인 완결")
    pre = grant_row("key", kid)
    cli("revoke", approval, "--reason", "acceptance")
    wait(lambda: n("SELECT count(*) FROM mint.litellm_grants WHERE "
                   f"instance_id={lit(iid())} AND target_type='key' AND target_id={lit(kid)} "
                   "AND item='mcp_server' AND NOT preexisting AND observed") == 0
         and A.psql(f"SELECT status FROM mint.jobs WHERE instance_id={lit(iid())} "
                    f"AND kind='sync_target' AND target_ref={lit('key:' + kid)} "
                    "ORDER BY created_at DESC LIMIT 1", "mint") == "done",
         limit("sync_seconds"), "철회 수렴")
    owned = n(f"SELECT count(*) FROM mint.litellm_grants WHERE instance_id={lit(iid())} "
              f"AND target_type='key' AND target_id={lit(kid)} AND item='mcp_server' "
              "AND NOT preexisting AND observed")
    observe(ctx, server_id=server, preexisting_recorded=bool(pre and pre["preexisting"]),
            preexisting_after_revoke=1 if has_server("key", kid) else 0, owned_after_revoke=owned)


def pin_mismatch_undo(ctx):
    A.http("POST", A.env("ACC_FIXTURE_URL").rstrip("/") + "/control", {"mode": "base"})
    cleanup(ctx)


@scenario("sync_pin_mismatch", undo=pin_mismatch_undo)
def sync_pin_mismatch(ctx):
    server = sv()
    # 아직 pin되지 않은 서버로 만든다(이미 맞게 pin한 서버는 pin 단계가 건너뛰어진다, 설계 21.4.3).
    lite_raw("DELETE", f"/v1/mcp/server/{server}/pin")
    A.psql("UPDATE mint.litellm_grants SET observed=false, applied_sha256=NULL WHERE "
           f"instance_id={lit(iid())} AND item='pin' AND server_id={lit(server)}", "mint")
    time.sleep(2)  # 로그의 --since는 초 단위라 내 해제 호출이 세어지지 않게 한다
    start = datetime.now(UTC)
    since = db_now()
    team, user = new_team(), new_user()
    _, kid = new_key(user)
    A.http("POST", A.env("ACC_FIXTURE_URL").rstrip("/") + "/control", {"mode": "description"})
    with paused("worker"):  # sync_server가 먼저 돌아 고정 불일치가 대상 작업보다 앞서게 한다
        approval = add_pending_approval("key", kid, server)
        add_pending_approval("team", team, server)
        enqueue("sync_server", server)
    wait(lambda: event_count("reapproval_requested", since) >= 1, limit("sync_seconds"),
         "재승인 요청")
    time.sleep(limit("observe_seconds") / 2)  # 늦게 도는 대상 작업이 권한을 내보내지 않는지 본다

    def granted(kind, target):
        return n(f"SELECT count(*) FROM mint.litellm_grants WHERE instance_id={lit(iid())} "
                 f"AND item='mcp_server' AND observed AND target_type={lit(kind)} "
                 f"AND target_id={lit(target)}")

    observe(ctx, server_id=server, key_grants=granted("key", kid),
            team_grants=granted("team", team),
            approval_status=A.psql(f"SELECT status FROM mint.approvals WHERE id={lit(approval)}",
                                   "mint"),
            unpin_calls=log_count(r"DELETE /v1/mcp/server/\S+/pin", start),
            # 설명 변경의 관측 사건도 같은 종류라서 pin 불일치가 낸 것(source=pin)만 센다.
            events={"reapproval_requested": n(
                f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} "
                f"AND kind='reapproval_requested' AND inserted_at >= {lit(since)} "
                "AND payload->>'source'='pin'")})


@scenario("sync_race_30", undo=cleanup)
def sync_race_30(ctx):
    server, rounds = sv(), 30
    subjects = []
    for i in range(rounds):
        user = new_user()
        key, kid = new_key(user, metadata={"acc": "init"})
        subjects.append((i, key, kid))
    barrier = threading.Barrier(rounds)

    def race(i, key, kid):
        barrier.wait()
        add_pending_approval("key", kid, server)  # MINT 쓰기를 부르는 쪽
        lite("POST", "/key/update", {"key": kid, "metadata": {"acc": f"foreign-{i}"}})

    threads = [threading.Thread(target=race, args=s) for s in subjects]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    deadline = limit("sync_seconds")
    wait(lambda: all(converged("key", kid) for _, _, kid in subjects), deadline, "30회 수렴")
    missing = sum(1 for _, _, kid in subjects if not has_server("key", kid))
    unalerted = 0
    for i, _, kid in subjects:
        info = lite("GET", "/key/info?key=" + kid)["info"]
        if (info.get("metadata") or {}).get("acc") != f"foreign-{i}":  # 비소유 필드가 덮였다
            unalerted += 0 if n(f"SELECT count(*) FROM mint.alerts WHERE instance_id={lit(iid())} "
                                f"AND dedup_key={lit('sync_foreign_change:key:' + kid)}") else 1
    observe(ctx, server_id=server, rounds=rounds, owned_missing=missing,
            foreign_change_without_alert=unalerted)


@scenario("sync_dedup", undo=cleanup)
def sync_dedup(ctx):
    import psycopg

    from mint_litellm.control.context import Context, Operator
    from mint_litellm.control.services.base import enqueue_job

    server = sv()
    _, kid = new_key(new_user())
    ref = f"key:{kid}"
    ids = []

    def click():
        with psycopg.connect(A.env("MINT_DATABASE_URL")) as conn:
            ids.append(enqueue_job(Context(conn, iid(), Operator("acceptance", "admin", None)),
                                   "sync_target", ref))

    with paused("worker"):  # 대기 행이 그대로 남아 있어야 센다
        threads = [threading.Thread(target=click) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        pending = n(f"SELECT count(*) FROM mint.jobs WHERE instance_id={lit(iid())} "
                    f"AND kind='sync_target' AND target_ref={lit(ref)} AND status='pending'")
    observe(ctx, server_id=server, pending_per_target=pending, requests=len(ids),
            distinct_job_ids=len(set(map(str, ids))))


@scenario("sync_lease_reclaim", undo=cleanup)
def sync_lease_reclaim(ctx):
    server = sv()
    start = datetime.now(UTC)
    user = new_user()
    _, kid = new_key(user)
    ref = f"key:{kid}"
    with paused("worker"):
        approval = add_pending_approval("key", kid, server)
        # 처리기가 LiteLLM에 쓴 뒤 기록 전에 죽은 상태: 소유 행(관측 전)·LiteLLM 값·만료된 임대
        A.psql("INSERT INTO mint.litellm_grants (id, instance_id, target_type, target_id, item, "
               f"server_id, observed) VALUES (gen_random_uuid(), {lit(iid())}, 'key', {lit(kid)}, "
               f"'mcp_server', {lit(server)}, false)", "mint")
        current = permission("key", kid)
        lite("POST", "/key/update", {"key": kid, "object_permission": {
            **current, "mcp_servers": [*(current.get("mcp_servers") or []), server],
            "mcp_tool_permissions": {**(current.get("mcp_tool_permissions") or {}),
                                     server: tool_names(server)}}})
        A.psql("UPDATE mint.jobs SET status='running', lease_owner='acc-crashed', "
               "lease_until=now() + interval '2 seconds', attempts=1 WHERE "
               f"instance_id={lit(iid())} AND kind='sync_target' AND target_ref={lit(ref)} "
               "AND status='pending'", "mint")
    seeded = permission("key", kid)
    wait(lambda: converged("key", kid), limit("sync_seconds"), "임대 회수 뒤 수렴")
    job = q1(f"SELECT status, attempts FROM mint.jobs WHERE instance_id={lit(iid())} "
             f"AND kind='sync_target' AND target_ref={lit(ref)} ORDER BY created_at DESC LIMIT 1")
    writes = log_count(r"POST /key/update", start) - 1  # 장애를 만든 내 쓰기 1건 제외
    observe(ctx, server_id=server, reexecutions=int(job["attempts"]) - 1,  # 심은 죽은 실행의 시도 1을 뺀다
            duplicate_writes=max(0, writes), permission_seeded=seeded,
            permission_final=permission("key", kid),
            converged=converged("key", kid) and has_server("key", kid),
            approval=approval)


@scenario("sync_revoke_race", undo=cleanup)
def sync_revoke_race(ctx):
    server, count = sv(), 6
    targets = []
    for _ in range(count):
        _, kid = new_key(new_user())
        approval = add_pending_approval("key", kid, server)
        targets.append((kid, approval))
    wait(lambda: all(A.psql(f"SELECT status FROM mint.approvals WHERE id={lit(a)}", "mint")
                     == "active" for _, a in targets), limit("sync_seconds"), "활성화")
    for kid, _ in targets:  # 작업 실행기가 바쁘게 돌도록 대상 작업을 한꺼번에 등록
        enqueue("sync_target", f"key:{kid}")
    overlap = False
    started = time.monotonic()
    for _kid, approval in targets:
        running = n(f"SELECT count(*) FROM mint.jobs WHERE instance_id={lit(iid())} "
                    "AND kind='sync_target' AND status='running'")
        cli("revoke", approval, "--reason", "acceptance")
        overlap = overlap or running > 0
    wait(lambda: not any(has_server("key", kid) for kid, _ in targets), 60, "철회 제거 확인")
    elapsed = time.monotonic() - started
    remaining = n(f"SELECT count(*) FROM mint.litellm_grants WHERE instance_id={lit(iid())} "
                  "AND item='mcp_server' AND NOT preexisting AND observed AND target_type='key' "
                  "AND target_id IN (" + ",".join(lit(k) for k, _ in targets) + ")")
    observe(ctx, server_id=server, overlap=overlap, remaining_owned=remaining,
            elapsed_seconds=elapsed)


# ================================================================ 수용검증 음성 7종

def fixture_control(mode):
    A.http("POST", A.env("ACC_FIXTURE_URL").rstrip("/") + "/control", {"mode": mode})


def fixture_undo(ctx):
    try:
        fixture_control("base")
    finally:
        cleanup(ctx)


def fixture_url():
    """LiteLLM이 합성 서버에 접속하는 주소(활성화된 합성 서버의 등록 값)."""
    return lite("GET", f"/v1/mcp/server/{sv()}")["url"]


def register_fixture_server():
    """운영자 경로: 합성 서버를 LiteLLM에 새 항목으로 등록한다."""
    alias = "acc_" + uuid.uuid4().hex[:8]
    created = lite("POST", "/v1/mcp/server", {
        "alias": alias, "server_name": alias, "url": fixture_url(), "transport": "http",
        "allow_all_keys": False})
    track("server", created["server_id"])
    return created["server_id"]


def submit_server(url, allow_all_keys=False):
    """제출 경로: 비관리자 팀 범위 키로 공개 서버 제출. 책임 사용자는 조직에 묶여 있어야 한다."""
    alias = "acc_" + uuid.uuid4().hex[:8]
    status, text = lite_raw("POST", "/v1/mcp/server/register", {
        "alias": alias, "server_name": alias, "url": url, "transport": "http",
        "description": "acceptance", "allow_all_keys": allow_all_keys},
        key=A.env("ACC_SUBMIT_KEY"))
    if status not in (200, 201):
        raise SystemExit(f"제출 실패(HTTP {status})")
    server_id = json.loads(text)["server_id"]
    track("server", server_id)
    return server_id


def create_intake(server_id, url=None):
    s = site()["intake"]
    r = s["readiness"]

    def text(value):
        return "예" if value is True else str(value)

    args = ["intake", "create", server_id, "--org", s["org_id"], "--purpose", s["purpose"],
            "--data-grade", s["data_grade"],
            "--allowed-resources", json.dumps(s["allowed_resources"]),
            "--provider", s["provider"], "--owner", s["owner_user_id"],
            "--credential-notice", text(r["credential_notice"]),
            "--revocation-record", text(r["revocation_record"]),
            "--audit-access-days", str(r["audit_access_days"]),
            "--data-return-terms", s["data_return_terms"]]
    url = url or next((e["url"] for e in site()["servers"].values()
                       if e["server_id"] == server_id and e.get("url")), None)
    if url:
        args += ["--url", url]
    return cli(*args)[1]["id"]


def intake_status(intake_id):
    return A.psql(f"SELECT status FROM mint.intakes WHERE id={lit(intake_id)}", "mint")


def checked(intake_id):
    return intake_status(intake_id) in ("passed", "failed", "indeterminate", "decided")


def decision_writes(intake_id):
    return (n(f"SELECT count(*) FROM mint.intakes WHERE id={lit(intake_id)} "
              "AND (decision IS NOT NULL OR decided_by IS NOT NULL)")
            + n(f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} "
                f"AND kind='intake_decided' AND payload->>'intake_id'={lit(intake_id)}"))


def negative_submission(ctx, url, allow_all_keys=False):
    start = datetime.now(UTC)
    server_id = submit_server(url, allow_all_keys)
    seen_open = lite("GET", f"/v1/mcp/server/{server_id}").get("allow_all_keys")
    wait(lambda: n(f"SELECT count(*) FROM mint.intakes WHERE instance_id={lit(iid())} "
                   f"AND server_id={lit(server_id)}"), 180, "제출 신청 수신")
    intake_id = A.psql(f"SELECT id FROM mint.intakes WHERE instance_id={lit(iid())} "
                       f"AND server_id={lit(server_id)} ORDER BY created_at LIMIT 1", "mint")
    create_intake(server_id)  # 필수 입력을 채우면 검사가 시작된다
    wait(lambda: A.psql(f"SELECT coalesce(decision,'') FROM mint.intakes "
                        f"WHERE id={lit(intake_id)}", "mint") == "rejected", 180, "자동 거절")
    time.sleep(5)  # 뒤늦은 시험 호출·재신청이 없는지 본다
    observe(ctx, intake_id=intake_id, submitted_allow_all_keys=seen_open is True,
            test_route_calls=probe_checks(start),
            test_route_log_calls=log_count(r"/mcp-rest/test/", start),
            observer_runs=observer_runs(start),
            reject_calls=log_count(r"PUT /v1/mcp/server/\S+/reject", start),
            resubmissions=n(f"SELECT count(*) FROM mint.intakes WHERE instance_id={lit(iid())} "
                            f"AND server_id={lit(server_id)}") - 1,
            failed_checks=n(f"SELECT count(*) FROM mint.intake_checks WHERE "
                            f"intake_id={lit(intake_id)} AND result='fail'"))


@scenario("intake_provider_denied", undo=cleanup)
def intake_provider_denied(ctx):
    # LiteLLM은 해석되지 않는 호스트의 제출을 400으로 거절하므로 해석되는 공개 호스트를 쓴다.
    negative_submission(ctx, f"https://example.org/mcp-{uuid.uuid4().hex[:8]}")


@scenario("intake_private_literal", undo=cleanup)
def intake_private_literal(ctx):
    """사설 리터럴 IP 제출은 LiteLLM이 받아 주고, MINT가 첫 제출 수신 작업 안에 운영자 입력 없이
    `url_guard`(IP_FORBIDDEN)로 거절하며 LiteLLM에도 거절을 알린다.

    같은 제출에서 URL만 해석되는 주소로 바꾼 대조군은 접수되고 결정되지 않은 채 입력을 기다린다.
    """
    start = datetime.now(UTC)
    before = n(f"SELECT count(*) FROM mint.intakes WHERE instance_id={lit(iid())}")
    upstream_before = upstream()

    def submit(url):
        alias = "acc_" + uuid.uuid4().hex[:8]
        return lite_raw("POST", "/v1/mcp/server/register", {
            "alias": alias, "server_name": alias, "url": url, "transport": "http",
            "description": "acceptance", "allow_all_keys": False}, key=A.env("ACC_SUBMIT_KEY"))

    status, text = submit("https://10.20.30.40/mcp")
    control_url = site()["servers"]["synthetic"]["url"] + "?c=" + uuid.uuid4().hex[:6]
    control_status, control_text = submit(control_url)
    control_id = json.loads(control_text)["server_id"] if control_status in (200, 201) else None
    if control_id:
        track("server", control_id)
    if status not in (200, 201):
        raise SystemExit(f"사설 IP 제출이 거절됨(HTTP {status}): 고정 판본의 동작과 다름")
    private_id = json.loads(text)["server_id"]
    track("server", private_id)
    # 첫 수신 작업(주기 1회) 안에 접수와 거절이 모두 끝나야 한다. 운영자 입력은 넣지 않는다.
    deadline = 2 * limit("submission_poll_seconds") + 30
    intake_id = wait(lambda: A.psql(
        f"SELECT id FROM mint.intakes WHERE instance_id={lit(iid())} AND "
        f"server_id={lit(private_id)} ORDER BY created_at LIMIT 1", "mint"), deadline,
        "사설 IP 제출 신청 수신")
    wait(lambda: A.psql(f"SELECT coalesce(decision,'') FROM mint.intakes WHERE "
                        f"id={lit(intake_id)}", "mint") == "rejected", deadline, "자동 거절")
    time.sleep(5)  # 뒤늦은 시험 호출·재신청이 없는지 본다
    guard = A.psql("SELECT reason_code FROM mint.intake_checks WHERE "
                   f"intake_id={lit(intake_id)} AND \"check\"='url_guard'", "mint")
    control_decision = A.psql(
        f"SELECT coalesce(decision,'') FROM mint.intakes WHERE server_id={lit(control_id)} "
        f"AND instance_id={lit(iid())}", "mint") if control_id else None
    new_rows = n(f"SELECT count(*) FROM mint.intakes WHERE instance_id={lit(iid())}") - before
    observe(ctx, intake_id=intake_id, litellm_accepted=status in (200, 201),
            intake_status=intake_status(intake_id), url_guard_reason=guard,
            reject_calls=log_count(r"PUT /v1/mcp/server/\S+/reject", start),
            test_route_calls=probe_checks(start),
            test_route_log_calls=log_count(r"/mcp-rest/test/", start),
            observer_runs=observer_runs(start),
            control_accepted=control_status in (200, 201), control_decision=control_decision,
            mint_intakes=new_rows - (1 if control_id else 0),
            upstream_calls=upstream() - upstream_before)


@scenario("intake_private_ip_guard", undo=cleanup)
def intake_private_ip_guard(ctx):
    """DS-174: 운영자 출처 신청에서 MINT url_guard가 사설 IP를 거부한다."""
    alias = "acc_" + uuid.uuid4().hex[:8]
    created = lite("POST", "/v1/mcp/server", {
        "alias": alias, "server_name": alias, "url": "https://10.20.30.40/mcp",
        "transport": "http", "allow_all_keys": False})
    track("server", created["server_id"])
    intake_id = create_intake(created["server_id"], "https://10.20.30.40/mcp")
    wait(lambda: A.psql(f"SELECT coalesce(decision,'') FROM mint.intakes WHERE id={lit(intake_id)}",
                        "mint") == "rejected", 180, "자동 거절")
    observe(ctx, intake_id=intake_id,
            url_guard_reason=A.psql(
                "SELECT reason_code FROM mint.intake_checks WHERE "
                f"intake_id={lit(intake_id)} AND \"check\"='url_guard'", "mint"),
            test_route_calls=probe_checks(datetime.now(UTC) - timedelta(minutes=3)))


@scenario("intake_allow_all_keys", undo=cleanup)
def intake_allow_all_keys(ctx):
    negative_submission(ctx, f"https://example.org/mcp-{uuid.uuid4().hex[:8]}",
                        allow_all_keys=True)


@scenario("intake_definitions_limit", undo=fixture_undo)
def intake_definitions_limit(ctx):
    fixture_control("limit")  # 도구 501개: 상한 500 초과
    server_id = register_fixture_server()
    intake_id = create_intake(server_id, fixture_url())
    wait(lambda: checked(intake_id), 180, "검사")
    result = intake_status(intake_id)
    # 정의 상한을 넘어 판별할 수 없는 서버는 고정할 도구 계약이 없어 예외로도 승인하지 않는다.
    # 거부 문구는 원인(정의 상한 초과)을 밝혀야 한다.
    second = A.env(ROLE_ENV["admin2"])
    refused = cli("intake", "except", intake_id, "--reason", "acceptance", "--valid-until",
                  iso(timedelta(days=89, hours=23)), "--second-approver", second,
                  role="approver", check=False)
    observe(ctx, intake_id=intake_id, result=result, except_refused=refused[0] != 0,
            reason_over_limit="정의 상한 초과" in refused[2],
            exception_approvals=n(f"SELECT count(*) FROM mint.approvals WHERE "
                                  f"instance_id={lit(iid())} AND "
                                  f"basis->>'intake_id'={lit(intake_id)}"))


@scenario("intake_same_requester", undo=fixture_undo)
def intake_same_requester(ctx):
    intake_id = create_intake(register_fixture_server(), fixture_url())  # 신청자 = 이 관리자
    wait(lambda: checked(intake_id), 180, "검사")
    refused = cli("intake", "approve", intake_id, role="admin", check=False)
    observe(ctx, intake_id=intake_id, refused_exit=refused[0],
            decision_writes=decision_writes(intake_id))


@scenario("intake_stale_evidence", undo=fixture_undo)
def intake_stale_evidence(ctx):
    intake_id = create_intake(register_fixture_server(), fixture_url())
    wait(lambda: intake_status(intake_id) == "passed", 180, "검사 통과")
    # 검사 기록은 추가 전용이라 시험 스택의 복제 역할로만 시각을 옮긴다
    A.psql("SET session_replication_role=replica; UPDATE mint.intake_checks SET "
           "ran_at = now() - interval '25 hours' WHERE intake_id=" + lit(intake_id)
           + " AND \"check\" IN ('connection','definitions')", "mint")
    age = float(A.psql("SELECT extract(epoch FROM now() - min(ran_at)) / 3600 FROM "
                       f"mint.intake_checks WHERE intake_id={lit(intake_id)} "
                       "AND \"check\" IN ('connection','definitions')", "mint"))
    refused = cli("intake", "approve", intake_id, role="approver", check=False)
    observe(ctx, intake_id=intake_id, evidence_age_hours=round(age, 3), refused_exit=refused[0],
            decision_writes=decision_writes(intake_id))


@scenario("intake_credentials_required", undo=fixture_undo)
def intake_credentials_required(ctx):
    fixture_control("unauthorized")
    base = A.env("ACC_FIXTURE_URL").rstrip("/")
    upstream_status = raw("POST", base + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})[0]
    test_status, test_text = lite_raw("POST", "/mcp-rest/test/connection", {
        "url": fixture_url(), "transport": "http", "auth_type": "none"})
    intake_id = create_intake(register_fixture_server(), fixture_url())
    wait(lambda: checked(intake_id), 180, "검사")
    observe(ctx, intake_id=intake_id, upstream_status=upstream_status,
            test_http_status=test_status, test_body_status=json.loads(test_text).get("status"),
            result=intake_status(intake_id))


# ================================================================ 되돌림 8종

def tagged(tag):
    return type("Tag", (), {"run_id": tag})


def export_root():
    return A.export_dir()


def newest_negative():
    names = [int(p.stem) for p in (export_root() / "negative").glob("*.json") if p.stem.isdigit()]
    return max(names, default=-1)


def file_backup_path(name):
    return A.state_file("export-" + name)


def keep_file(path):
    """원래 파일을 보관한다. 되돌릴 때 같은 바이트로 쓴다."""
    file_backup_path(path.name).write_bytes(path.read_bytes())


def put_back(name, target):
    saved = file_backup_path(name)
    if saved.exists():
        rel = target.relative_to(Path(A.env("ACC_EXPORT_HOST_DIR")))
        A.export_root(f"cp /b /x/{rel.as_posix()}; chown 65532:65532 /x/{rel.as_posix()}",
                      f"{saved}:/b:ro")
        saved.unlink()


def put_back_latest(ctx=None):
    put_back("latest.json", export_root() / "latest.json")


def restart_env(over):
    """공개 키 환경을 바꿔 판정·작업 서비스를 다시 만든다(compose는 호스트 환경으로 보간한다)."""
    base = shlex.split(os.environ.get("ACC_COMPOSE") or
                       f"docker compose -p {A.env('COMPOSE_PROJECT_NAME', 'mint-acc')} "
                       "-f deploy/compose.yaml")
    services = os.environ.get("ACC_PLUGIN_SERVICES", "litellm worker").split()
    done = subprocess.run([*base, "up", "-d", "--force-recreate", "--wait", *services],
                          cwd=A.ROOT, env={**os.environ, **over}, text=True, encoding="utf-8",
                          capture_output=True, timeout=600)
    if done.returncode:
        raise SystemExit("서비스 재생성 실패: " + done.stderr[-300:])


def original_keys():
    return {"MINT_EXPORT_HMAC_KEY": A.env("MINT_EXPORT_HMAC_KEY"),
            "MINT_EXPORT_HMAC_KEY_PREVIOUS": os.environ.get("MINT_EXPORT_HMAC_KEY_PREVIOUS", "")}


def restore_keys(ctx=None):
    restart_env(original_keys())


def new_hmac_key():
    import base64
    return base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"=").decode()


RESTORED_AT = [None]


def writes_since(since):
    """작업 실행기의 외부 쓰기(LiteLLM 쓰기 경로) 수. 로그가 없으면 소유 항목 갱신 시각으로 센다."""
    if RESTORED_AT[0] and RESTORED_AT[0] > since:
        since = RESTORED_AT[0]
    if site().get("decision_logs"):
        return log_count(r"(POST /(key|team)/update|PUT /v1/mcp/server|"
                         r"(POST|DELETE) /v1/mcp/server/\S+/pin)", since)
    return n(f"SELECT count(*) FROM mint.litellm_grants WHERE instance_id={lit(iid())} "
             f"AND last_applied_at >= {lit(since.isoformat())}")


LAST_MARK = [None]
LAST_SINCE = [None]


def cause_from_event(mark):
    """DS-175 ②: 차단 원인은 응답 본문이 아니라 판정 사건(snapshot의 cause)에서 읽는다."""
    for _ in range(10):
        body = A.psql("SELECT payload::text FROM mint.events WHERE kind='decision_evaluated' AND "
                      f"payload->>'litellm_call_id'={lit(mark)} LIMIT 1", "mint")
        if body:
            return next((c for c in CAUSES if c in body), None)
        time.sleep(1)
    # 재시작한 LiteLLM은 목록 단계에서 막혀 호출 표식의 판정 사건이 없다. 그 시각 이후 MINT 로그의 원인으로 읽는다.
    if LAST_SINCE[0]:
        for cause in CAUSES:
            if n(f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} AND "
                 f"inserted_at >= {lit(LAST_SINCE[0].isoformat())} "
                 f"AND payload::text LIKE {lit('%' + cause + '%')}") or log_count(
                     cause, LAST_SINCE[0]):
                return cause
    return None


def probe_once():
    fx = synthetic()
    try:
        status, text, LAST_MARK[0] = rest_call(sec("caller"), fx["tool"], fx["arguments"])
    except OSError:
        return 0, ""
    return status, text


def blocked_response(status, text, since):
    """집행 미확인 차단 응답인가. 재시작한 LiteLLM은 목록 단계에서 막혀 응답이 500 「Tool not found」로
    보이므로(본문에 MINT 코드 없음) 그 경우는 같은 시각 이후 MINT 로그의 차단 코드로 판정한다."""
    if status == 0 or status == 200:
        return False
    upper = text.upper()
    if "ENFORCEMENT" in upper:
        return True
    if "NOT FOUND" not in upper:
        return False
    # 목록 단계 거절은 호출 표식의 판정 사건이 없으므로 발견 판정 사건(discovery_evaluated)의 정지 사유로도 본다.
    return (log_count(r"MINT-ENFORCEMENT-UNVERIFIED", since) > 0 or n(
        f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} "
        f"AND kind='discovery_evaluated' AND inserted_at >= {lit(since.isoformat())} "
        "AND payload->'stop'->>'reason_code'='ENFORCEMENT_UNVERIFIED'") > 0)


def is_blocked():
    status, text = probe_once()
    return blocked_response(status, text, datetime.now(UTC) - timedelta(minutes=5))


def probe_blocked(seconds, expect=True):
    """호출을 반복해 (막힘|허용)이 될 때까지 걸린 시간.
    (걸린 시간, 원인, 그 뒤 추가 호출 5번의 업스트림 증가분, 처음 성립 순간까지의 증가분)."""
    started = time.monotonic()
    since = datetime.now(UTC)
    LAST_SINCE[0] = since
    before = upstream()
    while True:
        status, text = probe_once()
        # 허용을 기다릴 때는 200만 허용이다(재시작 중 LiteLLM의 「Tool not found」는 아직 막힘).
        if status and ((blocked_response(status, text, since)) if expect else status == 200):
            break
        if time.monotonic() - started > seconds:
            raise SystemExit(f"시간 상한 초과: 호출 {'차단' if expect else '허용'} ({seconds}s) "
                             f"마지막 응답 {status} {text[:300]!r}")
        time.sleep(2)
    elapsed = time.monotonic() - started
    first = upstream() - before
    cause = cause_from_event(LAST_MARK[0]) if LAST_MARK[0] else cause_of(text)
    for _ in range(5):
        probe_once()
    return elapsed, cause, upstream() - before - first, first


def revoke_and_export():
    """활성 승인을 철회하고 부정 상태 파일이 새 세대로 써질 때까지 기다린다."""
    approval = active_approval()
    if not approval:
        raise SystemExit("철회할 활성 승인이 없음")
    cli("revoke", approval, "--reason", "acceptance")
    target = epoch()
    wait(lambda: newest_negative() >= target
         and json.loads((export_root() / "latest.json").read_text(encoding="utf-8"))[
             "state_epoch"] >= target, 180, "부정 상태 파일 기록")
    return approval


def restore_after_backup(ctx, tag, mutate):
    A.db_backup(tagged(tag))
    mutate()
    started = datetime.now(UTC)
    A.db_restore(tagged(tag))
    # 철회가 일으킨 마지막 동기화 쓰기는 복원 전에 끝나므로 외부 쓰기는 복원이 끝난 뒤부터 센다.
    RESTORED_AT[0] = datetime.now(UTC)
    return started


def report_blocked(ctx, since, extra=None, from_check=None):
    elapsed, cause, upstream_calls, _ = probe_blocked(180)
    checked_ = cli("restore", "check", role="admin")[1] or {}
    observe(ctx, file_epoch=checked_.get("file_epoch"), db_epoch=checked_.get("db_epoch"),
            upstream_calls=upstream_calls, worker_external_writes=writes_since(since),
            elapsed_seconds=elapsed, cause=cause,
            events={"restore_blocked": event_count("restore_blocked", since.isoformat())},
            **(extra or {}), **(from_check(checked_) if from_check else {}))


@scenario("restore_backup_before_revoke")
def restore_backup_before_revoke(ctx):
    since = restore_after_backup(ctx, ctx.run_id + "-pre", revoke_and_export)
    report_blocked(ctx, since)


@scenario("restore_epoch_caught_up")
def restore_epoch_caught_up(ctx):
    since = restore_after_backup(ctx, ctx.run_id + "-pre", revoke_and_export)
    file_epoch = cli("restore", "check", role="admin")[1]["file_epoch"]
    rel = relation(sv())
    done = {"consumption_after_restore": 0, "confirmation_after_restore": 0,
            "observation_after_restore": 0}

    def call_approval():
        fx = synthetic()
        request = cli("call-approval", "request", "--org", rel["org_id"], "--principal-type",
                      "user", "--principal-id", "acc-restore", "--server", sv(), "--tool",
                      fx["tool"], "--arguments", json.dumps({"n": uuid.uuid4().hex}),
                      "--requested-by", "acc-restore")[1]["id"]
        cli("call-approval", "approve", request)
        return request

    # 복구 직후의 소비·확인·관측이 DB 세대를 파일 세대 이상으로 올린다(호출 경로 대신 같은 UPDATE)
    request = call_approval()
    A.psql("UPDATE mint.call_approvals SET status='consumed', consumed_invocation_id="
           f"gen_random_uuid() WHERE id={lit(request)}", "mint")
    done["consumption_after_restore"] = 1
    try:
        policy = A.psql("SELECT id FROM mint.policy_versions WHERE instance_id=" + lit(iid())
                        + " AND status='active' LIMIT 1", "mint")
        confirmation = str(uuid.uuid4())
        A.psql("INSERT INTO mint.self_confirmations (id, instance_id, org_id, principal_id, "
               "server_id, tool, args_fp, fp_key_version, policy_version_id, purpose, "
               "requested_by_key_token, expires_at) VALUES ("
               f"{lit(confirmation)}, {lit(iid())}, {lit(rel['org_id'])}, 'acc-restore', "
               f"{lit(sv())}, {lit(synthetic()['tool'])}, {lit(sha(confirmation))}, 1, "
               f"{lit(policy)}, 'acceptance', 'acc-key', now() + interval '10 minutes')", "mint")
        A.psql("UPDATE mint.self_confirmations SET status='cancelled' "
               f"WHERE id={lit(confirmation)}", "mint")
        done["confirmation_after_restore"] = 1
    except SystemExit:
        pass
    tool = synthetic()["tool"]
    A.psql("UPDATE mint.tool_contracts SET drift='description' WHERE instance_id="
           f"{lit(iid())} AND server_id={lit(sv())} AND tool={lit(tool)} AND status='approved'",
           "mint")
    A.psql("UPDATE mint.tool_contracts SET drift='none' WHERE instance_id="
           f"{lit(iid())} AND server_id={lit(sv())} AND tool={lit(tool)} AND status='approved'",
           "mint")
    done["observation_after_restore"] = 1
    while epoch() < file_epoch:  # 부족하면 호출별 승인 요청을 더해 올린다
        call_approval()
    report_blocked(ctx, since, {**done, "db_epoch_at_least_file": epoch() >= file_epoch})


@scenario("restore_consent")
def restore_consent(ctx):
    rel = relation(sv())
    consent = cli("consent", "add", "--org", rel["org_id"], "--user", "acc-consent", "--server",
                  sv(), "--purpose", "acceptance", "--data-scope", "acceptance", "--text-version",
                  "1", "--valid-until", iso(timedelta(days=1)), "--evidence-ref", "acceptance",
                  "--evidence-sha256", sha("acceptance"))[1]["id"]

    def mutate():
        cli("consent", "revoke", consent)
        target = epoch()
        wait(lambda: newest_negative() >= target, 180, "동의 철회 파일 기록")

    since = restore_after_backup(ctx, ctx.run_id + "-pre", mutate)
    # 검사 결과에 철회된 동의가 되돌릴 항목으로 나온다. 실제 재적용은 시험이 restore attest로 한다.
    report_blocked(ctx, since, from_check=lambda c: {"consent_reapplied": any(
        i.get("kind") == "consent" for i in c.get("items", []))})


def quiet_before_checkpoint(seconds):
    """작업 실행기의 주기 체크포인트(10분)는 지워진 latest.json을 다시 쓴다. 판정 주기(60초)와 호출
    관찰(180초) 안에 체크포인트가 끼면 파일이 되살아나 차단이 걸리지 않으므로, 다음 체크포인트까지
    `seconds` 넘게 남고 진행 중인 체크포인트가 없을 때 시작한다."""
    deadline = time.monotonic() + 900
    while True:
        gap = float(A.psql(
            "SELECT coalesce(extract(epoch FROM next_run_at - now()), 0) FROM mint.schedules "
            f"WHERE instance_id={lit(iid())} AND kind='export_checkpoint'", "mint") or 0)
        busy = n(f"SELECT count(*) FROM mint.jobs WHERE instance_id={lit(iid())} "
                 "AND kind='export_checkpoint' AND status IN ('pending', 'running')")
        if gap > seconds and not busy:
            return
        if time.monotonic() > deadline:
            raise SystemExit("체크포인트 사이의 조용한 구간을 기다리다 시간 초과")
        time.sleep(5)


@scenario("restore_latest_missing", undo=put_back_latest)
def restore_latest_missing(ctx):
    if not n(f"SELECT count(*) FROM mint.exports WHERE instance_id={lit(iid())} "
             "AND status='written'"):
        raise SystemExit("기록된 내보내기가 없어 export_missing을 만들 수 없음")
    latest = export_root() / "latest.json"
    quiet_before_checkpoint(240)
    keep_file(latest)
    since = datetime.now(UTC)
    A.export_unlink(latest)
    elapsed, cause, upstream_calls, _ = probe_blocked(180)
    observe(ctx, upstream_calls=upstream_calls, cause=cause, elapsed_seconds=elapsed,
            events={"restore_blocked": event_count("restore_blocked", since.isoformat())})


@scenario("restore_hmac_changed", undo=restore_keys)
def restore_hmac_changed(ctx):
    since = datetime.now(UTC)
    restart_env({"MINT_EXPORT_HMAC_KEY": new_hmac_key(), "MINT_EXPORT_HMAC_KEY_PREVIOUS": ""})
    elapsed, cause, upstream_calls, _ = probe_blocked(240)
    observe(ctx, upstream_calls=upstream_calls, cause=cause, elapsed_seconds=elapsed,
            events={"restore_blocked": event_count("restore_blocked", since.isoformat())})


@scenario("restore_previous_key", undo=restore_keys)
def restore_previous_key(ctx):
    original = original_keys()
    since = datetime.now(UTC)
    restart_env({"MINT_EXPORT_HMAC_KEY": new_hmac_key(),
                 "MINT_EXPORT_HMAC_KEY_PREVIOUS": original["MINT_EXPORT_HMAC_KEY"]})
    elapsed, _, _, first = probe_blocked(240, expect=False)
    observe(ctx, upstream_calls=first, restore_blocked=event_count(
        "restore_blocked", since.isoformat()), elapsed_seconds=elapsed)


@scenario("restore_accept_stale", undo=put_back_latest)
def restore_accept_stale(ctx):
    latest = export_root() / "latest.json"
    keep_file(latest)
    since = datetime.now(UTC)
    A.export_unlink(latest)
    probe_blocked(180)
    first = cli("restore", "accept-stale", "--reason", "acceptance", role="admin", check=False)
    time.sleep(70)  # 한 사람의 요청만으로 새 파일이 게시되어 풀리지 않는지 기다려 본다
    first_released = not is_blocked()
    second = cli("restore", "accept-stale", "--reason", "acceptance", "--second-approver",
                 A.env(ROLE_ENV["admin2"]), role="admin")
    released = probe_blocked(240, expect=False)[0] >= 0
    row = q1("SELECT requested_by, second_approver FROM mint.restore_requests WHERE "
             f"instance_id={lit(iid())} AND kind='stale_accepted' ORDER BY created_at DESC LIMIT 1")
    observe(ctx, first_operator_released=first_released, first_operator_exit=first[0],
            released=released and second[0] == 0,
            distinct_operators=len({row["requested_by"], row["second_approver"]} - {None}),
            events={"restore_stale_accepted": event_count("restore_stale_accepted",
                                                          since.isoformat())})


@scenario("restore_steady_24h")
def restore_steady_24h(ctx):
    total = int(os.environ.get("ACC_STEADY_SECONDS", "86400"))
    since = datetime.now(UTC)
    started = time.monotonic()
    stamps, blocked_samples = [started], 0
    fx, key = synthetic(), sec("caller")
    while time.monotonic() - started < total:
        time.sleep(30)
        stamps.append(time.monotonic())
        if len(stamps) % 20 == 0:  # 10분마다 실제 호출도 한 번(판정 경로의 오탐 확인)
            try:
                status, text, _ = rest_call(key, fx["tool"], fx["arguments"])
                blocked_samples += int(status != 200 and "ENFORCEMENT" in text.upper())
            except OSError:
                pass
    gaps = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    observe(ctx, duration_seconds=time.monotonic() - started,
            restore_false_positives=event_count("restore_blocked", since.isoformat())
            + blocked_samples, max_sampling_gap_seconds=max(gaps, default=0))


@scenario("restore_operator_revert", undo=cleanup)
def restore_operator_revert(ctx):
    """DS-176·178: 운영자 강등·삭제 뒤 DB를 되돌리면 권한이 되살아난다 → 차단 → attest로 되돌리고 유지."""
    tag = uuid.uuid4().hex[:6]
    demoted, removed = f"acc-demote-{tag}", f"acc-remove-{tag}"
    user = new_user()
    t_demoted = cli("operator", "add", demoted, "--role", "approver", "--user-id", user)[1]["token"]
    t_removed = cli("operator", "add", removed, "--role", "viewer")[1]["token"]

    def state():
        rows = q("SELECT name, role, expires_at IS NOT NULL AS ended FROM mint.operators "
                 f"WHERE instance_id={lit(iid())} AND name IN ({lit(demoted)}, {lit(removed)})")
        return {r["name"]: r for r in rows}

    def mutate():
        cli("operator", "set-role", demoted, "--role", "viewer")
        cli("operator", "remove", removed)
        target = epoch()
        wait(lambda: newest_negative() >= target and json.loads(
            (export_root() / "latest.json").read_text(encoding="utf-8"))["state_epoch"] >= target,
            180, "운영자 변경 파일 기록")

    since = restore_after_backup(ctx, ctx.run_id + "-pre", mutate)
    revived = state()
    elapsed, cause, upstream_calls, _ = probe_blocked(180)
    checked_ = cli("restore", "check", role="admin")[1] or {}
    writes = writes_since(since)
    attested = cli("restore", "attest", "--reason", "acceptance", role="admin")[1]
    probe_blocked(240, expect=False)
    time.sleep(20)
    after = state()
    restricted = ["intake", "approve", "00000000-0000-0000-0000-000000000000", "--reason", "x",
                  "--scope", "key", "--scope-id", "x"]
    demoted_rc, _, demoted_err = cli(*restricted, token=t_demoted, check=False)
    removed_rc, _, removed_err = cli(*restricted, token=t_removed, check=False)
    observe(ctx, file_epoch=checked_.get("file_epoch"), db_epoch=checked_.get("db_epoch"),
            upstream_calls=upstream_calls, worker_external_writes=writes,
            elapsed_seconds=elapsed, cause=cause,
            events={"restore_blocked": event_count("restore_blocked", since.isoformat())},
            operator_items_pending=sum(i.get("kind") == "operator"
                                       for i in checked_.get("items", [])),
            revived_before_attest=revived[demoted]["role"] == "approver"
            and not revived[removed]["ended"],
            reapplied_operators=sum(i["kind"] == "operator" for i in attested["reapplied"]),
            role_after=after[demoted]["role"], removed_after=after[removed]["ended"],
            demoted_token_rejected=demoted_rc != 0 and "역할로 실행할 수 없습니다" in demoted_err,
            removed_token_rejected=removed_rc != 0 and "만료" in removed_err)


# ================================================================ 본인 확인 14종

# 플러그인이 확인 행을 만들 때 쓰는 질의(plugin/snapshot.py request_confirmation)와 같은 문장
REQUEST_SQL = """
INSERT INTO mint.self_confirmations
    (id, instance_id, org_id, principal_id, server_id, tool, args_fp, fp_key_version,
     policy_version_id, purpose, requested_by_key_token, display, expires_at)
SELECT %(id)s, %(iid)s::mint.ident, %(org_id)s::mint.ident, %(principal_id)s, %(server_id)s,
       %(tool)s, %(args_fp)s, %(fp_key_version)s, %(policy_version_id)s::mint.ident, %(purpose)s,
       %(key_token)s, %(display)s, clock_timestamp() + interval '10 minutes'
WHERE (SELECT count(*) FROM mint.self_confirmations
       WHERE instance_id = %(iid)s AND principal_id = %(principal_id)s
         AND status = 'pending' AND expires_at > clock_timestamp()) < 20
ON CONFLICT DO NOTHING
"""
# 정책이 본인 확인을 요구하게 하는 승인 조건은 승인 명령의 --confirm-* 옵션(제품 경로)으로 넣는다.
# 승인 조건은 저장 뒤 바꿀 수 없다(트리거). 직접 UPDATE하지 않는다.
CONFIRM_ARGS = ("--confirm-purpose", "acceptance", "--confirm-field", "text")


def need_policy():
    text = "".join(p.read_text(encoding="utf-8")
                   for p in (A.ROOT / "policy" / "bundle").rglob("*.rego"))
    if "require_user_confirmation" not in text:
        raise A.Skip("정책 번들에 본인 확인 의무 규칙이 없음(G9 정책 확장 미병합)")


def active_policy():
    return A.psql("SELECT id FROM mint.policy_versions WHERE instance_id=" + lit(iid())
                  + " AND status='active' LIMIT 1", "mint")


def request_row(principal, args_fp, *, display=None, key_token="acc-k1"):
    """플러그인 로그인 역할로 확인 요청 행을 넣는다. 넣은 행 수(0|1)를 돌려준다."""
    import psycopg
    from psycopg.types.json import Jsonb

    params = {"id": str(uuid.uuid4()), "iid": iid(), "org_id": relation(sv())["org_id"],
              "principal_id": principal, "server_id": sv(), "tool": synthetic()["tool"],
              "args_fp": args_fp, "fp_key_version": 1, "policy_version_id": active_policy(),
              "purpose": "acceptance", "key_token": key_token, "display": Jsonb(display or {})}
    with psycopg.connect(A.env("ACC_PLUGIN_DATABASE_URL")) as conn:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                         (json.dumps([iid(), principal]),))
            return conn.execute(REQUEST_SQL, params).rowcount


STAFF_COOKIE = "__Host-mint_staff"


def http_login(path, cookie_name, key):
    """로그인 경로(관리자 /login, 직원 /staff/login)로 세션을 만든다. (클라이언트, 응답, 세션)."""
    import httpx

    client = httpx.Client(base_url=site()["api"], timeout=30, follow_redirects=False)
    reply = client.post(path, data={"key": key})
    found = re.search(re.escape(cookie_name) + r"=([^;]+)", reply.headers.get("set-cookie", ""))
    return client, reply, found.group(1) if found else None


def staff_login(key):
    return http_login("/staff/login", STAFF_COOKIE, key)


def staff_post(client, session, path):
    from mint_litellm.control.services.console_sessions import csrf_token

    return client.post(path, headers={"Cookie": f"{STAFF_COOKIE}={session}",
                                      "X-CSRF-Token": csrf_token(session)})


def staff_confirm(key, confirmation_id):
    """직원 화면 경로로 확인한다(그 키로 로그인해 확인 동작). 응답 상태를 돌려준다."""
    client, reply, session = staff_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"직원 로그인 실패(HTTP {reply.status_code})")
    return staff_post(client, session, f"/staff/confirmations/{confirmation_id}/confirm"
                      ).status_code


def confirmation_rows(**where):
    clause = " AND ".join(f"{k}={lit(v)}" for k, v in where.items())
    return q(f"SELECT id, status, display, expires_at, created_at, consumed_invocation_id "
             f"FROM mint.self_confirmations WHERE instance_id={lit(iid())} AND {clause} "
             "ORDER BY created_at")


@scenario("confirmation_freeze_columns")
def confirmation_freeze_columns(ctx):
    principal = "acc-" + uuid.uuid4().hex[:8]
    if request_row(principal, sha(principal), display={"text": "x"}) != 1:
        raise SystemExit("확인 행을 만들지 못함")
    row_id = confirmation_rows(principal_id=principal)[0]["id"]
    columns = {"principal_id": "'other'", "server_id": "'other'", "tool": "'other'",
               "args_fp": lit(sha("other")), "fp_key_version": "2", "policy_version_id": "'other'",
               "purpose": "'other'", "requested_by_key_token": "'other'",
               "expires_at": "now() + interval '1 day'", "created_at": "now()"}
    before = q1(f"SELECT * FROM mint.self_confirmations WHERE id={lit(row_id)}")
    rejected = True
    for column, value in columns.items():
        statement = f"UPDATE mint.self_confirmations SET {column} = {value} WHERE id={lit(row_id)}"
        # 플러그인 역할과 제어 역할(요청 열 변경 권한이 없는 쪽이 아니라 동결 트리거를 거치게)
        _, sqlstate = A.as_role("ACC_PLUGIN_DATABASE_URL", statement)
        rejected = rejected and sqlstate is not None
        try:
            A.psql("BEGIN; SET LOCAL ROLE mint_control; " + statement + "; COMMIT", "mint")
            rejected = False
        except SystemExit:
            pass
    after = q1(f"SELECT * FROM mint.self_confirmations WHERE id={lit(row_id)}")
    changed = [c for c in columns if before[c] != after[c]]
    observe(ctx, changed_columns=len(changed), rejected=rejected, attempted_columns=len(columns))


@scenario("confirmation_limit_20")
def confirmation_limit_20(ctx):
    principal = "acc-" + uuid.uuid4().hex[:8]
    before = upstream()
    inserted = [request_row(principal, sha(f"{principal}-{i}")) for i in range(21)]
    observe(ctx, pending=n(f"SELECT count(*) FROM mint.self_confirmations WHERE "
                           f"instance_id={lit(iid())} AND principal_id={lit(principal)} "
                           "AND status='pending'"),
            attempt_21_inserted=inserted[20], upstream_calls=upstream() - before)


@scenario("confirmation_expiry_10m")
def confirmation_expiry_10m(ctx):
    principal = "acc-" + uuid.uuid4().hex[:8]
    request_row(principal, sha(principal), display={"text": "표시 값"})
    row = confirmation_rows(principal_id=principal)[0]
    ttl = float(A.psql("SELECT extract(epoch FROM expires_at - created_at) FROM "
                       f"mint.self_confirmations WHERE id={lit(row['id'])}", "mint"))
    wait(lambda: A.psql(f"SELECT status FROM mint.self_confirmations WHERE id={lit(row['id'])}",
                        "mint") == "expired", 1000, "만료 전이", step=5)
    delay = float(A.psql("SELECT extract(epoch FROM clock_timestamp() - expires_at) FROM "
                         f"mint.self_confirmations WHERE id={lit(row['id'])}", "mint"))
    after = q1(f"SELECT display FROM mint.self_confirmations WHERE id={lit(row['id'])}")
    observe(ctx, ttl_seconds=round(ttl), expiry_delay_seconds=round(delay, 1),
            display=after["display"])


@scenario("confirmation_replica_unique", undo=cleanup)
def confirmation_replica_unique(ctx):
    import psycopg

    from mint_litellm.plugin.snapshot import CONSUME_CONFIRMATION_SQL

    principal = new_user()
    _, k1h = new_key(principal)
    k2, _ = new_key(principal)
    fp = sha(principal)
    results = []
    threads = [threading.Thread(target=lambda: results.append(
        request_row(principal, fp, key_token=k1h))) for _ in range(2)]  # 복제본 2개가 동시에 요청
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    rows = confirmation_rows(principal_id=principal)
    A.psql("INSERT INTO mint.org_bindings (id, instance_id, org_id, subject_type, subject_id, "
           f"created_by) VALUES (gen_random_uuid(), {lit(iid())}, "
           f"{lit(relation(sv())['org_id'])}, 'user', {lit(principal)}, 'acceptance')", "mint")
    if staff_confirm(k2, rows[0]["id"]) != 303:
        raise SystemExit("다른 키 확인 실패")
    row = q1(f"SELECT * FROM mint.self_confirmations WHERE id={lit(rows[0]['id'])}")
    consumed = []

    def consume():
        with psycopg.connect(A.env("ACC_PLUGIN_DATABASE_URL"), autocommit=True) as conn:
            consumed.append(conn.execute(CONSUME_CONFIRMATION_SQL, {
                "iid": iid(), "id": row["id"], "org_id": row["org_id"],
                "invocation_id": str(uuid.uuid4()), "principal_id": principal,
                "server_id": row["server_id"], "tool": row["tool"], "args_fp": row["args_fp"],
                "fp_key_version": row["fp_key_version"],
                "policy_version_id": row["policy_version_id"],
                "state_version": row["state_version"]}).rowcount)

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    observe(ctx, replicas=2, inserted=len(rows), consumed=sum(consumed),
            raw_inserts=sum(results))


# ---- 호출 경로가 필요한 확인 시험(정책 규칙이 있을 때만 장비에서 돈다)

def conf_world(*, team=False, call_approval=False):
    need_policy()
    server, tool = sv(), synthetic()["tool"]
    user = new_user()
    team_id = new_team([server]) if team else None
    # 팀 범위 호출은 user_id가 없는 팀 키여야 한다(user_id가 있으면 사용자 주체가 된다).
    k1, k1h = new_key(None if team else user, team_id, servers=[server])
    k2, k2h = new_key(user)
    rel = relation(server)
    cli("org", "bind", "--org", rel["org_id"], *(("--team", team_id) if team else ("--user", user)))
    scope = ("team", team_id) if team else ("key", k1h)
    args = ["approve", "--relation", rel["id"], "--scope", scope[0], "--scope-id", scope[1],
            "--tools", ",".join(tool_names(server)), "--valid-until", iso(timedelta(days=1)),
            "--basis", "acceptance", "--requested-by", user]
    if call_approval:
        args += ["--high-risk-tools", tool]
    args += ["--confirm-tool", tool, *CONFIRM_ARGS]
    approval = cli(*args)[1]["id"]
    return {"user": user, "k1": k1, "k1h": k1h, "k2": k2, "k2h": k2h,
            "org": rel["org_id"], "tool": tool, "approval": approval}


def wcall(w, args, startup_wait=900):
    """호출 한 번. 복원 직후 시작 유예 동안(집행 미확인·목록 단계 거절)은 같은 인자로 다시 보낸다."""
    deadline = time.monotonic() + startup_wait
    while True:
        before = upstream()
        status, text, mark = rest_call(w["k1"], w["tool"], args)
        time.sleep(site().get("settle_seconds", 2))
        starting = "ENFORCEMENT" in text.upper() or (status == 500 and "NOT FOUND" in text.upper())
        if not starting or time.monotonic() > deadline:
            break
        time.sleep(3)
    code = "MINT-CALL-APPROVAL-REQUIRED" if "MINT-CALL-APPROVAL-REQUIRED" in text else code_of(text)
    return {"status": status, "code": code, "mark": mark, "upstream": upstream() - before,
            "text": text[:200]}


def invocation_of(mark, seconds=15):
    return wait(lambda: A.psql(
        f"SELECT invocation_id FROM mint.events WHERE instance_id={lit(iid())} "
        f"AND kind='decision_evaluated' AND payload->>'litellm_call_id'={lit(mark)} LIMIT 1",
        "mint"), seconds, "판정 사건")


def confirm_pending(w):
    row = wait(lambda: next(iter(confirmation_rows(principal_id=w["user"], status="pending")),
                            None), 30, "확인 행 생성")
    if staff_confirm(w["k2"], row["id"]) != 303:
        raise SystemExit("다른 키 확인 실패")
    return row["id"]


def fresh_args():
    return {"text": "acceptance", "n": uuid.uuid4().hex}


def consumed_count(w):
    return n(f"SELECT count(*) FROM mint.self_confirmations WHERE instance_id={lit(iid())} "
             f"AND principal_id={lit(w['user'])} AND status='consumed'")


@scenario("confirmation_same_key", undo=cleanup)
def confirmation_same_key(ctx):
    w = conf_world()
    wcall(w, fresh_args())
    row = wait(lambda: next(iter(confirmation_rows(principal_id=w["user"], status="pending")),
                            None), 30, "확인 행 생성")
    status = staff_confirm(w["k1"], row["id"])  # 호출한 키와 같은 키로 로그인해 확인 시도
    observe(ctx, http_status=status, consumed=consumed_count(w),
            confirmed=n(f"SELECT count(*) FROM mint.self_confirmations WHERE "
                        f"instance_id={lit(iid())} AND principal_id={lit(w['user'])} "
                        "AND status IN ('confirmed','consumed')"))


@scenario("confirmation_other_key_once", undo=cleanup)
def confirmation_other_key_once(ctx):
    w = conf_world()
    args = fresh_args()
    first = wcall(w, args)
    confirm_pending(w)
    second, third = wcall(w, args), wcall(w, args)
    observe(ctx, upstream_calls=second["upstream"], consumed=consumed_count(w),
            second_upstream_calls=third["upstream"], first_code=first["code"],
            second_status=second["status"])


@scenario("confirmation_changed_args", undo=cleanup)
def confirmation_changed_args(ctx):
    w = conf_world()
    wcall(w, fresh_args())
    confirm_pending(w)
    other = wcall(w, fresh_args())
    observe(ctx, upstream_calls=other["upstream"], code=other["code"])


@scenario("confirmation_stale_policy", undo=cleanup)
def confirmation_stale_policy(ctx):
    w = conf_world()
    args = fresh_args()
    wcall(w, args)
    confirm_pending(w)
    # 같은 번들을 새 판본으로. 호스트에 opa 바이너리가 없어 스택 안의 CLI로 활성화한다.
    cli("policy", "activate", "acc-" + uuid.uuid4().hex[:8], stack=True)
    stale = wcall(w, args)
    observe(ctx, upstream_calls=stale["upstream"], code=stale["code"])


@scenario("confirmation_concurrent", undo=cleanup)
def confirmation_concurrent(ctx):
    w = conf_world()
    args = fresh_args()
    wcall(w, args)
    confirm_pending(w)
    results = []
    before = upstream()
    threads = [threading.Thread(target=lambda: results.append(wcall(w, args))) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    observe(ctx, submissions=len(results), consumed=consumed_count(w),
            upstream_calls=upstream() - before)


def approved_call(w, args):
    request = cli("call-approval", "request", "--org", w["org"], "--principal-type", "user",
                  "--principal-id", w["user"], "--server", sv(), "--tool", w["tool"],
                  "--arguments", json.dumps(args), "--requested-by", w["user"])[1]["id"]
    cli("call-approval", "approve", request)
    return request


def call_approvals_consumed(w):
    return n(f"SELECT count(*) FROM mint.call_approvals WHERE instance_id={lit(iid())} "
             f"AND principal_id={lit(w['user'])} AND consumed_invocation_id IS NOT NULL")


@scenario("confirmation_both_atomic", undo=cleanup)
def confirmation_both_atomic(ctx):
    w = conf_world(call_approval=True)
    args = fresh_args()
    approved_call(w, args)
    wcall(w, args)
    confirm_pending(w)
    final = wcall(w, args)
    observe(ctx, call_approvals_consumed=call_approvals_consumed(w),
            confirmations_consumed=consumed_count(w), upstream_calls=final["upstream"],
            invocation_id=invocation_of(final["mark"]))


class RowLock:
    """psql 세션 하나로 행 잠금을 쥐고 있다가 같은 트랜잭션에서 확인을 취소한다."""

    def __init__(self, row_id):
        argv = [*shlex.split(os.environ.get("ACC_COMPOSE") or
                             f"docker compose -p {A.env('COMPOSE_PROJECT_NAME', 'mint-acc')} "
                             "-f deploy/compose.yaml"),
                "exec", "-T", A.env("ACC_PG_SERVICE", "postgres"), "psql", "-U",
                A.env("ACC_PG_SUPERUSER", "postgres"), "-d", "mint", "-X", "-q", "-A", "-t",
                "-v", "ON_ERROR_STOP=1"]
        self.row_id = row_id
        self.proc = subprocess.Popen(argv, cwd=A.ROOT, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.proc.stdin.write("BEGIN;\nSELECT 'locked' FROM mint.self_confirmations WHERE id="
                              f"{lit(row_id)} FOR UPDATE;\n")
        self.proc.stdin.flush()
        if self.proc.stdout.readline().strip() != "locked":
            raise SystemExit("행 잠금을 얻지 못함")

    def cancel_and_release(self):
        self.proc.stdin.write("SET LOCAL ROLE mint_control;\nUPDATE mint.self_confirmations SET "
                              f"status='cancelled' WHERE id={lit(self.row_id)};\nCOMMIT;\n")
        self.proc.stdin.close()
        self.proc.wait(timeout=60)

    def cancel_when_contended(self, seconds=60):
        """다른 세션이 이 행 잠금을 기다리는 것이 보이는 즉시(수 ms 안) 확인을 취소하고 푼다.

        판정 예산(300ms)보다 오래 쥐면 플러그인이 잠금 대기 제한으로 먼저 포기해 「해제 뒤
        소비 실패」 경로를 타지 못하므로, 기다림이 시작된 직후에 푼다. 경합이 끝내 없으면 거짓.
        """
        self.proc.stdin.write(
            "DO $$ DECLARE t timestamptz := clock_timestamp() + "
            f"make_interval(secs => {int(seconds)}); BEGIN LOOP PERFORM pg_stat_clear_snapshot(); "
            "EXIT WHEN EXISTS (SELECT 1 FROM "
            "pg_stat_activity WHERE pid <> pg_backend_pid() AND wait_event_type = 'Lock' AND "
            "query ILIKE '%self_confirmations%'); IF clock_timestamp() > t THEN "
            "RAISE EXCEPTION 'no contention'; END IF; PERFORM pg_sleep(0.005); END LOOP; "
            "END $$;\nSET LOCAL ROLE mint_control;\nUPDATE mint.self_confirmations SET "
            f"status='cancelled' WHERE id={lit(self.row_id)};\nCOMMIT;\n")
        self.proc.stdin.close()
        return self.proc.wait(timeout=seconds + 30) == 0


@scenario("confirmation_both_rollback", undo=cleanup)
def confirmation_both_rollback(ctx):
    w = conf_world(call_approval=True)
    args = fresh_args()
    approved_call(w, args)
    wcall(w, args)
    row_id = confirm_pending(w)
    lock = RowLock(row_id)
    box = []
    before = upstream()
    thread = threading.Thread(target=lambda: box.append(wcall(w, args)))
    thread.start()
    # 플러그인이 호출별 승인을 소비한 뒤 확인 행 갱신에서 기다리기 시작하면 확인을 취소하고 푼다.
    # 풀린 뒤 확인 소비가 실패하면 같은 트랜잭션의 호출별 승인 소비도 되돌아가야 한다(설계 경로).
    contended = lock.cancel_when_contended()
    thread.join()
    # 사건은 호출 직후 또는 플러그인 주기의 버퍼 재적재 안에 DB에 나타나야 한다.
    observe(ctx, contended=contended, call_approvals_consumed=call_approvals_consumed(w),
            confirmations_consumed=consumed_count(w), upstream_calls=upstream() - before,
            invocation_id=invocation_of(box[0]["mark"], limit("observe_seconds") + 30),
            code=box[0]["code"])


@scenario("confirmation_team_no_row", undo=cleanup)
def confirmation_team_no_row(ctx):
    w = conf_world(team=True)
    since = db_now()
    blocked = wcall(w, fresh_args())
    observe(ctx, inserted=n(f"SELECT count(*) FROM mint.self_confirmations WHERE "
                            f"instance_id={lit(iid())} AND created_at >= {lit(since)}"),
            upstream_calls=blocked["upstream"], code=blocked["code"])


@scenario("confirmation_call_approval_only", undo=cleanup)
def confirmation_call_approval_only(ctx):
    """호출별 승인과 본인 확인이 함께 걸린 도구는 호출별 승인을 먼저 본다.

    승인이 없으면 확인 행을 만들지 않는다(승인되지 않은 호출을 이용자에게 확인시키지 않는다).
    승인이 생기면 그 다음 단계인 확인 행이 만들어진다.
    """
    w = conf_world(call_approval=True)
    args = fresh_args()
    blocked = wcall(w, args)
    rows_before = len(confirmation_rows(principal_id=w["user"]))
    approved_call(w, args)
    wcall(w, args)
    observe(ctx, upstream_calls=blocked["upstream"], code=blocked["code"],
            rows_before_approval=rows_before,
            rows_after_approval=len(confirmation_rows(principal_id=w["user"])))


# ================================================================ 인증·화면 9종(+이행 1종)

SESSION_COOKIE = "__Host-mint_session"


def console_user(role, name_prefix="acc"):
    """사람 사용자와 키, 그 사용자에 결속된 운영자 행(role이 None이면 운영자 행 없음)."""
    user = new_user()
    key, kid = new_key(user)
    if role:
        cli("operator", "add", f"{name_prefix}-{uuid.uuid4().hex[:8]}", "--role", role,
            "--user-id", user)
    return user, key, kid


def console_login(key):
    import httpx

    client = httpx.Client(base_url=site()["api"], timeout=30, follow_redirects=False)
    reply = client.post("/login", data={"key": key})
    found = re.search(re.escape(SESSION_COOKIE) + r"=([^;]+)", reply.headers.get("set-cookie", ""))
    return client, reply, found.group(1) if found else None


def console_request(client, method, path, session, body=None, *, csrf="valid"):
    from mint_litellm.control.services.console_sessions import csrf_token

    headers = {"Cookie": f"{SESSION_COOKIE}={session}"}
    if csrf == "valid":
        headers["X-CSRF-Token"] = csrf_token(session)
    elif csrf == "wrong":
        headers["X-CSRF-Token"] = "0" * 64
    return client.request(method, path, json=body, headers=headers)


def sessions_of(user, active_only=False):
    return n(f"SELECT count(*) FROM mint.console_sessions WHERE instance_id={lit(iid())} "
             f"AND user_id={lit(user)}" + (" AND revoked_at IS NULL AND idle_expiry > now() "
                                          "AND absolute_expiry > now()" if active_only else ""))


def org_probe(name):
    return n(f"SELECT count(*) FROM mint.orgs WHERE instance_id={lit(iid())} "
             f"AND org_id={lit(name)}")


@scenario("auth_no_plaintext", undo=cleanup)
def auth_no_plaintext(ctx):
    user, key, _ = console_user("viewer")
    client, reply, session = console_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"로그인 실패(HTTP {reply.status_code})")
    for path in ("/api/v1/overview", "/api/v1/servers", "/api/v1/ledger"):
        console_request(client, "GET", path, session, csrf="none")
    pg, su = A.env("ACC_PG_SERVICE", "postgres"), A.env("ACC_PG_SUPERUSER", "postgres")
    found, complete = {}, True

    def search(name, text_or_none):
        nonlocal complete
        if text_or_none is None:
            complete = False
            found[name] = 0
        else:
            found[name] = text_or_none.count(key)

    dump = A.compose("exec", "-T", pg, "pg_dump", "-U", su, "-d", "mint", "--data-only",
                     check=False, timeout=600)
    search("database", dump.stdout if dump.returncode == 0 else None)
    logs = A.compose("logs", "--no-color", check=False, timeout=300)
    search("logs", logs.stdout + logs.stderr if logs.returncode == 0 else None)
    rows = A.psql("SELECT coalesce(string_agg(s::text, E'\\n'), '') FROM mint.console_sessions s "
                  f"WHERE user_id={lit(user)}", "mint")
    search("sessions", rows)
    buffer = A.compose("exec", "-T", os.environ.get("ACC_BUFFER_SERVICE", "litellm"), "sh", "-c",
                       'grep -rF -- "$1" "$2" 2>/dev/null; true', "_", key,
                       os.environ.get("ACC_BUFFER_CONTAINER_DIR", "/var/lib/mint/buffer"),
                       check=False, timeout=300)
    search("buffer", buffer.stdout if buffer.returncode == 0 else None)
    observe(ctx, matches=sum(found.values()), per_location=found, search_complete=complete,
            searched_locations=sorted(found), sentinel_sha256=sha(key))


def session_end(ctx, how):
    user, key, _ = console_user("viewer")
    client, reply, session = console_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"로그인 실패(HTTP {reply.status_code})")
    started = A.psql("SELECT clock_timestamp()", "mint")
    if how == "block":
        lite("POST", "/key/block", {"key": key})
    else:
        lite("POST", "/key/delete", {"keys": [key]})
    wait(lambda: sessions_of(user, active_only=True) == 0, 360, "세션 종료", step=5)
    ended = float(A.psql("SELECT extract(epoch FROM max(revoked_at) - "
                         f"{lit(started)}::timestamptz) FROM mint.console_sessions "
                         f"WHERE instance_id={lit(iid())} AND user_id={lit(user)}", "mint"))
    after = console_request(client, "GET", "/api/v1/overview", session, csrf="none")
    observe(ctx, ended_seconds=round(ended, 1), active_sessions=sessions_of(user, True),
            api_status_after=after.status_code)


@scenario("auth_blocked_key", undo=cleanup)
def auth_blocked_key(ctx):
    session_end(ctx, "block")


@scenario("auth_deleted_key", undo=cleanup)
def auth_deleted_key(ctx):
    session_end(ctx, "delete")


@scenario("auth_unbound_viewer", undo=cleanup)
def auth_unbound_viewer(ctx):
    user, key, _ = console_user(None)  # 사람 키이지만 운영자 행이 없는 사용자
    _, reply, session = console_login(key)
    observe(ctx, http_status=reply.status_code, sessions_created=sessions_of(user),
            cookie_issued=session is not None)


@scenario("auth_viewer_write", undo=cleanup)
def auth_viewer_write(ctx):
    _, key, _ = console_user("viewer")
    client, reply, session = console_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"로그인 실패(HTTP {reply.status_code})")
    org = "acc-w-" + uuid.uuid4().hex[:8]
    since = db_now()
    result = console_request(client, "POST", "/api/v1/orgs", session,
                             {"org_id": org, "name": org})
    observe(ctx, http_status=result.status_code,
            mutations=org_probe(org) + n(
                f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} "
                f"AND kind='org_created' AND inserted_at >= {lit(since)}"))


@scenario("auth_csrf", undo=cleanup)
def auth_csrf(ctx):
    _, key, _ = console_user("admin")
    client, reply, session = console_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"로그인 실패(HTTP {reply.status_code})")
    since = db_now()
    org = "acc-c-" + uuid.uuid4().hex[:8]
    missing = console_request(client, "POST", "/api/v1/orgs", session,
                              {"org_id": org, "name": org}, csrf="none")
    wrong = console_request(client, "POST", "/api/v1/orgs", session,
                            {"org_id": org + "x", "name": org}, csrf="wrong")
    observe(ctx, http_status=missing.status_code, wrong_token_status=wrong.status_code,
            mutations=org_probe(org) + org_probe(org + "x") + n(
                f"SELECT count(*) FROM mint.events WHERE instance_id={lit(iid())} "
                f"AND kind='org_created' AND inserted_at >= {lit(since)}"))


@scenario("auth_escape", undo=cleanup)
def auth_escape(ctx):
    _, key, _ = console_user("admin")
    marker = "acc" + uuid.uuid4().hex[:6]
    payload = f"<script>document.title='{marker}'</script><img src=x onerror=alert(1)>"
    cli("org", "add", "acc-e-" + uuid.uuid4().hex[:8], "--name", payload)
    client, reply, session = console_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"로그인 실패(HTTP {reply.status_code})")
    page = console_request(client, "GET", "/admin", session, csrf="none")
    html = page.text
    raw_tags = html.count("<script>document.title") + html.count("<img src=x onerror")
    csp = page.headers.get("content-security-policy", "")
    observe(ctx, executed_scripts=raw_tags,
            escaped=("&lt;script&gt;" in html and marker in html and raw_tags == 0),
            csp_default_src_self="default-src 'self'" in csp, page_status=page.status_code)


STAFF_FORBIDDEN_HTTP = (
    ("POST", "/api/v1/orgs", {"org_id": "acc-staff", "name": "acc-staff"}),
    ("POST", "/api/v1/approvals", {"relation_id": "x", "scope_type": "key", "scope_id": "x",
                                   "tools": ["x"], "basis": "x", "requested_by": "x",
                                   "state_version": 1}),
    ("POST", "/api/v1/denials", {"scope_type": "server", "scope_id": "x", "reason": "x"}),
    ("POST", "/api/v1/settings/mode", {"mode": "observe", "state_version": 1}),
)
STAFF_FORBIDDEN_SQL = (
    "INSERT INTO mint.orgs (instance_id, org_id, name) VALUES ('{iid}', 'acc-staff-db', 'x')",
    "INSERT INTO mint.denials (id, instance_id, scope_type, scope_id, reason, created_by) "
    "VALUES (gen_random_uuid(), '{iid}', 'server', 'x', 'x', 'staff')",
    "UPDATE mint.approvals SET status = 'revoked' WHERE instance_id = '{iid}'",
    "SELECT mint.raise_epoch('{iid}', 1000000)",
)


def mutation_marks():
    return [n(f"SELECT count(*) FROM mint.{t} WHERE instance_id={lit(iid())}")
            for t in ("orgs", "denials", "events", "approvals")] + [
        n(f"SELECT count(*) FROM mint.approvals WHERE instance_id={lit(iid())} "
          "AND status='revoked'"), epoch()]


@scenario("auth_staff_write", undo=cleanup)
def auth_staff_write(ctx):
    from mint_litellm.control.services.console_sessions import csrf_token

    _, key, _ = console_user(None)  # 운영자 행이 없는 직원
    client, reply, session = staff_login(key)
    if reply.status_code != 303 or not session:
        raise SystemExit(f"직원 로그인 실패(HTTP {reply.status_code})")
    window = datetime.now(UTC)
    before = mutation_marks()
    accepted = 0
    for method, path, body in STAFF_FORBIDDEN_HTTP:
        # 직원 쿠키를 관리자 쿠키 이름으로도 실어 보낸다(어느 쪽으로도 인증되면 안 된다)
        headers = {"Cookie": f"{STAFF_COOKIE}={session}; {SESSION_COOKIE}={session}",
                   "X-CSRF-Token": csrf_token(session)}
        result = client.request(method, path, json=body, headers=headers)
        accepted += int(200 <= result.status_code < 300)
    refused = sum(int(A.as_role("ACC_STAFF_DATABASE_URL", statement.format(iid=iid()))[1]
                      is not None) for statement in STAFF_FORBIDDEN_SQL)
    after = mutation_marks()
    names = ("orgs", "denials", "events", "approvals", "revoked", "epoch")
    observe(ctx, api_mutations=accepted,
            mutation_detail={k: [a, b] for k, a, b in zip(names, before, after, strict=True)
                             if a != b},
            new_event_kinds=A.psql(
                "SELECT coalesce(string_agg(kind || ':' || coalesce(source_key, ''), ' | '), '') "
                f"FROM mint.events WHERE instance_id={lit(iid())} "
                f"AND inserted_at >= {lit(window.isoformat())}", "mint"),
            db_mutations=sum(abs(a - b) for a, b in zip(before, after, strict=True)),
            forbidden_operations_tested=len(STAFF_FORBIDDEN_HTTP), db_refused=refused,
            db_attempted=len(STAFF_FORBIDDEN_SQL))


SCREEN_PATHS = ("/", "/servers", "/intakes", "/approvals", "/contracts", "/revocations",
                "/call-approvals", "/ledger", "/policy", "/admin", "/staff",
                "/staff/confirmations", "/staff/consents")


@scenario("auth_screens_13", undo=cleanup)
def auth_screens_13(ctx):
    """화면 13개를 실제 세션으로 열고, 스크린샷·대비·키보드·문구 검수는 장비 도구가 맡는다."""
    spec = os.environ.get("ACC_UI_AUDIT_CMD")
    if not spec or not os.environ.get("ACC_UI_REVIEWER"):
        # DS-174·176: 도구가 없으면 합격으로 세지 않고 「미실행」(수동 검수 대기)으로 적는다.
        raise A.Skip("미실행: 화면별 대비 수치·키보드 초점 이동은 sol 검수·메인 캡처로 받음")
    _, admin_key, _ = console_user("admin")
    _, staff_key, _ = console_user(None)
    admin, admin_reply, admin_session = http_login("/login", SESSION_COOKIE, admin_key)
    staff, staff_reply, staff_session = staff_login(staff_key)
    if admin_reply.status_code != 303 or staff_reply.status_code != 303:
        raise SystemExit("화면 시험 로그인 실패")
    reachable = []
    for path in SCREEN_PATHS:
        client, cookie = ((staff, f"{STAFF_COOKIE}={staff_session}") if path.startswith("/staff")
                          else (admin, f"{SESSION_COOKIE}={admin_session}"))
        if client.get(path, headers={"Cookie": cookie}).status_code == 200:
            reachable.append(path)
    done = A.run([*json.loads(spec)], stdin=json.dumps({
        "base": site()["api"], "paths": reachable,
        "cookies": {"admin": [SESSION_COOKIE, admin_session],
                    "staff": [STAFF_COOKIE, staff_session]}}), timeout=1800)
    audit = json.loads(done.stdout)
    observe(ctx, screen_count=len(reachable), reachable=reachable,
            screenshots=audit["screenshots"], reviewer=os.environ["ACC_UI_REVIEWER"],
            explanatory_paragraphs=audit["explanatory_paragraphs"],
            allowed_consent_text=audit.get("allowed_consent_text", 0),  # DS-207 2: 허용: 동의 문언
            english_enums=audit["english_enums"], contrast_min=audit["contrast_min"],
            keyboard_failures=audit["keyboard_failures"])


# ================================================================ 이행 1종

def stage1_stack():
    from . import stage1

    state = Path(A.env("ACC_STATE_DIR")).parent
    return stage1.Stack(state / "stage1", A.ROOT, A.env("ACC_CERT_DIR"),
                        site()["counters"]["synthetic"], A.env("COMPOSE_PROJECT_NAME"))


def stage1_cleanup(ctx=None):
    if not os.environ.get("ACC_KEEP_STAGE1"):
        stage1_stack().teardown()


def stage1_measure():
    """1단계 SHA 스택 → 1단계 데이터 → `mint.sh upgrade` → 호출 측정(항목 12)."""
    from . import stage1

    head = A.run(["git", "rev-parse", "HEAD"]).stdout.strip()
    try:
        return stage1_stack().run(head)
    except stage1.Stage1Failure as error:
        raise SystemExit("이행 시험 실패: " + str(error)) from None


@scenario("migration_v001", undo=stage1_cleanup)
def migration_v001(ctx):
    measured = stage1_measure()
    observe(ctx, **{k: v for k, v in measured.items() if not k.startswith("confirmation_")})


@scenario("confirmation_v001_isolation", undo=stage1_cleanup)
def confirmation_v001_isolation(ctx):
    measured = stage1_measure()
    observe(ctx, confirmation_rows_seen=measured["confirmation_rows_seen"],
            confirmation_rows_consumed=measured["confirmation_rows_consumed"],
            stage1_call_approval_consumed=measured["stage1_call_approval_consumed"],
            ready_seconds_after_upgrade=measured["ready_seconds_after_upgrade"])
