# ruff: noqa: E501
"""엔드포인트 평면 합격 기준 실행기(오케스트레이터). 기기와 pj1에 ssh로 접속할 수 있는 곳에서 돌린다.

환경 변수(주소·계정은 저장소에 쓰지 않는다):
  EP_SSH_DEVICE  기기에 명령을 보내는 접두(예: "ssh -o BatchMode=yes user@host" 또는 "wsl -d kali-linux -- ssh ...")
  EP_SSH_PJ1     pj1에 명령을 보내는 접두
  EP_DEVICE_REPO 기기의 복제본 경로(기본 ~/mint-ep-repo), EP_HOME(기본 ~/mint-ep)
  EP_BASE        pj1이 닿는 스택 주소(예: http://기기주소:4500), EP_LOCAL_BASE(기기 안, 기본 http://localhost:4500)
사용: python accept.py --out <증거 폴더> [--only 이름,이름] [--dry]
각 기준은 (이름, 통과 여부 또는 None=미실행, 증거)를 내고 results.json·results.md로 남는다. 비밀은 출력하지 않는다.
모든 기준은 끝에 스택과 pj1을 시작 상태로 되돌리려 시도한다(승인 재부여, 멈춘 컨테이너 재개).
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOOK = HERE.parents[2] / "src" / "mint_litellm" / "endpoint" / "hook.py"
DRY = False
PJ1_DIR = "/tmp/mintx/ep"
LOG: list[dict] = []


def sh(prefix: str, command: str, stdin: str | None = None, timeout: int = 600) -> str:
    argv = [*shlex.split(prefix), command]
    if DRY:
        print("DRY", prefix.split()[-1] if prefix else "", command[:160])
        return "{}"
    done = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    return done.stdout + (done.stderr if done.returncode and not done.stdout else "")


def device(command: str, **kw) -> str:
    return sh(os.environ["EP_SSH_DEVICE"], command, **kw)


def pj1(command: str, **kw) -> str:
    return sh(os.environ["EP_SSH_PJ1"], command, **kw)


def j(text: str):
    try:
        return json.loads(text.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"raw": text[-300:]}


STATE = os.environ.get("EP_HOME", "~/mint-ep")
REPO = os.environ.get("EP_DEVICE_REPO", "~/mint-ep-repo")
BASE = os.environ.get("EP_BASE", "http://localhost:4500")
LOCAL = os.environ.get("EP_LOCAL_BASE", "http://localhost:4500")
COMPOSE = (
    f"cd {REPO}/deploy && COMPOSE_PROJECT_NAME=mintep EP_STATE={STATE} EP_PUBLIC_URL={BASE} "
    "docker compose --env-file .env -f compose.yaml -f ../tests/endpoint/device/ep.yaml"
)
SECRETS: dict = {}


def secrets() -> dict:
    if not SECRETS:
        SECRETS.update(j(device(f"cat {STATE}/ep.json")) if not DRY else {})
    return SECRETS


def cli(*args: str, token: str = "ADMIN_TOKEN") -> dict:
    env = f"MINT_OPERATOR_TOKEN={shlex.quote(secrets().get(token, ''))}"
    quoted = " ".join(shlex.quote(a) for a in args)
    return j(device(f"cd {REPO}/deploy && {env} ./mint.sh cli {quoted} --json < /dev/null"))


def client(side, sub: str, *args: str, key: str = "USER1_KEY", base: str | None = None) -> dict:
    """ep_client.py를 pj1(기본) 또는 기기에서 돌린다. 키는 환경 변수로만 넘긴다."""
    where = "device" if side is device else "pj1"
    script = (
        f"{REPO}/tests/endpoint/device/ep_client.py"
        if where == "device"
        else f"{PJ1_DIR}/ep_client.py"
    )
    contract = (
        f"--registry {STATE}/endpoint/registry.json"
        if where == "device"
        else f"--hook {PJ1_DIR}/hook.py --mcp-config ~/.claude.json"
    )
    command = (
        f"EPK={shlex.quote(secrets().get(key, ''))}; python3 {script} {sub} --base {base or (LOCAL if where == 'device' else BASE)} "
        f'--key "$EPK" {contract} ' + " ".join(args)
    )
    return j(side(command))


def pause(seconds: float) -> None:
    if not DRY:
        time.sleep(seconds)


def record(name: str, passed, **evidence) -> None:
    LOG.append({"name": name, "passed": passed, **evidence})
    print(
        f"{'PASS' if passed else 'FAIL' if passed is False else 'SKIP'} {name} {json.dumps(evidence)[:300]}"
    )


def claude_call(tool_args: str = '{"text":"hello"}') -> dict:
    """pj1의 실제 Claude Code로 도구 하나를 부르고 시작·실행 횟수를 센다(승인된 사용자 수준 설치가 되어 있어야 한다)."""
    text = pj1(
        "rm -f /tmp/mintx/count.log; timeout 120 ~/.local/bin/claude -p "
        f"{shlex.quote('Call the tool mcp__cnt__echo with this JSON arguments exactly once: ' + tool_args + ' If it is blocked, do not retry; report the error text.')} "
        "--allowedTools mcp__cnt__echo --max-turns 4 > /tmp/mintx/ask.out 2>&1; "
        "python3 -c \"import json;l=[json.loads(x) for x in open('/tmp/mintx/count.log')] if __import__('os').path.exists('/tmp/mintx/count.log') else [];"
        "print(json.dumps({'starts':sum(e['ev']=='start' for e in l),'calls':sum(e['ev']=='call' for e in l),'reply':open('/tmp/mintx/ask.out').read()[:240]}))\""
    )
    return j(text)


def reapprove() -> str:
    """철회한 뒤 같은 사용자·도구의 승인을 다시 만든다."""
    s = secrets()
    out = cli(
        "approve",
        "--relation",
        s.get("RELATION", ""),
        "--scope",
        "user",
        "--scope-id",
        "ep-user1",
        "--tools",
        "echo,slow",
        "--valid-until",
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400 * 30)),
        "--basis",
        "endpoint exploration",
        "--requested-by",
        "ep-owner",
        "--high-risk-tools",
        "slow",
        token="APPROVER_TOKEN",
    )
    new = out.get("approval_id") or out.get("id") or ""
    s["APPROVAL"] = new
    return new


def grant_call(arguments: dict) -> str:
    request = cli(
        "call-approval",
        "request",
        "--org",
        "org1",
        "--principal-type",
        "user",
        "--principal-id",
        "ep-user1",
        "--server",
        secrets().get("SERVER_ID", "srv-local-cnt"),
        "--tool",
        "slow",
        "--arguments",
        json.dumps(arguments),
        "--requested-by",
        "ep-admin",
    )
    ident = request.get("call_approval_id") or request.get("id") or ""
    cli("call-approval", "approve", ident, token="APPROVER_TOKEN")
    return ident


# ---- 기준 -----------------------------------------------------------------------------------------


def step_gate():
    """일반 사용자 키로 통과해야 하고(관리자 키 금지), 무키·만료·폐기·다른 조직 키는 거부된다."""
    allowed = client(pj1, "decide")
    noroute = client(pj1, "decide", key="USER1_NOROUTE_KEY")
    other_org = client(pj1, "decide", key="USER2_KEY")
    nokey = client(pj1, "decide", key="NO_SUCH")
    master = client(pj1, "decide", key="MASTER")
    record("gate-user-key", allowed.get("verdict") == "allow", detail=allowed.get("verdict"))
    record("gate-route-not-listed", noroute.get("status") != 200, status=noroute.get("status"))
    record(
        "gate-other-org",
        other_org.get("verdict") == "deny",
        answer=other_org.get("answer", {}).get("error"),
    )
    record("gate-no-such-key", nokey.get("status") in (400, 401, 403), status=nokey.get("status"))
    record(
        "gate-master-key",
        master.get("verdict") == "deny",
        answer=master.get("answer", {}).get("error"),
    )
    s = secrets()
    made = j(
        pj1(
            f'curl -s -X POST {BASE}/key/generate -H "Authorization: Bearer {s.get("MASTER", "")}" '
            '-H "Content-Type: application/json" -d \'{"user_id":"ep-user1","allowed_routes":["/mint/v1"],'
            '"duration":"8s","object_permission":{"mcp_servers":["srv-local-cnt"]}}\''
        )
    )
    short = made.get("key", "")
    pause(10)
    SECRETS["SHORT_KEY"] = short
    expired = client(pj1, "decide", key="SHORT_KEY")
    record("gate-expired-key", expired.get("status") == 401, status=expired.get("status"))


def step_kit():
    s = secrets()
    for name in ("ep_client.py", "make_registry.py"):
        pj1(
            f"mkdir -p {PJ1_DIR} && cat > {PJ1_DIR}/{name}",
            stdin=(HERE / name).read_text(encoding="utf-8"),
        )
    pj1(f"mkdir -p {PJ1_DIR} && cat > {PJ1_DIR}/hook.py", stdin=HOOK.read_text(encoding="utf-8"))
    pj1(
        f"umask 077; cat > {PJ1_DIR}/hdr", stdin=f"Authorization: Bearer {s.get('USER1_KEY', '')}\n"
    )
    pj1(
        f"cd {PJ1_DIR} && curl -fsS -H @hdr {BASE}/mint/v1/kit -o kit.tgz && rm -rf kit && mkdir kit && tar xzf kit.tgz -C kit"
    )
    before = pj1("sha256sum ~/.claude/settings.json | cut -c1-16")
    SECRETS["SETTINGS_SHA_BEFORE"] = before.strip()
    out = pj1(f"cd {PJ1_DIR}/kit/mint-kit && bash install.sh </dev/null 2>&1 | tail -3")
    reports = device(
        f"{COMPOSE} exec -T litellm cat /var/lib/mint/buffer/endpoint-reports.jsonl | tail -2"
    )
    record(
        "kit-install-user-level",
        "사용자 수준" in out and '"managed": false' in reports,
        out=out.strip()[-160:],
    )


def step_control():
    result = claude_call()
    record(
        "control-allow-runs-once", result.get("starts") == 1 and result.get("calls") == 1, **result
    )


def step_failures():
    """각 장애에서 실행 0회, 훅 안내 시간, 복구 뒤 허용 재개."""
    faults = {
        "decision-service-stopped": ("docker stop {c}", "docker start {c}"),
        "decision-service-paused": ("docker pause {c}", "docker unpause {c}"),
        "database-stopped": ("docker stop {pg}", "docker start {pg}"),
        "policy-engine-stopped": ("docker stop {opa}", "docker start {opa}"),
    }
    names = {"c": "mintep-litellm-1", "pg": "mintep-postgres-1", "opa": "mintep-opa-1"}
    for fault, (down, up) in faults.items():
        device(down.format(**names))
        pause(2)
        run = claude_call()
        hook = client(
            pj1,
            "hook-latency",
            "--key-file ~/.config/mint/key --hook ~/.local/lib/mint-endpoint/hook.py --n 3",
        )
        device(up.format(**names))
        started = time.time()
        recovered = None
        while not DRY and time.time() - started < 120:
            if client(pj1, "decide").get("verdict") == "allow":
                recovered = round(time.time() - started, 1)
                break
            pause(2)
        record(
            f"fail-{fault}",
            run.get("calls") == 0 and hook.get("max", 99999) <= 3000 and recovered is not None,
            calls=run.get("calls"),
            hook_max_ms=hook.get("max"),
            blocked=hook.get("blocked"),
            recovered_s=recovered,
        )


def step_identity():
    """다른 사용자·조직·인자 거부, 호출별 승인 1회 소비, 병렬 소비 1건 이하, 소비 직후 응답 유실."""
    ident = grant_call({"text": "approved"})
    first = client(pj1, "decide", '--tool slow --args \'{"text": "approved"}\'')
    again = client(pj1, "decide", '--tool slow --args \'{"text": "approved"}\'')
    record(
        "identity-call-approval-consumed-once",
        first.get("verdict") == "allow" and again.get("verdict") == "deny",
        first=first.get("verdict"),
        second=again.get("verdict"),
        approval=bool(ident),
    )
    grant_call({"text": "approved"})
    changed = client(pj1, "decide", '--tool slow --args \'{"text": "changed"}\'')
    record(
        "identity-changed-arguments",
        changed.get("verdict") == "deny",
        verdict=changed.get("verdict"),
    )
    grant_call({"text": "race"})
    race = client(pj1, "race", '--tool slow --args \'{"text": "race"}\' --n 8')
    record(
        "identity-parallel-consume",
        race.get("allowed", 99) <= 1,
        allowed=race.get("allowed"),
        verdicts=race.get("verdicts"),
    )
    grant_call({"text": "lost"})
    client(pj1, "lost-response", '--tool slow --args \'{"text": "lost"}\'')
    pause(1)
    after = client(pj1, "decide", '--tool slow --args \'{"text": "lost"}\'')
    events = cli("ledger", "list", "--kind", "decision_evaluated", "--limit", "20")
    record(
        "identity-response-lost-after-consume",
        after.get("verdict") == "deny",
        retried=after.get("verdict"),
        note="소비는 1건이고 재시도는 거부된다. 실행 여부는 단말의 주장(결과 미확인).",
        recent_events=len(events.get("events", events.get("items", [])) or []),
    )


def step_revoke():
    s = secrets()
    approval = s.get("APPROVAL", "")
    token = shlex.quote(s.get("APPROVER_TOKEN", ""))
    command = f"cd {REPO}/deploy && MINT_OPERATOR_TOKEN={token} ./mint.sh cli revoke {approval} --reason acceptance --json < /dev/null"
    result = client(device, "revoke-latency", f"--cmd {shlex.quote(command)}")
    delay = result.get("seconds_to_deny")
    record("revoke-approval-to-deny", delay is not None and delay <= 2.0, **result)
    run = claude_call()
    record("revoke-claude-call-blocked", run.get("calls") == 0, calls=run.get("calls"))
    reapprove()
    key_made = j(
        device(
            f'curl -s -X POST {LOCAL}/key/generate -H "Authorization: Bearer {s.get("MASTER", "")}" -H "Content-Type: application/json" '
            '-d \'{"user_id":"ep-user1","allowed_routes":["/mint/v1"],"object_permission":{"mcp_servers":["srv-local-cnt"]}}\''
        )
    )
    SECRETS["TEMP_KEY"] = key_made.get("key", "")
    first = client(pj1, "decide", key="TEMP_KEY")
    device(
        f'curl -s -X POST {LOCAL}/key/delete -H "Authorization: Bearer {s.get("MASTER", "")}" -H "Content-Type: application/json" '
        f'-d \'{{"keys":["{SECRETS["TEMP_KEY"]}"]}}\''
    )
    second = client(pj1, "decide", key="TEMP_KEY")
    record(
        "revoke-key-deleted",
        first.get("verdict") == "allow" and second.get("status") in (401, 403),
        before=first.get("verdict"),
        after=second.get("status"),
    )


def step_perf():
    for par in (1, 8):
        stats = client(
            pj1,
            "hook-latency",
            f"--key-file ~/.config/mint/key --hook ~/.local/lib/mint-endpoint/hook.py --n 100 --par {par}",
        )
        ok = stats.get("p95", 99999) <= 500 and stats.get("other", 1) == 0
        record(f"perf-hook-par{par}", ok, **stats)


def step_ghidra():
    record(
        "ghidra-readonly-query",
        None,
        note="pj1에 pyghidra-mcp가 설치되어 있지 않다. 설치·계약 승인 뒤 별도로 실행한다.",
    )


def step_uninstall():
    out = pj1(f"cd {PJ1_DIR}/kit/mint-kit && bash install.sh uninstall </dev/null 2>&1 | tail -2")
    after = pj1("sha256sum ~/.claude/settings.json | cut -c1-16").strip()
    record(
        "kit-uninstall-restores",
        after == SECRETS.get("SETTINGS_SHA_BEFORE"),
        sha_equal=after == SECRETS.get("SETTINGS_SHA_BEFORE"),
        out=out.strip()[-120:],
    )


STEPS = {
    "gate": step_gate,
    "kit": step_kit,
    "control": step_control,
    "identity": step_identity,
    "revoke": step_revoke,
    "failures": step_failures,
    "perf": step_perf,
    "ghidra": step_ghidra,
    "uninstall": step_uninstall,
}
ORDER = ["kit", "gate", "control", "identity", "revoke", "failures", "perf", "ghidra", "uninstall"]


def write(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(
        json.dumps(LOG, indent=1, ensure_ascii=False), encoding="utf-8"
    )
    rows = ["| 기준 | 결과 | 증거 |", "| --- | --- | --- |"]
    for item in LOG:
        mark = {True: "통과", False: "실패", None: "미실행"}[item["passed"]]
        detail = {k: v for k, v in item.items() if k not in ("name", "passed")}
        rows.append(
            f"| {item['name']} | {mark} | `{json.dumps(detail, ensure_ascii=False)[:200]}` |"
        )
    (out / "results.md").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    global DRY
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--only")
    parser.add_argument("--dry", action="store_true")
    args = parser.parse_args(argv)
    DRY = args.dry
    wanted = args.only.split(",") if args.only else ORDER
    for name in ORDER:
        if name in wanted:
            try:
                STEPS[name]()
            except Exception as exc:  # 한 기준의 오류가 나머지를 막지 않는다.
                record(name, False, error=type(exc).__name__, detail=str(exc)[:200])
    write(Path(args.out))
    return 0 if all(item["passed"] is not False for item in LOG) else 1


if __name__ == "__main__":
    sys.exit(main())
