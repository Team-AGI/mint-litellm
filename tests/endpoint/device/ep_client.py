# ruff: noqa: E501
"""합격 기준 실행에 쓰는 작은 클라이언트(표준 라이브러리만). pj1과 기기 양쪽에서 돌린다.

하위 명령 모두 JSON 한 줄을 출력한다.
  decide        결정 경로에 한 번 묻는다(상태 코드, 응답, 걸린 시간).
  race          같은 요청을 N개 동시에 보낸다(병렬 승인 소비 시험).
  lost-response 요청을 보내고 응답을 읽지 않은 채 연결을 닫는다(소비 직후 응답 유실 시험).
  revoke-latency 명령(승인 철회)이 끝난 뒤 첫 거부까지 걸린 시간(같은 시계로 잰다).
  hook-latency  훅 스크립트를 N번(병렬 P) 실제 프로세스로 실행해 지연 분위수를 낸다.
계약은 --registry(승인 계약 파일의 첫 서버, 작업 디렉터리만 /로 채움) 또는 --hook·--mcp-config(훅이 만드는 선언)로 정한다.
"""

import argparse
import concurrent.futures
import importlib.util
import json
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def load_hook(path):
    spec = importlib.util.spec_from_file_location("mint_hook", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["mint_hook"] = module
    spec.loader.exec_module(module)
    return module


def contract_for(args):
    if args.registry:
        with open(args.registry, encoding="utf-8") as handle:
            contract = json.load(handle)["servers"][0]["contract"]
        return {**contract, "cwd": "/"}
    hook = load_hook(args.hook)
    with open(args.mcp_config, encoding="utf-8") as handle:
        return hook.declared_contract(args.server, json.load(handle), "/")


def body_for(args):
    return {
        "server": args.server,
        "tool": args.tool,
        "arguments": json.loads(args.args),
        "contract": contract_for(args),
        "tool_use_id": args.tool_use_id,
    }


def post(base, key, body, timeout=10.0):
    request = urllib.request.Request(
        base.rstrip("/") + "/mint/v1/decide",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as reply:
            status, raw = reply.status, reply.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except OSError as exc:
        return {
            "status": None,
            "error": type(exc).__name__,
            "ms": (time.perf_counter() - started) * 1000,
        }
    try:
        answer = json.loads(raw)
    except ValueError:
        answer = {"raw": raw[:200].decode(errors="replace")}
    return {
        "status": status,
        "answer": answer,
        "ms": round((time.perf_counter() - started) * 1000, 1),
    }


def verdict(result):
    answer = result.get("answer") or {}
    return answer.get("decision") if result.get("status") == 200 else f"http-{result.get('status')}"


def percentiles(values):
    values = sorted(values)
    pick = lambda q: values[min(len(values) - 1, int(q * len(values)))]  # noqa: E731
    return {
        "n": len(values),
        "p50": round(statistics.median(values), 1),
        "p95": round(pick(0.95), 1),
        "max": round(values[-1], 1),
    }


def cmd_decide(args):
    result = post(args.base, args.key, body_for(args))
    return {**result, "verdict": verdict(result)}


def cmd_race(args):
    body = body_for(args)
    with concurrent.futures.ThreadPoolExecutor(args.n) as pool:
        results = list(pool.map(lambda _: post(args.base, args.key, body), range(args.n)))
    verdicts = [verdict(r) for r in results]
    return {"verdicts": verdicts, "allowed": verdicts.count("allow"), "n": args.n}


def cmd_lost_response(args):
    body = json.dumps(body_for(args)).encode()
    parts = urlsplit(args.base)
    head = (
        f"POST /mint/v1/decide HTTP/1.1\r\nHost: {parts.netloc}\r\nAuthorization: Bearer {args.key}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((parts.hostname, parts.port or 80), timeout=5) as sock:
        sock.sendall(head + body)
        sock.shutdown(socket.SHUT_WR)  # 응답을 읽지 않고 닫는다.
    return {"sent": True}


def cmd_revoke_latency(args):
    body = body_for(args)
    before = verdict(post(args.base, args.key, body))
    done = subprocess.run(args.cmd, shell=True, capture_output=True, text=True, timeout=120)
    started = time.perf_counter()
    polls = 0
    while time.perf_counter() - started < args.limit:
        polls += 1
        now = verdict(post(args.base, args.key, body, timeout=3))
        if now != "allow":
            return {
                "before": before,
                "after": now,
                "revoke_rc": done.returncode,
                "seconds_to_deny": round(time.perf_counter() - started, 3),
                "polls": polls,
            }
        time.sleep(args.interval)
    return {"before": before, "revoke_rc": done.returncode, "seconds_to_deny": None, "polls": polls}


def run_hook(args, event):
    started = time.perf_counter()
    done = subprocess.run(
        [
            args.python,
            args.hook,
            "--url",
            args.base,
            "--key-file",
            args.key_file,
            "--mcp-config",
            args.mcp_config,
        ],
        input=event,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return (time.perf_counter() - started) * 1000, done.returncode


def cmd_hook_latency(args):
    event = json.dumps(
        {
            "tool_name": f"mcp__{args.server}__{args.tool}",
            "mcp_server": {"name": args.server},
            "tool_input": json.loads(args.args),
            "tool_use_id": "latency",
            "cwd": args.cwd,
        }
    )
    run_hook(args, event)  # 준비 호출 한 번(연결 풀·파일 캐시), 표본에 넣지 않는다.
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(args.par) as pool:
        results = list(pool.map(lambda _: run_hook(args, event), range(args.n)))
    total = time.perf_counter() - started
    codes = [code for _, code in results]
    return {
        **percentiles([ms for ms, _ in results]),
        "par": args.par,
        "wall_s": round(total, 2),
        "allowed": codes.count(0),
        "blocked": codes.count(2),
        "other": len(codes) - codes.count(0) - codes.count(2),
    }


def parser():
    top = argparse.ArgumentParser()
    sub = top.add_subparsers(dest="command", required=True)

    def add(name, handler):
        p = sub.add_parser(name)
        p.set_defaults(handler=handler)
        p.add_argument("--base", required=True)
        p.add_argument("--key", default="")
        p.add_argument("--server", default="cnt")
        p.add_argument("--tool", default="echo")
        p.add_argument("--args", default='{"text": "hello"}')
        p.add_argument("--tool-use-id", default="client")
        p.add_argument("--registry")
        p.add_argument("--hook")
        p.add_argument("--mcp-config")
        return p

    add("decide", cmd_decide)
    race = add("race", cmd_race)
    race.add_argument("--n", type=int, default=8)
    add("lost-response", cmd_lost_response)
    rev = add("revoke-latency", cmd_revoke_latency)
    rev.add_argument("--cmd", required=True)
    rev.add_argument("--limit", type=float, default=10.0)
    rev.add_argument("--interval", type=float, default=0.1)
    lat = add("hook-latency", cmd_hook_latency)
    lat.add_argument("--n", type=int, default=100)
    lat.add_argument("--par", type=int, default=1)
    lat.add_argument("--python", default="python3")
    lat.add_argument("--key-file", required=True)
    lat.add_argument("--cwd", default="/tmp")
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    print(json.dumps(args.handler(args)))


if __name__ == "__main__":
    main()
