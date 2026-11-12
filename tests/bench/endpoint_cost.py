"""엔드포인트 비용 비교: 같은 작업을 직접 실행(대조군)과 MINT를 거친 실행으로 돌려 나란히 잰다.

사용:
  python tests/bench/endpoint_cost.py --workload W.json --agent ~/.mint/programs/mint_agent.py \\
      --url https://mint.example --key-file ~/.mint/key --contracts ~/.mint/contracts.json \\
      --state-dir ~/.mint/state [--ca-file CA.pem] [--no-keepalive] \\
      [--revoke-cmd '...'] [--restore-cmd '...'] [--storage-cmd '...'] [--output out.json]

작업 파일(JSON):
  {"server": {"name": "srv-1", "argv": ["/path/server", "arg"], "env": {"KEY": "value"}},
   "cases": [{"id": "read-1", "tool": "read", "arguments": {...}, "expect": "allow",
              "effect_file": "/tmp/effects/read-1"},
             {"id": "write-out", "tool": "write", "arguments": {...}, "expect": "block",
              "effect_file": "/tmp/effects/write-out"}]}
  ``expect``는 MINT가 내려야 하는 판정이다. ``effect_file``이 있으면 호출 전에 지우고 호출 뒤
  줄 수를 효과 횟수로 센다(서버가 효과마다 한 줄을 적는다). 허용 호출은 효과 1(``effects``로 바꿈),
  차단 호출은 0이 기대값이다. ``server.argv``는 승인된 서버 계약의 실행 파일·인자와 같아야 한다.

잰 것(팔마다 ``direct``와 ``mint``):
  성공률(허용해야 할 호출 중 실행되어 성공한 비율), 오허용(차단해야 할 호출이 실행됨),
  오차단(허용해야 할 호출이 막힘), 효과 횟수가 기대값과 다른 호출 수, 서버 시작 시간,
  판정(훅 ``pre`` 전체) 시간과 호출 전체 시간의 p50·p95·p99.
  ``mint``만: 철회 전파 시간(``--revoke-cmd`` 실행이 끝난 뒤 같은 호출이 막힐 때까지),
  호출당 저장 증가(``--storage-cmd``가 출력한 바이트 수의 전후 차이 / 훅 호출 수).
  ``--revoke-cmd``는 승인 철회·키 삭제 등 권한을 거두는 명령, ``--restore-cmd``는 되돌리는 명령이다.
  ``--storage-cmd``는 MINT 저장소의 크기(바이트)를 마지막 줄에 출력하는 명령이다.

연결 재사용 효과는 같은 작업을 ``--no-keepalive``를 주고 한 번, 주지 않고 한 번 돌려 판정 시간을
비교한다. 장비에서 돌릴 때는 대조군과 MINT를 같은 시각 근처에 실행한다(실행마다 ±20% 흔들림).
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from typing import Any

CALL_TIMEOUT = 30.0
PROTOCOL = "-".join(("2025", "06", "18"))


def percentile(values: Sequence[float], pct: float) -> float | None:
    """가장 가까운 순위 방식. 값이 없으면 None."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))
    return round(ordered[int(rank) - 1], 2)


def spread(values: Sequence[float]) -> dict[str, float | None]:
    return {f"p{p}": percentile(values, p) for p in (50, 95, 99)} | {"n": len(values)}


class Stdio:
    """표준 입출력으로 말하는 MCP 서버 하나(줄 단위 JSON-RPC)."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={**os.environ, **env},
        )  # fmt: skip
        self.lines: queue.Queue[bytes] = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.next_id = 0

    def _pump(self) -> None:
        for line in self.proc.stdout:  # type: ignore[union-attr]
            self.lines.put(line)
        self.lines.put(b"")

    def send(self, message: dict[str, Any]) -> None:
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")  # type: ignore[union-attr]
        self.proc.stdin.flush()  # type: ignore[union-attr]

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        deadline = time.monotonic() + CALL_TIMEOUT
        while True:
            line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            if not line:
                raise RuntimeError("server closed its output")
            try:
                reply = json.loads(line)
            except ValueError:
                continue
            if reply.get("id") == self.next_id:
                return reply

    def initialize(self) -> None:
        reply = self.request("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "mint-bench", "version": "1"},
        })  # fmt: skip
        if "error" in reply:
            raise RuntimeError("initialize failed")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call(self, tool: str, arguments: dict[str, Any]) -> tuple[bool, Any]:
        """(성공 여부, 결과). 규약 오류와 ``isError``는 실패이다."""
        try:
            reply = self.request("tools/call", {"name": tool, "arguments": arguments})
        except (RuntimeError, queue.Empty):
            return False, None
        result = reply.get("result")
        return "error" not in reply and not (result or {}).get("isError"), result

    def close(self) -> None:
        try:
            self.proc.stdin.close()  # type: ignore[union-attr]
            self.proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait()


class Arm:
    """한 팔(``direct`` 또는 ``mint``). 서버를 띄우는 명령과 호출 앞뒤 훅이 다르다."""

    def __init__(self, name: str, args: argparse.Namespace, workload: dict[str, Any]) -> None:
        self.name = name
        self.args = args
        self.server = workload["server"]
        self.env = {str(k): str(v) for k, v in (self.server.get("env") or {}).items()}

    def server_argv(self) -> list[str]:
        if self.name == "direct":
            return list(self.server["argv"])
        return [self.args.python, self.args.agent, "run", "--server", self.server["name"],
                "--contracts", self.args.contracts]  # fmt: skip

    def hook(self, command: str, event: dict[str, Any]) -> tuple[int, float]:
        """훅 하나를 하네스처럼 실행한다. (종료 코드, 걸린 ms)."""
        argv = [self.args.python, self.args.agent, command, "--url", self.args.url,
                "--key-file", self.args.key_file, "--contracts", self.args.contracts,
                "--state-dir", self.args.state_dir]  # fmt: skip
        if self.args.ca_file:
            argv += ["--ca-file", self.args.ca_file]
        if self.args.no_keepalive:
            argv.append("--no-keepalive")
        started = time.perf_counter()
        done = subprocess.run(argv, input=json.dumps(event).encode(), capture_output=True,
                              timeout=30)  # fmt: skip
        return done.returncode, (time.perf_counter() - started) * 1000

    def event(self, case: dict[str, Any], use_id: str) -> dict[str, Any]:
        name = self.server["name"]
        return {"tool_name": f"mcp__{name}__{case['tool']}", "mcp_server": {"name": name},
                "tool_input": case["arguments"], "tool_use_id": use_id}  # fmt: skip

    def starts(self, count: int) -> list[float]:
        times = []
        for _ in range(count):
            started = time.perf_counter()
            server = Stdio(self.server_argv(), self.env)
            try:
                server.initialize()
            except (RuntimeError, queue.Empty, OSError):
                server.close()
                continue  # 시작하지 못한 시도는 시간에 넣지 않는다.
            times.append((time.perf_counter() - started) * 1000)
            server.close()
        return times

    def run_call(self, server: Stdio, case: dict[str, Any], use_id: str) -> dict[str, Any]:
        effect_file = case.get("effect_file")
        if effect_file and os.path.exists(effect_file):
            os.unlink(effect_file)
        started = time.perf_counter()
        allowed, decision_ms = True, None
        if self.name == "mint":
            code, decision_ms = self.hook("pre", self.event(case, use_id))
            allowed = code == 0
        ok = False
        if allowed:
            ok, result = server.call(case["tool"], case["arguments"])
            if self.name == "mint":
                event = self.event(case, use_id) | {"tool_response": result}
                self.hook("post" if ok else "post-failure", event)
        total_ms = (time.perf_counter() - started) * 1000
        effects = None
        if effect_file:
            try:
                with open(effect_file, encoding="utf-8") as handle:
                    effects = sum(1 for line in handle if line.strip())
            except OSError:
                effects = 0
        expected = case.get("effects", 1 if case["expect"] == "allow" else 0)
        return {"id": case["id"], "expect": case["expect"], "allowed": allowed, "ok": ok,
                "decision_ms": decision_ms, "total_ms": total_ms,
                "effects": effects, "expected_effects": expected}  # fmt: skip

    def run(self, cases: list[dict[str, Any]], repeat: int) -> list[dict[str, Any]]:
        server = Stdio(self.server_argv(), self.env)
        server.initialize()
        records: list[dict[str, Any]] = []
        try:
            for _ in range(repeat):
                for case in cases:
                    use_id = f"bench_{self.name}_{len(records)}"
                    records.append(self.run_call(server, case, use_id))
        finally:
            server.close()
        return records


def summarize(records: list[dict[str, Any]], starts: list[float]) -> dict[str, Any]:
    allow = [r for r in records if r["expect"] == "allow"]
    block = [r for r in records if r["expect"] == "block"]
    counted = [r for r in records if r["effects"] is not None]
    decisions = [r["decision_ms"] for r in records if r["decision_ms"] is not None]
    success = sum(r["allowed"] and r["ok"] for r in allow)
    return {
        "calls": len(records),
        "success_rate": round(success / len(allow), 4) if allow else None,
        "wrong_allow": sum(r["allowed"] for r in block),
        "wrong_block": sum(not r["allowed"] for r in allow),
        "effects_total": sum(r["effects"] for r in counted),
        "effects_expected": sum(r["expected_effects"] for r in counted),
        "effect_mismatches": sum(r["effects"] != r["expected_effects"] for r in counted),
        "start_ms": spread(starts),
        "decision_ms": spread(decisions),
        "call_ms": spread([r["total_ms"] for r in records]),
    }


def shell(command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)


def storage_bytes(command: str) -> int:
    return int(shell(command).stdout.strip().splitlines()[-1])


def revocation(arm: Arm, case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """철회 명령이 끝난 시각부터 같은 호출이 막히기까지. 시간 안에 막히지 않으면 전파 실패."""
    event = arm.event(case, "bench_revoke_probe")
    if arm.hook("pre", event)[0] != 0:
        return {"propagated": False, "note": "the probe call was not allowed before revocation"}
    done = shell(args.revoke_cmd)
    started = time.monotonic()
    result: dict[str, Any] = {"revoke_exit": done.returncode, "propagated": False}
    while time.monotonic() - started < args.revoke_timeout:
        if arm.hook("pre", event)[0] != 0:
            result.update(propagated=True, seconds=round(time.monotonic() - started, 3))
            break
        time.sleep(args.poll)
    if args.restore_cmd:
        shell(args.restore_cmd)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--workload", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--contracts", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--ca-file")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--no-keepalive", action="store_true")
    parser.add_argument("--arms", default="direct,mint")
    parser.add_argument("--repeat", type=int, default=20)
    parser.add_argument("--starts", type=int, default=10)
    parser.add_argument("--revoke-cmd")
    parser.add_argument("--restore-cmd")
    parser.add_argument("--revoke-timeout", type=float, default=120.0)
    parser.add_argument("--poll", type=float, default=0.1)
    parser.add_argument("--storage-cmd")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    for flag in ("agent", "key_file", "contracts", "state_dir", "ca_file"):
        if getattr(args, flag):
            setattr(args, flag, os.path.expanduser(getattr(args, flag)))

    with open(args.workload, encoding="utf-8") as handle:
        workload = json.load(handle)
    report: dict[str, Any] = {
        "workload": os.path.basename(args.workload),
        "repeat": args.repeat,
        "keepalive": not args.no_keepalive,
    }
    for name in args.arms.split(","):
        arm = Arm(name, args, workload)
        starts = arm.starts(args.starts)
        before = storage_bytes(args.storage_cmd) if name == "mint" and args.storage_cmd else None
        records = arm.run(workload["cases"], args.repeat)
        report[name] = summarize(records, starts)
        if before is not None:
            hooks = sum(2 if r["allowed"] else 1 for r in records)  # 판정 + (허용이면) 결과 보고
            grown = storage_bytes(args.storage_cmd) - before
            report[name]["storage"] = {"bytes_grown": grown, "hook_calls": hooks,
                                       "bytes_per_call": round(grown / hooks, 1)}  # fmt: skip
        if name == "mint" and args.revoke_cmd:
            probe = next((c for c in workload["cases"] if c["expect"] == "allow"), None)
            if probe is not None:
                report[name]["revocation"] = revocation(arm, probe, args)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
