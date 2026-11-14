"""결과 본문 검사 비용을 입력 종류·크기별로 재고 탐지기별 시간을 나눠 보여 준다.

사용: ``uv run python scripts/bench_result_scan.py [반복 횟수]``
"""

import base64
import json
import random
import sys
import time

from mint_litellm.plugin.policy import result_scan, sensitive_scan
from mint_litellm.plugin.result import screen_result

MIB = 1024 * 1024


def make_log(n: int) -> str:
    rnd, out, size = random.Random(1), [], 0
    while size < n:
        line = (
            f"2026-01-02T03:04:{rnd.randrange(60):02d}Z INFO worker-{rnd.randrange(99)} "
            f"request id={rnd.randrange(10**9)} path=/api/v1/items/{rnd.randrange(9999)} "
            f"status=200 took={rnd.random():.3f}s user=alice@corp.io\n"
        )
        out.append(line)
        size += len(line)
    return "".join(out)[:n]


def make_json(n: int) -> str:
    rnd, rows, size = random.Random(2), [], 0
    while size < n:
        row = {
            "id": rnd.randrange(10**8),
            "name": f"item {rnd.randrange(999)}",
            "tags": ["a", "b"],
            "price": rnd.random() * 100,
            "ok": True,
            "note": "plain text value here",
        }
        text = json.dumps(row)
        rows.append(text)
        size += len(text) + 2
    return ("[" + ", ".join(rows) + "]")[:n]


def make_base64(n: int) -> str:
    rnd = random.Random(3)
    blob = base64.b64encode(rnd.randbytes(n * 3 // 4)).decode()
    return "\n".join(blob[i : i + 76] for i in range(0, len(blob), 76))[:n]


def timed(fn, reps):
    best = 1e9
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t)
    return best * 1000


POLICY = {"scan": True, "response_scan": "mask", "enforce": True}


def main() -> None:
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    makers = {"log": make_log, "json": make_json, "base64": make_base64}
    for mib in (1, 8):
        for name, make in makers.items():
            text, cap = make(mib * MIB), 32 * MIB
            rows = {
                "instructions": (result_scan.scan_instructions, {}),
                "sensitive+entropy": (sensitive_scan.scan_sensitive, {"entropy": True}),
            }
            ms = {
                k: timed(lambda f=f, kw=kw, t=text, c=cap: f([t], c, **kw), reps)
                for k, (f, kw) in rows.items()
            }
            ms["screen_result"] = timed(
                lambda t=text: screen_result(
                    {"allowed": True, "result_policy": POLICY}, size=len(t), items=1, texts=[t]
                ),
                reps,
            )
            parts = " ".join(f"{k}={v:.0f}ms" for k, v in ms.items())
            total = ms["instructions"] + ms["sensitive+entropy"]
            print(f"{mib}MiB {name:7s} total={total:.0f}ms  {parts}")


if __name__ == "__main__":
    main()
