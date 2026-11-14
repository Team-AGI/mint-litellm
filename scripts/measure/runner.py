"""구성들을 교차·무작위 순서로 돌리며 호출마다 구간 시간을 JSONL로 남긴다.

사용: ``python scripts/measure/runner.py --corpus corpus/seed.jsonl --runs 10 --out out.jsonl``
구성 파일의 ``base_url``과 ``configs/baseline.json``의 자원 동등 값이 채워져 있어야 실행한다.
구간 시간은 응답의 ``Server-Timing`` 헤더(예: ``pre;dur=1.2, upstream;dur=30``)에서 읽는다.
헤더가 없으면 종단 시간만 남는다.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent


def plan(config_ids: list[str], runs: int, seed: int) -> list[dict]:
    """반복마다 구성 순서를 새로 섞는다. 고정 순서에서 오는 데움·캐시 편향을 줄인다."""
    rnd = random.Random(seed)
    slots = []
    for run in range(runs):
        order = list(config_ids)
        rnd.shuffle(order)
        slots += [{"run": run, "position": i, "config": c} for i, c in enumerate(order)]
    return slots


def parse_server_timing(header: str | None) -> dict[str, float]:
    out: dict[str, float] = {}
    for part in (header or "").split(","):
        name, _, rest = part.strip().partition(";")
        for item in rest.split(";"):
            key, _, value = item.strip().partition("=")
            if key == "dur" and name:
                try:
                    out[name] = float(value)
                except ValueError:
                    pass
    return out


def check_ready(baseline: dict, configs: list[dict]) -> None:
    missing = [k for k, v in baseline["parity"].items() if v is None]
    if missing:
        raise SystemExit(f"자원 동등 값이 비어 있다: {', '.join(missing)}")
    unset = [c["id"] for c in configs if "CONFIGURE_ME" in c["base_url"]]
    if unset:
        raise SystemExit(f"base_url이 비어 있다: {', '.join(unset)}")


def http_send(cfg: dict, case: dict, timeout: float) -> tuple[int, dict[str, float]]:
    body = json.dumps(
        {
            "server_name": case["request"]["server"],
            "name": case["request"]["tool"],
            "arguments": case["request"]["args"],
        }
    ).encode()
    req = urllib.request.Request(
        cfg["base_url"] + cfg["endpoint"],
        body,
        {
            "content-type": "application/json",
            "authorization": "Bearer " + os.environ.get(cfg["api_key_env"], ""),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as reply:
            return reply.status, parse_server_timing(reply.headers.get("Server-Timing"))
    except urllib.error.HTTPError as exc:
        return exc.code, parse_server_timing(exc.headers.get("Server-Timing"))


Send = Callable[[dict, dict, float], tuple[int, dict[str, float]]]


def run_slot(
    cfg: dict,
    cases: list[dict],
    slot: dict,
    n_cold: int,
    n_warm: int,
    send: Send,
    timeout: float = 30.0,
):
    """한 구성의 한 반복: 재시작 뒤 앞 ``n_cold``건은 cold, 이어지는 ``n_warm``건은 warm."""
    if cfg.get("restart_command"):
        subprocess.run(cfg["restart_command"], shell=True, check=True)
    for i in range(n_cold + n_warm):
        case = cases[i % len(cases)]
        started = time.perf_counter()
        try:
            status, segments = send(cfg, case, timeout)
            error = None
        except Exception as exc:  # 실패도 분모에 남긴다
            status, segments, error = 0, {}, type(exc).__name__
        yield {
            **slot,
            "phase": "cold" if i < n_cold else "warm",
            "case": case["id"],
            "status": status,
            "action": cfg["status_to_action"].get(str(status), "error"),
            "total_ms": (time.perf_counter() - started) * 1000,
            "segments_ms": segments,
            "error": error,
        }


def percentile(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, round(q * (len(s) - 1)))]


def paired_difference(
    records: list[dict], a: str, b: str, q: float, boot: int = 2000, seed: int = 0
) -> dict:
    """반복별 ``q`` 분위 종단 지연 차이(b - a)와 반복 단위 부트스트랩 95% 구간.

    허용 결과(action == allow)끼리만 비교한다. 이 값은 종단 지연 분위의 차이이며
    추가된 지연의 분위가 아니다.
    """
    per_run: dict[int, dict[str, list[float]]] = {}
    for r in records:
        if r["phase"] == "warm" and r["action"] == "allow" and r["config"] in (a, b):
            per_run.setdefault(r["run"], {}).setdefault(r["config"], []).append(r["total_ms"])
    diffs = [
        percentile(v[b], q) - percentile(v[a], q) for v in per_run.values() if a in v and b in v
    ]
    rnd = random.Random(seed)
    means = sorted(statistics.fmean(rnd.choices(diffs, k=len(diffs))) for _ in range(boot))
    return {
        "runs": len(diffs),
        "per_run": diffs,
        "mean": statistics.fmean(diffs),
        "ci95": (means[int(0.025 * boot)], means[int(0.975 * boot) - 1]),
    }


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--cold", type=int, default=20)
    ap.add_argument("--warm", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--footnote", action="store_true", help="기능 축소 변형도 포함")
    args = ap.parse_args()
    baseline = json.loads((HERE / "configs/baseline.json").read_text(encoding="utf-8"))
    paths = baseline["configurations"]
    if args.footnote:
        paths = paths + baseline["footnote_configurations"]
    configs = {
        c["id"]: c for c in (json.loads((HERE / p).read_text(encoding="utf-8")) for p in paths)
    }
    check_ready(baseline, list(configs.values()))
    cases = [c for c in load_jsonl(args.corpus) if c["mode"] == "enforce"]
    with args.out.open("w", encoding="utf-8", newline="\n") as out:
        for slot in plan(list(configs), args.runs, args.seed):
            cfg = configs[slot["config"]]
            for rec in run_slot(cfg, cases, slot, args.cold, args.warm, http_send):
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
