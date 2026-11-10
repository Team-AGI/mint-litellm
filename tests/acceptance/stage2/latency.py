"""복제본 2·동시 8, 예열 후 4라운드 교대. DEBUG ref와 원장으로 표본을 결속한다."""

import concurrent.futures
import hashlib
import json
import math
import re
import time
import uuid
from datetime import UTC, datetime

import httpx

PATTERN = re.compile(r"decision_ms=([0-9.]+) ref=(\S+) allowed=(true|false)")


def quantiles(values):
    assert values and all(math.isfinite(value) and value >= 0 for value in values)
    ordered = sorted(values)
    return {label: ordered[max(0, math.ceil(len(ordered) * q) - 1)]
            for label, q in (("p50", .5), ("p95", .95), ("p99", .99))}


def arguments(kind):
    if kind == "small":
        return {"text": "x"}
    if kind == "large_string":
        return {"text": "x" * (128 * 1024)}
    # 문자열 하나가 4KB를 넘지 않는 정확히 64KiB JSON 인자.
    values = {f"k{i}": "x" * 3000 for i in range(21)}
    values["padding"] = ""
    size = len(json.dumps(values, separators=(",", ":")).encode())
    values["padding"] = "x" * (65536 - size)
    assert len(values["padding"]) <= 4096
    assert len(json.dumps(values, separators=(",", ":")).encode()) == 65536
    return values


def timed_batch(rig, fixture, bases, args, count, *, workers=8, blocked=False):
    def one(index):
        mark = "acc-perf-" + uuid.uuid4().hex
        started = time.perf_counter()
        # 각 스레드는 별도 클라이언트. timeout도 원시 실패로 기록한다.
        reply = httpx.post(
            bases[index % len(bases)].rstrip("/") + "/mcp-rest/tools/call",
            headers={"Authorization": "Bearer " + rig.secret("caller"),
                     "x-litellm-call-id": mark},
            json={"server_id": fixture["server_id"], "name": fixture["performance_tool"],
                  "arguments": args}, timeout=30,
        )
        elapsed = (time.perf_counter() - started) * 1000
        by = None
        if blocked:
            # DS-206: 막혀야 할 큰 문자열 호출은 탐지 사유로 막히거나, 복제본이 잠시 멈춰 예산을 넘기면
            # 의존 장애 코드로 fail-closed 된다(둘 다 업스트림 미전송). 후자의 건수·비율을 보고한다.
            if reply.status_code == 403 and "MINT-POLICY-DETECT-" in reply.text:
                by = "detect"
            else:
                assert (reply.status_code == 403 and "MINT-DEPENDENCY-" in reply.text
                        and "not_dispatched" in reply.text), (reply.status_code, reply.text[:300])
                by = reply.text.split("MINT-DEPENDENCY-")[1][:3].strip('\\"').lower()
        else:
            assert reply.status_code == 200 and not reply.json().get("isError", False), (
                reply.status_code, reply.text[:300])
        return {"mark": mark, "rtt_ms": elapsed, "replica": index % len(bases), "by": by,
                "at": datetime.now(UTC).isoformat()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, range(count)))


def extract(lines, refs, *, allowed=True):
    samples = {}
    for line in lines.splitlines():
        match = PATTERN.search(line)
        if match and match[2] in refs:
            assert match[2] not in samples, "중복 DEBUG ref: 로그 수집 중복 또는 이중 판정"
            assert (match[3] == "true") is allowed, "기대와 다른 허용/차단 판정"
            samples[match[2]] = float(match[1])
    assert set(samples) == set(refs), f"decision_ms 누락 {len(set(refs) - samples.keys())}건"
    return list(samples.values())


def warm_up(rig, fixture, seconds=900):
    """복원·재시작 직후 계약 관측이 재시도 후퇴로 늦으면 도구가 숨는다. 호출이 허용될 때까지 기다린다."""
    deadline = time.monotonic() + seconds
    while True:
        reply = httpx.post(
            rig.site["litellm"][0].rstrip("/") + "/mcp-rest/tools/call",
            headers={"Authorization": "Bearer " + rig.secret("caller")},
            json={"server_id": fixture["server_id"], "name": fixture["performance_tool"],
                  "arguments": {}}, timeout=30)
        if reply.status_code == 200:
            return
        assert time.monotonic() < deadline, (reply.status_code, reply.text[:200])
        time.sleep(5)


def measure(rig, fixture):
    warm_up(rig, fixture)
    bases = rig.site["litellm"]
    assert len(bases) == 2
    plain = [rig.site["plain"]]
    report = {"method": "decision_ms", "replicas": 2, "concurrency": 8,
              "rounds": 4, "count_per_round": 800, "scenarios": []}
    for kind in ("small", "64kb", "large_string"):
        args = arguments(kind)
        blocked = kind == "large_string"
        state = rig.rows("servers", "server_id=%s", [fixture["server_id"]])[0]
        assert state["contract_status"] == "managed"
        # 이후 패턴 계산과 관리 계약 스냅숏이 실제 입력에 들어왔는지는 원장으로 검증한다.
        for workers in (1, 2, 4, 8):
            timed_batch(rig, fixture, bases, args, 8, workers=workers, blocked=blocked)
            timed_batch(rig, fixture, plain, args, 8, workers=workers)
        since = datetime.now(UTC).isoformat()
        mint_samples, plain_samples = [], []
        upstream_hits = 0  # 순정 LiteLLM 라운드는 같은 업스트림을 치므로 MINT 라운드 앞뒤로만 센다
        for index in range(4):
            order = ((bases, mint_samples), (plain, plain_samples))
            for endpoints, target in (order if index % 2 == 0 else reversed(order)):
                mint_round = blocked and endpoints == bases
                before = rig.counter(fixture["server_id"]) if mint_round else 0
                target.extend(timed_batch(rig, fixture, endpoints, args, 800,
                                          blocked=mint_round))
                if mint_round:
                    time.sleep(3)  # 계수 역프록시 기록이 따라오게 한다
                    upstream_hits += rig.counter(fixture["server_id"]) - before
        marks = [sample["mark"] for sample in mint_samples]
        dependency = [sample for sample in mint_samples if sample["by"] not in (None, "detect")]
        if blocked:  # DS-206: 보안 속성은 업스트림 0이다
            assert upstream_hits == 0, f"막힌 호출이 업스트림에 닿음: {upstream_hits}"
        rows = rig.sql(
            "SELECT payload FROM mint.events WHERE instance_id=%s "
            "AND kind='decision_evaluated' AND payload->>'litellm_call_id'=ANY(%s)",
            [rig.iid, marks],
        )
        assert len(marks) == 3200 and len(rows) >= len(marks) - len(dependency)
        # 의존 장애로 막힌 호출은 스냅숏을 못 읽어 세대·정책 ID가 없을 수 있다(DS-206).
        assert all(row["payload"]["state_epoch"] is not None for row in rows
                   if not blocked or row["payload"]["policy_ids"])
        # 본문 미저장 계약을 지킨다. 패턴 불리언 자체는 원장에 저장되지 않는다.
        # 대형 문자열의 보수적 패턴 판정은 실제 적용된 정책 ID로 확인한다.
        if blocked:
            detected = [row for row in rows if row["payload"]["policy_ids"]]
            assert len(detected) >= len(marks) - len(dependency)
            assert all({"POL-E-07", "POL-E-09", "POL-E-14"} <= set(
                row["payload"]["policy_ids"],
            ) for row in detected), "패턴 계산이 정책 판정에 반영되지 않음"
        refs = {row["payload"]["decision_ref"] for row in rows}
        assert len(refs) == len(rows)
        logs = []
        for command in rig.site["decision_logs"]:
            result = rig.command([*command, "--since", since])
            logs.append(result.stdout + "\n" + result.stderr)
        raw = "\n".join(logs)
        samples = extract(raw, refs, allowed=not blocked)
        path = rig.root / ("decision_" + kind + ".log")
        path.parent.mkdir(parents=True, exist_ok=True)
        selected = [match.group() for line in raw.splitlines()
                    if (match := PATTERN.search(line)) and match[2] in refs]
        path.write_text("\n".join(selected) + "\n", encoding="utf-8", newline="\n")
        mq, pq = quantiles([s["rtt_ms"] for s in mint_samples]), quantiles(
            [s["rtt_ms"] for s in plain_samples],
        )
        report["scenarios"].append({
            "kind": kind, "argument_bytes": len(json.dumps(args, separators=(",", ":")).encode()),
            "samples": len(samples), "decision_ms": quantiles(samples),
            "expected_action": "block" if blocked else "allow",
            "mint_rtt_ms": mq, "plain_rtt_ms": pq,
            "supplemental_rtt_difference_ms": {key: mq[key] - pq[key] for key in mq},
            "raw_log": str(path), "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            **({"ds206": {
                "dependency_blocked": len(dependency), "of": len(marks),
                "ratio": len(dependency) / len(marks),
                "codes": sorted({sample["by"] for sample in dependency}),
                "at": [sample["at"] for sample in dependency],
                "upstream_calls": upstream_hits,
                "log_signature": {name: raw.count(name) for name in (
                    "사건 기록 실패", "스냅숏 조회 실패", "discarding closed connection")},
                "rtt_over_1s": sum(sample["rtt_ms"] > 1000 for sample in mint_samples)}}
               if blocked else {}),
        })
    return report
