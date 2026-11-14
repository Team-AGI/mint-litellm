"""라벨 코퍼스와 관측 결과로 기대 동작별 혼동행렬과 Wilson 구간을 계산한다.

사용: ``python scripts/measure/score.py corpus.jsonl observed.jsonl [--split heldout]``
``evaluated``(판정)와 ``enforced``(실제 집행)를 따로 채점한다. 건너뛴 사례와
오류는 분모에서 빼지 않고 별도 열로 보인다.
오류 0건이어도 95% 상한은 대략 3/N이므로 상한을 함께 낸다.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

LABELS = ("allow", "deny", "hold", "mask", "observe")
Z = 1.959964


def wilson(k: int, n: int, z: float = Z) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def required_n(p: float, margin: float, z: float = Z) -> int:
    """비율 ``p`` 근처를 ``±margin``으로 추정하는 데 필요한 독립 표본 수(정규 근사).

    ``p``가 0이면 3/margin(오류 0건일 때 95% 상한이 margin 이하가 되는 수)을 쓴다.
    """
    if p <= 0:
        return math.ceil(3 / margin)
    return math.ceil(z * z * p * (1 - p) / (margin * margin))


def score(corpus: list[dict], observed: list[dict], field: str, split: str | None = None) -> dict:
    obs = {o["id"]: o for o in observed}
    matrix: dict[str, Counter] = {label: Counter() for label in LABELS}
    groups: dict[str, set] = {label: set() for label in LABELS}
    unseen = skipped = errors = 0
    for case in corpus:
        if split and case["split"] != split:
            continue
        o = obs.get(case["id"])
        if o is None:
            unseen += 1
            continue
        skipped += bool(o.get("skipped"))
        errors += bool(o.get("error"))
        matrix[case["expect"]][o.get(field) or "none"] += 1
        groups[case["expect"]].add(case["group"])
    rows = {}
    for label in LABELS:
        n = sum(matrix[label].values())
        k = matrix[label][label]
        flagged = sum(matrix[x][label] for x in LABELS)
        rows[label] = {
            "n": n,
            "groups": len(groups[label]),
            "correct": k,
            "recall": k / n if n else None,
            "recall_ci95": wilson(k, n),
            "error_rate_upper95": wilson(n - k, n)[1] if n else None,
            "precision": k / flagged if flagged else None,
            "precision_ci95": wilson(k, flagged),
            "confusion": dict(matrix[label]),
        }
    return {
        "field": field,
        "split": split,
        "unseen": unseen,
        "skipped": skipped,
        "errors": errors,
        "labels": rows,
    }


def load(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=Path)
    ap.add_argument("observed", type=Path)
    ap.add_argument("--split", choices=("tune", "heldout"), default="heldout")
    args = ap.parse_args()
    corpus, observed = load(args.corpus), load(args.observed)
    for field in ("evaluated", "enforced"):
        print(json.dumps(score(corpus, observed, field, args.split), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
