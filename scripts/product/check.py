"""docs/product 기준 문서를 서로, 그리고 코드와 대조한다. TRACEABILITY_MATRIX.csv를 만든다.

실행: python scripts/product/check.py [--quiet]
오류가 하나라도 있으면 종료 코드 1이다. 경고는 종료 코드에 영향을 주지 않는다.
"""

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory  # noqa: E402

ROOT = inventory.ROOT
DOCS = ROOT / "docs" / "product"
LIFECYCLE = [
    "DISCOVERED",
    "SPECIFIED",
    "IMPLEMENTED",
    "BACKEND_VERIFIED",
    "GUI_VERIFIED",
    "POLICY_VERIFIED",
    "REGRESSION_VERIFIED",
    "RELEASE_READY",
    "BLOCKED",
]
GUI_OR_ABOVE = set(LIFECYCLE[4:8])
FM = re.compile(r"FM-\d+")
API = re.compile(r"\b(GET|POST|PUT|DELETE) (/\S*)")

errors: list[str] = []
warnings: list[str] = []


def read(name: str) -> list[dict]:
    path = DOCS / name
    if not path.exists():
        errors.append(f"{name} 없음")
        return []
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    for number, row in enumerate(rows, 2):
        if None in row or None in row.values():  # 따옴표 없는 쉼표로 칸 수가 어긋남
            errors.append(f"{name} {number}행: 칸 수가 머리글과 다름(쉼표는 따옴표로 감쌀 것)")
    return rows


def require_columns(name: str, rows: list[dict], cols: list[str]) -> None:
    if rows and (missing := [c for c in cols if c not in rows[0]]):
        errors.append(f"{name}: 열 없음 {missing}")


def main() -> int:
    quiet = "--quiet" in sys.argv
    routes = inventory.routes()
    actions = inventory.actions()
    features = read("FEATURE_REGISTER.csv")
    matrix = read("SCREEN_ACTION_MATRIX.csv")
    policies = read("POLICY_CONTROL_MATRIX.csv")
    require_columns(
        "FEATURE_REGISTER.csv",
        features,
        [
            "feature_id",
            "name",
            "roles",
            "priority",
            "lifecycle",
            "gui_status",
            "evidence",
            "open_issues",
            "scenarios",
            "reqs",
        ],
    )
    require_columns(
        "SCREEN_ACTION_MATRIX.csv",
        matrix,
        [
            "screen_id",
            "action_id",
            "label",
            "roles",
            "feature_id",
            "api",
            "policy_id",
            "success_state",
            "failure_state",
            "audit_event",
            "test_id",
            "status",
        ],
    )

    # 기능
    fm = {}
    for row in features:
        fid = row.get("feature_id", "")
        if fid in fm:
            errors.append(f"기능 ID 중복: {fid}")
        fm[fid] = row
        if row.get("lifecycle") not in LIFECYCLE:
            errors.append(f"{fid}: lifecycle 값이 틀림 {row.get('lifecycle')!r}")
        if row.get("lifecycle") in GUI_OR_ABOVE and "QA-" not in (row.get("evidence") or ""):
            errors.append(f"{fid}: {row['lifecycle']}인데 독립 QA 증거(QA-…)가 없음")
        if row.get("lifecycle") == "BLOCKED" and not row.get("open_issues"):
            errors.append(f"{fid}: BLOCKED인데 막힌 이유가 없음")

    # 요구사항 → 기능
    brief = (
        (DOCS / "PRODUCT_BRIEF.md").read_text(encoding="utf-8")
        if (DOCS / "PRODUCT_BRIEF.md").exists()
        else ""
    )
    reqs = {}
    for line in brief.splitlines():
        m = re.match(r"\|\s*(REQ-\d+)\s*\|", line)
        if m:
            cells = [c.strip() for c in line.strip("|").split("|")]
            ids = set()
            for a, b in re.findall(r"FM-(\d+)~FM-(\d+)", cells[-1]):
                ids |= {f"FM-{n:02d}" for n in range(int(a), int(b) + 1)}
            ids |= set(FM.findall(cells[-1]))
            reqs[m.group(1)] = sorted(ids)
            if not ids:
                errors.append(f"{m.group(1)}: 연결된 기능 없음")
            for f in ids:
                if fm and f not in fm:
                    errors.append(f"{m.group(1)}: 등록부에 없는 기능 {f}")

    # 화면 동작
    seen = set()
    by_feature = defaultdict(list)
    covered_api = []
    for row in matrix:
        aid = row.get("action_id", "")
        if aid in seen:
            errors.append(f"화면 동작 ID 중복: {aid}")
        seen.add(aid)
        fids = FM.findall(row.get("feature_id") or "")
        if not fids:
            errors.append(
                f"{aid}: 연결된 기능 없음({row.get('feature_id') or '빈칸'}) · {row.get('label')}"
            )
        for f in fids:
            by_feature[f].append(row)
            if fm and f not in fm:
                errors.append(f"{aid}: 등록부에 없는 기능 {f}")
        planned_status = row.get("status") in ("DISCOVERED", "SPECIFIED")
        for method, path in API.findall(row.get("api") or ""):
            planned = "(신규" in path  # 설계만 된 새 경로
            key = inventory.norm(re.sub(r"\(.*$", "", path))
            covered_api.append((method, key))
            exists = any(r["method"] == method and inventory.matches(key, r["key"]) for r in routes)
            if planned and not planned_status and not exists:
                errors.append(f"{aid}: {row['status']}인데 새 라우트가 코드에 없음 {method} {key}")
            elif planned and exists and planned_status:
                warnings.append(f"{aid}: 새 라우트가 생겼으니 api의 (신규)와 상태를 고칠 것")
            elif not planned and not exists:
                errors.append(f"{aid}: 코드에 없는 라우트 {method} {key}")
        if row.get("status") in GUI_OR_ABOVE and not row.get("test_id", "").startswith("QA-"):
            errors.append(f"{aid}: {row['status']}인데 독립 QA 시험 ID가 없음")

    # 화면에 있는 모든 POST 동작이 시트에 있어야 한다
    for a in actions:
        if a["method"] != "POST":
            continue
        if not any(m == "POST" and inventory.matches(a["target"], k) for m, k in covered_api):
            errors.append(
                f"시트에 없는 화면 동작: {a['screen']} → POST {a['target']} 「{a['label']}」"
            )
    # 화면에서 닿지 않는 화면용 POST 라우트(JS 호출일 수 있어 경고)
    for r in routes:
        if (
            r["method"] == "POST"
            and not r["path"].startswith("/api/")
            and not any(
                a["method"] == "POST" and inventory.matches(a["target"], r["key"]) for a in actions
            )
        ):
            warnings.append(f"화면 양식이 없는 POST 라우트: {r['path']} ({r['handler']})")

    # 기능 쪽 공백
    for fid, row in fm.items():
        if not row.get("scenarios") and row.get("priority") == "P0":
            errors.append(f"{fid}: P0인데 시나리오 없음")
        if fid not in by_feature and "staff" in (row.get("roles") or "") + (row.get("roles") or ""):
            warnings.append(f"{fid}: 화면 동작 없음({row.get('name')})")

    # 정책
    catalog = json.load(open(ROOT / "policy" / "catalog.json", encoding="utf-8"))
    have = {p.get("control_id") for p in policies}
    for p in catalog["policies"]:
        if p["id"] not in have:
            errors.append(f"정책 통제표에 없는 정책 {p['id']}")
    for row in matrix:
        for pid in re.findall(
            r"(?:POL-[A-Z]-\d+|REASON-[A-Z_]+|RULE-R\d+)", row.get("policy_id") or ""
        ):
            if pid not in have:
                errors.append(f"{row.get('action_id')}: 정책 통제표에 없는 {pid}")

    # 추적표
    out = DOCS / "TRACEABILITY_MATRIX.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(
            [
                "req",
                "feature_id",
                "feature",
                "lifecycle",
                "gui_status",
                "scenarios",
                "actions",
                "apis",
                "policies",
                "tests",
                "evidence",
                "gaps",
            ]
        )
        for req, ids in sorted(reqs.items()):
            for fid in ids:
                row = fm.get(fid, {})
                acts = by_feature.get(fid, [])
                gaps = []
                if not row:
                    gaps.append("등록부 없음")
                if not row.get("scenarios"):
                    gaps.append("시나리오")
                if not acts:
                    gaps.append("화면 동작")
                if not any(a.get("test_id") for a in acts):
                    gaps.append("시험")
                if "QA-" not in (row.get("evidence") or ""):
                    gaps.append("독립 GUI 증거")
                w.writerow(
                    [
                        req,
                        fid,
                        row.get("name", ""),
                        row.get("lifecycle", ""),
                        row.get("gui_status", ""),
                        row.get("scenarios", ""),
                        " ".join(a["action_id"] for a in acts),
                        " ".join(sorted({a.get("api", "") for a in acts if a.get("api")})),
                        " ".join(
                            sorted({a.get("policy_id", "") for a in acts if a.get("policy_id")})
                        ),
                        " ".join(sorted({a.get("test_id", "") for a in acts if a.get("test_id")})),
                        row.get("evidence", "")[:80],
                        " ".join(gaps),
                    ]
                )

    counts = defaultdict(int)
    for row in fm.values():
        counts[row.get("lifecycle")] += 1
    print(f"기능 {len(fm)} · 화면 동작 {len(matrix)} · 정책 {len(policies)} · 요구사항 {len(reqs)}")
    print("기능 상태: " + ", ".join(f"{k} {counts[k]}" for k in LIFECYCLE if counts[k]))
    print(f"오류 {len(errors)} · 경고 {len(warnings)} · 추적표 {out.relative_to(ROOT).as_posix()}")
    if not quiet:
        for e in errors:
            print("  오류:", e)
        for w_ in warnings:
            print("  경고:", w_)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
