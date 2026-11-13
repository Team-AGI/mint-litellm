"""계약 드리프트 비교: 승인본과 관측본을 항목별로 맞추고, 선택한 항목을 줄 단위로 대조한다."""

import difflib
import hashlib
import json
from typing import Any

from mint_litellm.control import change_summary

DEPLOYMENT = "(배포)"
# 줄 비교 상한: 한쪽이라도 이 줄 수(정규화 JSON)나 바이트 수를 넘으면 줄 비교를 하지 않는다.
COMPARE_LIMIT_LINES = 2000
COMPARE_LIMIT_BYTES = 256 * 1024


def _pretty(text: str | None) -> list[str]:
    if text is None:
        return []
    try:
        value = json.loads(text)
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).splitlines()
    except ValueError:
        return text.split("\n")


def changes(info: dict[str, Any]) -> list[dict[str, Any]]:
    """``contract diff`` 결과에서 추가·삭제·변경된 항목(도구와 배포)을 낸다."""
    approved = {
        (c["credential_scope"], c["tool"]): c for c in info["tools"] if c["status"] == "approved"
    }
    observed = {
        (o["scope"], o["name"]): o for o in info["observations"] if o["kind"] == "tool"
    }
    rows = []
    for key in sorted(set(approved) | set(observed)):
        a, o = approved.get(key), observed.get(key)
        if a is not None and (o is None or a["drift"] == "removed"):
            kind = "removed"
        elif a is None:
            kind = "added"
        elif a["canonical_text"] != o["canonical_text"]:
            kind = "changed"
        else:
            continue
        rows.append({
            "scope": key[0], "name": key[1], "change": kind,
            "approved": a["canonical_text"] if a else None,
            "observed": o["canonical_text"] if o else None,
            "summary": (o or {}).get("change_summary") or change_summary.tool_summary(
                a["canonical_text"] if a else None, o["canonical_text"] if o else None),
        })
    deployment = next((d for d in info["deployments"] if d["status"] == "approved"), None)
    seen = next((o for o in info["observations"] if o["kind"] == "deployment"), None)
    if deployment is not None and seen is not None and (
        deployment["canonical_text"] != seen["canonical_text"]
    ):
        rows.append({
            "scope": "", "name": DEPLOYMENT, "change": "changed",
            "approved": deployment["canonical_text"], "observed": seen["canonical_text"],
            "summary": seen.get("change_summary") or "",
        })
    return rows


def _meta(text: str | None) -> dict[str, Any]:
    raw = (text or "").encode("utf-8")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def side_by_side(approved: str | None, observed: str | None) -> dict[str, Any]:
    """줄마다 (내용, 바뀐 줄 여부). 상한을 넘으면 줄 비교 없이 각 판본의 해시·크기만 낸다."""
    skipped = {"skipped": True, "approved": _meta(approved), "observed": _meta(observed)}
    if any(len((t or "").encode("utf-8")) > COMPARE_LIMIT_BYTES for t in (approved, observed)):
        return skipped
    left, right = _pretty(approved), _pretty(observed)
    if max(len(left), len(right)) > COMPARE_LIMIT_LINES:
        return skipped
    match = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    out_left: list[tuple[str, bool]] = []
    out_right: list[tuple[str, bool]] = []
    for tag, i1, i2, j1, j2 in match.get_opcodes():
        same = tag == "equal"
        out_left += [(line, not same) for line in left[i1:i2]]
        out_right += [(line, not same) for line in right[j1:j2]]
    return {"skipped": False, "approved": out_left, "observed": out_right}
