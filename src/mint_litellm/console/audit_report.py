"""감사 보고서: 기간을 정해 정책 적용 범위·호출 판정·승인·변경·경보·단말·증적을 한 문서로 모은다.

문서는 구역마다 요약 항목과 표를 가진 한국어 구조 하나로 만들고, 화면·CSV 묶음·JSON이 같은 구조를
쓴다. 기존 조회(``dashboard_reads``·``reads``·``endpoint_kits``)를 그대로 부르고 기간 경계가 필요한
집계만 ``services.audit_report``에 둔다.
"""

import csv
import io
import json
import os
import zipfile
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import psycopg

from mint_litellm.console import labels
from mint_litellm.console.api import safe_cell
from mint_litellm.console.pages.endpoints_admin import endpoint_view
from mint_litellm.console.templating import local_time, span
from mint_litellm.control import endpoint_kits
from mint_litellm.control.errors import ControlError
from mint_litellm.control.services import audit_report as period_reads
from mint_litellm.control.services import dashboard_reads, reads

RANGES = (("7d", "7일", 7), ("30d", "30일", 30), ("90d", "90일", 90))
DEFAULT_RANGE = "30d"
MAX_DAYS = 366
POLICY_CLASS = {
    "unconditional": "무조건 집행",
    "conditional": "조건부 집행",
    "partial": "부분 집행",
    "semi_auto_evidence": "증적 반자동",
}
WATCHED = ("partial", "conditional")
_REPO_CATALOG = Path(__file__).resolve().parents[3] / "policy" / "catalog.json"


def resolve_period(
    zone: ZoneInfo,
    range_name: str | None,
    since: str | None,
    until: str | None,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """조직 시간대 기준 ``[시작, 끝)``. 날짜를 주면 시작일 0시~끝일 24시, 아니면 최근 N일."""
    today = (now or datetime.now(UTC)).astimezone(zone).date()
    try:
        last = date.fromisoformat(until) if until else today
        if since:
            first = date.fromisoformat(since)
        else:
            days = {r: d for r, _, d in RANGES}.get(range_name or DEFAULT_RANGE)
            if days is None:
                raise ControlError("기간은 7일·30일·90일 중에서 고르거나 날짜로 지정하십시오.")
            first = last - timedelta(days=days - 1)
    except ValueError:
        raise ControlError("날짜는 YYYY-MM-DD 형식이어야 합니다.") from None
    if first > last:
        raise ControlError("시작일이 끝일보다 늦습니다.")
    if (last - first).days >= MAX_DAYS:
        raise ControlError(f"기간은 최대 {MAX_DAYS}일까지 지정할 수 있습니다.")
    return (
        datetime(first.year, first.month, first.day, tzinfo=zone),
        datetime(last.year, last.month, last.day, tzinfo=zone) + timedelta(days=1),
    )


def load_catalog(root: Path | None) -> dict[str, Any] | None:
    for path in (
        *([root / "policy" / "catalog.json"] if root else []),
        Path(os.environ.get("MINT_POLICY_ROOT") or "/opt/mint") / "policy" / "catalog.json",
        _REPO_CATALOG,
    ):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


def _section(title: str, summary: list[tuple[str, Any]], tables: list[dict] | None = None) -> dict:
    return {
        "title": title,
        "summary": [{"label": k, "value": v} for k, v in summary],
        "tables": tables or [],
    }


def _table(title: str, columns: list[str], rows: list[list[Any]]) -> dict:
    return {"title": title, "columns": columns, "rows": rows}


def _percent(part: int, whole: int) -> str:
    return f"{round(100 * part / whole)}%" if whole else "—"


def _policy(catalog: dict[str, Any] | None) -> dict:
    if catalog is None:
        return _section("정책 적용 범위", [("정책 목록", "읽지 못함")])
    policies = catalog.get("policies", [])
    count = Counter(p["class"] for p in policies)
    rule: dict[str, list[str]] = {}
    for item in (*catalog.get("rules", []), *catalog.get("checks", [])):
        for pid in item.get("reference_policies", []):
            if item["description"] not in rule.setdefault(pid, []):
                rule[pid].append(item["description"])
    rows = [
        [p["id"], labels.pick(POLICY_CLASS, p["class"]), " / ".join(rule.get(p["id"], [])) or "—"]
        for p in policies
        if p["class"] in WATCHED
    ]
    return _section(
        "정책 적용 범위",
        [("전체 정책", len(policies)), *((name, count[k]) for k, name in POLICY_CLASS.items())],
        [_table("일부 또는 조건부로 집행되는 정책", ["정책", "구분", "적용되는 규칙"], rows)],
    )


def _decisions(data: dict) -> dict:
    t = data["totals"]
    family: Counter[str] = Counter()
    for r in data["reasons"]:
        family[labels.outcome_reason(r["code"])] += r["n"]
    summary = [("판정", t["total"])]
    summary += [(labels.OUTCOME_BUCKET[b], t[b]) for b in dashboard_reads.BUCKETS]
    return _section(
        "호출 판정",
        summary,
        [
            _table("차단 사유", ["사유", "건수"], [[k, n] for k, n in family.most_common()]),
            _table(
                "호출이 많은 서버",
                ["서버", "호출", "차단"],
                [[r["server_id"], r["calls"], r["blocked"]] for r in data["servers"]],
            ),
        ],
    )


def _approvals(data: dict) -> dict:
    reasons = [[(r["reason"] or "사유 없음")[:120], r["n"]] for r in data["denial_reasons"]]
    return _section(
        "승인",
        [
            ("승인 요청", data["opened"]),
            ("사람이 승인", data["by_person"]),
            ("자동 규칙이 승인", data["by_rule"]),
            ("보류 뒤 완료", data["held_completed"]),
            ("결정까지 걸린 중앙값", span(data["median_seconds"])),
            ("거부", data["denied"]),
            ("사용 없이 만료", data["expired_unused"]),
        ],
        [_table("거부 사유", ["사유", "건수"], reasons)],
    )


def _changes(counts: dict[str, int], versions: list[dict], zone: str) -> dict:
    rows = [
        [
            v["id"],
            labels.pick(labels.POLICY_VERSION, v["status"]),
            local_time(v["activated_at"], zone),
            labels.actor(v["activated_by"]),
        ]
        for v in versions
    ]
    return _section(
        "변경",
        [(labels.EVENT_KIND[k], n) for k, n in counts.items()],
        [_table("정책 판본", ["판본", "상태", "적용 시각", "적용자"], rows)],
    )


def _alerts(rows: list[dict]) -> dict:
    table = [
        [
            labels.pick(labels.ALERT_KIND, r["kind"]),
            labels.ALERT_SEVERITY[r["severity"]].text,
            r["opened"],
            r["closed"],
            r["still_open"],
        ]
        for r in rows
    ]
    return _section(
        "경보",
        [
            ("기간 중 발생", sum(r["opened"] for r in rows)),
            ("기간 중 해결", sum(r["closed"] for r in rows)),
            ("지금 열려 있음", sum(r["still_open"] for r in rows)),
        ],
        [_table("경보 종류별", ["종류", "심각도", "발생", "해결", "지금 열림"], table)],
    )


def _endpoints(conn: psycopg.Connection, instance: str, now: datetime) -> dict:
    view = endpoint_view(endpoint_kits.installs(conn, instance), [], now)
    live = [r for r in view["rows"] if r["group"]]
    cover = dashboard_reads.endpoint_coverage(conn, instance)
    kinds = Counter(k for r in live for k in r["violations"])
    count = view["count"]
    share = f"{_percent(cover['managed'], cover['total'])} ({cover['managed']}/{cover['total']})"
    return _section(
        "엔드포인트 현황(보고서 생성 시점)",
        [
            ("관리 대상 엔드포인트", len(live)),
            ("관리형 비율", share),
            ("정책 적용", count["applied"]),
            ("미적용", count["unapplied"]),
            ("보고 끊김", count["stale"]),
            ("격리 없이 실행", kinds["sandbox"]),
            ("호스트 제한 미집행", kinds["egress"]),
            ("실행기 밖 패키지", sum(len(r.get("outside_processes") or []) for r in live)),
        ],
    )


def _evidence(data: dict, zone: str) -> dict:
    sealed = f"{data['sealed']} ({_percent(data['sealed'], data['events'])})"
    return _section(
        "증적 무결성",
        [
            ("기간 중 기록", data["events"]),
            ("봉인된 기록", sealed),
            ("봉인 묶음", data["batches"]),
            ("마지막 봉인 번호", data["last_seal_seq"] or "—"),
            ("마지막 봉인 시각", local_time(data["last_sealed_at"], zone)),
            ("내보내기 성공", data["exports_written"]),
            ("내보내기 실패", data["exports_failed"]),
            ("마지막 내보내기", local_time(data["last_export_at"], zone)),
        ],
    )


def build(
    conn: psycopg.Connection,
    instance: str,
    start: datetime,
    end: datetime,
    *,
    zone: ZoneInfo,
    catalog: dict[str, Any] | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    name = zone.key
    versions = [
        v
        for v in reads.policy_versions(conn, instance)
        if v["activated_at"] and start <= v["activated_at"] < end
    ]
    sections = [
        _policy(catalog),
        _decisions(dashboard_reads.period_decisions(conn, instance, start, end)),
        _approvals(period_reads.approvals(conn, instance, start, end)),
        _changes(period_reads.changes(conn, instance, start, end), versions, name),
        _alerts(period_reads.alerts(conn, instance, start, end)),
        _endpoints(conn, instance, now),
        _evidence(period_reads.evidence(conn, instance, start, end), name),
    ]
    orgs = ", ".join(o["name"] for o in reads.orgs(conn, instance)) or "—"
    return {
        "meta": {
            "instance": instance,
            "orgs": orgs,
            "from": f"{start:%Y-%m-%d}",
            "to": f"{end - timedelta(days=1):%Y-%m-%d}",
            "generated_at": local_time(now, name),
            "time_zone": labels.pick(labels.TIME_ZONE, name),
        },
        "sections": sections,
    }


def to_zip(report: dict[str, Any]) -> bytes:
    """구역마다 CSV 하나(요약, 이어서 표). 엑셀용 BOM을 붙이고 수식 시작 문자는 막는다."""

    def csv_text(rows: list[list[Any]]) -> str:
        buf = io.StringIO()
        csv.writer(buf).writerows([[safe_cell(c) if c != "" else "" for c in r] for r in rows])
        return "﻿" + buf.getvalue()

    meta = report["meta"]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "00_개요.csv",
            csv_text(
                [
                    [label, meta[key]]
                    for label, key in (
                        ("서버", "instance"),
                        ("조직", "orgs"),
                        ("시작", "from"),
                        ("끝", "to"),
                        ("생성", "generated_at"),
                        ("시간대", "time_zone"),
                    )
                ]
            ),
        )
        for number, section in enumerate(report["sections"], 1):
            rows: list[list[Any]] = [["항목", "값"]]
            rows += [[i["label"], i["value"]] for i in section["summary"]]
            for table in section["tables"]:
                rows += [[], [table["title"]], table["columns"], *table["rows"]]
            name = section["title"].split("(")[0]
            archive.writestr(f"{number:02d}_{name}.csv", csv_text(rows))
    return out.getvalue()
