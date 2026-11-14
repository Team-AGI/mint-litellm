"""감사 보고서: 시드한 배치의 구역별 숫자, CSV 묶음, 역할별 접근, 화면 렌더링."""

import io
import json
import uuid
import zipfile
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from console_fixtures import TOKENS

from mint_litellm.console import audit_report
from mint_litellm.control.errors import ControlError

from .test_approval_metrics import seed as seed_approval
from .test_dashboard import decision
from .test_staff_pages import STAFF_COOKIE

INSTANCE = "inst1"
ZONE = ZoneInfo("Asia/Seoul")


def bearer(role: str = "viewer") -> dict:
    return {"Authorization": f"Bearer {TOKENS[role]}"}


def report(world, role="viewer", query="") -> dict:
    response = world.client.get(f"/api/v1/reports/audit{query}", headers=bearer(role))
    assert response.status_code == 200, response.text
    return response.json()


def section(data: dict, title: str) -> dict:
    return next(s for s in data["sections"] if s["title"].startswith(title))


def values(data: dict, title: str) -> dict:
    return {i["label"]: i["value"] for i in section(data, title)["summary"]}


def event(world, kind: str, days_ago: int = 0) -> None:
    world.query(
        "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key, payload)"
        " VALUES (%s, %s, now() - make_interval(days => %s), %s, %s, '{}'::jsonb)",
        uuid.uuid4(),
        INSTANCE,
        days_ago,
        kind,
        f"{kind}:{uuid.uuid4()}",
    )


def alert(world, kind, severity, resolved=False, days_ago=1):
    alert_id = uuid.uuid4()
    world.query(
        "INSERT INTO mint.alerts (id, instance_id, kind, severity, dedup_key, first_at)"
        " VALUES (%s, %s, %s, %s, %s, now() - make_interval(days => %s))",
        alert_id,
        INSTANCE,
        kind,
        severity,
        str(uuid.uuid4()),
        days_ago,
    )
    if resolved:
        world.query(
            "UPDATE mint.alerts SET status = 'resolved', resolved_at = now() WHERE id = %s",
            alert_id,
        )


def days_back(n: int) -> str:
    return (datetime.now(ZONE) - timedelta(days=n)).strftime("%Y-%m-%d")


@pytest.fixture
def seeded(world):
    decision(world)
    decision(world)
    decision(
        world, outcome="blocked", enforced="block", reason="SERVER_SUSPENDED", server="srv-wait"
    )
    decision(world, hours_ago=24 * 40)  # 기간 밖
    seed_approval(world, status="approved", approved_by="human-2", decided="3 minutes")
    seed_approval(world, status="approved", approved_by="rule:" + str(uuid.uuid4()), window=30)
    seed_approval(world, status="rejected")
    world.query(
        "UPDATE mint.call_approvals SET decision_reason = '범위 밖' WHERE status = 'rejected'"
    )
    seed_approval(world, status="expired")
    event(world, "server_registered")
    event(world, "server_registered", days_ago=60)
    event(world, "contract_approved")
    event(world, "export_written")
    alert(world, "call_spike", "high")
    alert(world, "call_spike", "high", resolved=True)
    alert(world, "contract_drift", "medium", days_ago=80)
    return world


def test_each_section_counts_only_the_period(seeded):
    data = report(seeded, query=f"?from={days_back(29)}")
    assert [s["title"].split("(")[0] for s in data["sections"]] == [
        "정책 적용 범위",
        "호출 판정",
        "승인",
        "변경",
        "경보",
        "엔드포인트 현황",
        "증적 무결성",
    ]
    d = values(data, "호출 판정")
    assert (d["판정"], d["허용"], d["차단"]) == (3, 2, 1)
    assert section(data, "호출 판정")["tables"][0]["rows"] == [["중지된 서버", 1]]
    assert ["srv-ok", 2, 0] in section(data, "호출 판정")["tables"][1]["rows"]
    a = values(data, "승인")
    assert [
        a[k] for k in ("승인 요청", "사람이 승인", "자동 규칙이 승인", "거부", "사용 없이 만료")
    ] == [
        4,
        1,
        1,
        1,
        1,
    ]
    assert a["결정까지 걸린 중앙값"] != "—"
    assert section(data, "승인")["tables"][0]["rows"] == [["범위 밖", 1]]
    c = values(data, "변경")
    assert (c["서버 등록"], c["계약 승인"]) == (1, 1)
    al = values(data, "경보")
    # 80일 전에 열린 경보는 기간 밖이지만 아직 열려 있으므로 현재 열림에는 센다
    assert (al["기간 중 발생"], al["기간 중 해결"], al["지금 열려 있음"]) == (2, 1, 2)
    e = values(data, "증적")
    assert e["내보내기 성공"] == 1 and e["기간 중 기록"] >= 5


def test_the_policy_section_lists_only_partial_and_conditional_rules_without_dev_text(world):
    s = section(report(world), "정책")
    assert {r[1] for r in s["tables"][0]["rows"]} == {"조건부 집행", "부분 집행"}
    text = json.dumps(s, ensure_ascii=False)
    assert "src/" not in text and ".rego" not in text and "::" not in text


def test_a_custom_period_includes_both_end_dates(seeded):
    old = days_back(60)
    data = report(seeded, query=f"?from={old}&to={old}")
    assert values(data, "변경")["서버 등록"] == 1
    assert values(data, "호출 판정")["판정"] == 0
    assert data["meta"]["from"] == data["meta"]["to"] == old


@pytest.mark.parametrize(
    "query",
    ["?from=no-date", "?from=2100-01-02&to=2100-01-01", "?from=1999-01-01"],
)
def test_a_bad_period_is_refused(world, query):
    response = world.client.get(f"/api/v1/reports/audit{query}", headers=bearer("admin"))
    assert response.status_code == 400


def test_the_zip_has_one_csv_per_section_with_the_same_numbers(seeded):
    response = seeded.client.get("/api/v1/reports/audit?format=zip", headers=bearer("admin"))
    assert response.headers["content-type"] == "application/zip"
    assert "attachment" in response.headers["content-disposition"]
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    names = archive.namelist()
    assert names[0] == "00_개요.csv" and len(names) == 8
    judgement = archive.read("02_호출 판정.csv").decode("utf-8-sig")
    assert "판정,3" in judgement and "중지된 서버,1" in judgement
    assert archive.read("03_승인.csv").decode("utf-8-sig").count("범위 밖") == 1


def test_csv_cells_cannot_start_a_spreadsheet_formula():
    meta = dict.fromkeys(("instance", "orgs", "from", "to", "generated_at", "time_zone"), "x")
    summary = [{"label": "항목", "value": "=1+1"}]
    doc = {"meta": meta, "sections": [{"title": "승인", "summary": summary, "tables": []}]}
    archive = zipfile.ZipFile(io.BytesIO(audit_report.to_zip(doc)))
    assert "'=1+1" in archive.read("01_승인.csv").decode("utf-8-sig")


def test_the_period_is_resolved_in_the_zone_and_validated():
    now = datetime(2031, 5, 10, 15, 30, tzinfo=UTC)  # 서울 5월 11일 0시 30분
    start, end = audit_report.resolve_period(ZONE, "7d", None, None, now)
    assert (start.date(), end.date()) == (date(2031, 5, 5), date(2031, 5, 12))
    with pytest.raises(ControlError):
        audit_report.resolve_period(ZONE, "1y", None, None, now)


@pytest.mark.parametrize("role", ["admin", "approver", "viewer"])
def test_every_operator_role_can_read_it(world, role):
    assert report(world, role)["meta"]["instance"] == INSTANCE


def test_without_login_and_for_staff_nothing_is_shown(world):
    assert world.client.get("/api/v1/reports/audit").status_code == 401
    assert world.client.get("/reports/audit").headers["location"] == "/login"
    stranger = world.client.__class__(
        world.app, base_url="https://testserver", follow_redirects=False
    )
    stranger.cookies.set(STAFF_COOKIE, "x" * 40)
    assert stranger.get("/reports/audit").headers["location"] == "/login"
    assert stranger.get("/api/v1/reports/audit").status_code == 401


def test_the_page_renders_a_printable_document_with_downloads(seeded, admin):
    page = admin.get("/reports/audit?range=30d")
    assert page.status_code == 200
    for text in (
        "감사 보고서",
        "1. 정책 적용 범위",
        "7. 증적 무결성",
        "중지된 서버",
        "report.css",
        "format=zip",
    ):
        assert text in page.text
    assert "page-start" in page.text and "data-print" in page.text
    assert admin.get("/reports/audit?since=no-date&until=no-date").status_code == 400
    assert 'href="/reports/audit"' in admin.get("/policy").text
    assert 'href="/reports/audit"' in admin.get("/").text
    css = admin.get("/static/report.css").text
    assert "size: A4" in css and "break-before: page" in css
