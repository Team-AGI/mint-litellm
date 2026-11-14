"""화면 요소→동작 표: 모든 링크·POST·구 경로가 실제 경로로 이어진다(404·500 없음)."""

import html
import re

from console_pages_support import PAGES

# 새 화면 경로(경로 계약)와 탭·필터 쿼리
SCREENS = [
    "/approvals?tab=servers", "/approvals?tab=renewals", "/approvals?tab=rules",
    "/approvals?tab=rules&new=1", "/approvals?tab=calls&focus=00000000-0000-0000-0000-000000000000",
    "/servers?filter=changed", *(
        f"/servers/srv-ok?tab={t}"
        for t in ("overview", "contract", "tools", "packages", "vulns", "usage", "evidence")
    ),
    "/intakes", "/intakes?status=stalled", "/access?tab=approvals", "/access?tab=dormant",
    "/access?tab=denials", "/access?tab=allowlists", "/endpoints?tab=installs",
    "/endpoints?tab=local-mcp", "/endpoints?state=violation", "/alerts?status=open",
    "/alerts?severity=high", "/ledger?result=blocked&range=7d",
    "/policy", "/reports/audit", "/admin?tab=operators", "/admin?tab=orgs",
    "/admin?tab=suggestions",
]
# 구 경로 -> 도착지(경로 계약)
LEGACY = {
    "/call-approvals": "/approvals?tab=calls",
    "/contracts": "/servers?filter=changed",
    "/contracts/srv-ok?scope=a": "/servers/srv-ok?tab=contract&scope=a",
    "/revocations": "/access?tab=denials",
    "/endpoints/mcp": "/endpoints?tab=local-mcp",
    "/alerts/abc": "/alerts?open=abc",
    "/approvals/new?relation_id=r1": "/approvals/review/r1",
}
# 요소·동작 표의 POST 동작과 직원 화면 경로(경로 변수는 임의 값)
POSTS = [
    "/call-approvals/x/approve", "/call-approvals/x/reject", "/call-approvals/bulk/approve",
    "/call-approval-rules", "/call-approval-rules/x/disable", "/approvals", "/approvals/renew",
    "/approvals/x/revoke", "/approvals/x/recertify", "/approvals/dormant/keep",
    "/approvals/dormant/revoke", "/servers/x/suspend", "/servers/x/resume",
    "/servers/x/evidence", "/contracts/x/reapprove", "/intakes", "/intakes/new",
    "/intakes/x/recheck", "/intakes/x/decision", "/intakes/x/evidence", "/denials",
    "/denials/x/lift", "/allowlists", "/allowlists/x/lift", "/alerts/x/acknowledge",
    "/policy/shadow/apply", "/policy/shadow/cancel", "/policy/mode", "/operators/x/role",
    "/operators/x/remove", "/orgs", "/orgs/x/close", "/org-suggestions/x/apply",
    "/staff/consents", "/staff/consents/x/revoke", "/staff/confirmations/x/confirm",
    "/staff/confirmations/x/reject", "/staff/confirmations/x/cancel", "/staff/endpoint/kit",
    "/staff/endpoint/revoke",
]
STAFF_GETS = ["/staff", "/staff/confirmations", "/staff/endpoint", "/staff/requests",
              "/staff/consents", "/staff/login"]
LINK = re.compile(r'(?:href|formaction|action)="(/[^"#]*)"')


def resolves(app, method: str, path: str) -> bool:
    scope = {"type": "http", "method": method, "path": path.split("?")[0]}
    return any(route.matches(scope)[0].name == "FULL" for route in app.routes)


def test_every_post_and_staff_route_in_the_action_table_resolves(world):
    app = world.client.app
    missing = [p for p in POSTS if not resolves(app, "POST", p)]
    missing += [p for p in STAFF_GETS if not resolves(app, "GET", p)]
    assert missing == []


def test_old_paths_redirect_to_the_new_screens_and_every_new_screen_renders(admin):
    for old, new in LEGACY.items():
        response = admin.get(old, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == new, old
    for path in SCREENS:
        response = admin.get(path)
        assert response.status_code == 200, (path, response.text[:200])


def test_every_link_on_every_screen_resolves(admin):
    seen: set[str] = set()
    for page in [*PAGES, *SCREENS]:
        for target in LINK.findall(admin.get(page).text):
            target = html.unescape(target)
            if target in seen or target.startswith(("/static/", "/logout")):
                continue
            seen.add(target)
            if not resolves(admin.app, "GET", target):
                continue  # form action(POST 경로)
            response = admin.get(target, follow_redirects=False)
            assert response.status_code in (200, 303), (page, target, response.status_code)
    assert len(seen) > 40
