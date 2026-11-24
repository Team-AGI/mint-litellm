"""단말 화면의 「앱」 구역: 목록, 상태 표시명, 회수 버튼, 안내 한 줄."""

from datetime import UTC, datetime
from types import SimpleNamespace

from mint_litellm.console.pages.endpoints_admin import STATES, VIOLATIONS, endpoint_view
from mint_litellm.console.templating import templates

from .test_screen_polish import render

WHEN = datetime(2026, 11, 3, tzinfo=UTC)
ROW = {"user_id": "u1", "team_id": "t", "state": "managed", "claude_version": "1",
       "mcp_servers": [], "issued_at": WHEN, "reported_at": None}
LIVE = "0197c0de-0000-7000-8000-00000000000a"


def app(name, state, app_id):
    return {"id": app_id, "name": name, "state": state, "created_at": WHEN, "expires_at": WHEN,
            "revoked_at": WHEN if state == "revoked" else None, "key_alias": f"mint-kit-app-{name}"}


APPS = [app("bot", "active", LIVE), app("old", "expired", LIVE[:-1] + "b"),
        app("gone", "revoked", LIVE[:-1] + "c")]


def drawer(role, apps):
    view = endpoint_view([{**ROW, "apps": apps}], [], datetime(2026, 11, 4, tzinfo=UTC))
    actor = SimpleNamespace(csrf="t", role=role, user_id="u",
                            session=SimpleNamespace(operator_name="n"))
    return templates.get_template("endpoints.html").render({
        **view, "actor": actor, "path": "/endpoints", "notice": None, "error": None,
        "zone_label": "z", "tab": "installs", "state": "", "STATES": STATES,
        "VIOLATIONS": VIOLATIONS, "selected": view["rows"][0]})


def test_the_admin_drawer_lists_apps_with_korean_states_and_revokes_only_active_ones():
    html = drawer("admin", APPS)
    for text in ("<h3>앱</h3>", "bot", "old", "gone", "사용 중", "만료", "회수됨", "자격 회수"):
        assert text in html, text
    assert html.count("/endpoints/apps/") == 1  # 사용 중인 앱 하나만 회수 대상
    assert f"/endpoints/apps/{LIVE}/revoke" in html
    assert "mint-kit-app" not in html and "key_alias" not in html


def test_a_viewer_sees_the_apps_but_no_revoke_button_and_no_apps_is_said_plainly():
    assert "bot" in drawer("viewer", APPS) and "자격 회수" not in drawer("viewer", APPS)
    assert "만든 앱이 없습니다" in drawer("admin", [])


def test_the_staff_screen_lists_own_apps_with_the_how_to_line():
    html = render("staff_endpoint.html", rows=[ROW], active=True, apps=APPS)
    for text in ("<h2>앱</h2>", "bot", "사용 중", "만료", "회수됨", "자격 회수",
                 "PC 터미널에서", "mint app new 이름"):
        assert text in html, text
    assert html.count("/staff/endpoint/apps/") == 1
    assert "mint-kit-app" not in html


def test_without_apps_the_staff_screen_shows_only_the_how_to_line():
    html = render("staff_endpoint.html", rows=[ROW], active=True, apps=[])
    assert "mint app new 이름" in html and "자격 회수" not in html
    assert "<th>만든 날</th>" not in html
