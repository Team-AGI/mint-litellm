"""공통 화면 틀: 역할별 메뉴, 사이드바 크기, 거부 화면·오류 화면 두 틀, 단추·낱말 규칙."""

import re
from pathlib import Path
from types import SimpleNamespace

from mint_litellm.console import labels
from mint_litellm.console.templating import ICONS, ROOT_MENU, is_root, menu_for

HTML = {"accept": "text/html"}
ROOT = Path(__file__).resolve().parents[3] / "src/mint_litellm/console"
STATIC = ROOT / "static"
TEMPLATES = ROOT / "templates"


def _nav(html: str) -> str:
    return re.findall(r'<nav\b[^>]*class="sidebar".*?</nav>', html, re.S)[0]


def menu_names(html: str) -> list[str]:
    return re.findall(r'<span class="nav-text">([^<]+)</span>', _nav(html))


def groups(html: str) -> list[str]:
    return re.findall(r'<div class="group-title">([^<]+)</div>', _nav(html))


def text_of(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html)


def test_the_menu_follows_the_new_structure_for_admins(world, admin):
    html = admin.get("/").text
    # Root가 아닌 관리자도 강제 조치 기록은 본다(긴급 통제는 Root만)
    assert groups(html) == ["처리할 일", "MCP 서버", "사람·단말", "감사", "설정", "Root"]
    assert menu_names(html) == [
        "대시보드", "시작하기", "승인 센터", "경보", "MCP 서버", "도입 신청", "접근 통제",
        "하네스 기본 기능", "사람", "단말", "가입 요청", "호출 기록", "감사 보고서", "사용량",
        "정책", "설정·운영자", "강제 조치 기록",
    ]


def test_the_menu_leaves_out_screens_the_role_cannot_use(world):
    viewer = menu_names(world.session_client("viewer").get("/").text)
    approver = menu_names(world.session_client("approver").get("/").text)
    assert viewer == ["대시보드", "경보", "MCP 서버", "도입 신청", "접근 통제", "단말", "호출 기록",
                      "감사 보고서", "사용량"]
    assert approver == ["대시보드", "승인 센터", "경보", "MCP 서버", "도입 신청", "접근 통제",
                        "단말", "호출 기록", "감사 보고서", "사용량"]


def _real_request(world, path, method="GET"):
    from starlette.requests import Request

    request = Request({
        "type": "http", "method": method, "path": path, "query_string": b"", "headers": [],
        "scheme": "https", "server": ("testserver", 443), "app": world.app, "state": {},
    })
    request.state.request_id = "r-1"
    return request


def _request(*paths):
    return SimpleNamespace(app=SimpleNamespace(routes=[SimpleNamespace(path=p) for p in paths]))


def _operator(name, role="admin"):
    return SimpleNamespace(role=role, session=SimpleNamespace(operator_name=name))


def test_setup_moves_to_settings_when_nothing_is_left_to_do():
    ctx = {"request": _request()}
    pending = menu_for(ctx, _operator("kim"), {"setup": 2})
    done = menu_for(ctx, _operator("kim"), {"setup": 0})
    assert pending[0][1][1][0] == "/setup"
    assert [i[0] for i in done[0][1]] == ["/"] and done[-1][1][-1][0] == "/setup"


def test_the_root_menu_needs_both_a_root_operator_and_an_existing_screen():
    root, admin = _operator("root"), _operator("kim")
    assert is_root(root) and not is_root(admin) and not is_root(_operator("root", "viewer"))
    assert [g for g, _ in menu_for({"request": _request()}, root)][-1] != ROOT_MENU[0]
    both = _request("/root", "/root/actions")
    shown = menu_for({"request": both}, root)
    assert shown[-1][0] == "Root"
    assert [i[1] for i in shown[-1][1]] == ["긴급 통제", "강제 조치 기록"]
    shown = menu_for({"request": both}, admin)
    assert [i[1] for i in shown[-1][1]] == ["강제 조치 기록"]  # 기록 열람은 관리자도


def test_the_sidebar_fits_sixteen_items_at_1440_by_900():
    css = (STATIC / "console.css").read_text(encoding="utf-8")
    item = int(re.search(r"--nav-item-h: (\d+)px", css).group(1))
    group = int(re.search(r"--nav-group-h: (\d+)px", css).group(1))
    assert (item, group) == (36, 24)
    # 상단 바 64 + 안쪽 여백 16 + 제목 줄 36 + 항목 16 + 그룹 제목 5 + 그룹 사이 5×9
    assert 64 + 16 + 36 + 16 * item + 5 * group + 5 * 9 <= 900
    assert "radial-gradient" in css.split(".sidebar {")[1].split("}")[0]  # 넘칠 때 그림자


def test_a_role_denial_page_has_the_denial_frame(world):
    page = world.session_client("viewer").get("/signup-requests", headers=HTML)
    assert page.status_code == 403 and 'class="sidebar"' in page.text
    text = text_of(page.text)
    assert "이 작업은 관리자가 할 수 있습니다" in text
    for part in ("지금 내 역할", "조회자", "막은 규칙", "영향 범위", "가입 요청", "해결",
                 "참조 번호", "요청 문구 복사", "권한이 있는 사람:"):
        assert part in text, part
    assert 'data-copy="[MINT 권한 요청]' in page.text
    assert "정책 거부가 아닙니다" not in text


def test_a_not_found_page_has_the_error_frame_and_does_not_repeat_the_title(world, admin):
    page = admin.get("/servers/없음", headers=HTML)
    assert page.status_code == 404
    text = text_of(page.text)
    for part in ("정책 거부가 아닙니다", "하던 일", "참조 번호", "다시 시도", "MCP 서버 화면으로"):
        assert part in text, part
    assert "지금 내 역할" not in text and "요청 문구 복사" not in text
    title = re.search(r"<h1>(.*?)</h1>", page.text).group(1)
    # 제목과 같은 문장이 본문에 따로 되풀이되지 않는다(문서 제목·h1 두 곳만 통째로 같다).
    assert len(re.findall(rf">\s*{re.escape(title)}\s*<", page.text)) == 1


def test_a_system_error_has_its_own_title_and_a_stale_conflict_keeps_the_plain_frame(world, admin):
    from mint_litellm.console.error_pages import TITLES, error_page

    assert TITLES[500] != "요청을 처리하지 못했습니다"
    request = _real_request(world, "/intakes/x", "POST")
    page = error_page(request, 409, "화면을 연 뒤 상태가 바뀌었습니다.", "r-1", "CONFLICT")
    body = page.body.decode()
    assert page.status_code == 409 and "화면을 연 뒤 상태가 바뀌었습니다." in body
    assert "정책 거부가 아닙니다" not in body and "지금 내 역할" not in body


def test_a_logged_out_denial_shows_the_frame_without_a_menu(world):
    from mint_litellm.console.error_pages import error_page

    request = _real_request(world, "/signup-requests")
    page = error_page(request, 403, "관리자만 가입 요청을 처리할 수 있습니다.", "r-2")
    body = page.body.decode()
    assert "지금 내 역할" in body and 'class="sidebar"' not in body and "요청 문구 복사" in body


def test_processing_state_and_button_kinds_exist():
    js = (STATIC / "console.js").read_text(encoding="utf-8")
    assert "처리 중…" in js and 'addEventListener("submit"' in js and "aria-busy" in js
    css = (STATIC / "console.css").read_text(encoding="utf-8")
    for rule in ("button.danger-outline", "td button.danger", ".blocked-action", ".banner.warn"):
        assert rule in css
    macros = (TEMPLATES / "macros.html").read_text(encoding="utf-8")
    for name in ("blocked_button", "banner", "copy_button", "denied", "failed", "error_frame"):
        assert f"{{% macro {name}(" in macros


def test_a_confirm_dialog_trigger_is_an_outline_button_and_the_last_button_is_filled():
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=True)
    env.globals.update(ICONS=ICONS, L=labels)
    ui = env.get_template("macros.html").module
    actor = SimpleNamespace(csrf="c")
    html = str(ui.confirm_dialog("d1", "차단", "제목", "영향", "/x", actor, "차단"))
    assert 'class="danger-outline" data-dialog-open="d1"' in html
    assert '<button type="submit" class="danger">' in html
    blocked = str(ui.blocked_button("차단", "관리자만 할 수 있습니다", "danger-outline"))
    assert "disabled" in blocked and "관리자만 할 수 있습니다" in blocked
    banner = ui.banner("error", "저장하지 못했습니다", "연결 끊김", "/x", "다시")
    assert 'role="alert"' in str(banner)


def test_severity_and_state_do_not_share_an_icon_or_colour():
    shown = list(labels.ALERT_SEVERITY.values())
    assert len({s.level for s in shown}) == 4 and all(s.level.startswith("sev-") for s in shown)
    assert labels.ALERT_STATUS["open"].level == "wait"
    assert all(s.level in ICONS for s in shown) and ICONS["sev-high"] != ICONS["error"]
    css = (STATIC / "console.css").read_text(encoding="utf-8")
    for level in ("critical", "high", "medium", "low"):
        assert f".badge.sev-{level}" in css


def test_unknown_kinds_are_named_not_shown_raw():
    assert labels.pick(labels.ALERT_KIND, "operational_check") == "운영 자기 점검"
    assert labels.pick(labels.ALERT_KIND, "brand_new_kind") == "알 수 없는 종류(brand_new_kind)"
    assert labels.pick(labels.ALERT_KIND, None) == "—"


def test_the_staff_menu_uses_the_agreed_words():
    from mint_litellm.console.templating import STAFF_MENU

    assert [name for _, name, _ in STAFF_MENU[0][1]] == [
        "내 MCP 서버", "서버 신청", "내 요청", "내 사용량", "내 PC"
    ]
