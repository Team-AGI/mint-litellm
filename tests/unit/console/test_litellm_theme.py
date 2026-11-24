"""로그인 입력 의미와 두 콘솔의 비밀번호 경고를 확인한다."""

from types import SimpleNamespace

import pytest

from .test_screen_polish import render


def test_login_fields_match_the_supported_account_types():
    admin = render("login.html")
    staff = render("staff_login.html")
    assert '아이디 또는 이메일<input name="username"' in admin
    assert '이메일<input type="email" name="username"' in staff
    for name in ("login.html", "staff_login.html"):
        assert "회사 계정으로 로그인" in render(name, sso=True)


@pytest.mark.parametrize("name,href", [
    ("base.html", "/account/password"),
    ("staff_base.html", "/staff/account/password"),
])
def test_default_password_warning_is_optional_and_links_to_the_existing_page(name, href):
    warning = "기본 비밀번호를 쓰고 있습니다. 지금 바꾸십시오."
    assert warning not in render(name)
    assert warning not in render(name, default_password=False)
    html = render(name, default_password=True)
    assert warning in html and f'<a href="{href}">비밀번호 바꾸기</a>' in html


@pytest.mark.parametrize("name", ["base.html", "staff_base.html"])
def test_navigation_keeps_accessible_names_when_only_icons_are_visible(name):
    html = render(name)
    assert 'aria-controls="sidebar"' in html and 'data-sidebar-toggle' in html
    assert 'class="nav-icon"' in html and 'class="nav-text"' in html
    assert 'aria-label="메뉴"' in html


@pytest.mark.parametrize("name,href", [
    ("base.html", "/account/password"),
    ("staff_base.html", "/staff/account/password"),
])
def test_mobile_menu_keeps_the_account_actions_available(name, href):
    actor = SimpleNamespace(csrf="t", role="admin", key_token="pw:user", label="직원",
                            session=SimpleNamespace(operator_name="root", key_token="pw:root"))
    html = render(name, actor=actor, litellm_open=True)
    mobile = html.split('<div class="mobile-account group">')[1].split('</div>')[0]
    assert f'href="{href}"' in mobile and "LiteLLM 콘솔" in mobile
