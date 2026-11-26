"""변경 경로의 역할은 서버가 확인한다(폼을 직접 보내도 우회할 수 없다). Root 운영자 삭제 제한."""

import pytest
from console_fixtures import TOKENS
from console_pages_support import form_post

from mint_litellm.console.pages import router
from mint_litellm.console.route_roles import ROUTE_ROLES
from mint_litellm.control import operators as op_domain
from mint_litellm.control.errors import ControlError

ADMIN_FORMS = {
    "/builtin-tools/block": {"harness": "claude", "tool": "WebSearch"},
    "/people/block": {"user_id": "u-1"},
    "/people/operator": {"user_id": "u-1", "role": "approver"},
    "/policy/mode": {"mode": "enforce", "state_version": "1"},
    "/operators/viewer/remove": {"state_version": "1", "confirm_name": "viewer"},
    "/servers/srv-ok/suspend": {},
    "/endpoints/revoke": {},
    "/allowlists": {},
}


def test_every_mutating_page_route_has_a_declared_role():
    posts = {r.path for r in router.routes if r.methods and r.methods & {"POST", "PUT", "DELETE"}}
    assert posts - set(ROUTE_ROLES) == set(), "역할을 적지 않은 변경 경로"
    assert set(ROUTE_ROLES) - posts == set(), "존재하지 않는 경로가 표에 있음"


@pytest.mark.parametrize("path", sorted(ADMIN_FORMS))
@pytest.mark.parametrize("role", ["approver", "viewer"])
def test_admin_only_posts_are_forbidden_to_lower_roles(world, path, role):
    client = world.session_client(role)
    done = form_post(world, client, path, **ADMIN_FORMS[path])
    assert done.status_code == 403, (path, done.status_code)
    assert world.query("SELECT count(*) FROM mint.denials") == [(0,)]


def test_an_approver_still_blocks_a_tool_through_the_denial_form(world):
    client = world.session_client("approver")
    assert form_post(world, client, "/builtin-tools/block", harness="claude",
                     tool="WebSearch").status_code == 403


def _operator(world, name, role="admin"):
    world.query(
        "INSERT INTO mint.operators (instance_id, name, role, token_hash, user_id)"
        " VALUES ('inst1', %s, %s, %s, %s)",
        name, role, op_domain.hash_token(TOKENS["admin"] + name), name)


def _remove(world, actor, name):
    from mint_litellm.control.context import Context
    from mint_litellm.control.db.connection import connect
    from mint_litellm.control.services import operators as service

    with connect(world.config.database_url) as conn:
        operator = op_domain.authenticate(conn, "inst1", TOKENS[actor])
        service.remove(Context(conn, "inst1", operator), name)


def test_only_root_removes_a_root_operator_and_the_default_root_never(world):
    _operator(world, "boss2")
    _operator(world, "root")
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'boss2']")
    with pytest.raises(ControlError, match="Root만"):
        _remove(world, "admin", "boss2")
    with pytest.raises(ControlError, match="기본 Root"):
        _remove(world, "admin", "root")
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'admin', 'boss2']")
    _remove(world, "admin", "boss2")  # Root 표지가 있는 관리자는 다른 Root를 삭제할 수 있다
    with pytest.raises(ControlError, match="기본 Root"):
        _remove(world, "admin", "root")


def test_the_operator_table_disables_the_delete_button_for_root_rows(world):
    _operator(world, "boss2")
    world.query("UPDATE mint.settings SET root_operators = ARRAY['root', 'boss2']")
    html = world.session_client("admin").get("/admin").text
    assert "Root 운영자는 Root만 삭제할 수 있습니다" in html
    assert 'action="/operators/boss2/remove"' not in html
