"""하네스 기본 기능 화면: 도구별 차단·허용과 호출 판정 반영."""

import re

import pytest
from console_pages_support import INSTANCE, form_post


def test_an_admin_blocks_and_allows_a_builtin_tool(world, admin):
    html = admin.get("/builtin-tools").text
    assert "<h1>하네스 기본 기능</h1>" in html and "Claude Code" in html and "Codex" in html
    assert 'name="tool" value="Bash"' in html
    done = form_post(world, admin, "/builtin-tools/block", harness="claude", tool="Bash")
    assert done.status_code == 303, done.text
    assert world.query("SELECT scope_type, scope_id, server_id, tools FROM mint.denials"
                       " WHERE lifted_at IS NULL") == [
        ("server", "builtin:claude", "builtin:claude", ["Bash"])]
    html = admin.get("/builtin-tools").text
    denial, version = world.query("SELECT id::text, state_version FROM mint.denials")[0]
    assert f'value="{denial}"' in html
    lifted = form_post(world, admin, "/builtin-tools/allow", denial_id=denial,
                       state_version=version)
    assert lifted.status_code == 303, lifted.text
    assert world.query("SELECT count(*) FROM mint.denials WHERE lifted_at IS NULL") == [(0,)]


def test_unknown_builtins_and_viewers_are_refused(world, admin):
    bad = form_post(world, admin, "/builtin-tools/block", harness="claude", tool="rm")
    assert bad.status_code == 400
    viewer = world.session_client("viewer")
    page = viewer.get("/builtin-tools").text
    assert not re.search(r'action="/builtin-tools/block"', page)
    assert form_post(world, viewer, "/builtin-tools/block", harness="codex",
                     tool="apply_patch").status_code == 403
    assert world.query("SELECT count(*) FROM mint.denials") == [(0,)]


def test_a_denial_still_needs_a_known_server(world):
    with pytest.raises(Exception, match="unknown server"):
        world.query("INSERT INTO mint.denials (id, instance_id, scope_type, scope_id, server_id,"
                    " reason, created_by) VALUES (gen_random_uuid(), %s, 'server', 'nope',"
                    " 'nope', 'r', 'admin')", INSTANCE)
