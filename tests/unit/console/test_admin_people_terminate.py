"""관리자 화면: 사람, 이용 종료, 등록부 내보내기, 로컬 MCP 신청 값 넘기기."""

import csv
import io
from types import SimpleNamespace

from console_pages_support import INSTANCE, add_approval, form_post


def add_person(world, user_id="u-1", email="kim@acme.test", teams="[]"):
    world.query(
        "INSERT INTO mint.directory_users (instance_id, user_id, email, litellm_role, team_ids)"
        " VALUES (%s, %s, %s, 'internal_user', %s::jsonb)", INSTANCE, user_id, email, teams)


def test_the_people_screen_lists_blocks_and_designates(world, admin):
    add_person(world)
    html = admin.get("/people").text
    assert "kim@acme.test" in html and "일반 사용자" in html and "정상" in html
    assert 'href="/people"' in html
    assert form_post(world, admin, "/people/block", user_id="u-1", reason="점검").status_code == 303
    sql = "SELECT scope_id, server_id FROM mint.denials WHERE lifted_at IS NULL"
    assert world.query(sql) == [("u-1", None)]
    assert "일부 차단" in admin.get("/people").text
    assert "MCP 차단 해제" in admin.get("/people?open=u-1").text
    assert form_post(world, admin, "/people/unblock", user_id="u-1").status_code == 303
    assert world.query(sql) == []
    assert form_post(world, admin, "/people/block", user_id="nobody").status_code == 404
    object.__setattr__(world.config, "litellm_admin", SimpleNamespace(
        get_user={"u-1": {"user_role": "internal_user"}}.get))
    got = form_post(world, admin, "/people/operator", user_id="u-1", role="viewer")
    assert got.status_code == 303, got.text
    assert "조회자" in admin.get("/people").text
    assert "kim" not in admin.get("/people?q=zzz").text
    viewer = world.session_client("viewer")
    assert form_post(world, viewer, "/people/operator", user_id="u-1").status_code == 403


def test_the_denial_form_suggests_people(world, admin):
    add_person(world)
    html = admin.get("/access?tab=denials&new=1").text
    assert '<option value="u-1">kim@acme.test</option>' in html


def relation(world):
    return world.query(
        "SELECT id, state_version FROM mint.usage_relations WHERE server_id = 'srv-ok'")[0]


def test_ending_a_relation_shows_the_impact_then_terminates_and_finishes(world, admin):
    add_person(world, "human-5", "five@acme.test")
    add_approval(world)
    html = admin.get("/servers/srv-ok?tab=usage").text
    assert "이용 종료" in html and "승인 1건" in html and "사용자 1명" in html
    rid, version = relation(world)
    viewer = world.session_client("viewer")
    path = f"/servers/srv-ok/relations/{rid}/terminate"
    assert form_post(world, viewer, path, state_version=version).status_code == 403
    assert form_post(world, admin, path, state_version=version).status_code == 303
    assert world.query("SELECT status FROM mint.usage_relations WHERE id = %s", rid) == [
        ("terminating",)]
    assert world.query("SELECT status FROM mint.approvals WHERE relation_id = %s", rid) == [
        ("revoked",)]
    assert "종료 완료" in admin.get("/servers/srv-ok?tab=usage").text
    finish = form_post(world, admin, f"/servers/srv-ok/relations/{rid}/finish",
                       state_version=relation(world)[1])
    assert finish.status_code == 409 and "증빙" in finish.text
    assert "삭제·반환 증빙 붙이기" in admin.get("/servers/srv-ok?tab=usage").text
    assert form_post(world, admin, f"/servers/srv-ok/relations/{rid}/evidence",
                     summary="자료를 모두 삭제함").status_code == 303
    assert "삭제·반환 증빙 붙이기" not in admin.get("/servers/srv-ok?tab=usage").text
    finish = form_post(world, admin, f"/servers/srv-ok/relations/{rid}/finish",
                       state_version=relation(world)[1])
    assert finish.status_code == 303
    assert world.query("SELECT status FROM mint.usage_relations WHERE id = %s", rid) == [
        ("terminated",)]
    other = f"/servers/nope/relations/{rid}/terminate"
    assert form_post(world, admin, other, state_version=version).status_code == 404


def test_the_registry_is_exported_as_csv(world, admin):
    add_approval(world)
    got = admin.get("/servers/export")
    assert got.status_code == 200 and "text/csv" in got.headers["content-type"]
    rows = list(csv.reader(io.StringIO(got.text.lstrip("\ufeff"))))
    assert rows[0] == ["MCP 서버", "제공자", "승인 상태", "승인 범위", "만료", "신청자"]
    mine = [r for r in rows if r[0] == "srv-ok"]
    assert mine and mine[0][2] == "유효" and mine[0][3] == "사용자 human-5"
    assert "/servers/export" in admin.get("/servers").text


def test_a_local_mcp_from_an_endpoint_opens_the_command_form(world, admin):
    add_person(world, "u-9", "nine@acme.test")
    html = admin.get("/intakes/new", params={
        "server_id": "my-tool", "provider": "npx", "package": "@x/my-tool", "kind": "stdio",
        "owner_user_id": "u-9", "purpose": "발견"}).text
    assert 'name="owner_user_id" value="u-9"' in html and 'name="local" value="1"' in html
    assert "소스 저장소 주소" in html and "npx @x/my-tool" in html
    assert 'name="name" value="my_tool"' in html
    plain = admin.get("/intakes/new").text
    assert 'name="local"' not in plain
    got = form_post(world, admin, "/intakes", server_url="https://example.com/mcp",
                    purpose="x", local="1", owner_user_id="u-9")
    assert got.status_code == 400 and "소스 저장소" in got.text
    got = form_post(world, admin, "/intakes", server_url="https://example.com/mcp",
                    purpose="x", owner_user_id="ghost")
    assert got.status_code == 400 and "사람 목록" in got.text, got.text[-600:]
