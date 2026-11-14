"""단말 MCP 목록 화면: 관리 대상 밖의 항목, 같은 항목을 가진 단말 수, 신청 시작 연결."""

import hashlib
import json

import pytest

INSTANCE = "inst1"


def add_install(world, user, mode, items, *, revoked=False):
    alias = f"mint-kit-{user}"
    world.query(
        "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
        " issued_by, install_mode, reported_at, local_mcp, revoked_at)"
        " VALUES (%s, %s, %s, %s, 'admin', %s, now(), %s::jsonb,"
        " CASE WHEN %s THEN now() END)",
        INSTANCE, hashlib.sha256(alias.encode()).hexdigest(), user, alias, mode,
        json.dumps(items), revoked,
    )


def item(name, kind="stdio", target="npx", **extra):
    return {"harness": "claude", "name": name, "kind": kind, "target": target,
            "package": None, "first_seen": "2026-01-02T03:04:05+00:00"} | extra


@pytest.fixture
def listed(world):
    shared = item("files", package="@scope/server-files@1.2.0")
    add_install(world, "human-1", "managed", [shared, item("docs", "http", "docs.example.com")])
    add_install(world, "human-2", "user", [shared | {"harness": "codex"}])
    add_install(world, "human-3", "managed", [item("gone")], revoked=True)
    add_install(world, "human-4", "removed", [item("removed")])
    return world.session_client("admin").get("/endpoints?tab=local-mcp").text


def test_the_list_shows_what_is_configured_and_how_many_endpoints_share_it(listed):
    assert "관리 밖 MCP" in listed
    assert "docs.example.com" in listed and "원격(HTTP)" in listed and "로컬 실행" in listed
    assert "@scope/server-files@1.2.0" in listed
    assert listed.count("2대") == 2 and "1대" in listed  # files는 두 단말, docs는 한 단말
    assert "Claude Code" in listed and "Codex" in listed
    assert "관리되지 않음" in listed and "관리형" in listed


def test_revoked_and_removed_installs_are_not_listed(listed):
    assert ">gone<" not in listed and ">removed<" not in listed


def test_each_row_starts_an_intake_prefilled_from_the_entry(listed):
    assert "도입 신청" in listed
    assert "/intakes/new?server_id=docs&amp;provider=docs.example.com" in listed
    assert "owner_user_id=human-1" in listed


def test_the_old_mcp_path_redirects_to_the_tab(world):
    response = world.session_client("admin").get("/endpoints/mcp", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/endpoints?tab=local-mcp"
    assert "tab=local-mcp" in world.session_client("admin").get("/endpoints").text


def test_an_empty_list_says_so(world):
    html = world.session_client("viewer").get("/endpoints?tab=local-mcp").text
    assert "보고된 관리 대상 밖의 MCP 서버가 없습니다" in html


def test_the_new_intake_form_is_prefilled_and_escapes_what_it_shows(world):
    client = world.session_client("admin")
    html = client.get(
        "/intakes/new", params={"server_id": "docs", "provider": '"><script>x</script>',
                                "purpose": "설정에서 발견"},
    ).text
    assert 'name="server_id" value="docs"' in html and "<script>x" not in html
    assert "설정에서 발견" in html and "신청 등록" in html


def fields(world, client):
    return {
        "csrf": world.csrf(client), "server_id": "docs", "provider": "docs.example.com",
        "owner_user_id": "human-1", "purpose": "목적", "data_grade": "internal",
        "allowed_resources": "[]", "credential_notice": "a", "revocation_record": "b",
        "audit_access_days": "90", "data_return_terms": "삭제",
    }


def test_a_viewer_cannot_submit_the_form_and_a_failed_submit_keeps_the_values(world):
    viewer = world.session_client("viewer").get("/intakes/new").text
    assert "신청 등록" not in viewer
    admin = world.session_client("admin")
    response = admin.post("/intakes", data=fields(world, admin))
    assert response.status_code == 403 and 'value="docs.example.com"' in response.text
    assert "제어 평면 키" in response.text  # 제어 평면 키가 없으면 LiteLLM을 읽을 수 없다.
    world.with_control_key()
    bad = admin.post("/intakes", data={**fields(world, admin), "allowed_resources": "not json"})
    assert bad.status_code == 400 and "입력 값이 올바르지 않습니다" in bad.text
    assert 'value="human-1"' in bad.text
