"""화면 시험: 운영자·조직과 조직 제안."""

import uuid

from console_pages_support import (
    INSTANCE,
    form_post,
)


def test_closing_an_org_needs_its_identifier_typed(world, admin):
    version = world.query("SELECT state_version FROM mint.orgs WHERE org_id = 'acme'")[0][0]
    # 이용 관계가 열려 있어도 닫기 자체는 서비스 규칙을 따른다. 이름 확인이 먼저다.
    wrong = form_post(world, admin, "/orgs/acme/close", state_version=version, confirm_name="x")
    assert wrong.status_code == 400 and "이름을 정확히 입력" in wrong.text
    assert world.query("SELECT status FROM mint.orgs WHERE org_id = 'acme'")[0][0] == "active"


def add_suggestion(world, subject_id, rule="email_domain", subject_type="user"):
    world.query(
        "INSERT INTO mint.org_suggestions (id, instance_id, subject_type, subject_id, org_id,"
        " rule, matched, calls) VALUES (%s, %s, %s, %s, 'acme', %s, 'acme.example', 3)",
        str(uuid.uuid4()), INSTANCE, subject_type, subject_id, rule)
    sql = "SELECT id FROM mint.org_suggestions WHERE subject_id = %s"
    return world.query(sql, subject_id)[0][0]


def test_org_suggestions_are_listed_and_applied_or_ignored_by_an_admin(world, admin):
    first, second, third = (add_suggestion(world, f"sug-{i}") for i in range(3))
    html = admin.get("/admin").text
    assert "조직 연결 제안" in html and "이메일 도메인 (3건)" in html and "sug-0" in html
    viewer = world.session_client("viewer")
    assert "/apply" not in viewer.get("/admin").text
    assert form_post(world, viewer, f"/org-suggestions/{first}/apply").status_code == 403
    assert admin.post(f"/org-suggestions/{first}/apply", data={}).status_code == 403  # CSRF
    assert form_post(world, admin, f"/org-suggestions/{first}/apply").status_code == 303
    bound = world.query("SELECT org_id FROM mint.org_bindings WHERE subject_id = 'sug-0'")
    assert bound[0][0] == "acme"
    assert form_post(world, admin, f"/org-suggestions/{second}/ignore").status_code == 303
    assert form_post(world, admin, "/org-suggestions/rule", rule="email_domain").status_code == 303
    status = "SELECT status FROM mint.org_suggestions WHERE id = %s"
    assert world.query(status, third)[0][0] == "applied"
    assert world.query(status, second)[0][0] == "ignored"
    assert "조직 연결 제안" not in admin.get("/admin").text
