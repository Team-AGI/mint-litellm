"""조직 연결 제안: 규칙, 점검 작업, 적용·무시·일괄 적용, 도메인 대응표."""

from types import SimpleNamespace

import pytest
from ctl_fixtures import INSTANCE

pytest.importorskip("psycopg")

from mint_litellm.control import jobs, org_suggest, orgs  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.services import orgs as org_service  # noqa: E402
from mint_litellm.types.identity import SubjectType  # noqa: E402

ORGS = {"acme": "ACME Corp", "beta": "Beta"}


def test_rules_pick_the_first_match_and_skip_bound_subjects():
    teams = [
        {"team_id": "t1", "team_alias": "beta-ops", "metadata": {"mint_org": "acme"}},
        {"team_id": "t2", "team_alias": "ACME-data"},
        {"team_id": "t3", "team_alias": "acmeless"},  # 접두사 뒤가 문자라 아니다
        {"team_id": "t4", "team_alias": "beta", "metadata": {"mint_org": "nope"}},
        {"team_id": "t5", "team_alias": "acme-x"},  # 이미 묶임
    ]
    users = [
        {"user_id": "u1", "user_email": "Kim@Acme.example"},
        {"user_id": "u2", "user_email": "x@other.example"},
        {"user_id": "u3", "user_email": None},
    ]
    got = org_suggest.propose(
        teams, users, ORGS, {("team", "t5")}, {"acme.example": "acme"}, "mint_org",
        {("user", "u1"): 4, ("team", "t2"): 9},
    )
    assert [(p["subject_id"], p["org_id"], p["rule"], p["calls"]) for p in got] == [
        ("t2", "acme", "team_alias", 9),
        ("u1", "acme", "email_domain", 4),
        ("t1", "acme", "team_metadata", 0),
        ("t4", "beta", "team_alias", 0),
    ]


def test_an_alias_matching_two_orgs_equally_is_not_proposed():
    assert org_suggest._alias_org("x-y", {"a": "x", "b": "x"}) is None


@pytest.fixture
def world(ctx):
    orgs.add(ctx, "acme", "ACME")
    orgs.add(ctx, "beta", "Beta")
    org_service.set_domain(ctx, "@Acme.Example", "acme")
    return ctx


def scan(ctx, teams, users):
    fake = SimpleNamespace(list_teams=lambda: teams, list_users=lambda: users)
    settings = SimpleNamespace(org_meta_key="mint_org")
    org_suggest.run(jobs.JobContext(ctx.conn, INSTANCE, {}, settings, fake))
    return fetchall(
        ctx.conn, "SELECT subject_id, status, rule FROM mint.org_suggestions ORDER BY subject_id"
    )


def test_scan_stores_proposals_without_binding_and_refreshes_them(world):
    ctx = world
    teams = [{"team_id": "t1", "team_alias": "acme-ops"}, {"team_id": "t2", "metadata": {}}]
    users = [{"user_id": "u1", "user_email": "a@acme.example"}]
    assert [r["subject_id"] for r in scan(ctx, teams, users)] == ["t1", "u1"]
    assert fetchone(ctx.conn, "SELECT count(*) AS n FROM mint.org_bindings")["n"] == 0
    # 규칙이 더 맞지 않으면 열린 제안은 사라진다
    assert [r["subject_id"] for r in scan(ctx, teams[:0], users)] == ["u1"]


def test_apply_binds_through_the_bind_service_and_ignored_stays_closed(world):
    ctx = world
    users = [{"user_id": "u1", "user_email": "a@acme.example"}]
    scan(ctx, [{"team_id": "t1", "team_alias": "acme-ops"}], users)
    rows = {r["subject_id"]: r["id"] for r in org_service.list_suggestions(ctx)}
    org_service.apply_suggestion(ctx, str(rows["t1"]))
    bound = fetchone(ctx.conn, "SELECT org_id FROM mint.org_bindings WHERE subject_id = 't1'")
    assert bound["org_id"] == "acme"
    assert fetchone(
        ctx.conn, "SELECT count(*) AS n FROM mint.events WHERE kind = 'org_binding_created'"
    )["n"] == 1
    org_service.ignore_suggestion(ctx, str(rows["u1"]))
    again = scan(ctx, [], users)
    assert {r["subject_id"]: r["status"] for r in again} == {"t1": "applied", "u1": "ignored"}
    with pytest.raises(ControlError):
        org_service.apply_suggestion(ctx, str(rows["u1"]))


def test_bulk_apply_covers_one_rule_and_skips_what_cannot_bind(world):
    ctx = world
    users = [{"user_id": f"u{i}", "user_email": "a@acme.example"} for i in range(3)]
    scan(ctx, [{"team_id": "t1", "team_alias": "beta-x"}], users)
    orgs.bind(ctx, "acme", SubjectType.USER, "u1")  # 제안이 열린 뒤 묶여 적용할 수 없다
    assert org_service.apply_rule(ctx, "email_domain") == 2
    rows = fetchall(ctx.conn, "SELECT subject_id FROM mint.org_bindings")
    assert {r["subject_id"] for r in rows} == {"u0", "u1", "u2"}
    assert [r["subject_id"] for r in org_service.list_suggestions(ctx)] == ["t1", "u1"]


def test_domain_table_rejects_closed_orgs_and_bad_names(world):
    ctx = world
    with pytest.raises(ControlError):
        org_service.set_domain(ctx, "a@b", "acme")
    with pytest.raises(ControlError):
        org_service.unset_domain(ctx, "missing.example")
    org_service.unset_domain(ctx, "acme.example")
    assert org_service.list_domains(ctx) == []
