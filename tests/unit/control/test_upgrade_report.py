"""업그레이드 뒤 남는 사람의 결정 목록. DB가 없으면(MINT_TEST_DATABASE_URL) 건너뛴다."""

import json
from datetime import UTC, datetime, timedelta

from ctl_fixtures import INSTANCE

from mint_litellm.control import upgrade_report
from mint_litellm.control.services import evidence

from .test_recert import seed_approval

PERIOD = timedelta(days=90)
SERVER = "ctl-everything"
SHA = "a" * 64


def collect(conn, kit="kit-new"):
    return upgrade_report.collect(
        conn, INSTANCE, now=datetime.now(UTC), recert_period=PERIOD, current_kit=kit
    )


def whats(conn, **kw):
    return [item["what"] for item in collect(conn, **kw)]


def set_auth(conn, auth_type):
    conn.execute("UPDATE mint.servers SET auth_type = %s WHERE server_id = %s", (auth_type, SERVER))


def add_approval(conn, conditions):
    """같은 관계에 조건이 있는 승인을 하나 더 만든다(조건은 만든 뒤 바꿀 수 없다)."""
    relation = conn.execute("SELECT relation_id FROM mint.approvals LIMIT 1").fetchone()[0]
    conn.execute(
        "INSERT INTO mint.approvals (id, instance_id, org_id, relation_id, class, server_id,"
        " tools, scope_type, scope_id, valid_from, valid_until, conditions, basis, granted_by,"
        " requested_by, status) VALUES (gen_random_uuid(), %s, 'acme', %s, 'standard', %s,"
        " ARRAY['echo'], 'user', 'human-2', now(), now() + interval '30 days', %s, '{}',"
        " 'root', 'someone', 'active')",
        (INSTANCE, relation, SERVER, json.dumps(conditions)),
    )


def test_a_fresh_install_has_nothing_left_to_decide(conn):
    assert collect(conn) == []
    assert upgrade_report.render([]) == "업그레이드 뒤 사람이 정할 일: 없음"


def test_recertification_lists_due_and_held_approvals_separately(conn, ctx, litellm):
    seed_approval(conn, ctx, litellm, 95)
    assert whats(conn) == ["재확인 기한이 된 승인 1건"]
    conn.execute("UPDATE mint.approvals SET recert_held_at = now()")
    assert whats(conn) == ["재확인이 늦어 보류되어 호출이 막힌 승인 1건"]


def test_forwarding_servers_need_an_approval_that_allows_the_token_forward(conn, ctx, litellm):
    seed_approval(conn, ctx, litellm, 1)
    assert whats(conn) == []
    set_auth(conn, "true_passthrough")
    assert "allow_token_forward" in whats(conn)[0] and SERVER in whats(conn)[0]
    conn.execute("UPDATE mint.approvals SET status = 'revoked', revoked_at = now()")
    assert whats(conn) == []
    add_approval(conn, {"allow_token_forward": True})
    assert whats(conn) == []
    add_approval(conn, {})
    assert len(collect(conn)) == 1


def test_an_oauth_server_with_scopes_but_an_empty_approved_contract_needs_one_reapproval(
    conn, ctx, litellm
):
    seed_approval(conn, ctx, litellm, 1)
    conn.execute(
        "INSERT INTO mint.deployment_contracts (id, instance_id, server_id, canonical_text,"
        " sha256, url, url_sha256, transport, auth_type, status) VALUES (gen_random_uuid(), %s,"
        " %s, '{}', %s, 'http://u.test', %s, 'http', 'oauth2', 'candidate')",
        (INSTANCE, SERVER, SHA, SHA),
    )
    conn.execute("UPDATE mint.deployment_contracts SET status = 'approved'")
    assert whats(conn) == []
    conn.execute(
        "UPDATE mint.servers SET deployment_drift = true,"
        " deployment_drift_fields = ARRAY['oauth_scopes'] WHERE server_id = %s", (SERVER,)
    )
    item = collect(conn)[0]
    assert SERVER in item["what"] and f"contract diff {SERVER}" in item["next"]
    conn.execute("UPDATE mint.servers SET deployment_drift = false")
    assert collect(conn) == []


def test_unpinned_packages_need_acceptance_evidence_until_it_is_attached(conn, ctx, litellm):
    seed_approval(conn, ctx, litellm, 1)
    # 원격 서버로 두고 패키지 행만 맞춘다(실행 계약 열의 모양 제약은 이 시험의 대상이 아니다).
    conn.execute("ALTER TABLE mint.servers DROP CONSTRAINT servers_identity_shape")
    conn.execute("UPDATE mint.servers SET exec_contract_sha256 = %s WHERE server_id = %s",
                 (SHA, SERVER))
    conn.execute(
        "INSERT INTO mint.server_packages (id, instance_id, server_id, exec_contract_sha256,"
        " ecosystem, name, pinned, registry) VALUES (gen_random_uuid(), %s, %s, %s, 'npm',"
        " 'tool', false, 'registry.npmjs.org')",
        (INSTANCE, SERVER, SHA),
    )
    item = collect(conn)[0]
    assert SERVER in item["what"] and "evidence attach unpinned_acceptance" in item["next"]
    evidence.attach(ctx, "unpinned_acceptance", SERVER, summary="검토함")
    assert collect(conn) == []


def test_kits_that_never_reported_or_report_an_old_version_are_listed(conn):
    def install(alias, kit_version, reported, revoked=False):
        conn.execute(
            "INSERT INTO mint.endpoint_installs (instance_id, key_token, user_id, key_alias,"
            " issued_by, install_mode, kit_version, reported_at, revoked_at)"
            " VALUES (%s, %s, 'u', %s, 'root', %s, %s, %s, %s)",
            (INSTANCE, alias, alias, "managed" if reported else None, kit_version,
             datetime.now(UTC) if reported else None, datetime.now(UTC) if revoked else None),
        )

    install("never", None, False)
    install("old", "kit-old", True)
    install("current", "kit-new", True)
    install("revoked", None, False, revoked=True)
    assert whats(conn) == [
        "주기 보고를 한 적 없는 단말 설치 묶음 1건", "이전 판본의 단말 설치 묶음 1건"
    ]
    assert "단말 설치」" in collect(conn)[0]["next"]


def test_the_rendered_list_names_the_resolving_screen_or_command(conn, ctx, litellm):
    seed_approval(conn, ctx, litellm, 95)
    text = upgrade_report.render(collect(conn))
    assert text.splitlines()[0] == "업그레이드 뒤 사람이 정할 일 1건"
    assert "해결: 콘솔 승인 내역에서 「재확인」" in text
