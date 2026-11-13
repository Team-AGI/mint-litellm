"""정책 시험 적용: 시험 판본 지정·취소, 평소 활성화 경로로의 적용, 집계 읽기."""

from pathlib import Path

import pytest
from ctl_fixtures import INSTANCE, make_ctx

psycopg = pytest.importorskip("psycopg")

from mint_litellm.control import policy_versions  # noqa: E402
from mint_litellm.control.db.connection import fetchall, fetchone  # noqa: E402
from mint_litellm.control.errors import ControlError  # noqa: E402
from mint_litellm.control.services import policy as policy_service  # noqa: E402
from mint_litellm.control.services import reads  # noqa: E402

SHA = "ab" * 32
SOURCE = policy_versions.PolicySource(
    root=Path("."), opa="opa", bundle_path=Path("shadow.tar.gz"), opa_url="http://shadow.test",
    timeout_seconds=1,
)


@pytest.fixture
def conn(fresh_db):
    with psycopg.connect(fresh_db) as connection:
        connection.execute(
            "INSERT INTO mint.policy_versions (instance_id, id, catalog_sha256, bundle_sha256)"
            " VALUES (%s, 'v2', %s, %s)", (INSTANCE, SHA, SHA),
        )
        yield connection


@pytest.fixture
def prepared(monkeypatch):
    monkeypatch.setattr(policy_versions, "prepare_shadow", lambda *a, **k: SHA)


def kinds(conn):
    return [r["kind"] for r in fetchall(conn, "SELECT kind FROM mint.events ORDER BY inserted_at")]


def test_a_shadow_version_is_set_replaced_and_cancelled_with_events(conn, prepared):
    ctx = make_ctx(conn)
    assert reads.policy_shadow(conn, INSTANCE) is None
    policy_service.shadow_set(ctx, "url", "v2", SOURCE)
    assert reads.policy_shadow(conn, INSTANCE)["version_id"] == "v2"
    policy_service.shadow_set(ctx, "url", "v2", SOURCE)
    assert policy_service.shadow_cancel(ctx) == "v2"
    assert reads.policy_shadow(conn, INSTANCE) is None
    with pytest.raises(ControlError):
        policy_service.shadow_cancel(ctx)
    # 같은 판본을 다시 시험해도 사건 키가 겹치지 않는다
    policy_service.shadow_set(ctx, "url", "v2", SOURCE)
    assert kinds(conn) == ["policy_shadow_set", "policy_shadow_set", "policy_shadow_cleared",
                           "policy_shadow_set"]


def test_only_admins_set_or_cancel_a_shadow_version(conn, prepared):
    viewer = make_ctx(conn, "v", "viewer")
    with pytest.raises(ControlError):
        policy_service.shadow_set(viewer, "url", "v2", SOURCE)
    with pytest.raises(ControlError):
        policy_service.shadow_cancel(viewer)


def test_promoting_goes_through_the_normal_activation_and_ends_the_shadow(
    conn, prepared, monkeypatch
):
    ctx = make_ctx(conn)
    policy_service.shadow_set(ctx, "url", "v2", SOURCE)
    seen = []
    monkeypatch.setattr(policy_versions, "activate", lambda *a: seen.append(a[3:5]))
    policy_service.activate(ctx, "url", "v2", SOURCE)
    assert seen == [("root", "v2")]
    assert reads.policy_shadow(conn, INSTANCE) is None


def test_activating_another_version_keeps_the_shadow(conn, prepared, monkeypatch):
    ctx = make_ctx(conn)
    policy_service.shadow_set(ctx, "url", "v2", SOURCE)
    monkeypatch.setattr(policy_versions, "activate", lambda *a: None)
    policy_service.activate(ctx, "url", "v9", SOURCE)
    assert reads.policy_shadow(conn, INSTANCE)["version_id"] == "v2"


def test_the_report_groups_flips_by_direction(conn, prepared):
    ctx = make_ctx(conn)
    policy_service.shadow_set(ctx, "url", "v2", SOURCE)
    rows = [
        ("srv", "echo", "Allow", "Block", "", "R1", 3, ["i1", "i2"]),
        ("srv", "echo", "Block", "Allow", "R1", "", 2, ["i3"]),
        ("srv", "read", "Allow", "Alert", "", "R3", 4, ["i4"]),
        ("srv", "read", "Alert", "RequireApproval", "", "R4", 1, []),
    ]
    for server, tool, active, shadow, a_reason, s_reason, calls, samples in rows:
        conn.execute(
            "INSERT INTO mint.policy_shadow_results (instance_id, version_id, server_id, tool,"
            " active_result, shadow_result, active_reason, shadow_reason, calls, samples)"
            " VALUES (%s, 'v2', %s, %s, %s, %s, %s, %s, %s, %s)",
            (INSTANCE, server, tool, active, shadow, a_reason, s_reason, calls, samples),
        )
    conn.execute(
        "INSERT INTO mint.policy_shadow_stats (instance_id, version_id, evaluated, same, errors)"
        " VALUES (%s, 'v2', 50, 40, 1)", (INSTANCE,),
    )
    report = reads.policy_shadow(conn, INSTANCE)
    assert report["totals"] == {"allow_to_deny": 4, "deny_to_allow": 2, "other": 4}
    assert report["stats"]["evaluated"] == 50 and report["flips"][0]["calls"] == 4
    assert fetchone(conn, "SELECT 1 AS x FROM mint.policy_shadow")["x"] == 1
