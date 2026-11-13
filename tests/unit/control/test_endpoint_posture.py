"""설치 보고 기반 점검: 폐기 서버 항목 잔존(POL-D-02)과 관리되지 않는 설치(POL-E-06).

``findings``는 데이터베이스 없이 돈다. ``scan``은 MINT_TEST_DATABASE_URL이 없으면 건너뛴다.
"""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mint_litellm.control import endpoint_posture

ROOT = Path(__file__).resolve().parents[3]


def row(mode, servers=(), alias="mint-kit-a", user="u1"):
    return {"user_id": user, "key_alias": alias, "install_mode": mode, "mcp_servers": list(servers)}


def test_a_terminated_server_left_in_a_report_is_a_stale_entry():
    wanted = endpoint_posture.findings(
        [row("managed", ["live", "gone", "ending"])],
        {"live": "approved", "gone": "terminated", "ending": "terminating"},
    )
    assert sorted(wanted) == [
        "endpoint_stale_server:mint-kit-a:ending",
        "endpoint_stale_server:mint-kit-a:gone",
    ]
    kind, severity, subject = wanted["endpoint_stale_server:mint-kit-a:gone"]
    assert (kind, severity) == ("endpoint_stale_server", "high")
    assert subject == {"user_id": "u1", "key_alias": "mint-kit-a", "server_id": "gone"}


def test_only_a_user_level_install_is_marked_unmanaged():
    assert endpoint_posture.findings([row("managed")], {}) == {}
    wanted = endpoint_posture.findings([row("user")], {})
    assert list(wanted) == ["endpoint_unmanaged:mint-kit-a"]
    assert wanted["endpoint_unmanaged:mint-kit-a"][:2] == ("endpoint_unmanaged", "medium")


def test_servers_that_are_still_in_use_or_unknown_raise_nothing():
    wanted = endpoint_posture.findings(
        [row("managed", ["live", "suspended", "unknown"])],
        {"live": "approved", "suspended": "suspended"},
    )
    assert wanted == {}
    assert endpoint_posture.findings([{**row("managed"), "mcp_servers": None}], {}) == {}


def test_a_process_or_autostart_of_a_server_that_is_not_approved_is_stale():
    installs = [{
        **row("managed"),
        "processes": [{"server": "gone", "count": 2}, {"server": "live", "count": 1}],
        "autostart": [
            {"kind": "cron", "name": "@reboot", "server": "gone"},
            {"kind": "systemd", "name": "live.service", "server": "live"},
            {"kind": "run_key", "name": "mcp", "server": None},
        ],
    }]
    wanted = endpoint_posture.findings(installs, {"live": "approved", "gone": "terminated"})
    assert sorted(wanted) == [
        "endpoint_stale_autostart:mint-kit-a:cron:@reboot",
        "endpoint_stale_process:mint-kit-a:gone",
    ]
    kind, severity, subject = wanted["endpoint_stale_process:mint-kit-a:gone"]
    assert (kind, severity) == ("endpoint_stale_process", "high")
    assert subject["server_id"] == "gone" and subject["count"] == 2
    # 폐기가 아니어도 승인 상태가 아니거나 레지스트리에 없는 서버가 돌면 잔존으로 본다.
    for status in ("rejected", "awaiting_approval", None):
        found = endpoint_posture.findings(installs, {"live": "approved", "gone": status})
        assert "endpoint_stale_process:mint-kit-a:gone" in found, status
    assert not endpoint_posture.findings(installs, {"live": "approved", "gone": "suspended"})


def test_an_inventory_of_approved_servers_or_none_at_all_is_clean():
    clean = {**row("managed"), "processes": [{"server": "live", "count": 1}],
             "autostart": [{"kind": "autostart", "name": "a.desktop", "server": "live"}]}
    assert endpoint_posture.findings([clean], {"live": "approved"}) == {}
    unreported = {**row("managed"), "processes": None, "autostart": None}
    assert endpoint_posture.findings([unreported], {}) == {}
    assert endpoint_posture.findings([{**row("removed"), "processes": []}], {}) == {}


def test_the_catalog_names_the_policies_these_alerts_report():
    catalog = json.loads((ROOT / "policy/catalog.json").read_text(encoding="utf-8"))
    by_id = {c["id"]: c for c in catalog["checks"]}
    assert set(endpoint_posture.KINDS) == set(by_id)
    assert by_id["endpoint_stale_server"]["reference_policies"] == ["POL-D-02"]
    assert by_id["endpoint_unmanaged"]["reference_policies"] == ["POL-E-06"]
    assert by_id["endpoint_stale_process"]["reference_policies"] == ["POL-D-04"]
    assert by_id["endpoint_stale_autostart"]["reference_policies"] == ["POL-D-04"]
    assert "POL-D-04" in by_id["endpoint_silent"]["reference_policies"]
    assert by_id["endpoint_key_expiring"]["reference_policies"] == ["POL-E-06"]


NOW = datetime(2030, 1, 10, 12, tzinfo=UTC)


def timed(mode, reported_hours_ago=1, expires_in_days=60):
    return {**row(mode), "now": NOW,
            "reported_at": None if reported_hours_ago is None
            else NOW - timedelta(hours=reported_hours_ago),
            "expires_at": None if expires_in_days is None
            else NOW + timedelta(days=expires_in_days)}


def test_an_install_that_stopped_reporting_is_silent_until_it_reports_again():
    assert endpoint_posture.findings([timed("managed", 23)], {}) == {}
    wanted = endpoint_posture.findings([timed("managed", 25)], {})
    kind, severity, subject = wanted["endpoint_silent:mint-kit-a"]
    assert (kind, severity) == ("endpoint_silent", "medium")
    assert subject["last_reported_at"] == (NOW - timedelta(hours=25)).isoformat()
    assert "endpoint_silent:mint-kit-a" in endpoint_posture.findings([timed("user", 25)], {})
    # 기준 시간은 설정으로 바꾼다.
    assert endpoint_posture.findings([timed("managed", 25)], {}, timedelta(hours=48)) == {}


def test_removed_and_never_reported_installs_are_not_silent():
    assert endpoint_posture.findings([timed("removed", 500)], {}) == {}
    assert endpoint_posture.findings([timed("managed", None)], {}) == {}


def test_a_key_within_seven_days_of_expiry_is_flagged_and_a_renewed_one_is_not():
    assert endpoint_posture.findings([timed("managed", 1, 8)], {}) == {}
    wanted = endpoint_posture.findings([timed("managed", 1, 6)], {})
    assert list(wanted) == ["endpoint_key_expiring:mint-kit-a"]
    assert wanted["endpoint_key_expiring:mint-kit-a"][:2] == ("endpoint_key_expiring", "medium")
    # 이미 만료된 키도 계속 알린다. 만료가 없는 옛 키와 제거 보고는 제외한다.
    assert endpoint_posture.findings([timed("managed", 1, -2)], {})
    assert endpoint_posture.findings([timed("managed", 1, None)], {}) == {}
    assert endpoint_posture.findings([timed("removed", 1, 1)], {}) == {}


psycopg = pytest.importorskip("psycopg")
from ctl_fixtures import INSTANCE  # noqa: E402

from mint_litellm.control import endpoint_kits, servers  # noqa: E402
from mint_litellm.types.exec_contract import ExecContract  # noqa: E402

CONTRACT = ExecContract(
    executable="/usr/bin/node", argv=["/opt/srv/index.js"], executable_sha256="ab" * 32
)


class Issuer:
    def generate_kit_key(self, *, user_id, team_id, alias):
        return f"sk-{alias}"

    def delete_kit_keys(self, aliases):
        pass


def report(conn, mode, servers_=()):
    conn.execute(
        "UPDATE mint.endpoint_installs SET install_mode = %s, kit_version = 'k',"
        " mcp_servers = %s::jsonb, reported_at = now() WHERE revoked_at IS NULL",
        (mode, json.dumps(list(servers_))),
    )


def open_alerts(conn):
    return sorted(
        r[0] for r in conn.execute(
            "SELECT dedup_key FROM mint.alerts WHERE status <> 'resolved'"
        ).fetchall()
    )


def test_the_scan_opens_each_alert_once_and_closes_it_when_the_condition_is_gone(ctx, conn):
    servers.register_local(ctx, "local-1", CONTRACT)
    conn.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'local-1'")
    endpoint_kits.issue_key(
        conn, Issuer(), INSTANCE, user_id="u1", team_id="t1", issued_by="u1"
    )
    # 보고 전의 키는 점검 대상이 아니다.
    assert endpoint_posture.scan(conn, INSTANCE) == 0
    report(conn, "user", ["local-1"])
    assert endpoint_posture.scan(conn, INSTANCE) == 1
    assert open_alerts(conn) == [f"endpoint_unmanaged:{_alias(conn)}"]
    # 다시 돌려도 새로 열지 않고 횟수도 올리지 않는다.
    assert endpoint_posture.scan(conn, INSTANCE) == 0
    assert conn.execute("SELECT max(count) FROM mint.alerts").fetchone()[0] == 1

    conn.execute("UPDATE mint.servers SET status = 'terminating' WHERE server_id = 'local-1'")
    assert endpoint_posture.scan(conn, INSTANCE) == 1
    assert open_alerts(conn) == [
        f"endpoint_stale_server:{_alias(conn)}:local-1",
        f"endpoint_unmanaged:{_alias(conn)}",
    ]
    # 관리형으로 다시 설치하고 항목을 지우면 둘 다 닫힌다.
    report(conn, "managed", [])
    assert endpoint_posture.scan(conn, INSTANCE) == 0
    assert open_alerts(conn) == []


def test_a_removal_report_and_a_revoked_key_close_the_alerts(ctx, conn):
    servers.register_local(ctx, "local-1", CONTRACT)
    conn.execute("UPDATE mint.servers SET status = 'approved' WHERE server_id = 'local-1'")
    endpoint_kits.issue_key(conn, Issuer(), INSTANCE, user_id="u1", team_id=None, issued_by="u1")
    report(conn, "user", [])
    endpoint_posture.scan(conn, INSTANCE)
    assert len(open_alerts(conn)) == 1
    report(conn, "removed", [])
    endpoint_posture.scan(conn, INSTANCE)
    assert open_alerts(conn) == []
    report(conn, "user", [])
    endpoint_posture.scan(conn, INSTANCE)
    endpoint_kits.revoke_keys(conn, Issuer(), INSTANCE, "u1")
    endpoint_posture.scan(conn, INSTANCE)
    assert open_alerts(conn) == []


def _alias(conn):
    return conn.execute("SELECT key_alias FROM mint.endpoint_installs").fetchone()[0]


def test_the_scan_opens_and_closes_alerts_for_a_leftover_process_and_autostart(ctx, conn):
    servers.register_local(ctx, "local-1", CONTRACT)
    conn.execute("UPDATE mint.servers SET status = 'rejected' WHERE server_id = 'local-1'")
    endpoint_kits.issue_key(conn, Issuer(), INSTANCE, user_id="u1", team_id=None, issued_by="u1")
    conn.execute(
        "UPDATE mint.endpoint_installs SET install_mode = 'removed', kit_version = 'k',"
        " mcp_servers = '[]'::jsonb, reported_at = now(), processes = %s::jsonb,"
        " autostart = %s::jsonb WHERE revoked_at IS NULL",
        (json.dumps([{"server": "local-1", "count": 1}]),
         json.dumps([{"kind": "cron", "name": "@reboot", "server": "local-1"}])),
    )
    assert endpoint_posture.scan(conn, INSTANCE) == 2
    assert open_alerts(conn) == [
        f"endpoint_stale_autostart:{_alias(conn)}:cron:@reboot",
        f"endpoint_stale_process:{_alias(conn)}:local-1",
    ]
    conn.execute(
        "UPDATE mint.endpoint_installs SET processes = '[]'::jsonb, autostart = '[]'::jsonb"
        " WHERE revoked_at IS NULL"
    )
    endpoint_posture.scan(conn, INSTANCE)
    assert open_alerts(conn) == []


def test_silence_and_expiry_alerts_open_and_close_with_the_reports(conn):
    endpoint_kits.issue_key(conn, Issuer(), INSTANCE, user_id="u1", team_id=None, issued_by="u1")
    report(conn, "managed", [])
    alias = _alias(conn)
    assert endpoint_posture.scan(conn, INSTANCE) == 0
    conn.execute(
        "UPDATE mint.endpoint_installs SET reported_at = now() - interval '25 hours',"
        " expires_at = now() + interval '3 days'"
    )
    assert endpoint_posture.scan(conn, INSTANCE) == 2
    assert open_alerts(conn) == [f"endpoint_key_expiring:{alias}", f"endpoint_silent:{alias}"]
    # 보고가 다시 와서 키가 늘어나면 둘 다 닫힌다.
    conn.execute(
        "UPDATE mint.endpoint_installs SET reported_at = now(),"
        " expires_at = now() + interval '90 days'"
    )
    assert endpoint_posture.scan(conn, INSTANCE) == 0
    assert open_alerts(conn) == []
    # 제거 보고는 침묵으로 보지 않는다.
    conn.execute(
        "UPDATE mint.endpoint_installs SET install_mode = 'removed',"
        " reported_at = now() - interval '300 hours'"
    )
    assert endpoint_posture.scan(conn, INSTANCE) == 0
