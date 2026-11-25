"""설치 상태 보고 경로: 설치 묶음에 발급한 키의 보고만 받고, 파일 경로나 키는 받지 않는다."""

import pytest
from plugin_helpers import KEY
from test_endpoint_routes import KEY_HEADER, FakeDatabase, build, post

REPORT = "/mint/v1/endpoint/report"


def report(**override):
    data = {"kit_version": "k" * 64, "action": "installed", "mode": "managed",
            "claude_version": "2.1.0 (Claude Code)", "mcp_servers": ["srv-1"]}
    return data | override


@pytest.fixture
def stored(monkeypatch):
    """발급된 키의 행 하나만 있는 저장소 대역."""
    calls = []

    async def report_install(self, instance_id, key_token, **fields):
        calls.append((instance_id, key_token, fields))
        return "recorded" if key_token == KEY else "unknown"

    monkeypatch.setattr(FakeDatabase, "report_install", report_install, raising=False)
    return calls


def test_a_managed_install_report_is_stored_for_the_calling_key(tmp_path, stored):
    client, _ = build(tmp_path)
    assert post(client, REPORT, report()).json() == {
        "recorded": True, "renewed": False, "retired": []}
    (_, key_token, fields), = stored
    assert key_token == KEY
    assert fields == {"mode": "managed", "kit_version": "k" * 64,
                      "claude_version": "2.1.0 (Claude Code)", "mcp_servers": ["srv-1"],
                      "processes": None, "autostart": None, "outside_processes": None,
                      "removed": None,
                      "local_mcp": None, "tool_lists": None, "hook_trust": None,
                      "update_error": None, "ai_clients": None, "plaintext_keys": None,
                      "scan_errors": None, "offline_calls": None, "paused_ack": None}


def test_the_process_and_autostart_inventory_is_stored_as_plain_rows(tmp_path, stored):
    client, _ = build(tmp_path)
    body = report(
        processes=[{"server": "srv-1", "count": 2}],
        autostart=[{"kind": "cron", "name": "@reboot", "server": "srv-1"},
                   {"kind": "systemd", "name": "mcp.service"}],
    )
    assert post(client, REPORT, body).status_code == 200
    fields = stored[0][2]
    assert fields["processes"] == [
        {
            "server": "srv-1", "count": 2, "sandbox": None, "egress_refused": None,
            "egress_unfiltered": None, "egress_filtered": None,
        }  # fmt: skip
    ]
    assert fields["autostart"] == [{"kind": "cron", "name": "@reboot", "server": "srv-1"},
                                   {"kind": "systemd", "name": "mcp.service", "server": None}]


def test_packages_run_outside_the_launcher_are_stored_and_arguments_are_refused(tmp_path, stored):
    client, _ = build(tmp_path)
    items = [{"package": "@a/mcp-x", "ecosystem": "npm", "count": 2}]
    assert post(client, REPORT, report(outside_processes=items)).status_code == 200
    assert stored[0][2]["outside_processes"] == items
    bad = [{"package": "mcp-x --token=abc", "ecosystem": "npm", "count": 1}]
    assert post(client, REPORT, report(outside_processes=bad)).status_code == 422


@pytest.mark.parametrize(("body", "mode"), [
    (report(mode="user"), "user"),
    (report(action="removed", mode="none", mcp_servers=[]), "removed"),
])
def test_user_level_and_removal_reports_keep_their_own_state(tmp_path, stored, body, mode):
    client, _ = build(tmp_path)
    assert post(client, REPORT, body).status_code == 200
    assert stored[0][2]["mode"] == mode


def test_a_key_the_kit_did_not_issue_is_not_recorded(tmp_path, stored):
    client, _ = build(tmp_path)
    other = {"Authorization": "Bearer sk-other"}
    assert post(client, REPORT, report(), headers=other).status_code == 404


@pytest.mark.parametrize("body", [
    report(action="installed", mode="none"),
    report(action="removed", mode="managed"),
    report(mode="root"),
    report(key="sk-x"),
    report(mcp_servers=["a"] * 257),
    report(processes=[{"server": "a", "count": 0}]),
    report(processes=[{"server": "a", "count": 1, "pid": 4}]),
    report(autostart=[{"kind": "registry", "name": "x"}]),
    report(autostart=[{"kind": "cron", "name": "x"}] * 65),
])
def test_a_report_that_does_not_fit_the_shape_is_refused(tmp_path, stored, body):
    client, _ = build(tmp_path)
    assert post(client, REPORT, body).status_code == 422
    assert stored == []


def test_the_report_route_needs_a_key_and_a_ready_store(tmp_path, monkeypatch):
    client, _ = build(tmp_path)
    assert post(client, REPORT, report(), headers={}).status_code == 401

    async def broken(self, *args, **kwargs):
        raise OSError("down")

    monkeypatch.setattr(FakeDatabase, "report_install", broken, raising=False)
    assert post(client, REPORT, report()).status_code == 503
    big = " " * (192 * 1024 + 1)
    assert client.post(REPORT, content=big, headers=KEY_HEADER).status_code == 413


@pytest.mark.parametrize(("outcome", "status", "body"), [
    ("recorded", 200, {"recorded": True, "renewed": False, "retired": []}),
    ("renewed", 200, {"recorded": True, "renewed": True, "retired": []}),
])
def test_a_report_near_expiry_says_the_key_was_extended(
    tmp_path, monkeypatch, outcome, status, body
):
    async def report_install(self, *args, **fields):
        return outcome

    monkeypatch.setattr(FakeDatabase, "report_install", report_install, raising=False)
    client, _ = build(tmp_path)
    reply = post(client, REPORT, report())
    assert (reply.status_code, reply.json()) == (status, body)


def test_an_expired_key_is_refused_with_a_clear_error(tmp_path, monkeypatch):
    async def report_install(self, *args, **fields):
        return "expired"

    monkeypatch.setattr(FakeDatabase, "report_install", report_install, raising=False)
    client, _ = build(tmp_path)
    reply = post(client, REPORT, report())
    assert reply.status_code == 403 and "expired" in reply.text


def test_the_answer_lists_the_servers_the_control_plane_treats_as_retired(
    tmp_path, stored, monkeypatch
):
    seen = []

    async def retired_servers(self, instance_id, reported):
        seen.append(reported)
        return ["old-srv"]

    monkeypatch.setattr(FakeDatabase, "retired_servers", retired_servers, raising=False)
    client, _ = build(tmp_path)
    body = report(
        processes=[{"server": "proc-srv", "count": 1}],
        autostart=[{"kind": "cron", "name": "@reboot", "server": "auto-srv"}],
    )
    assert post(client, REPORT, body).json()["retired"] == ["old-srv"]
    assert seen == [["srv-1", "proc-srv", "auto-srv"]]


def test_a_report_still_succeeds_when_the_retired_list_cannot_be_built(
    tmp_path, stored, monkeypatch
):
    async def broken(self, *args):
        raise OSError("down")

    monkeypatch.setattr(FakeDatabase, "retired_servers", broken, raising=False)
    client, _ = build(tmp_path)
    assert post(client, REPORT, report()).json() == {"recorded": True, "renewed": False}


def test_removed_items_are_passed_on_as_plain_rows(tmp_path, stored):
    client, _ = build(tmp_path)
    removed = [{"kind": "config", "server": "old-srv", "target": "claude"},
               {"kind": "process", "server": "old-srv"}]
    assert post(client, REPORT, report(removed=removed)).status_code == 200
    assert stored[0][2]["removed"] == [
        {"kind": "config", "server": "old-srv", "target": "claude"},
        {"kind": "process", "server": "old-srv", "target": None},
    ]


@pytest.mark.parametrize("removed", [
    [{"kind": "file", "server": "a"}],
    [{"kind": "config", "server": "a", "path": "/etc/x"}],
    [{"kind": "config", "server": "a"}] * 257,
])
def test_a_removed_list_that_does_not_fit_is_refused(tmp_path, stored, removed):
    client, _ = build(tmp_path)
    assert post(client, REPORT, report(removed=removed)).status_code == 422


def test_unmanaged_mcp_entries_are_passed_on_as_plain_rows(tmp_path, stored):
    client, _ = build(tmp_path)
    items = [
        {"harness": "claude", "name": "files", "kind": "stdio", "target": "npx",
         "package": "@scope/server-files@1.2.0"},
        {"harness": "codex", "name": "docs", "kind": "http", "target": "docs.example.com"},
    ]
    assert post(client, REPORT, report(local_mcp=items)).status_code == 200
    assert stored[0][2]["local_mcp"] == [{**items[0]}, {**items[1], "package": None}]


@pytest.mark.parametrize("item", [
    {"target": "user:secret@host.example.com"},
    {"target": "host.example.com/path?token=abc"},
    {"target": "node", "package": "pkg --token abc"},
    {"target": "node", "args": ["--token", "abc"]},
    {"target": "node", "env": {"TOKEN": "abc"}},
    {"kind": "websocket"},
])
def test_a_local_mcp_entry_cannot_carry_credentials_or_arguments(tmp_path, stored, item):
    client, _ = build(tmp_path)
    entry = {"harness": "claude", "name": "x", "kind": "stdio", "target": "node"} | item
    assert post(client, REPORT, report(local_mcp=[entry])).status_code == 422
    assert stored == []


def test_the_answer_carries_the_approved_server_list(tmp_path, stored, monkeypatch):
    desired = [{"name": "srv-1", "version": "v", "contract": {"executable": "/usr/bin/x"}}]

    async def desired_servers(self, instance_id, key_token):
        return desired

    monkeypatch.setattr(FakeDatabase, "desired_servers", desired_servers, raising=False)
    client, _ = build(tmp_path)
    assert post(client, REPORT, report()).json()["desired"] == desired


def test_a_nul_character_in_the_body_is_refused_before_the_database(tmp_path, stored):
    client, _ = build(tmp_path)
    assert post(client, REPORT, report(kit_version="k\u0000")).status_code == 422
    assert stored == []

AI = {
    "client": "cursor",
    "version": None,
    "connection": "hook",
    "coverage": "pre_call",
    "servers": 2,
    "unmanaged": 0,
}


def test_ai_client_coverage_keys_and_offline_calls_are_stored(tmp_path, stored):
    client, _ = build(tmp_path)
    body = report(
        ai_clients=[AI | {"client": "windsurf", "restart_needed": True}],
        plaintext_keys=[{"client": "cursor", "entry": "gh", "kind": "github", "where": "env"}],
        scan_errors=["lmstudio"],
        offline_calls=[
            {
                "server": "s",
                "tool": "t",
                "harness": "claude",
                "at": "2026-01-02T03:04:05+00:00",
                "count": 3,
            }
        ],
        paused_ack=4,
    )
    assert post(client, REPORT, body).status_code == 200
    fields = stored[0][2]
    assert (
        fields["ai_clients"][0]["client"] == "windsurf"
        and fields["ai_clients"][0]["restart_needed"]
    )
    assert fields["plaintext_keys"] == [
        {"client": "cursor", "entry": "gh", "kind": "github", "where": "env"}
    ]
    assert fields["scan_errors"] == ["lmstudio"] and fields["paused_ack"] == 4
    assert fields["offline_calls"][0]["at"] == "2026-01-02T03:04:05Z" or fields["offline_calls"][0][
        "at"
    ].startswith("2026-01-02T03:04:05")


@pytest.mark.parametrize(
    "bad",
    [
        {"ai_clients": [AI | {"client": "emacs"}]},
        {"ai_clients": [AI | {"coverage": "great"}]},
        {"ai_clients": [AI | {"servers": 257}]},
        {
            "plaintext_keys": [
                {
                    "client": "cursor",
                    "entry": "x",
                    "kind": "github",
                    "where": "env",
                    "value": "ghp_secret",
                }
            ]
        },
        {
            "offline_calls": [
                {
                    "server": "s",
                    "tool": "t",
                    "harness": "h",
                    "at": "2026-01-02T03:04:05+00:00",
                    "count": 0,
                }
            ]
        },
        {"paused_ack": -1},
    ],
)
def test_malformed_coverage_fields_are_refused(tmp_path, stored, bad):
    client, _ = build(tmp_path)
    assert post(client, REPORT, report(**bad)).status_code == 422


def test_the_answer_carries_the_pause_and_reconnect_state(tmp_path, stored, monkeypatch):
    async def control(self, instance_id, key_token, clients=False):
        found = {"paused": True, "pause_gen": 2, "ignored": ["x"]}
        if clients:
            found |= {"reconnect": True, "intake_requests": [{"name": "x", "purpose": "문서 검색"}]}
        return found

    monkeypatch.setattr(FakeDatabase, "endpoint_control", control, raising=False)
    client, _ = build(tmp_path)
    plain = post(client, REPORT, report()).json()
    assert plain["paused"] is True and "reconnect" not in plain and "intake_requests" not in plain
    answer = post(client, REPORT, report(capabilities=["clients"])).json()
    assert answer["paused"] is True and answer["pause_gen"] == 2 and answer["reconnect"] is True
    assert answer["ignored"] == ["x"] and answer["intake_requests"][0]["name"] == "x"


def test_a_paused_key_is_denied_on_the_decide_path_with_the_pause_code(tmp_path, monkeypatch):
    from test_endpoint_routes import body

    from mint_litellm.endpoint import decide as decide_module

    async def paused(self, instance_id, key_token):
        return True

    monkeypatch.setattr(FakeDatabase, "endpoint_paused", paused, raising=False)
    decide_module._pause_seen.clear()
    client, _ = build(tmp_path)
    answer = post(client, "/mint/v1/decide", body()).json()
    decide_module._pause_seen.clear()
    assert answer["decision"] == "deny"
    assert answer["error"]["code"] == "MINT-ENDPOINT-PAUSED"
    assert "재개되면 바로 다시 호출하십시오" in answer["error"]["guidance"]


def test_a_removal_report_retires_only_the_calling_pcs_key(tmp_path, stored, monkeypatch):
    from mint_litellm.endpoint import apps

    retired, issuer = [], object()

    async def retire_install(self, instance_id, key_token, given):
        retired.append((key_token, given))
        return True

    monkeypatch.setattr(FakeDatabase, "retire_install", retire_install, raising=False)
    monkeypatch.setattr(apps, "issuer", lambda: issuer)
    client, _ = build(tmp_path)
    body = report(action="removed", mode="none", mcp_servers=[])
    assert post(client, REPORT, body).json() == {"recorded": True, "retired": True}
    assert retired == [(KEY, issuer)]  # 같은 사람의 다른 PC 키는 건드리지 않는다
    assert post(client, REPORT, report()).status_code == 200 and len(retired) == 1
