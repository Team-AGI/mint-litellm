import re
from pathlib import Path

import pytest

import mint_litellm
from mint_litellm.types.cli_commands import (
    COMMANDS,
    CONTROL_PLANE_ALLOWED_ROUTES,
    LITELLM_CREDENTIAL_FIELDS,
    OperatorRole,
)
from mint_litellm.types.events import EventKind
from mint_litellm.types.reason_codes import OBSERVATION_CANDIDATES
from mint_litellm.types.settings import (
    MINT_SETTINGS,
    OBSERVATION_ITEMS,
    SELF_CHECK_DESCRIPTIONS,
    SETTINGS_TABLE,
    SelfCheckItem,
    SettingGrade,
    SettingLocation,
)

ROOT = Path(mint_litellm.__file__).resolve().parents[2]
DOCS = ROOT / "docs"
MIGRATION = Path(mint_litellm.__file__).parent / "control" / "db" / "migrations" / "001_initial.sql"


def read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def test_there_are_eight_self_check_items_with_descriptions():
    assert [int(i) for i in SelfCheckItem] == list(range(1, 9))
    assert set(SELF_CHECK_DESCRIPTIONS) == set(SelfCheckItem)


def test_required_rows_cover_every_self_check_item():
    covered = {c for r in SETTINGS_TABLE if r.grade is SettingGrade.REQUIRED for c in r.self_checks}
    assert covered == set(SelfCheckItem)


def test_only_required_rows_map_to_self_checks_and_file_checks():
    for row in SETTINGS_TABLE:
        if row.grade is not SettingGrade.REQUIRED:
            assert not row.self_checks and not row.file_check_only, row.key
    file_only = [r.key for r in SETTINGS_TABLE if r.file_check_only]
    assert file_only == ["mcp_servers.<이름>.server_id"]


def test_row_counts_by_grade():
    counts = {g: sum(r.grade is g for r in SETTINGS_TABLE) for g in SettingGrade}
    assert counts == {
        SettingGrade.REQUIRED: 21,
        SettingGrade.RECOMMENDED: 8,
        SettingGrade.OBSERVATION: 1,
    }


def test_observation_items():
    assert OBSERVATION_ITEMS == (
        "spend_log_arguments_stored",
        "guardrail_optout_subjects",
        "auth_cache_shared",
        "unbound_keys",
    )


def test_settings_doc_lists_every_row_and_item():
    doc = read("설정.md")
    for row in SETTINGS_TABLE:
        assert f"`{row.key}`" in doc, row.key
    for row in MINT_SETTINGS:
        assert f"`{row.key}`" in doc, row.key
    for name in OBSERVATION_ITEMS:
        assert f"`{name}`" in doc, name
    for route in CONTROL_PLANE_ALLOWED_ROUTES:
        assert f"`{route}`" in doc, route
    for field in LITELLM_CREDENTIAL_FIELDS:
        assert f"`{field}`" in doc, field


def test_control_plane_routes():
    assert CONTROL_PLANE_ALLOWED_ROUTES == (
        "/v1/mcp/server",
        "/key/info",
        "/team/info",
        "/user/info",
        "/key/list",
        "/team/list",
        "/guardrails/list",
        "/key/update",
        "/team/update",
    )


def test_every_cli_read_stays_inside_the_allowed_routes():
    for command in COMMANDS:
        for read_path in command.litellm_reads:
            assert any(
                read_path == r or read_path.startswith(r + "/")
                for r in CONTROL_PLANE_ALLOWED_ROUTES
            ), (command.name, read_path)


def test_command_table_is_unique_and_documented():
    names = [c.name for c in COMMANDS]
    assert len(names) == len(set(names))
    doc = read("CLI.md")
    for command in COMMANDS:
        assert f"`mint-litellm {command.name}`" in doc, command.name


def test_only_first_setup_commands_run_without_a_token():
    names = [c.name for c in COMMANDS if c.unauthenticated]
    assert names == ["init", "doctor", "operator bootstrap"]
    for command in COMMANDS:
        assert command.unauthenticated == (not command.roles)


def test_command_roles_follow_the_operator_role_model():
    approver_commands = {
        "approve",
        "deny",
        "denial lift",
        "revoke",
        "call-approval request",
        "call-approval approve",
        "call-approval reject",
        "call-approval cancel",
        "contract reapprove",
        "intake approve",
        "intake reject",
        "intake except",
    }
    for command in COMMANDS:
        if command.unauthenticated:
            continue
        assert OperatorRole.ADMIN in command.roles, command.name
        if command.name in approver_commands:
            assert OperatorRole.APPROVER in command.roles, command.name
            assert OperatorRole.VIEWER not in command.roles
        elif command.roles == frozenset(OperatorRole):
            assert command.name in {
                "check", "status", "ledger list", "alert list", "sync status", "intake list",
                "intake show", "contract show", "contract diff"}
        else:
            assert command.roles == frozenset({OperatorRole.ADMIN}), command.name


def test_command_events_are_control_events():
    for command in COMMANDS:
        for kind in command.events:
            assert isinstance(kind, EventKind)


def test_limits_doc_covers_the_declared_limitations():
    doc = read("보장과-한계.md")
    for needle in (
        "prompts/*",
        "resources/*",
        "/mcp/proxy",
        "disable_spend_logs",
        "store_prompts_in_spend_logs",
        "opted_out_global_guardrails",
        "60초",
        "mcp_rpm_limit",
        "revoked_after_snapshot",
        "call_outcome_unknown",
        "buffer_replayed",
        "buffer_overflow",
        "evidence: stderr",
        "로그 드라이버",
        "restore attest",
        "sync_divergence",
        "수렴은 상한 보장이 아니라 목표",
        "시점 일관성",
        "MINT-UNSUPPORTED",
        "operator_attested",
        "guardrail_optout_subjects",
        "서비스 계정 표식",
        "unbound_keys",
        "확인하지 않았다",
        "정규화하지 않음",
        "유일한 허용 근거",
        "redirect_uri",
    ):
        assert needle in doc, needle


SQL = MIGRATION.read_text(encoding="utf-8")


def sql_array(pattern: str) -> set[str]:
    match = re.search(pattern, SQL, re.S)
    assert match, pattern
    return set(re.findall(r"'([A-Z_]+)'", match.group(1)))


def test_schema_defaults_use_the_same_observation_families_as_the_types():
    expected = {r.value for r in OBSERVATION_CANDIDATES}
    assert sql_array(r"observable_reasons\s+text\[\] NOT NULL DEFAULT ARRAY\[(.*?)\]") == expected
    assert sql_array(r"CHECK \(observable_reasons <@ ARRAY\[(.*?)\]\)") == expected


@pytest.mark.parametrize("kind", list(EventKind))
def test_event_kinds_satisfy_the_column_check(kind):
    assert re.fullmatch(r"[a-z][a-z_]*", kind.value)


def test_bootstrap_and_relation_terminate_commands():
    by_name = {c.name: c for c in COMMANDS}
    bootstrap = by_name["operator bootstrap"]
    assert bootstrap.unauthenticated and bootstrap.roles == frozenset()
    assert bootstrap.events == (EventKind.OPERATOR_ADDED,)
    assert bootstrap.litellm_reads == ("/user/info",)
    terminate = by_name["relation terminate"]
    assert terminate.roles == frozenset({OperatorRole.ADMIN})
    assert terminate.events == (EventKind.RELATION_TERMINATING, EventKind.APPROVAL_REVOKED)


def test_observation_items_used_by_rows_are_declared():
    used = {r.observation_item for r in SETTINGS_TABLE if r.observation_item}
    assert used <= set(OBSERVATION_ITEMS)
    assert {"auth_cache_shared", "spend_log_arguments_stored", "unbound_keys"} <= used


def test_each_setting_row_has_one_location():
    by_key = {r.key: r.location for r in SETTINGS_TABLE}
    assert by_key["MCP_TRUSTED_REDIRECT_ORIGINS"] is SettingLocation.ENVIRONMENT
    assert (
        by_key["use_x_forwarded_for, mcp_trusted_proxy_ranges"] is SettingLocation.GENERAL_SETTINGS
    )


def test_restore_is_described_only_as_a_scope_of_a_later_release():
    from pathlib import Path

    from mint_litellm.types.cli_commands import COMMANDS

    doc = read("보장과-한계.md")
    for line in doc.splitlines():
        if "restore --attest" in line:
            assert "현재 판본에는 복원 명령이 없고" in line
    assert not any("restore" in command.name for command in COMMANDS)
    script = Path(__file__).resolve().parents[2] / "deploy" / "mint.sh"
    assert "restore" not in script.read_text(encoding="utf-8")
