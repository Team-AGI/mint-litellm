"""원격 서버 호출의 대상·행위 결속: 추출 규칙과 승인 매칭.

- 프로필 표에서 대상·행위를 뽑고 빠진 인자에는 서버의 기본값을 적용한다.
- 변경·실행 호출은 받은 때의 대상·행위와 같은 승인에서만 통과하고, 풀 수 없으면 전송 전에 막는다.
- 프로필이 없는 서버는 기존 동작 그대로이다.
"""

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from plugin_helpers import (
    FP_KEY,
    approval,
    call_approval,
    config,
    evaluator,
    harness,
    request,
    resolved_server,
    snapshot,
)

from mint_litellm import cli
from mint_litellm.compat.litellm_1_106 import _credential_ref
from mint_litellm.control.errors import ControlError
from mint_litellm.plugin.config import PluginConfig
from mint_litellm.plugin.pipeline import evaluate_request
from mint_litellm.types import target as target_module
from mint_litellm.types.fingerprint import argument_fingerprint
from mint_litellm.types.target import (
    EXECUTE,
    READ,
    WRITE,
    Target,
    TargetUnresolved,
    bind_target,
    effective_profile,
    parse_profile_map,
    select_profile,
)

TRIGGER = {
    "method": "run_workflow", "owner": "Acme", "repo": "App", "workflow_id": "ci.yml",
    "ref": "main",
}
RUN_WORKFLOW = "actions_run_trigger.run_workflow"


def bound(profile, tool, arguments, server="srv-1"):
    return bind_target(profile, server, tool, arguments)


@pytest.mark.parametrize(
    ("profile", "tool", "arguments", "expected"),
    [
        ("github", "actions_run_trigger", TRIGGER, Target("acme/app", RUN_WORKFLOW, EXECUTE)),
        ("github", "get_file_contents", {"owner": "acme", "repo": "app", "path": "a"},
         Target("acme/app", "get_file_contents", READ)),
        ("github", "issue_write", {"method": "create", "owner": "acme", "repo": "app"},
         Target("acme/app", "issue_write.create", WRITE)),
        ("github", "get_me", {}, Target(None, "get_me", READ)),
        ("n8n", "n8n_test_workflow", {"workflowId": "7"},
         Target("srv-1/7", "n8n_test_workflow.auto", EXECUTE)),
        ("n8n", "n8n_test_workflow", {"workflowId": "7", "method": "prepare"},
         Target("srv-1/7", "n8n_test_workflow.prepare", READ)),
        ("n8n", "n8n_test_workflow", {"workflowId": "7", "method": "prepare", "exposeToMcp": True},
         Target("srv-1/7", "n8n_test_workflow.expose", EXECUTE)),
        ("n8n", "n8n_test_workflow", {"workflowId": "7", "instance": "prod"},
         Target("prod/7", "n8n_test_workflow.auto", EXECUTE)),
        ("n8n", "n8n_autofix_workflow", {"id": "7"},
         Target("srv-1/7", "n8n_autofix_workflow.false", READ)),
        ("n8n", "n8n_autofix_workflow", {"id": "7", "applyFixes": True},
         Target("srv-1/7", "n8n_autofix_workflow.true", WRITE)),
        ("n8n", "n8n_executions", {}, Target("srv-1/*", "n8n_executions.list", READ)),
        ("n8n", "n8n_executions", {"action": "delete", "id": "9"},
         Target("srv-1/*", "n8n_executions.delete", WRITE)),
        ("n8n", "n8n_update_full_workflow", {"id": "7", "name": "x"},
         Target("srv-1/7", "n8n_update_full_workflow", WRITE)),
        ("n8n", "n8n_manage_credentials", {"action": "Delete"},
         Target("srv-1", "n8n_manage_credentials.delete", WRITE)),
    ],
)
def test_target_action_and_effect_come_from_the_profile_table(profile, tool, arguments, expected):
    assert bound(profile, tool, arguments) == expected


@pytest.mark.parametrize(
    ("profile", "tool", "arguments"),
    [
        ("github", "actions_run_trigger", {"method": "run_workflow", "repo": "app"}),
        ("github", "actions_run_trigger", {"method": "run_workflow", "owner": "a/b", "repo": "c"}),
        ("github", "actions_run_trigger", {"owner": ["acme"], "repo": "app"}),
        ("github", "create_issue", {"owner": "acme", "repo": " "}),
        ("n8n", "n8n_test_workflow", {}),
        ("n8n", "n8n_test_workflow", {"workflowId": "*"}),
        ("n8n", "n8n_update_full_workflow", {"id": "7 8"}),
    ],
)
def test_a_changing_call_whose_target_cannot_be_told_is_unresolved(profile, tool, arguments):
    with pytest.raises(TargetUnresolved):
        bound(profile, tool, arguments)


def test_a_profile_without_an_unlisted_rule_does_not_know_other_tools(monkeypatch):
    monkeypatch.setitem(target_module.PROFILES, "tiny", {"tools": {}})
    with pytest.raises(TargetUnresolved):
        bound("tiny", "anything", {})


def test_a_read_only_tool_is_not_blocked_when_its_target_is_missing():
    assert bound("github", "list_commits", {}) == Target(None, "list_commits", READ)


def test_profile_map_parsing():
    assert parse_profile_map(" gh = github , n8n-prod=n8n,") == {"gh": "github", "n8n-prod": "n8n"}
    assert parse_profile_map("") == {}
    assert parse_profile_map("gh=none") == {"gh": "none"}
    for bad in ("gh", "gh=nope", "=github"):
        with pytest.raises(ValueError):
            parse_profile_map(bad)


def test_the_profile_is_selected_from_the_deployment_host_or_the_tool_names():
    assert select_profile("https://api.githubcopilot.com/mcp/", []) == "github"
    assert select_profile("https://ghe.corp.example/mcp", ["issue_write", "get_file_contents"]) == (
        "github")
    assert select_profile("https://n8n.corp.example", ["n8n_get_workflow", "n8n_executions"]) == (
        "n8n")
    assert select_profile("https://n8n.corp.example", ["n8n_get_workflow"]) is None
    assert select_profile(None, ["search"]) is None
    assert select_profile("not a url", ()) is None
    # 두 프로필의 근거가 함께 맞으면 고르지 않는다.
    both = ["issue_write", "get_file_contents", "n8n_get_workflow", "n8n_executions"]
    assert select_profile("https://x.example", both) is None


def test_the_environment_overrides_the_automatic_selection():
    assert effective_profile({}, "s", "github") == ("github", "auto")
    assert effective_profile({"s": "n8n"}, "s", "github") == ("n8n", "config")
    assert effective_profile({"s": "none"}, "s", "github") is None
    assert effective_profile({"other": "n8n"}, "s", None) is None


def test_the_plugin_config_reads_profiles_and_rejects_a_bad_value():
    env = {
        "MINT_INSTANCE_ID": "i", "MINT_DATABASE_URL": "postgresql://x",
        "MINT_OPA_URL": "http://o", "MINT_TARGET_PROFILES": "gh=github",
    }
    assert PluginConfig.from_env(env).target_profiles == {"gh": "github"}
    assert PluginConfig.from_env({**env, "MINT_TARGET_PROFILES": ""}).target_profiles == {}
    with pytest.raises(RuntimeError, match="MINT_TARGET_PROFILES"):
        PluginConfig.from_env({**env, "MINT_TARGET_PROFILES": "gh=nope"})


# --- 파이프라인 -------------------------------------------------------------------------------

REQUIRE = evaluator(
    "RequireApproval", policy_ids=("R2",), obligations=({"type": "require_call_approval"},)
)


def row(arguments, **override):
    fields = {
        "tool": "actions_run_trigger", "target": "acme/app", "action": RUN_WORKFLOW,
        "args_fp": argument_fingerprint(arguments, FP_KEY),
    }
    return call_approval(**(fields | override))


def decide(
    tmp_path, snap, *, arguments=TRIGGER, tool="actions_run_trigger", profiles=None, resolved=None
):
    cfg = config(tmp_path, target_profiles={"srv-1": "github"} if profiles is None else profiles)
    snap = replace(snap, approvals=(approval(tools=(tool,)),))
    h = harness(tmp_path, snap, cfg=cfg)
    extra = {} if resolved is None else {"resolved": resolved}
    req = request(tool_name=tool, arguments=arguments, **extra)
    return h, asyncio.run(evaluate_request(req, h.deps))


def test_an_approval_bound_to_the_same_target_and_action_is_consumed_with_them(tmp_path):
    h, outcome = decide(tmp_path, snapshot(call_approvals=(row(TRIGGER),)))
    assert outcome.allowed
    consumed = h.store.consumed[0]
    assert (consumed.target, consumed.action) == ("acme/app", RUN_WORKFLOW)
    assert (outcome.snapshot.bound_target, outcome.snapshot.bound_action) == (
        "acme/app", RUN_WORKFLOW)


@pytest.mark.parametrize(
    "override",
    [
        {"target": "acme/other"},
        {"action": "actions_run_trigger.rerun_workflow_run"},
        {"target": None, "action": None},
        {"action": None},
    ],
    ids=["other-repo", "other-method", "unbound-row", "no-action"],
)
def test_an_approval_with_the_same_arguments_but_another_target_or_action_does_not_match(
    tmp_path, override
):
    h, outcome = decide(tmp_path, snapshot(call_approvals=(row(TRIGGER, **override),)))
    assert outcome.error.code == "MINT-CALL-APPROVAL-REQUIRED"
    assert h.store.consumed == []


def test_a_changing_call_needs_an_approval_even_when_the_policy_asks_for_none(tmp_path):
    h, outcome = decide(tmp_path, snapshot())
    assert outcome.error.code == "MINT-CALL-APPROVAL-REQUIRED"
    assert h.store.consumed == []


def test_a_call_outside_the_approved_target_is_blocked_before_dispatch(tmp_path):
    other = {**TRIGGER, "repo": "secrets"}
    h, outcome = decide(tmp_path, snapshot(call_approvals=(row(TRIGGER),)), arguments=other)
    assert not outcome.allowed and h.store.consumed == []


def test_an_unresolvable_changing_call_is_held_and_names_the_reason(tmp_path):
    arguments = {"method": "run_workflow", "repo": "app"}
    approval = row(arguments, target="x/app")
    h, outcome = decide(tmp_path, snapshot(call_approvals=(approval,)), arguments=arguments)
    assert outcome.error.code == "MINT-CALL-APPROVAL-REQUIRED"
    assert outcome.snapshot.stop.detail.startswith("target: owner")
    assert h.store.consumed == []


def test_a_read_call_needs_no_approval_but_is_recorded_with_its_target(tmp_path):
    arguments = {"owner": "Acme", "repo": "App", "path": "README.md"}
    h, outcome = decide(tmp_path, snapshot(), arguments=arguments, tool="get_file_contents")
    assert outcome.allowed
    assert outcome.snapshot.bound_target == "acme/app"


def test_the_profile_chosen_from_the_deployment_binds_calls_and_is_recorded(tmp_path):
    snap = snapshot(call_approvals=(row(TRIGGER),), auto_profile="github")
    h, outcome = decide(tmp_path, snap, profiles={})
    assert outcome.allowed
    assert (outcome.snapshot.target_profile, outcome.snapshot.target_profile_source) == (
        "github", "auto")
    h, outcome = decide(tmp_path, snapshot(auto_profile="github"), profiles={})
    assert outcome.error.code == "MINT-CALL-APPROVAL-REQUIRED"


def test_a_configured_profile_overrides_or_switches_off_the_automatic_one(tmp_path):
    snap = snapshot(auto_profile="github")
    _, outcome = decide(tmp_path, snap, profiles={"srv-1": "none"})
    assert outcome.allowed and outcome.snapshot.target_profile is None
    snap = snapshot(call_approvals=(row(TRIGGER),), auto_profile="n8n")
    _, outcome = decide(tmp_path, snap, profiles={"srv-1": "github"})
    assert outcome.allowed
    assert (outcome.snapshot.target_profile, outcome.snapshot.target_profile_source) == (
        "github", "config")


def test_a_server_without_a_profile_keeps_the_existing_behavior(tmp_path):
    h, outcome = decide(tmp_path, snapshot(), profiles={})
    assert outcome.allowed
    assert outcome.snapshot.bound_target is None and outcome.snapshot.bound_action is None
    # 대상이 묶인 승인은 프로필이 없는 서버의 호출에는 쓰이지 않는다.
    snap = snapshot(
        call_approvals=(row(TRIGGER),), approvals=(approval(tools=("actions_run_trigger",)),)
    )
    required = harness(tmp_path, snap, evaluate=REQUIRE, cfg=config(tmp_path))
    req = request(tool_name="actions_run_trigger", arguments=TRIGGER)
    blocked = asyncio.run(evaluate_request(req, required.deps))
    assert blocked.error.code == "MINT-CALL-APPROVAL-REQUIRED"


def test_the_remote_credential_principal_is_recorded_when_the_registry_has_one(tmp_path):
    resolved = resolved_server(credential_ref="oauth2-client:app-1")
    _, outcome = decide(tmp_path, snapshot(), profiles={}, resolved=resolved)
    assert outcome.snapshot.resolved_credential_ref == "oauth2-client:app-1"
    _, outcome = decide(tmp_path, snapshot(), profiles={})
    assert outcome.snapshot.resolved_credential_ref is None


def test_the_credential_reference_never_carries_the_token():
    token = "ghp_secret_token_value"
    ref = _credential_ref(SimpleNamespace(authentication_token=token, client_id="c"))
    assert ref.startswith("static:") and token not in ref and len(ref) == len("static:") + 16
    oauth = _credential_ref(SimpleNamespace(authentication_token=None, client_id="c"))
    assert oauth == "oauth2-client:c"
    assert _credential_ref(SimpleNamespace(authentication_token="", client_id=None)) is None


# --- 운영자 명령 ------------------------------------------------------------------------------


def command(server, tool, arguments=None, args_fp=None, profiles="gh=github"):
    args = SimpleNamespace(
        server=server, tool=tool, args_fp=args_fp,
        arguments=None if arguments is None else json.dumps(arguments), args_file=None,
    )
    return SimpleNamespace(args=args, environ={"MINT_TARGET_PROFILES": profiles})


def test_the_operator_command_uses_the_profile_chosen_from_the_deployment(monkeypatch):
    run = command("srv", "actions_run_trigger", TRIGGER, profiles="")
    monkeypatch.setattr(cli, "_deployment_basis", lambda _run: [
        {"server_id": "srv", "url": "https://api.githubcopilot.com/mcp/", "tools": []}])
    assert cli._bound_target(run) == ("acme/app", RUN_WORKFLOW)
    run = command("srv", "actions_run_trigger", TRIGGER, profiles="srv=none")
    assert cli._bound_target(run) == (None, None)


def test_the_check_shows_which_profile_each_server_uses():
    from mint_litellm.control import checks

    report = checks.Report()
    deployments = [
        {"server_id": "gh", "url": "https://api.githubcopilot.com/mcp/", "tools": None},
        {"server_id": "plain", "url": "https://mcp.example", "tools": ["search"]},
    ]
    checks.target_profile_findings(report, deployments, {"MINT_TARGET_PROFILES": "wf=n8n"})
    (finding,) = report.findings
    assert finding.item == "호출 대상 프로필" and finding.level is checks.Level.INFO
    assert finding.message == "gh=github(자동), wf=n8n(덮어씀)"
    report = checks.Report()
    checks.target_profile_findings(report, [], {"MINT_TARGET_PROFILES": "bad"})
    assert report.failed


def test_the_operator_command_extracts_the_same_target_as_the_plugin(monkeypatch):
    monkeypatch.setattr(cli, "_deployment_basis", lambda _run: [])
    got = cli._bound_target(command("gh", "actions_run_trigger", TRIGGER))
    assert got == ("acme/app", RUN_WORKFLOW)
    assert cli._bound_target(command("other", "actions_run_trigger", TRIGGER)) == (None, None)


@pytest.mark.parametrize(
    "run",
    [
        command("gh", "actions_run_trigger", args_fp="a" * 64),
        command("gh", "actions_run_trigger", {"method": "run_workflow"}),
        command("gh", "actions_run_trigger", ["not", "an", "object"]),
        command("gh", "actions_run_trigger", TRIGGER, profiles="gh=nope"),
    ],
    ids=["fingerprint-only", "no-target", "not-an-object", "bad-profile"],
)
def test_the_operator_command_refuses_what_cannot_be_bound(run):
    with pytest.raises(ControlError):
        cli._bound_target(run)
