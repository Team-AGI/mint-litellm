"""원격 서버 호출의 대상·행위 추출. 서버별 규칙은 코드가 아니라 ``PROFILES`` 표(데이터)이다.

호출 인자에서 대상(예: 저장소, 워크플로)과 행위(도구와 하위 방식)를 구조적으로 뽑고, 빠진 인자에는
서버가 실제로 쓰는 기본값을 적용한다. 호출별 승인은 이 값에 묶이고 매칭은 완전 일치만 인정한다.
프로필이 없는 서버는 이 모듈을 거치지 않는다(기존 동작 그대로).

규칙(``tools`` 값, 없는 도구는 ``unlisted``)의 항목:

- ``target``: 대상을 이루는 인자 이름 목록. ``이름``은 필수, ``이름=기본값``은 빠지면 기본값을 쓴다.
  기본값 ``$server``는 호출이 향한 서버 식별자이다.
- ``operation``: 같은 도구 안에서 행위를 가르는 인자(``이름`` 또는 ``이름=기본값``). 선택 사항.
- ``effect``: ``read``(읽기만)·``write``(변경)·``execute``(실행) 중 기본 효과.
- ``effects``: 하위 방식 값별 효과(기본 효과를 덮는다). 값은 소문자로 비교한다.
- ``escalate``: ``{인자: 방식}``. 그 인자가 참이면 ``방식``이 행위이고 효과는 기본 효과다.

프로필에도 규칙에도 없는 도구는 풀 수 없는 호출이다(``TargetUnresolved``).

서버에 어느 프로필을 쓸지는 승인된 배포 계약에서 자동으로 고른다(``select_profile``). 프로필의
``match``는 선택 근거로, ``hosts``(URL 호스트)에 들거나 ``tools``(도구 이름 서명) 중 둘 이상이
승인된 도구에 있으면 그 프로필이다. 환경 변수 값은 이 선택을 덮어쓴다(``none``은 끈다).
"""

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

READ, WRITE, EXECUTE = "read", "write", "execute"

# 대상 구성 요소로 받는 값. 구분자(/)와 공백을 막아 다른 대상이 같은 문자열이 되지 않게 한다.
_COMPONENT = re.compile(r"[A-Za-z0-9_.@:-]{1,128}", re.ASCII)
_READ_ONLY_RULE = {"target": [], "effect": READ}

_GITHUB_READ = (
    "get_file_contents", "get_repository_tree", "get_file_blame", "list_branches", "list_commits",
    "get_commit", "list_tags", "get_tag", "list_releases", "get_latest_release",
    "get_release_by_tag", "issue_read", "list_issues", "pull_request_read", "list_pull_requests",
    "actions_get", "actions_list", "get_job_logs", "list_code_scanning_alerts",
    "get_code_scanning_alert", "list_dependabot_alerts", "get_dependabot_alert",
    "list_secret_scanning_alerts", "get_secret_scanning_alert", "list_discussions",
    "get_discussion", "get_discussion_comments", "search_code", "search_commits",
)
_GITHUB_READ_ANYWHERE = (
    "get_me", "search_repositories", "search_issues", "search_pull_requests", "search_users",
    "list_notifications", "get_notification_details", "list_gists", "get_gist", "get_teams",
    "get_team_members",
)
_N8N_READ = (
    "tools_documentation", "search_nodes", "get_node", "validate_node", "search_templates",
    "get_template", "n8n_health_check", "n8n_list_catalog", "n8n_explore_node_resources",
)

# 대상 인자 이름과 기본값은 각 서버 저장소의 도구 입력 스키마에서 확인한 값이다.
PROFILES: dict[str, dict[str, Any]] = {
    "github": {
        "match": {
            "hosts": ("api.githubcopilot.com",),
            "tools": ("actions_run_trigger", "get_file_contents", "issue_write",
                      "create_pull_request", "pull_request_read", "list_issues"),
        },
        "fold_case": True,
        # 목록에 없는 도구는 owner/repo를 대상으로 하는 변경으로 본다. 둘이 없으면 풀 수 없다.
        "unlisted": {"target": ["owner", "repo"], "operation": "method", "effect": WRITE},
        "tools": {
            **{t: {"target": ["owner", "repo"], "operation": "method", "effect": READ}
               for t in _GITHUB_READ},
            **{t: _READ_ONLY_RULE for t in _GITHUB_READ_ANYWHERE},
            "actions_run_trigger": {
                "target": ["owner", "repo"], "operation": "method", "effect": EXECUTE},
        },
    },
    "n8n": {
        "match": {
            "hosts": (),
            "tools": ("n8n_create_workflow", "n8n_get_workflow", "n8n_list_workflows",
                      "n8n_test_workflow", "n8n_executions", "n8n_update_full_workflow"),
        },
        "unlisted": {"target": ["instance=$server"], "operation": "action", "effect": WRITE},
        "tools": {
            **{t: _READ_ONLY_RULE for t in _N8N_READ},
            "n8n_list_workflows": {"target": ["instance=$server"], "effect": READ},
            "n8n_get_workflow": {"target": ["instance=$server", "id"], "effect": READ},
            "n8n_validate_workflow": {"target": ["instance=$server", "id"], "effect": READ},
            "n8n_create_workflow": {"target": ["instance=$server"], "effect": WRITE},
            "n8n_deploy_template": {"target": ["instance=$server"], "effect": WRITE},
            "n8n_update_full_workflow": {"target": ["instance=$server", "id"], "effect": WRITE},
            "n8n_update_partial_workflow": {"target": ["instance=$server", "id"], "effect": WRITE},
            "n8n_delete_workflow": {"target": ["instance=$server", "id"], "effect": WRITE},
            # applyFixes를 주지 않으면 고칠 내용을 미리 보기만 한다.
            "n8n_autofix_workflow": {
                "target": ["instance=$server", "id"], "operation": "applyFixes=false",
                "effect": WRITE, "effects": {"false": READ}},
            # method를 주지 않으면 auto이고, auto는 웹훅·폼·채팅 트리거로 워크플로를 실행한다.
            "n8n_test_workflow": {
                "target": ["instance=$server", "workflowId"], "operation": "method=auto",
                "effect": EXECUTE, "effects": {"prepare": READ},
                "escalate": {"exposeToMcp": "expose"}},
            # action을 주지 않으면 list이다. 목록은 특정 워크플로로 좁히지 않을 수 있다.
            "n8n_executions": {
                "target": ["instance=$server", "workflowId=*"], "operation": "action=list",
                "effect": WRITE, "effects": {"get": READ, "list": READ}},
            "n8n_workflow_versions": {
                "target": ["instance=$server", "id"], "operation": "mode=list",
                "effect": WRITE, "effects": {"list": READ, "get": READ, "diff": READ},
                "escalate": {"exposeToMcp": "expose"}},
        },
    },
}


class TargetUnresolved(Exception):
    """프로필이 있는 서버의 호출에서 대상이나 행위를 정할 수 없다."""


@dataclass(frozen=True)
class Target:
    """대상(대상이 없는 읽기 도구는 None)·행위·효과(``read``·``write``·``execute``)."""

    target: str | None
    action: str
    effect: str


OFF = "none"


def select_profile(url: str | None, tools: Collection[str]) -> str | None:
    """승인된 배포 계약의 URL과 도구 이름으로 고른 프로필. 근거가 없거나 둘 이상이면 None."""
    try:
        host = (urlsplit(url).hostname or "").lower() if url else ""
    except ValueError:
        host = ""
    names = set(tools)
    found = [
        name for name, profile in PROFILES.items()
        if host in profile.get("match", {}).get("hosts", ())
        or len(names & set(profile.get("match", {}).get("tools", ()))) >= 2
    ]
    return found[0] if len(found) == 1 else None


def effective_profile(
    overrides: Mapping[str, str], server_id: str, auto: str | None
) -> tuple[str, str] | None:
    """서버에 쓸 (프로필, 출처). 출처는 ``config``(환경 변수 덮어쓰기)나 ``auto``이다."""
    if server_id in overrides:
        name = overrides[server_id]
        return None if name == OFF else (name, "config")
    return None if auto is None else (auto, "auto")


def parse_profile_map(text: str) -> dict[str, str]:
    """``서버=프로필`` 쉼표 목록(``MINT_TARGET_PROFILES``). 형식이 틀리면 ``ValueError``."""
    mapping: dict[str, str] = {}
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        server, sep, profile = (s.strip() for s in item.partition("="))
        if not sep or not server or (profile not in PROFILES and profile != OFF):
            raise ValueError(
                f"'{item}' must be <server_id>=<profile> ({', '.join([*PROFILES, OFF])})")
        mapping[server] = profile
    return mapping


def _scalar(value: Any, name: str) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    raise TargetUnresolved(f"{name} is not a scalar")


def _read(arguments: Mapping[str, Any], spec: str, server_id: str) -> str | None:
    """``이름[=기본값]`` 항목의 값. 빠졌으면 기본값이고, 기본값이 없으면 None."""
    name, has_default, default = spec.partition("=")
    value = arguments.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        if not has_default:
            return None
        return server_id if default == "$server" else default
    return _scalar(value, name)


def _component(arguments: Mapping[str, Any], spec: str, server_id: str, fold: bool) -> str:
    """대상의 한 구성 요소. 받은 값은 평범한 식별자여야 하고, 기본값은 검사하지 않는다."""
    name = spec.partition("=")[0]
    value = arguments.get(name)
    if value is None or (isinstance(value, str) and not value.strip()):
        text = _read(arguments, spec, server_id)
        if text is None:
            raise TargetUnresolved(f"{name} is missing")
        return text
    text = _scalar(value, name)
    if fold:
        text = text.lower()
    if not _COMPONENT.fullmatch(text):
        raise TargetUnresolved(f"{name} is not a plain identifier")
    return text


def bind_target(
    profile_name: str, server_id: str, tool: str, arguments: Mapping[str, Any]
) -> Target:
    """프로필 규칙으로 호출의 대상·행위·효과를 정한다. 정할 수 없으면 ``TargetUnresolved``."""
    profile = PROFILES[profile_name]
    rule = profile["tools"].get(tool) or profile.get("unlisted")
    if rule is None:
        raise TargetUnresolved("tool is not in the profile")
    fold = profile.get("fold_case", False)
    read_only = rule["effect"] == READ and not rule.get("effects")
    try:
        parts = [_component(arguments, spec, server_id, fold) for spec in rule["target"]]
        operation = None
        effect = rule["effect"]
        if "operation" in rule:
            operation = _read(arguments, rule["operation"], server_id)
            if operation is not None:
                operation = operation.lower()
                effect = rule.get("effects", {}).get(operation, effect)
        for flag, forced in rule.get("escalate", {}).items():
            if (_read(arguments, flag, server_id) or "").lower() == "true":
                operation, effect = forced, rule["effect"]
    except TargetUnresolved:
        if read_only:
            return Target(None, tool, READ)  # 읽기만 하는 도구는 대상을 못 정해도 막지 않는다.
        raise
    return Target(
        "/".join(parts) if parts else None, f"{tool}.{operation}" if operation else tool, effect
    )
