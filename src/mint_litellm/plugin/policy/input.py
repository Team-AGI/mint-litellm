"""판정 스냅숏에서 정책 입력에 허용된 값만 추출한다."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from mint_litellm.plugin.policy.patterns import NAMES as PATTERN_NAMES
from mint_litellm.types.identity import Principal

_FIELDS = {
    "server": (
        "id", "status", "transport", "auth_type", "provider_allowed", "auth_server_allowed",
        "contract_status", "identity_kind", "exec_contract_sha256", "exec_contract_version",
    ),
    # risk_grade: 계약 관리 서버에서 지금 승인된 도구 계약의 위험 등급(계약이 없으면 키가 없다).
    # action_type: 같은 계약의 행위 유형(읽기·쓰기·삭제·외부 전송·자격 접근).
    "tool": ("name", "risk_grade", "action_type"),
    "arguments": ("keys", "sizes", "patterns"),
    "approval": ("present", "id", "class", "scope_type", "expires_in_days", "conditions"),
    "consent": ("status", "source"),
    "settings": ("high_risk_tools",),
}
_FIELDS["principal"] = (
    "type", "id", "key_id", "org_id", "org_source", "team_id", "claimed_end_user_id"
)
_FIELDS["time"] = ("iso", "ns")


def has_only_policy_fields(value: Mapping[str, Any]) -> bool:
    if not set(value) <= set(_FIELDS) | {"mode", "operation"}:
        return False
    if not all(
        name not in value
        or (isinstance(value[name], Mapping) and set(value[name]) <= set(fields))
        for name, fields in _FIELDS.items()
    ):
        return False
    arguments = value.get("arguments", {})
    keys = arguments.get("keys", [])
    sizes = arguments.get("sizes", {})
    patterns = arguments.get("patterns", {})
    return (
        isinstance(patterns, Mapping)
        and set(patterns) <= set(PATTERN_NAMES)
        and all(type(v) is bool for v in patterns.values())
        and isinstance(keys, list)
        and all(isinstance(key, str) for key in keys)
        and isinstance(sizes, Mapping)
        and all(isinstance(k, str) and type(v) is int and v >= 0 for k, v in sizes.items())
    )


def policy_input(
    *,
    principal: Principal,
    server: Mapping[str, Any],
    tool: Mapping[str, Any],
    argument_keys: list[str],
    argument_sizes: Mapping[str, int],
    approval: Mapping[str, Any],
    consent: Mapping[str, Any],
    now: datetime,
    high_risk_tools: list[str],
    mode: str,
    operation: str,
    argument_patterns: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must have a timezone")
    if not all(isinstance(key, str) for key in argument_keys):
        raise ValueError("argument keys must be strings")
    if not all(
        isinstance(key, str) and type(size) is int and size >= 0
        for key, size in argument_sizes.items()
    ):
        raise ValueError("argument sizes must be nonnegative integers")
    instant = now.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = instant - epoch
    ns = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    sections = {
        "server": server,
        "tool": tool,
        "arguments": {"keys": list(argument_keys), "sizes": dict(argument_sizes)},
        "approval": approval,
        "consent": consent,
        "settings": {"high_risk_tools": list(high_risk_tools)},
    }
    if argument_patterns is not None:
        sections["arguments"]["patterns"] = dict(argument_patterns)
    result: dict[str, Any] = {
        "principal": {
            "type": principal.principal_type.value,
            "id": principal.principal_id,
            "key_id": principal.key_id,
            "org_id": principal.org_id,
            "org_source": principal.org_source.value if principal.org_source else None,
            "team_id": principal.team_id,
            "claimed_end_user_id": principal.claimed_end_user_id,
        },
        "time": {"iso": now.isoformat(), "ns": ns},
        "mode": mode,
        "operation": operation,
    }
    for key in ("id", "key_id", "org_id", "org_source"):
        if result["principal"][key] is None:
            del result["principal"][key]
    for name, values in sections.items():
        allowed = _FIELDS[name]
        if name == "approval" and values.get("present") is False:
            result[name] = {"present": False}
        else:
            result[name] = {key: values[key] for key in allowed if key in values}
    return result
