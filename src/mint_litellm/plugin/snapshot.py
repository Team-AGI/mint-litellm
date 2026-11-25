"""판정 스냅숏과 플러그인의 DB 접근.

스냅숏은 트랜잭션 블록 없이 단일 질의 한 번으로 읽는다. 한 문장은 하나의 스냅숏을 보므로 상태
세대와 서버·관계·승인·거부·호출별 승인·동의·설정·정책 판본이 같은 시점의 값이다. 왕복을 줄이려고
BEGIN·COMMIT을 따로 보내지 않는다. 상태 캐시는 없다. LiteLLM의 표는 읽지 않는다.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
import re
import socket
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from mint_litellm.endpoint.refresh import (
    merge_local_mcp,
    revoke_names,
    scoped_desired,
    without_network,
)
from mint_litellm.endpoint.remediation import (
    merge_offline_calls,
    offline_call_events,
    remediation_events,
    retired_names,
)
from mint_litellm.plugin.buffer import ConsumeRequest, ConsumptionLost
from mint_litellm.types.canonical import sha256
from mint_litellm.types.events import Event, EventKind, control_source_key
from mint_litellm.types.identity import OrgStatus, SubjectType
from mint_litellm.types.reason_codes import OBSERVATION_CANDIDATES, Reason
from mint_litellm.types.settings import Mode
from mint_litellm.types.target import select_profile

STAGE2_SNAPSHOT_SQL = """
WITH
s AS (SELECT * FROM mint.settings WHERE instance_id = %(iid)s),
srv AS (
    SELECT * FROM mint.servers WHERE instance_id = %(iid)s AND server_id = %(server_id)s
),
b AS (
    SELECT * FROM mint.org_bindings
    WHERE instance_id = %(iid)s
      AND ((subject_type = 'team' AND subject_id = %(team_id)s)
        OR (subject_type = 'user' AND subject_id = %(user_id)s))
),
o AS (
    SELECT org_id, status FROM mint.orgs
    WHERE instance_id = %(iid)s
      AND org_id IN (SELECT org_id FROM b UNION
                     SELECT default_org_id FROM s WHERE default_org_id IS NOT NULL)
),
ap AS (
    SELECT * FROM mint.approvals
    WHERE instance_id = %(iid)s AND server_id = %(server_id)s AND status <> 'pending'
      AND ((scope_type = 'key' AND scope_id = %(key_id)s)
        OR (scope_type = 'user' AND scope_id = %(user_id)s)
        OR (scope_type = 'team' AND scope_id = %(team_id)s)
        OR (scope_type = 'org' AND scope_id IN (SELECT org_id FROM o)))
)
SELECT jsonb_build_object(
    'now', now(),
    'epoch', (SELECT epoch FROM mint.state_epoch WHERE instance_id = %(iid)s),
    'settings', (SELECT to_jsonb(s) FROM s),
    'bindings', (SELECT coalesce(jsonb_agg(to_jsonb(b)), '[]'::jsonb) FROM b),
    'orgs', (SELECT coalesce(jsonb_agg(to_jsonb(o)), '[]'::jsonb) FROM o),
    'server', (SELECT to_jsonb(srv) FROM srv),
    'tool_contracts', (
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'id', t.id, 'credential_scope', t.credential_scope, 'tool', t.tool,
            'drift', t.drift, 'version', t.version, 'risk_grade', t.risk_grade,
            'action_type', t.action_type, 'input_keys', to_jsonb(t.input_keys))), '[]'::jsonb)
        FROM mint.tool_contracts t
        WHERE t.instance_id = %(iid)s AND t.server_id = %(server_id)s
          AND t.tool = %(tool)s AND t.status = 'approved'
          AND EXISTS (SELECT 1 FROM srv
                      WHERE contract_status = 'managed' OR identity_kind = 'stdio')
    ),
    'approved_contracts', (
        SELECT count(*) FROM mint.tool_contracts t, srv
        WHERE t.instance_id = %(iid)s AND t.server_id = %(server_id)s AND t.status = 'approved'
          AND t.credential_scope = CASE WHEN srv.auth_type IN ('oauth_delegate',
              'true_passthrough') THEN 'per_user' ELSE 'server' END
    ),
    'call_review_tools', (
        SELECT coalesce(array_agg(c.tool), '{}') FROM mint.call_review_tools c
        WHERE c.instance_id = %(iid)s AND c.server_id = %(server_id)s
    ),
    'provisional_contract', (
        SELECT jsonb_build_object('action_type', p.action_type, 'risk_grade', p.risk_grade,
            'input_keys', to_jsonb(p.input_keys))
        FROM mint.provisional_contracts p
        WHERE p.instance_id = %(iid)s AND p.server_id = %(server_id)s AND p.tool = %(tool)s
    ),
    'deployment_basis', (
        SELECT jsonb_build_object('url', d.url, 'oauth_scopes', to_jsonb(d.oauth_scopes),
            'tools', coalesce(d.allowed_tools, '{}') ||
            coalesce((SELECT array_agg(DISTINCT t.tool) FROM mint.tool_contracts t
                      WHERE t.instance_id = d.instance_id AND t.server_id = d.server_id
                        AND t.status = 'approved'), '{}'))
        FROM mint.deployment_contracts d
        WHERE d.instance_id = %(iid)s AND d.server_id = %(server_id)s AND d.status = 'approved'
    ),
    'allowlists', (
        SELECT coalesce(jsonb_agg(to_jsonb(a)), '[]'::jsonb) FROM mint.allowlists a
        WHERE a.instance_id = %(iid)s AND a.id = ANY (SELECT unnest(basis_allowlist_ids) FROM srv)
    ),
    'egress_targets', (
        SELECT coalesce(jsonb_agg(jsonb_build_object('value', e.value, 'org_id', e.org_id)),
                        '[]'::jsonb)
        FROM mint.allowlists e
        WHERE e.instance_id = %(iid)s AND e.kind = 'egress_target' AND e.status = 'active'
          AND e.valid_from <= now() AND now() < e.valid_until
    ),
    'relations', (
        SELECT coalesce(jsonb_agg(to_jsonb(r)), '[]'::jsonb) FROM mint.usage_relations r
        WHERE r.instance_id = %(iid)s AND r.id IN (SELECT relation_id FROM ap)
    ),
    'negative_relation', EXISTS (
        SELECT 1 FROM mint.usage_relations r
        WHERE r.instance_id = %(iid)s AND r.server_id = %(server_id)s
          AND r.status IN ('terminating', 'terminated')
          AND r.id IN (SELECT a.relation_id FROM mint.approvals a
              WHERE a.instance_id = %(iid)s AND a.server_id = %(server_id)s
                AND ((a.scope_type = 'key' AND a.scope_id = %(key_id)s)
                  OR (a.scope_type = 'user' AND a.scope_id = %(user_id)s)
                  OR (a.scope_type = 'team' AND a.scope_id = %(team_id)s)
                  OR (a.scope_type = 'org' AND a.scope_id IN (SELECT org_id FROM o))))
    ),
    'approvals', (SELECT coalesce(jsonb_agg(to_jsonb(ap)), '[]'::jsonb) FROM ap),
    'denials', (
        SELECT coalesce(jsonb_agg(to_jsonb(d)), '[]'::jsonb) FROM mint.denials d
        WHERE d.instance_id = %(iid)s AND d.lifted_at IS NULL
          AND (d.server_id IS NULL OR d.server_id = %(server_id)s)
          AND ((d.scope_type = 'key' AND d.scope_id = %(key_id)s)
            OR (d.scope_type = 'user' AND d.scope_id = %(user_id)s)
            OR (d.scope_type = 'team' AND d.scope_id = %(team_id)s)
            OR (d.scope_type = 'org' AND d.scope_id IN (SELECT org_id FROM o))
            OR (d.scope_type = 'server' AND d.scope_id = %(server_id)s))
    ),
    'call_approvals', (
        SELECT coalesce(jsonb_agg(to_jsonb(c) || jsonb_build_object('uses', (
            SELECT count(*) FROM mint.call_approval_uses u WHERE u.call_approval_id = c.id))),
            '[]'::jsonb) FROM mint.call_approvals c
        WHERE c.instance_id = %(iid)s AND c.status = 'approved'
          AND c.server_id = %(server_id)s AND c.tool = %(tool)s
          AND c.principal_id = %(principal_id)s
    ),
    'consents', (
        SELECT coalesce(jsonb_agg(to_jsonb(k)), '[]'::jsonb) FROM mint.consents k
        WHERE k.instance_id = %(iid)s AND k.server_id = %(server_id)s
          AND k.human_user_id = %(user_id)s
    ),
    'policy_version', (
        SELECT to_jsonb(p) FROM mint.policy_versions p
        WHERE p.instance_id = %(iid)s AND p.status = 'active'
    )
) AS doc
"""

# v001 데이터베이스에는 계약 표가 없다. 같은 질의에서 계약 부분만 빈 목록으로 바꾼다.
SNAPSHOT_SQL = re.sub(
    r"'tool_contracts', \(.*?\),\s+'allowlists'",
    "'tool_contracts', '[]'::jsonb,\n    'allowlists'",
    STAGE2_SNAPSHOT_SQL,
    count=1,
    flags=re.S,
)

# 단말 키는 설치·앱 행의 현재 팀으로 판정한다(키 자체의 팀은 발급 때 값으로 굳어 있다).
# 행이 없으면 호출이 싣고 온 팀을 쓴다.
_EFFECTIVE_TEAM_CTE = """
kit AS (
    SELECT team_id FROM mint.endpoint_installs
    WHERE instance_id = %(iid)s AND revoked_at IS NULL
      AND %(key_id)s IN (key_token, mcp_key_token)
    UNION ALL
    SELECT team_id FROM mint.endpoint_apps
    WHERE instance_id = %(iid)s AND revoked_at IS NULL AND key_token = %(key_id)s
),
eff AS (
    SELECT CASE WHEN EXISTS (SELECT 1 FROM kit) THEN (SELECT team_id FROM kit LIMIT 1)
                ELSE %(team_id)s::text END AS team_id
),
"""

CONFIRMATION_SNAPSHOT_SQL = (
    STAGE2_SNAPSHOT_SQL.replace("%(team_id)s", "(SELECT team_id FROM eff)")
    .replace("WITH" + chr(10), "WITH" + _EFFECTIVE_TEAM_CTE, 1)
    .replace(
        "'now', now(),",
        "'now', now()," + chr(10) + "    'effective_team', (SELECT team_id FROM eff),",
        1,
    )
).replace(
    "'consents', (",
    """'self_confirmations', (
        SELECT coalesce(jsonb_agg(to_jsonb(c) - 'display'), '[]'::jsonb)
        FROM mint.self_confirmations c
        WHERE c.instance_id = %(iid)s AND c.status = 'confirmed'
          AND c.server_id = %(server_id)s AND c.tool = %(tool)s
          AND c.principal_id = %(user_id)s
    ),
    'consents', (""",
)

CONSUME_CONFIRMATION_SQL = """
UPDATE mint.self_confirmations
SET status = 'consumed', consumed_invocation_id = %(invocation_id)s,
    consumed_at = clock_timestamp()
WHERE instance_id = %(iid)s AND id = %(id)s AND status = 'confirmed'
  AND org_id = %(org_id)s AND principal_id = %(principal_id)s
  AND confirmed_by_user_id = %(principal_id)s
  AND server_id = %(server_id)s AND tool = %(tool)s AND args_fp = %(args_fp)s
  AND fp_key_version = %(fp_key_version)s AND policy_version_id = %(policy_version_id)s
  AND state_version = %(state_version)s AND expires_at > clock_timestamp()
  AND (NOT (SELECT require_separate_confirm_key FROM mint.settings WHERE instance_id = %(iid)s)
       OR confirmed_by_key_token <> requested_by_key_token)
  AND contract_id IS NOT DISTINCT FROM %(contract_id)s::uuid
  AND (%(contract_id)s::uuid IS NULL OR EXISTS (
       SELECT 1 FROM mint.tool_contracts t
       WHERE t.instance_id = %(iid)s AND t.id = %(contract_id)s::uuid AND t.status = 'approved'))
"""

INSERT_EVENT_SQL = """
INSERT INTO mint.events
    (event_id, instance_id, inserted_at, kind, source_key, invocation_id, attempt_id,
     actor, subject, payload)
SELECT %s::uuid, %s, %s::timestamptz, %s, %s, %s::uuid, %s::integer, %s, %s::jsonb, %s::jsonb
WHERE mint.claim_event_key(%s, %s, %s::uuid)
"""

_CONSUME_MATCH = """
  AND principal_type = %(principal_type)s AND principal_id = %(principal_id)s
  AND server_id = %(server_id)s AND tool = %(tool)s AND args_fp = %(args_fp)s
  AND policy_version_id = %(policy_version_id)s AND {contract}
  AND state_version = %(state_version)s
  AND exec_contract_sha256 IS NOT DISTINCT FROM %(exec_contract_sha256)s::text
  AND (%(exec_contract_sha256)s::text IS NULL OR EXISTS (
       SELECT 1 FROM mint.servers s
       WHERE s.instance_id = %(iid)s AND s.server_id = %(server_id)s
         AND s.exec_contract_sha256 = %(exec_contract_sha256)s::text))
"""

CONSUME_SQL = """
UPDATE mint.call_approvals
SET status = 'consumed', consumed_invocation_id = %(invocation_id)s
WHERE instance_id = %(iid)s AND id = %(id)s AND status = 'approved'
  AND valid_until IS NULL AND expires_at > clock_timestamp()
""" + _CONSUME_MATCH.format(contract="contract_version IS NULL")

# 기간 승인 한 건의 사용 횟수 상한. 인자 지문을 풀어 쓰는 대신 폭주를 막는다.
# ponytail: 상한 검사와 삽입이 한 문장이라 동시 호출이 겹치면 동시 수만큼 넘을 수 있다.
WINDOW_MAX_USES = 50

# 기간을 고른 승인의 사용: 승인 행은 그대로 두고 호출마다 사용 표에 한 행을 넣는다. 같은 결속
# 조건이 지금도 맞고 기간 안이며 사용 횟수가 상한 미만일 때만 한 행이 들어가며, 한 호출은 한
# 번만 기록된다.
WINDOW_CONSUME_HEAD = f"""
INSERT INTO mint.call_approval_uses (instance_id, call_approval_id, invocation_id)
SELECT instance_id, id, %(invocation_id)s::uuid FROM mint.call_approvals
WHERE instance_id = %(iid)s AND id = %(id)s AND status = 'approved'
  AND valid_until > clock_timestamp()
  AND (SELECT count(*) FROM mint.call_approval_uses u
       WHERE u.call_approval_id = call_approvals.id) < {WINDOW_MAX_USES}
"""
WINDOW_CONSUME_TAIL = " ON CONFLICT DO NOTHING"

# 로컬 실행 서버의 호출별 승인: 받은 때의 실행 계약이 서버 행의 지금 계약일 때만 소비한다.
_EXEC_BOUND = """
  AND exec_contract_sha256 = %(exec_contract_sha256)s::text
  AND EXISTS (SELECT 1 FROM mint.servers s
              WHERE s.instance_id = %(iid)s AND s.server_id = %(server_id)s
                AND s.exec_contract_sha256 = %(exec_contract_sha256)s::text)
"""
CONSUME_EXEC_SQL = CONSUME_SQL + _EXEC_BOUND

# 계약 관리 서버의 호출별 승인: 받은 때의 계약이 지금도 승인된 계약일 때만 소비한다.
_CONTRACT_BOUND = (
    "contract_id = %(contract_id)s::uuid AND EXISTS (SELECT 1 FROM mint.tool_contracts t"
    " WHERE t.instance_id = %(iid)s AND t.id = %(contract_id)s::uuid AND t.status = 'approved')"
)
CONSUME_BOUND_SQL = CONSUME_SQL.replace("contract_version IS NULL", _CONTRACT_BOUND)

# 프로필이 있는 서버의 호출별 승인: 받은 때의 대상·행위와 같을 때만 소비한다.
CONSUME_TARGET_SQL = (
    " AND target IS NOT DISTINCT FROM %(target)s::text AND action = %(action)s::text"
)


def consume_sql(consume: ConsumeRequest) -> str:
    """소비 요청의 결속에 맞는 문장. 기간 승인은 사용 표 삽입, 1회 승인은 소비 전이이다."""
    target = CONSUME_TARGET_SQL if consume.action is not None else ""
    if consume.windowed:
        exec_bound = _EXEC_BOUND if consume.exec_contract_sha256 is not None else ""
        contract = (
            "contract_version IS NULL" if consume.contract_id is None or exec_bound
            else _CONTRACT_BOUND
        )
        return (WINDOW_CONSUME_HEAD + _CONSUME_MATCH.format(contract=contract) + exec_bound
                + target + WINDOW_CONSUME_TAIL)
    return (
        CONSUME_EXEC_SQL if consume.exec_contract_sha256 is not None
        else CONSUME_SQL if consume.contract_id is None
        else CONSUME_BOUND_SQL
    ) + target


NEGATIVE_STATE_SQL = """
SELECT
    coalesce((SELECT status = 'revoked' FROM mint.approvals
              WHERE instance_id = %(iid)s AND id = %(approval_id)s), false)
 OR coalesce((SELECT status IN ('terminating', 'terminated') FROM mint.usage_relations
              WHERE instance_id = %(iid)s AND id = %(relation_id)s), false)
 OR coalesce((SELECT status IN ('rejected', 'suspended', 'terminating', 'terminated')
              FROM mint.servers
              WHERE instance_id = %(iid)s AND server_id = %(server_id)s), false)
 OR EXISTS (
        SELECT 1 FROM mint.denials d
        WHERE d.instance_id = %(iid)s AND d.lifted_at IS NULL
          AND (d.server_id IS NULL OR d.server_id = %(server_id)s)
          AND (d.tools IS NULL OR %(tool)s = ANY (d.tools))
          AND (d.org_id IS NULL OR d.org_id = %(org_id)s)
          AND ((d.scope_type = 'key' AND d.scope_id = %(key_id)s)
            OR (d.scope_type = 'user' AND d.scope_id = %(user_id)s)
            OR (d.scope_type = 'team' AND d.scope_id = %(team_id)s)
            OR (d.scope_type = 'org' AND d.scope_id = %(org_id)s)
            OR (d.scope_type = 'server' AND d.scope_id = %(server_id)s)))
"""


def _time(value: Any) -> datetime:
    return datetime.fromisoformat(value)


def _maybe_time(value: Any) -> datetime | None:
    return None if value is None else _time(value)


@dataclass(frozen=True)
class SettingsRow:
    mode: Mode = Mode.ENFORCE
    observable_reasons: frozenset[Reason] = OBSERVATION_CANDIDATES
    observable_policy_ids: frozenset[str] = frozenset()
    default_org_id: str | None = None
    settings_version: int | None = None
    control_key_token: str | None = None
    require_separate_confirm_key: bool = True


@dataclass(frozen=True)
class ServerRow:
    id: str
    server_id: str
    status: str
    url_sha256: str | None  # 로컬 실행(stdio) 서버는 없다
    transport: str
    auth_type: str
    basis_allowlist_ids: tuple[str, ...]
    contract_status: str = "none"
    issuer: str | None = None
    last_observed_at: datetime | None = None
    deployment_drift: bool = False
    pin_blocked: bool = False  # 고정 불일치·해제 미완료 표지(관측 모드로 풀 수 없다)
    vuln_blocked: bool = False  # 치명 취약점 조치 기한이 지난 서버(관측 모드로 풀 수 없다)
    instance_mismatch: bool = False  # 다른 인스턴스와 계약·설정이 달라 막는 서버(예외 증빙 전까지)
    approved_contracts: int | None = None  # 승인 계약 수. None은 알 수 없음(1단계 스키마)
    identity_kind: str = "remote"
    exec_contract_sha256: str | None = None
    exec_contract_version: int | None = None
    # 승인 계약의 OAuth 범위. None은 알 수 없음
    approved_oauth_scopes: tuple[str, ...] | None = None


@dataclass(frozen=True)
class AllowlistRow:
    id: str
    kind: str
    status: str
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True)
class RelationRow:
    id: str
    status: str
    purpose: str | None = None


@dataclass(frozen=True)
class ApprovalRow:
    id: str
    org_id: str
    relation_id: str
    approval_class: str
    tools: tuple[str, ...]
    scope_type: str
    scope_id: str
    valid_from: datetime
    valid_until: datetime
    conditions: Mapping[str, Any]
    status: str
    # 재확인 유예가 지나 보류됐다(운영자가 재확인할 때까지 이 승인은 쓰지 않는다).
    recert_held: bool = False
    # 신청 승인으로 만든 승인은 서버의 모든 도구(앞으로 생기는 도구 포함)에 적용한다.
    all_tools: bool = False
    requested_by: str | None = None


@dataclass(frozen=True)
class DenialRow:
    id: str
    org_id: str | None
    scope_type: str
    scope_id: str
    server_id: str | None
    tools: tuple[str, ...] | None


@dataclass(frozen=True)
class CallApprovalRow:
    id: UUID
    org_id: str
    principal_type: str
    principal_id: str
    server_id: str
    tool: str
    args_fp: str
    fp_key_version: int
    policy_version_id: str
    contract_version: str | None
    expires_at: datetime
    state_version: int
    contract_id: str | None = None
    target: str | None = None
    action: str | None = None
    exec_contract_sha256: str | None = None
    # 승인할 때 고른 사용 기간의 끝. 비어 있으면 1회 승인이다.
    valid_until: datetime | None = None
    # 기간 승인의 지금까지 사용 횟수(스냅숏 시점).
    uses: int = 0


@dataclass(frozen=True)
class ConfirmationRow:
    id: UUID
    org_id: str
    principal_id: str
    server_id: str
    tool: str
    args_fp: str
    fp_key_version: int
    policy_version_id: str
    expires_at: datetime
    state_version: int
    confirmed_by_user_id: str
    confirmed_by_key_token: str
    requested_by_key_token: str
    contract_id: str | None = None
    exec_contract_sha256: str | None = None


@dataclass(frozen=True)
class ConsentRow:
    id: str
    org_id: str
    purpose: str
    source: str
    granted_at: datetime
    valid_until: datetime
    revoked_at: datetime | None


@dataclass(frozen=True)
class PolicyVersionRow:
    id: str
    bundle_sha256: str


@dataclass(frozen=True)
class ToolContractRow:
    id: str
    credential_scope: str
    tool: str
    drift: str
    version: int
    risk_grade: str | None = None
    action_type: str | None = None
    # 계약의 입력 정의에 있는 항목 이름. 알 수 없으면 None이다.
    input_keys: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ProvisionalRow:
    """관측한 도구 목록으로 만든 임시 계약. 입력 항목이 없으면 ``input_keys``는 None(알 수 없음)."""

    action_type: str
    risk_grade: str
    input_keys: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Snapshot:
    now: datetime
    epoch: int | None
    settings: SettingsRow | None
    bindings: Mapping[tuple[SubjectType, str], str]
    org_status: Mapping[str, OrgStatus]
    server: ServerRow | None
    allowlists: Mapping[str, AllowlistRow]
    relations: Mapping[str, RelationRow]
    approvals: tuple[ApprovalRow, ...]
    denials: tuple[DenialRow, ...]
    call_approvals: tuple[CallApprovalRow, ...]
    consents: tuple[ConsentRow, ...]
    policy_version: PolicyVersionRow | None
    tool_contracts: tuple[ToolContractRow, ...] = ()
    provisional: ProvisionalRow | None = None
    negative_relation: bool = False
    self_confirmations: tuple[ConfirmationRow, ...] = ()
    # (값, 조직 또는 None): 지금 유효한 허용 목적지 목록. 패턴 계산의 허용 호스트에 쓴다.
    egress_targets: tuple[tuple[str, str | None], ...] = ()
    # 서버의 승인된 배포 계약에서 고른 대상·행위 프로필(근거가 없으면 None).
    auto_profile: str | None = None
    # 관리자가 「호출별 검토」로 지정한 이 서버의 도구(여기 있는 도구만 호출마다 승인을 받는다)
    call_review_tools: frozenset[str] = frozenset()
    # 서버의 마지막 승인된 수용 신청이 적은 자료 등급. 수용 신청 없이 등록된 서버는 None.
    data_grade: str | None = None
    # 단말 키는 설치·앱 행의 현재 팀, 그 밖의 키는 None(호출이 싣고 온 팀을 그대로 쓴다).
    effective_team: str | None = None
    has_effective_team: bool = False


def parse_snapshot(doc: Mapping[str, Any]) -> Snapshot:
    """질의 결과 JSON을 값 객체로 바꾼다."""
    settings = doc.get("settings")
    server = doc.get("server")
    policy = doc.get("policy_version")
    basis = doc.get("deployment_basis") or {}
    return Snapshot(
        now=_time(doc["now"]),
        epoch=doc.get("epoch"),
        settings=None
        if settings is None
        else SettingsRow(
            mode=Mode(settings["mode"]),
            observable_reasons=frozenset(Reason(r) for r in settings["observable_reasons"]),
            observable_policy_ids=frozenset(settings["observable_policy_ids"]),
            default_org_id=settings.get("default_org_id"),
            settings_version=settings["settings_version"],
            control_key_token=settings.get("control_key_token"),
            require_separate_confirm_key=settings.get("require_separate_confirm_key", True),
        ),
        bindings={
            (SubjectType(b["subject_type"]), b["subject_id"]): b["org_id"] for b in doc["bindings"]
        },
        org_status={o["org_id"]: OrgStatus(o["status"]) for o in doc["orgs"]},
        server=None
        if server is None
        else ServerRow(
            id=server["id"],
            server_id=server["server_id"],
            status=server["status"],
            url_sha256=server["url_sha256"],
            transport=server["transport"],
            auth_type=server["auth_type"],
            basis_allowlist_ids=tuple(server["basis_allowlist_ids"]),
            contract_status=server.get("contract_status", "none"),
            issuer=server.get("issuer"),
            last_observed_at=_maybe_time(server.get("last_observed_at")),
            deployment_drift=server.get("deployment_drift", False),
            pin_blocked="pin_reapproval" in (server.get("deployment_drift_fields") or ()),
            vuln_blocked=server.get("vuln_blocked_at") is not None,
            instance_mismatch=server.get("instance_mismatch_at") is not None,
            approved_contracts=doc.get("approved_contracts"),
            identity_kind=server.get("identity_kind", "remote"),
            exec_contract_sha256=server.get("exec_contract_sha256"),
            exec_contract_version=server.get("exec_contract_version"),
            approved_oauth_scopes=(
                None if basis.get("oauth_scopes") is None else tuple(basis["oauth_scopes"])
            ),
        ),
        allowlists={
            a["id"]: AllowlistRow(
                id=a["id"],
                kind=a["kind"],
                status=a["status"],
                valid_from=_time(a["valid_from"]),
                valid_until=_time(a["valid_until"]),
            )
            for a in doc["allowlists"]
        },
        relations={
            r["id"]: RelationRow(id=r["id"], status=r["status"], purpose=r.get("purpose"))
            for r in doc["relations"]
        },
        approvals=tuple(
            ApprovalRow(
                id=a["id"],
                org_id=a["org_id"],
                relation_id=a["relation_id"],
                approval_class=a["class"],
                tools=tuple(a["tools"]),
                scope_type=a["scope_type"],
                scope_id=a["scope_id"],
                valid_from=_time(a["valid_from"]),
                valid_until=_time(a["valid_until"]),
                conditions=a["conditions"],
                status=a["status"],
                recert_held=a.get("recert_held_at") is not None,
                all_tools=bool((a.get("basis") or {}).get("intake_id")),
                requested_by=a.get("requested_by"),
            )
            for a in doc["approvals"]
        ),
        denials=tuple(
            DenialRow(
                id=d["id"],
                org_id=d["org_id"],
                scope_type=d["scope_type"],
                scope_id=d["scope_id"],
                server_id=d["server_id"],
                tools=None if d["tools"] is None else tuple(d["tools"]),
            )
            for d in doc["denials"]
        ),
        call_approvals=tuple(
            CallApprovalRow(
                id=UUID(c["id"]),
                org_id=c["org_id"],
                principal_type=c["principal_type"],
                principal_id=c["principal_id"],
                server_id=c["server_id"],
                tool=c["tool"],
                args_fp=c["args_fp"],
                fp_key_version=c["fp_key_version"],
                policy_version_id=c["policy_version_id"],
                contract_version=c["contract_version"],
                expires_at=_time(c["expires_at"]),
                state_version=c["state_version"],
                contract_id=c.get("contract_id"),
                target=c.get("target"),
                action=c.get("action"),
                exec_contract_sha256=c.get("exec_contract_sha256"),
                valid_until=_maybe_time(c.get("valid_until")),
                uses=c.get("uses", 0),
            )
            for c in doc["call_approvals"]
        ),
        consents=tuple(
            ConsentRow(
                id=k["id"],
                org_id=k["org_id"],
                purpose=k["purpose"],
                source=k["source"],
                granted_at=_time(k["granted_at"]),
                valid_until=_time(k["valid_until"]),
                revoked_at=_maybe_time(k["revoked_at"]),
            )
            for k in doc["consents"]
        ),
        policy_version=None
        if policy is None
        else PolicyVersionRow(id=policy["id"], bundle_sha256=policy["bundle_sha256"]),
        tool_contracts=tuple(
            ToolContractRow(
                c["id"], c["credential_scope"], c["tool"], c["drift"], c["version"],
                c.get("risk_grade"), c.get("action_type"),
                None if c.get("input_keys") is None else tuple(c["input_keys"]),
            )
            for c in doc.get("tool_contracts", ())
        ),
        provisional=(
            None
            if not doc.get("provisional_contract")
            else ProvisionalRow(
                doc["provisional_contract"]["action_type"],
                doc["provisional_contract"]["risk_grade"],
                tuple(doc["provisional_contract"].get("input_keys") or ()) or None,
            )
        ),
        negative_relation=bool(doc.get("negative_relation", False)),
        self_confirmations=tuple(
            ConfirmationRow(**{
                **{k: c[k] for k in ConfirmationRow.__dataclass_fields__
                   if k not in ("contract_id", "exec_contract_sha256")},
                "id": UUID(c["id"]), "expires_at": _time(c["expires_at"]),
                "contract_id": c.get("contract_id"),
                "exec_contract_sha256": c.get("exec_contract_sha256"),
            }) for c in doc.get("self_confirmations", ())
        ),
        egress_targets=tuple((e["value"], e["org_id"]) for e in doc.get("egress_targets", [])),
        call_review_tools=frozenset(doc.get("call_review_tools") or ()),
        auto_profile=select_profile(basis.get("url"), basis.get("tools") or ()),
        data_grade=None if server is None else server.get("data_grade"),
        effective_team=doc.get("effective_team"),
        has_effective_team="effective_team" in doc,
    )


@dataclass(frozen=True)
class SnapshotQuery:
    instance_id: str
    server_id: str
    tool: str
    principal_id: str | None
    key_id: str | None
    user_id: str | None
    team_id: str | None


@dataclass(frozen=True)
class NegativeStateQuery:
    instance_id: str
    server_id: str
    tool: str
    key_id: str | None
    user_id: str | None
    team_id: str | None
    org_id: str | None
    approval_id: str | None
    relation_id: str | None


@dataclass(frozen=True)
class RegisteredServer:
    server_id: str
    status: str
    url_sha256: str | None
    transport: str
    auth_type: str
    issuer: str | None = None
    contract_status: str = "none"
    identity_kind: str = "remote"
    exec_contract_sha256: str | None = None
    exec_contract_version: int | None = None


# 이 시간(초) 넘게 쓰지 않은 연결은 쓰기 전에 확인한다. 풀의 확인 기능은 실패마다 1초 넘게
# 쉬므로 쓰지 않는다.
_IDLE_CHECK_SECONDS = 0.2


class _StaleConnection(Exception):
    pass


def _retrieve(task: asyncio.Future[Any]) -> None:
    """버려진 작업의 결과를 읽어 「처리되지 않은 예외」 경고를 막는다."""
    if not task.cancelled():
        task.exception()


def _sever(conn: Any) -> None:
    """연결의 소켓을 양방향으로 닫아 기다리던 읽기가 곧바로 실패하게 한다.

    소켓 번호는 닫지 않는다. 이벤트 루프가 그 번호를 감시하는 중에 닫으면 일부 플랫폼의 선택기가
    오류를 낸다. 서버가 응답하지 않아도 이쪽 상태만으로 읽기가 끝난다.
    """
    sock = socket.socket(fileno=conn.pgconn.socket)
    try:
        sock.shutdown(socket.SHUT_RDWR)
    finally:
        sock.detach()


# 만료까지 이만큼 남았을 때부터 보고가 키의 만료 시각을 늘린다.
RENEW_WINDOW = timedelta(days=14)


@dataclass
class PluginDatabase:
    """판정 프로세스 전용 연결. 상태 표 조회와 사건 추가, 호출별 승인 소비만 한다.

    DB가 응답하지 않아도 호출한 쪽의 시간 제한(판정 예산)에서 끝나도록 세 겹으로 건다. 한동안 쓰지
    않은 연결은 쓰기 전에 살아 있는지 확인해, 재시작된 서버가 끊은 연결이 판정에 쓰이지 않게 한다.
    서버 쪽 잠금 제한(``lock_timeout``)은 ``acquire_timeout``과 같고 문장 제한
    (``statement_timeout``)은 그 열 배(최소 1초)이며, 연결 시도에는 ``connect_timeout``을 건다.
    응답이 아예 없는 연결에는 이 제한들이 소용없으므로 호출한 쪽이 기다리기를 그만두면 연결을
    끊어 버린다(``_run``).
    """

    dsn: str
    max_size: int = 8
    acquire_timeout: float = 0.3
    _pool: Any = field(default=None, init=False, repr=False)
    # 연결 오류를 마지막으로 본 시각. 이보다 먼저 쓴 연결은 함께 끊겼을 수 있어 쓰기 전에 확인한다.
    _failed_at: float = field(default=0.0, init=False, repr=False)
    # 2단계 표(자기 확인)가 있는 데이터베이스인지. 있다고 한 번 확인되면 다시 묻지 않는다.
    _confirmations_table: bool = field(default=False, init=False, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def _connection(self):
        if self._pool is None:
            async with self._lock:
                if self._pool is None:
                    from psycopg_pool import AsyncConnectionPool, PoolTimeout

                    milliseconds = max(10, int(self.acquire_timeout * 1000))
                    # 문장은 호출한 쪽이 포기한 뒤에도 서버에서 끝까지 갈 수 있게(커밋 결과 불명)
                    # 예산의 열 배까지 두고, 잠금 대기는 예산에서 끊는다.
                    statement_ms = max(1000, milliseconds * 10)
                    # 연결은 처음부터 max_size까지 열어 둔다(축소하지 않는다). 최소 1개로 열면 몰린
                    # 요청이 새 연결을 만드는 시간이 획득 예산(0.3초)을 넘겨 판정이 차단된다.
                    pool = AsyncConnectionPool(
                        self.dsn,
                        min_size=self.max_size,
                        max_size=self.max_size,
                        kwargs={
                            "autocommit": True,
                            # libpq는 2초보다 짧은 값을 2초로 본다.
                            "connect_timeout": max(2, math.ceil(self.acquire_timeout)),
                            "options": (
                                f"-c statement_timeout={statement_ms}"
                                f" -c lock_timeout={milliseconds}"
                            ),
                        },
                        open=False,
                        timeout=self.acquire_timeout,
                    )
                    await pool.open()
                    # 첫 사용(기동 자가 점검)에서 연결이 다 찰 때까지 기다린다. 시간이 넘으면 열린
                    # 채로 두어 백그라운드가 채우게 하고, 호출은 획득 예산 안에서 차단되어 닫힌다.
                    with contextlib.suppress(PoolTimeout):
                        await pool.wait(timeout=max(2, math.ceil(self.acquire_timeout)))
                    self._pool = pool
        return self._pool.connection()

    async def close(self) -> None:
        pool, self._pool = self._pool, None
        if pool is not None:
            await pool.close()

    async def _run(self, work: Callable[[Any], Awaitable[Any]]) -> Any:
        """연결을 빌려 ``work(conn)``을 돌린다.

        호출한 쪽이 시간 초과나 취소로 기다리기를 그만두면 작업은 따로 정리한다. psycopg는 취소된
        작업이 응답 없는 연결에서 질의 취소를 5초씩 두 번 기다리므로, 작업을 취소하지 않고 연결을
        끊어 그 기다림 없이 실패하게 한다. 끊어진 연결은 풀이 버리고 새로 만든다. 연결을 아직 빌리지
        못했다면 빌리는 일을 취소한다.
        """
        from psycopg import OperationalError

        held: list[Any] = []

        async def job() -> Any:
            for _ in range(self.max_size + 1):
                try:
                    async with await self._connection() as conn:
                        # 쥔 동안에만 끊을 대상이다. 풀로 돌아간 연결은 다른 호출이 쓴다.
                        held[:] = [conn]
                        try:
                            used = getattr(conn, "_mint_used", 0.0)
                            if (
                                time.monotonic() - used > _IDLE_CHECK_SECONDS
                                or used < self._failed_at
                            ):
                                try:
                                    await conn.execute("")
                                except OperationalError:
                                    # 나가면 풀이 끊어진 연결을 버리고, 다음에는 다른 연결을 받는다.
                                    self._failed_at = time.monotonic()
                                    raise _StaleConnection from None
                            try:
                                return await work(conn)
                            except OperationalError:
                                self._failed_at = time.monotonic()
                                raise
                            finally:
                                conn._mint_used = time.monotonic()
                        finally:
                            held.clear()
                except _StaleConnection:
                    continue
            raise OperationalError("no usable database connection")

        task = asyncio.ensure_future(job())
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if held:
                with contextlib.suppress(Exception):
                    _sever(held[0])
            else:
                task.cancel()
            task.add_done_callback(_retrieve)
            raise

    async def read_snapshot(self, query: SnapshotQuery) -> Snapshot:
        params = {
            "iid": query.instance_id,
            "server_id": query.server_id,
            "tool": query.tool,
            "principal_id": query.principal_id,
            "key_id": query.key_id,
            "user_id": query.user_id,
            "team_id": query.team_id,
        }

        async def read(conn: Any) -> Any:
            # v001 DB도 읽는다. 표가 있다고 확인된 뒤에는 질의 한 번이 전부다. 상태 값 자체는 아래
            # 단일 질의의 같은 스냅숏이다.
            if not self._confirmations_table:
                probe = await conn.execute("SELECT to_regclass('mint.self_confirmations')")
                self._confirmations_table = (await probe.fetchone())[0] is not None
            cursor = await conn.execute(
                CONFIRMATION_SNAPSHOT_SQL if self._confirmations_table else SNAPSHOT_SQL, params
            )
            return await cursor.fetchone()

        row = await self._run(read)
        if row is None:
            raise RuntimeError("snapshot query returned no row")
        return parse_snapshot(row[0])

    async def insert_event(self, event: Event, consume: ConsumeRequest | None = None) -> bool:
        from psycopg.types.json import Jsonb

        row = (
            event.event_id,
            event.instance_id,
            event.inserted_at,
            event.kind.value,
            event.source_key,
            event.invocation_id,
            event.attempt_id,
            event.actor,
            None if event.subject is None else Jsonb(event.subject),
            Jsonb(event.payload),
            event.instance_id,
            event.source_key,
            event.event_id,
        )
        consumes = consume is not None and (
            consume.call_approval_id is not None or consume.confirmation is not None
        )

        async def write(conn: Any) -> bool:
            if not consumes:
                # 소비할 것이 없으면 삽입 한 문장이 곧 원자 단위다. 트랜잭션 블록을 열지 않는다.
                cursor = await conn.execute(INSERT_EVENT_SQL, row)
                return cursor.rowcount == 1
            await conn.set_isolation_level(None)
            await conn.set_read_only(False)
            async with conn.transaction():
                cursor = await conn.execute(INSERT_EVENT_SQL, row)
                inserted = cursor.rowcount == 1
                if consume is not None and consume.call_approval_id is not None:
                    cursor = await conn.execute(
                        consume_sql(consume),
                        {
                            "iid": event.instance_id,
                            "id": consume.call_approval_id,
                            "invocation_id": consume.invocation_id,
                            "principal_type": consume.principal_type,
                            "principal_id": consume.principal_id,
                            "server_id": consume.server_id,
                            "tool": consume.tool,
                            "args_fp": consume.args_fp,
                            "policy_version_id": consume.policy_version_id,
                            "state_version": consume.state_version,
                            "contract_id": consume.contract_id,
                            "target": consume.target,
                            "action": consume.action,
                            "exec_contract_sha256": consume.exec_contract_sha256,
                        },
                    )
                    if cursor.rowcount != 1:
                        raise ConsumptionLost
                if consume is not None and consume.confirmation is not None:
                    sc = consume.confirmation
                    cursor = await conn.execute(CONSUME_CONFIRMATION_SQL, {
                        "iid": event.instance_id, "id": sc.id, "org_id": sc.org_id,
                        "invocation_id": consume.invocation_id,
                        "principal_id": consume.principal_id, "server_id": consume.server_id,
                        "tool": consume.tool, "args_fp": consume.args_fp,
                        "fp_key_version": sc.fp_key_version,
                        "policy_version_id": consume.policy_version_id,
                        "state_version": sc.state_version, "contract_id": consume.contract_id,
                        "exec_contract_sha256": consume.exec_contract_sha256,
                    })
                    if cursor.rowcount != 1:
                        raise ConsumptionLost("CONFIRMATION_REQUIRED")
                if consume is not None and consume.confirmation is not None and not inserted:
                    raise ConsumptionLost(
                        "CALL_APPROVAL_REQUIRED" if consume.call_approval_id is not None
                        else "CONFIRMATION_REQUIRED"
                    )
            return inserted

        return await self._run(write)

    async def request_confirmation(self, params: Mapping[str, Any]) -> None:
        """주체별 상한 검사와 부분 UNIQUE 삽입을 직렬화한다. 표시 값은 이 표에만 쓴다."""
        from psycopg import IsolationLevel
        from psycopg.types.json import Jsonb

        async def write(conn: Any) -> None:
            await conn.set_isolation_level(IsolationLevel.READ_COMMITTED)
            await conn.set_read_only(False)
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (json.dumps([params["iid"], params["principal_id"]]),),
                )
                await conn.execute("""
                    INSERT INTO mint.self_confirmations
                        (id, instance_id, org_id, principal_id, server_id, tool, args_fp,
                         fp_key_version, policy_version_id, purpose, requested_by_key_token,
                         display, expires_at, contract_id, exec_contract_sha256)
                    SELECT %(id)s, %(iid)s::mint.ident, %(org_id)s::mint.ident, %(principal_id)s,
                           %(server_id)s,
                           %(tool)s, %(args_fp)s, %(fp_key_version)s,
                           %(policy_version_id)s::mint.ident, %(purpose)s, %(key_token)s,
                           %(display)s,
                           clock_timestamp() + interval '10 minutes', %(contract_id)s::uuid,
                           %(exec_contract_sha256)s::text
                    WHERE (SELECT count(*) FROM mint.self_confirmations
                           WHERE instance_id = %(iid)s AND principal_id = %(principal_id)s
                             AND status = 'pending' AND expires_at > clock_timestamp()) < 20
                    ON CONFLICT DO NOTHING
                """, {**params, "display": Jsonb(params.get("display") or {})})

        await self._run(write)

    async def request_call_approval(self, params: Mapping[str, Any]) -> str | None:
        """막힌 호출의 호출별 승인 요청을 연다. 같은 호출의 대기 요청이 있으면 그것을 돌려준다.

        열린 요청의 식별자(없으면 None: 주체별 대기 상한 초과). 승인은 하지 않는다.
        """
        from psycopg import IsolationLevel
        from psycopg.types.json import Jsonb

        async def write(conn: Any) -> str | None:
            await conn.set_isolation_level(IsolationLevel.READ_COMMITTED)
            await conn.set_read_only(False)
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (json.dumps([params["iid"], params["principal_id"], "call_approval"]),),
                )
                cursor = await conn.execute("""
                    SELECT id FROM mint.call_approvals
                    WHERE instance_id = %(iid)s AND principal_type = %(principal_type)s
                      AND principal_id = %(principal_id)s AND server_id = %(server_id)s
                      AND tool = %(tool)s AND args_fp = %(args_fp)s AND status = 'pending'
                      AND expires_at > clock_timestamp()
                    LIMIT 1
                """, params)
                row = await cursor.fetchone()
                if row is not None:
                    return str(row[0])
                # 맞는 상시 승인 규칙이 있으면 대기 없이 규칙이 정한 기간 승인으로 연다.
                cursor = await conn.execute("""
                    SELECT mint.open_rule_approval(
                        %(id)s::uuid, %(iid)s::mint.ident, %(org_id)s::mint.ident,
                        %(principal_type)s, %(principal_id)s, %(server_id)s, %(tool)s,
                        %(args_fp)s, %(fp_key_version)s, %(policy_version_id)s::mint.ident,
                        %(requested_by)s, %(minutes)s, %(contract_id)s::uuid,
                        %(exec_contract_sha256)s::text, %(target)s, %(action)s, %(display)s)
                """, {**params, "display": Jsonb(params.get("display") or {})})
                row = await cursor.fetchone()
                if row is not None and row[0] is not None:
                    return str(row[0])
                cursor = await conn.execute("""
                    INSERT INTO mint.call_approvals
                        (id, instance_id, org_id, principal_type, principal_id, server_id, tool,
                         args_fp, fp_key_version, policy_version_id, status, requested_by,
                         expires_at, contract_id, exec_contract_sha256, target, action, display)
                    SELECT %(id)s, %(iid)s::mint.ident, %(org_id)s::mint.ident,
                           %(principal_type)s, %(principal_id)s, %(server_id)s, %(tool)s,
                           %(args_fp)s, %(fp_key_version)s, %(policy_version_id)s::mint.ident,
                           'pending', %(requested_by)s,
                           clock_timestamp() + make_interval(mins => %(minutes)s),
                           %(contract_id)s::uuid, %(exec_contract_sha256)s::text,
                           %(target)s, %(action)s, %(display)s
                    WHERE (SELECT count(*) FROM mint.call_approvals
                           WHERE instance_id = %(iid)s AND principal_id = %(principal_id)s
                             AND status = 'pending' AND expires_at > clock_timestamp()) < 20
                    RETURNING id
                """, {**params, "display": Jsonb(params.get("display") or {})})
                row = await cursor.fetchone()
                return None if row is None else str(row[0])

        return await self._run(write)

    async def call_approval_status(self, instance_id: str, call_id: str) -> str | None:
        """호출별 승인 요청의 현재 상태. 없거나 기한이 지났으면 None. 승인 대기 보류가 읽는다."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT status FROM mint.call_approvals WHERE instance_id = %s AND id = %s"
                " AND (status <> 'pending' OR expires_at > clock_timestamp())",
                (instance_id, call_id),
            )
            return await cursor.fetchone()

        row = await self._run(read)
        return None if row is None else str(row[0])

    async def mark_call_hold_timeout(self, instance_id: str, call_id: str) -> None:
        """승인 대기가 시간 초과로 끝나 호출자가 응답받았음을 요청에 남긴다(요청은 대기로 둔다)."""

        async def write(conn: Any) -> None:
            await conn.set_read_only(False)
            async with conn.transaction():
                await conn.execute(
                    "UPDATE mint.call_approvals SET hold_timed_out_at = clock_timestamp()"
                    " WHERE instance_id = %s AND id = %s AND status = 'pending'",
                    (instance_id, call_id),
                )

        await self._run(write)

    async def confirmation_status(
        self, instance_id: str, wait: tuple[str, str, str, str]
    ) -> str | None:
        """같은 호출(주체·서버·도구·인자 지문)의 본인 확인 요청 상태. 본인 확인 보류가 읽는다.

        기한 안의 대기·확인 요청이 있으면 그 상태를, 아니면 가장 최근에 거절·취소된 상태를 돌려준다.
        소비된 것은 이 호출의 몫이 아니므로 보지 않는다. 없으면 None.
        """
        principal_id, server_id, tool, args_fp = wait

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT status FROM mint.self_confirmations"
                " WHERE instance_id = %s AND principal_id = %s AND server_id = %s AND tool = %s"
                " AND args_fp = %s AND status <> 'consumed' AND expires_at > clock_timestamp()"
                " ORDER BY created_at DESC LIMIT 1",
                (instance_id, principal_id, server_id, tool, args_fp),
            )
            return await cursor.fetchone()

        row = await self._run(read)
        return None if row is None else str(row[0])

    async def recent_call_outcome(self, params: Mapping[str, Any]) -> tuple[str, str | None] | None:
        """같은 호출(주체·서버·도구·인자 지문)의 가장 최근 거부·만료 결과. 없으면 None.

        ``minutes`` 안에 거부됐으면 ``("rejected", 사유)``, 승인이 쓰이지 않고 끝났으면
        ``("expired", None)``이다. 행은 시간이 지나면 조회에서 빠지므로 거부가 쌓이지 않는다.
        """

        async def read(conn: Any) -> Any:
            cursor = await conn.execute("""
                SELECT outcome, reason FROM (
                    SELECT CASE WHEN status = 'rejected' THEN 'rejected' ELSE 'expired' END
                               AS outcome,
                           decision_reason AS reason,
                           CASE WHEN status = 'rejected' THEN coalesce(decided_at, expires_at)
                                ELSE coalesce(valid_until, expires_at) END AS at
                    FROM mint.call_approvals
                    WHERE instance_id = %(iid)s AND principal_type = %(principal_type)s
                      AND principal_id = %(principal_id)s AND server_id = %(server_id)s
                      AND tool = %(tool)s AND args_fp = %(args_fp)s
                      AND fp_key_version = %(fp_key_version)s
                      AND (status IN ('rejected', 'expired')
                           OR (status = 'approved'
                               AND coalesce(valid_until, expires_at) <= clock_timestamp()))
                ) t
                WHERE at > clock_timestamp() - make_interval(mins => %(minutes)s)
                ORDER BY at DESC LIMIT 1
            """, params)
            return await cursor.fetchone()

        row = await self._run(read)
        return None if row is None else (row[0], row[1])

    async def call_approval_outcomes(
        self, instance_id: str, user_id: str, since: datetime | None
    ) -> tuple[str, list[dict[str, Any]]]:
        """사용자 본인의 호출별 승인 중 ``since`` 뒤에 사람이 승인·거부한 것(최근 하루, 최대 20건).

        돌려주는 값은 다음 조회에 쓸 커서(데이터베이스 시각)와 목록이다. ``since``가 없으면 목록은
        비어 있다. 규칙이 자동으로 연 승인은 알릴 일이 아니므로 뺀다.
        """

        async def read(conn: Any) -> Any:
            cursor = await conn.execute("SELECT clock_timestamp()")
            now = (await cursor.fetchone())[0]
            if since is None:
                return now, []
            cursor = await conn.execute(
                "SELECT server_id, tool, CASE WHEN status = 'rejected' THEN 'rejected'"
                " ELSE 'approved' END, decision_reason, decided_at FROM mint.call_approvals"
                " WHERE instance_id = %s AND principal_type = 'user' AND principal_id = %s"
                " AND status IN ('approved', 'consumed', 'rejected')"
                " AND decided_at > %s AND decided_at > clock_timestamp() - interval '1 day'"
                " AND coalesce(approved_by, '') NOT LIKE 'rule:%%'"
                " ORDER BY decided_at LIMIT 20",
                (instance_id, user_id, since),
            )
            return now, await cursor.fetchall()

        now, rows = await self._run(read)
        return now.isoformat(), [
            {"server": r[0], "tool": r[1], "outcome": r[2], "reason": r[3],
             "at": r[4].isoformat()}
            for r in rows
        ]

    async def read_decision(
        self, instance_id: str, invocation_id: UUID, attempt_id: int
    ) -> dict[str, Any] | None:
        """호출의 판정 사건 본문. 없으면 None. 결과 보고가 호출 컨텍스트를 다시 만들 때 읽는다."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT payload FROM mint.events WHERE instance_id = %s"
                " AND kind = 'decision_evaluated' AND invocation_id = %s AND attempt_id = %s",
                (instance_id, invocation_id, attempt_id),
            )
            return await cursor.fetchone()

        row = await self._run(read)
        return None if row is None else row[0]

    async def report_install(
        self,
        instance_id: str,
        key_token: str,
        *,
        mode: str,
        kit_version: str,
        claude_version: str | None,
        mcp_servers: Sequence[str],
        processes: Sequence[dict[str, Any]] | None = None,
        autostart: Sequence[dict[str, Any]] | None = None,
        outside_processes: Sequence[dict[str, Any]] | None = None,
        removed: Sequence[dict[str, Any]] | None = None,
        local_mcp: Sequence[dict[str, Any]] | None = None,
        tool_lists: Sequence[dict[str, Any]] | None = None,
        hook_trust: str | None = None,
        update_error: str | None = None,
        host: str | None = None,
        os: str | None = None,
        ai_clients: Sequence[dict[str, Any]] | None = None,
        plaintext_keys: Sequence[dict[str, Any]] | None = None,
        scan_errors: Sequence[str] | None = None,
        offline_calls: Sequence[dict[str, Any]] | None = None,
        paused_ack: int | None = None,
    ) -> str:
        """설치 묶음에 발급한 키의 설치 상태 보고를 남기고 결과를 돌려준다.

        ``unknown``: 해제되었거나 발급하지 않은 키. ``expired``: 만료된 키(아무것도 남기지 않는다).
        ``renewed``: 기록하고 만료 시각을 ``ttl_days``만큼 늘렸다(만료 14일 안).
        ``recorded``: 기록만 했다.
        """
        from psycopg.types.json import Jsonb

        async def write(conn: Any) -> Any:
            async with conn.transaction():
                cursor = await conn.execute(
                    "SELECT expires_at IS NOT NULL AND expires_at <= clock_timestamp(),"
                    " expires_at IS NOT NULL AND expires_at <= clock_timestamp() + %s,"
                    " user_id, key_alias, local_mcp, offline_calls"
                    " FROM mint.endpoint_installs WHERE instance_id = %s AND key_token = %s"
                    " AND revoked_at IS NULL FOR UPDATE",
                    (RENEW_WINDOW, instance_id, key_token),
                )
                row = await cursor.fetchone()
                if row is None:
                    return "unknown"
                if row[0]:
                    return "expired"
                # 보고에 로컬 MCP 목록이 없으면(이전 묶음·SYSTEM 보고기) 앞서 보고한 목록을 둔다.
                seen = row[4] if local_mcp is None else merge_local_mcp(
                    local_mcp, row[4], datetime.now(UTC).isoformat()
                )
                kept_calls = merge_offline_calls(row[5], offline_calls)
                await conn.execute(
                    "UPDATE mint.endpoint_installs SET install_mode = %s, kit_version = %s,"
                    " claude_version = %s, mcp_servers = %s, processes = %s, autostart = %s,"
                    " local_mcp = %s, outside_processes = %s, hook_trust = %s,"
                    " update_error = %s, host = coalesce(%s, host), os = coalesce(%s, os),"
                    " ai_clients = coalesce(%s, ai_clients),"
                    " plaintext_keys = coalesce(%s, plaintext_keys),"
                    " scan_errors = coalesce(%s, scan_errors), offline_calls = %s,"
                    " paused_ack = coalesce(%s::int, paused_ack),"
                    " paused_ack_at = CASE WHEN %s::int IS NULL THEN paused_ack_at"
                    " ELSE clock_timestamp() END,"
                    " reported_at = clock_timestamp(), expires_at = CASE WHEN %s"
                    " THEN clock_timestamp() + make_interval(days => ttl_days) ELSE expires_at END"
                    " WHERE instance_id = %s AND key_token = %s",
                    (mode, kit_version, claude_version, Jsonb(list(mcp_servers)),
                     None if processes is None else Jsonb(list(processes)),
                     None if autostart is None else Jsonb(list(autostart)),
                     None if seen is None else Jsonb(list(seen)),
                     None if outside_processes is None else Jsonb(list(outside_processes)),
                     hook_trust, update_error, host, os,
                     None if ai_clients is None else Jsonb(list(ai_clients)),
                     None if plaintext_keys is None else Jsonb(list(plaintext_keys)),
                     None if scan_errors is None else Jsonb(list(scan_errors)),
                     None if kept_calls is None else Jsonb(kept_calls),
                     paused_ack, paused_ack, row[1], instance_id, key_token),
                )
                for item in tool_lists or ():
                    await conn.execute(
                        "INSERT INTO mint.endpoint_tool_lists (instance_id, server_id, key_token,"
                        " tools, tools_sha256, truncated) VALUES (%s, %s, %s, %s, %s, %s)"
                        " ON CONFLICT (instance_id, server_id, key_token) DO UPDATE SET"
                        " tools = EXCLUDED.tools, tools_sha256 = EXCLUDED.tools_sha256,"
                        " truncated = EXCLUDED.truncated, reported_at = clock_timestamp()"
                        " WHERE mint.endpoint_tool_lists.tools_sha256 <> EXCLUDED.tools_sha256",
                        (instance_id, item["server"], key_token, Jsonb(item["tools"]),
                         sha256(item["tools"]), item["truncated"]),
                    )
                return ("renewed" if row[1] else "recorded", row[2], row[3])

        outcome = await self._run(write)
        if isinstance(outcome, str):
            return outcome
        status, user_id, key_alias = outcome
        # 지웠다는 보고는 항목마다 사건으로 남긴다(단말의 주장이다). 같은 보고는 한 번만 남는다.
        for event in remediation_events(
            instance_id, user_id=user_id, key_alias=key_alias, removed=removed or (),
            at=datetime.now(UTC),
        ):
            await self.insert_event(event)
        for event in offline_call_events(
            instance_id, user_id=user_id, key_alias=key_alias, calls=offline_calls or (),
            at=datetime.now(UTC),
        ):
            await self.insert_event(event)
        return str(status)

    async def endpoint_paused(self, instance_id: str, key_token: str) -> bool:
        """설치 키가 관리자에 의해 연결 중지 상태인가."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT paused_at IS NOT NULL FROM mint.endpoint_installs"
                " WHERE instance_id = %s AND key_token = %s AND revoked_at IS NULL",
                (instance_id, key_token),
            )
            return await cursor.fetchone()

        row = await self._run(read)
        return bool(row and row[0])

    async def endpoint_control(
        self, instance_id: str, key_token: str, clients: bool = False
    ) -> dict[str, Any]:
        """보고 응답에 싣는 관리자 지시: 중지 여부·세대, 연결 복구 요청(한 번만), 제외한 서버,
        직원이 동의하고 올린 신청 요청(아직 보내지 않은 것, 보낸 뒤 표시). 연결 복구와 신청 요청은
        사용자 권한 보고기(``clients``)에만 싣고 그때만 보냄 처리한다."""

        async def run(conn: Any) -> Any:
            async with conn.transaction():
                cursor = await conn.execute(
                    "SELECT user_id, reconnect_requested, paused_at IS NOT NULL, pause_gen"
                    " FROM mint.endpoint_installs WHERE instance_id = %s AND key_token = %s"
                    " AND revoked_at IS NULL FOR UPDATE",
                    (instance_id, key_token),
                )
                row = await cursor.fetchone()
                if row is None:
                    return None
                user_id = row[0]
                reconnect = bool(row[1]) and clients
                if reconnect:
                    await conn.execute(
                        "UPDATE mint.endpoint_installs SET reconnect_requested = false"
                        " WHERE instance_id = %s AND key_token = %s",
                        (instance_id, key_token),
                    )
                cursor = await conn.execute(
                    "SELECT server_name FROM mint.endpoint_ignored_servers"
                    " WHERE instance_id = %s AND user_id = %s ORDER BY server_name LIMIT 256",
                    (instance_id, user_id),
                )
                ignored = [r[0] for r in await cursor.fetchall()]
                found = {"paused": row[2], "pause_gen": row[3], "ignored": ignored}
                cursor = await conn.execute(  # 웹으로 낸 신청을 기다리는 중이면 짧은 주기로
                    "SELECT mint.endpoint_user_awaiting(%s, %s)", (instance_id, key_token))
                if (await cursor.fetchone())[0]:
                    found["awaiting"] = True
                if clients:
                    cursor = await conn.execute(
                        "UPDATE mint.endpoint_intake_requests SET sent_at = clock_timestamp()"
                        " WHERE instance_id = %s AND user_id = %s AND sent_at IS NULL"
                        " RETURNING server_name, purpose",
                        (instance_id, user_id),
                    )
                    found["reconnect"] = reconnect
                    found["intake_requests"] = [
                        {"name": r[0], "purpose": r[1]} for r in await cursor.fetchall()
                    ]
                return found

        found = await self._run(run)
        if found is None:
            raise LookupError("no such kit key")
        return found

    async def record_delivery(
        self, instance_id: str, key_token: str, stage: str, servers: Sequence[str],
        versions: Mapping[str, int] | None = None, reasons: Mapping[str, str] | None = None,
    ) -> None:
        """단말이 알린 적용 단계를 그 키 범위 승인 신청의 결정 버전에 남긴다.

        단말이 받은 버전(서버 이름 -> 버전)이 있으면 그 버전에, 없으면 최신 버전에 남긴다."""
        if not servers:
            return
        pinned = json.dumps({n: int(v) for n, v in (versions or {}).items() if n in servers})
        why = json.dumps({n: str(v)[:80] for n, v in (reasons or {}).items() if n in servers})

        async def write(conn: Any) -> None:
            await conn.execute(
                "SELECT mint.endpoint_record_delivery(%s, %s, %s, %s, %s::jsonb, %s::jsonb)",
                (instance_id, key_token, stage, list(servers), pinned, why),
            )

        await self._run(write)

    async def endpoint_scope(self, instance_id: str, key_token: str) -> list[dict[str, Any]]:
        """이 설치 키의 범위에 닿는 묶음 서버(DB 함수가 키·범위를 판정한다)."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT server_id, pack_sha256, pack_manifest, exec_contract, permit_until"
                " FROM mint.endpoint_scope(%s, %s)",
                (instance_id, key_token),
            )
            return await cursor.fetchall()

        keys = ("server_id", "pack_sha256", "pack_manifest", "exec_contract", "permit_until")
        return [dict(zip(keys, row, strict=True)) for row in await self._run(read)]

    async def endpoint_my_intakes(self, instance_id: str, key_token: str) -> list[dict[str, Any]]:
        """이 설치 키로 낸 신청 최근 20건."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT id, server_id, status, decision, reason, created_at,"
                " check_name, reason_code, pack_ready"
                " FROM mint.endpoint_my_intakes(%s, %s) ORDER BY created_at DESC LIMIT 20",
                (instance_id, key_token),
            )
            return await cursor.fetchall()

        keys = ("id", "server_id", "status", "decision", "reason", "created_at",
                "check_name", "reason_code", "pack_ready")
        return [dict(zip(keys, row, strict=True)) for row in await self._run(read)]

    async def endpoint_submit_intake(
        self, key_token: str, request_id: UUID, payload: Mapping[str, Any]
    ) -> UUID:
        """단말 신청 접수. 충돌·한도·형식은 DB 함수가 예외로 알린다."""
        from psycopg.types.json import Jsonb

        async def write(conn: Any) -> Any:
            async with conn.transaction():
                cursor = await conn.execute(
                    "SELECT mint.endpoint_submit_intake(%s, %s, %s)",
                    (key_token, request_id, Jsonb(dict(payload))),
                )
                return (await cursor.fetchone())[0]

        return await self._run(write)  # type: ignore[no-any-return]

    async def endpoint_submit_remote_intake(
        self, key_token: str, request_id: UUID, payload: Mapping[str, Any]
    ) -> UUID:
        """단말 키로 올리는 원격 서버 신청 접수(직원 신청과 같은 신청을 만든다)."""
        from psycopg.types.json import Jsonb

        async def write(conn: Any) -> Any:
            async with conn.transaction():
                cursor = await conn.execute(
                    "SELECT mint.endpoint_submit_remote_intake(%s, %s, %s)",
                    (key_token, request_id, Jsonb(dict(payload))),
                )
                return (await cursor.fetchone())[0]

        return await self._run(write)  # type: ignore[no-any-return]

    async def endpoint_apps_list(self, instance_id: str, key_token: str) -> list[dict[str, Any]]:
        """이 설치 키 주인의 앱 목록(최근 순). 키 값은 없다."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT a.id, a.name, a.key_alias, a.created_at, a.expires_at, a.revoked_at"
                " FROM mint.endpoint_installs i JOIN mint.endpoint_apps a"
                " ON a.instance_id = i.instance_id AND a.user_id = i.user_id"
                " WHERE i.instance_id = %s AND i.key_token = %s AND i.revoked_at IS NULL"
                " ORDER BY a.created_at DESC LIMIT 50",
                (instance_id, key_token),
            )
            return await cursor.fetchall()

        keys = ("id", "name", "key_alias", "created_at", "expires_at", "revoked_at")
        return [dict(zip(keys, row, strict=True)) for row in await self._run(read)]

    async def endpoint_app_create(
        self, instance_id: str, key_token: str, name: str, days: int, issuer: Any
    ) -> dict[str, Any]:
        """앱 키를 만들고 기록한다(같은 사람의 발급은 한 번에 하나). 키 값은 돌려주기만 한다.

        ``issuer``는 ``generate_app_key``·``delete_kit_keys``를 가진 LiteLLM 클라이언트(블로킹이라
        스레드에서 부른다). 거절은 ``AppRefused``이다.
        """
        import secrets
        from hashlib import sha256 as digest

        from psycopg.rows import dict_row

        from mint_litellm.control import kit_key_sync
        from mint_litellm.control.litellm_write import APP_ALIAS_PREFIX
        from mint_litellm.endpoint.apps import ACTOR, MAX_ACTIVE_APPS, AppRefused

        async def write(conn: Any) -> dict[str, Any]:
            cursor = await conn.execute(
                "SELECT user_id, team_id FROM mint.endpoint_installs"
                " WHERE instance_id = %s AND key_token = %s AND revoked_at IS NULL",
                (instance_id, key_token),
            )
            install = await cursor.fetchone()
            if install is None:
                raise AppRefused(404, "no such kit key")
            user_id, team_id = install
            async with conn.transaction():
                await conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))",
                    (f"endpoint-app:{instance_id}:{user_id}",),
                )
                cursor = await conn.execute(
                    "SELECT name FROM mint.endpoint_apps WHERE instance_id = %s AND user_id = %s"
                    " AND revoked_at IS NULL AND expires_at > now()",
                    (instance_id, user_id),
                )
                names = [row[0] for row in await cursor.fetchall()]
                if name in names:
                    raise AppRefused(409, "같은 이름의 앱이 이미 있습니다.")
                if len(names) >= MAX_ACTIVE_APPS:
                    raise AppRefused(409, "앱은 한 사람당 10개까지 만들 수 있습니다.")
                async with conn.cursor(row_factory=dict_row) as rows:
                    await rows.execute(
                        kit_key_sync.APPLICABLE_SQL,
                        kit_key_sync.applicable_params(instance_id, user_id, team_id, ""),
                    )
                    servers, tools = kit_key_sync.fold_permission(await rows.fetchall())
                alias = f"{APP_ALIAS_PREFIX}{name}-{secrets.token_hex(3)}"
                key = await asyncio.to_thread(
                    issuer.generate_app_key, user_id=user_id, team_id=team_id, alias=alias,
                    name=name, days=days,
                    permission={"mcp_servers": servers, "mcp_tool_permissions": tools},
                )
                try:
                    cursor = await conn.execute(
                        "INSERT INTO mint.endpoint_apps (instance_id, user_id, team_id,"
                        " install_key_token, name, key_alias, key_token, expires_at)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s,"
                        " clock_timestamp() + make_interval(days => %s))"
                        " RETURNING id, expires_at",
                        (instance_id, user_id, team_id, key_token, name, alias,
                         digest(key.encode()).hexdigest(), days),
                    )
                    made = await cursor.fetchone()
                except BaseException:
                    await asyncio.to_thread(issuer.delete_kit_keys, [alias])
                    raise
            return {"id": str(made[0]), "name": name, "key": key, "key_alias": alias,
                    "expires_at": made[1], "servers": servers, "user_id": user_id}

        made = await self._run(write)
        await self.insert_event(Event(
            instance_id=instance_id, inserted_at=datetime.now(UTC),
            kind=EventKind.ENDPOINT_APP_CREATED,
            source_key=control_source_key(EventKind.ENDPOINT_APP_CREATED, made["id"], 1),
            actor=ACTOR,
            subject={"user_id": made["user_id"], "key_alias": made["key_alias"]},
            payload={"app": name, "user_id": made["user_id"], "days": days,
                     "servers": made["servers"]},
        ))
        return made  # type: ignore[no-any-return]

    async def endpoint_app_revoke(
        self, instance_id: str, key_token: str, app_id: UUID, issuer: Any
    ) -> bool:
        """설치 키 주인의 앱 하나를 회수한다. 주인의 앱이 아니면 거짓, 이미 회수됐어도 참(멱등)."""
        from mint_litellm.endpoint.apps import ACTOR

        async def find(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT a.name, a.key_alias, a.user_id, a.revoked_at IS NOT NULL"
                " FROM mint.endpoint_installs i JOIN mint.endpoint_apps a"
                " ON a.instance_id = i.instance_id AND a.user_id = i.user_id"
                " WHERE i.instance_id = %s AND i.key_token = %s AND i.revoked_at IS NULL"
                " AND a.id = %s",
                (instance_id, key_token, app_id),
            )
            return await cursor.fetchone()

        row = await self._run(find)
        if row is None:
            return False
        name, alias, user_id, done = row
        if done:
            return True
        await asyncio.to_thread(issuer.delete_kit_keys, [alias])

        async def mark(conn: Any) -> Any:
            cursor = await conn.execute(
                "UPDATE mint.endpoint_apps SET revoked_at = clock_timestamp(), revoked_by = %s"
                " WHERE instance_id = %s AND id = %s AND revoked_at IS NULL",
                (user_id, instance_id, app_id),
            )
            return cursor.rowcount

        if await self._run(mark):
            await self.insert_event(Event(
                instance_id=instance_id, inserted_at=datetime.now(UTC),
                kind=EventKind.ENDPOINT_APP_REVOKED,
                source_key=control_source_key(EventKind.ENDPOINT_APP_REVOKED, str(app_id), 2),
                actor=ACTOR, subject={"user_id": user_id, "key_alias": alias},
                payload={"app": name, "user_id": user_id},
            ))
        return True

    async def retire_install(
        self, instance_id: str, key_token: str, issuer: Any, successor: str | None = None
    ) -> bool:
        """설치 묶음이 제거·재설치를 알린 PC 한 대의 키만 해제한다(같은 사람의 다른 PC는 그대로).

        LiteLLM 키(설치·게이트웨이·이 PC의 앱)를 먼저 지우고 MINT 기록을 해제한다. 지우지 못하면
        해제하지 않는다(키가 살아 있는데 해제된 것처럼 보이지 않게). 재설치(``successor``가 같은
        사람의 활성 설치 키)이면 이 PC의 앱 자격은 지우지 않고 새 키로 옮긴다. 해제했으면 참."""
        from mint_litellm.endpoint.apps import ACTOR

        async def find(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT i.user_id, i.key_alias, i.mcp_key_alias, coalesce(array_agg(a.key_alias)"
                " FILTER (WHERE a.key_alias IS NOT NULL), '{}')"
                " FROM mint.endpoint_installs i LEFT JOIN mint.endpoint_apps a"
                " ON a.instance_id = i.instance_id AND a.install_key_token = i.key_token"
                " AND a.revoked_at IS NULL"
                " WHERE i.instance_id = %s AND i.key_token = %s AND i.revoked_at IS NULL"
                " GROUP BY i.user_id, i.key_alias, i.mcp_key_alias",
                (instance_id, key_token),
            )
            return await cursor.fetchone()

        row = await self._run(find)
        if row is None or issuer is None:
            return False
        user_id, alias, mcp_alias, apps = row

        async def heir(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT 1 FROM mint.endpoint_installs WHERE instance_id = %s AND key_token = %s"
                " AND user_id = %s AND revoked_at IS NULL", (instance_id, successor, user_id))
            return await cursor.fetchone()

        moved = bool(successor and successor != key_token and await self._run(heir))
        doomed = [alias, mcp_alias, *([] if moved else apps)]
        await asyncio.to_thread(issuer.delete_kit_keys, [a for a in doomed if a])

        async def retire(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT mint.endpoint_retire_install(%s, %s, %s)",
                (instance_id, key_token, successor if moved else None))
            return (await cursor.fetchone())[0]

        if not await self._run(retire):
            return False
        await self.insert_event(Event(
            instance_id=instance_id, inserted_at=datetime.now(UTC),
            kind=EventKind.ENDPOINT_REVOKED,
            source_key=control_source_key(EventKind.ENDPOINT_REVOKED, key_token, 2),
            actor=ACTOR, subject={"user_id": user_id, "key_alias": alias},
            payload={"user_id": user_id, "installs": 1, "key_alias": alias,
                     "reason": "PC에서 제거·재설치"},
        ))
        return True

    async def endpoint_inspections(self, instance_id: str, key_token: str) -> list[dict[str, Any]]:
        """이 설치 키에 유효한(발급·소비) 검사용 승인."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT id, intake_id, server_id, pack_sha256, contract, expires_at"
                " FROM mint.endpoint_inspections_list(%s, %s)", (instance_id, key_token))
            return await cursor.fetchall()

        keys = ("id", "intake_id", "server_id", "pack_sha256", "contract", "expires_at")
        return [dict(zip(keys, row, strict=True)) for row in await self._run(read)]

    async def endpoint_inspection_start(
        self, instance_id: str, key_token: str, inspection_id: UUID
    ) -> None:
        """실행권을 한 번 소비한다. 없음·충돌은 DB 함수가 예외로 알린다."""

        async def write(conn: Any) -> Any:
            async with conn.transaction():
                await conn.execute("SELECT mint.endpoint_inspection_start(%s, %s, %s)",
                                   (instance_id, key_token, inspection_id))

        await self._run(write)

    async def endpoint_inspection_submit(
        self, instance_id: str, key_token: str, inspection_id: UUID, body: Mapping[str, Any]
    ) -> None:
        """검사 결과를 기록한다(처리는 작업이 한다). 같은 본문은 멱등이다."""
        from psycopg.types.json import Jsonb

        async def write(conn: Any) -> Any:
            async with conn.transaction():
                await conn.execute("SELECT mint.endpoint_inspection_submit(%s, %s, %s, %s)",
                                   (instance_id, key_token, inspection_id, Jsonb(dict(body))))

        await self._run(write)

    async def endpoint_inspection_pack(
        self, instance_id: str, key_token: str, server_id: str, pack_sha256: str
    ) -> dict[str, Any] | None:
        """이 키·이 묶음의 유효한 검사용 승인이 가리키는 후보 묶음(없으면 None)."""

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT server_id, pack_sha256, pack_manifest"
                " FROM mint.endpoint_inspection_pack(%s, %s, %s, %s)",
                (instance_id, key_token, server_id, pack_sha256))
            return await cursor.fetchone()

        row = await self._run(read)
        return None if row is None else dict(
            zip(("server_id", "pack_sha256", "pack_manifest"), row, strict=True))

    async def desired_servers(self, instance_id: str, key_token: str) -> list[dict[str, Any]]:
        """설치 보고 응답에 실을 승인된 로컬 서버 목록(이름·계약·판본). 이 키의 범위에 닿는 것만."""
        scope = await self.endpoint_scope(instance_id, key_token)

        async def legacy(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT server_id FROM mint.endpoint_legacy_network(%s, %s)",
                (instance_id, key_token),
            )
            return await cursor.fetchall()

        old = {name for (name,) in await self._run(legacy)} if scope else set()
        scope = [  # 이전 신청의 network none은 직원이 정한 값이 아니다(열린 네트워크로 내려준다)
            {**r, "exec_contract": without_network(r["exec_contract"])}
            if r["server_id"] in old else r
            for r in scope
        ]
        items = scoped_desired(scope)

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT server_id, decision_version"
                " FROM mint.endpoint_decision_versions(%s, %s, %s)",
                (instance_id, key_token, [i["name"] for i in items]),
            )
            return await cursor.fetchall()

        if items:
            versions = {name: int(v) for name, v in await self._run(read)}
            for item in items:
                if item["name"] in versions:
                    item["decision_version"] = versions[item["name"]]
        return items

    async def revoke_servers(
        self, instance_id: str, reported: Sequence[str], desired: Sequence[str]
    ) -> list[str]:
        """단말이 보고한 승인 서버 중 이 키의 범위에 없는 이름."""
        rows = await self.registered_servers(instance_id)
        return revoke_names({r.server_id: r.status for r in rows if r.identity_kind == "stdio"},
                            reported, desired)

    async def retired_servers(self, instance_id: str, reported: Sequence[str]) -> list[str]:
        """설치 보고 응답에 실을 폐기·미승인 로컬 서버 이름."""
        rows = await self.registered_servers(instance_id)
        statuses = {r.server_id: r.status for r in rows if r.identity_kind == "stdio"}
        return retired_names(statuses, reported)

    async def read_epoch(self, instance_id: str) -> int | None:
        async def read(conn: Any) -> Any:
            cursor = await conn.execute(
                "SELECT epoch FROM mint.state_epoch WHERE instance_id = %s", (instance_id,)
            )
            return await cursor.fetchone()

        row = await self._run(read)
        return None if row is None else row[0]

    async def has_negative_state(self, query: NegativeStateQuery) -> bool:
        params = {
            "iid": query.instance_id,
            "server_id": query.server_id,
            "tool": query.tool,
            "key_id": query.key_id,
            "user_id": query.user_id,
            "team_id": query.team_id,
            "org_id": query.org_id,
            "approval_id": query.approval_id,
            "relation_id": query.relation_id,
        }

        async def read(conn: Any) -> Any:
            cursor = await conn.execute(NEGATIVE_STATE_SQL, params)
            return await cursor.fetchone()

        row = await self._run(read)
        return bool(row and row[0])

    async def registered_servers(self, instance_id: str) -> Sequence[RegisteredServer]:
        async def read(conn: Any) -> Any:
            probe = await conn.execute("SELECT to_regclass('mint.tool_contracts')")
            stage2 = (await probe.fetchone())[0] is not None
            columns = (
                "issuer, contract_status, identity_kind, exec_contract_sha256,"
                " exec_contract_version"
                if stage2 else "NULL, 'none', 'remote', NULL, NULL"
            )
            cursor = await conn.execute(
                "SELECT server_id, status, url_sha256, transport, auth_type, " + columns +
                " FROM mint.servers WHERE instance_id = %s ORDER BY server_id",
                (instance_id,),
            )
            return await cursor.fetchall()

        rows = await self._run(read)
        return [RegisteredServer(*row) for row in rows]

    async def contract_tools(self, instance_id: str) -> dict[str, tuple[str, ...]]:
        """관리 중인 서버별 계약 도구 이름. 승인·드리프트·폐기 후보를 가리지 않는다."""

        async def read(conn: Any) -> Any:
            probe = await conn.execute("SELECT to_regclass('mint.tool_contracts')")
            if (await probe.fetchone())[0] is None:
                return []
            cursor = await conn.execute(
                "SELECT t.server_id, t.tool FROM mint.tool_contracts t"
                " JOIN mint.servers s ON s.instance_id = t.instance_id"
                " AND s.server_id = t.server_id AND s.contract_status = 'managed'"
                " WHERE t.instance_id = %s GROUP BY t.server_id, t.tool"
                " ORDER BY t.server_id, t.tool",
                (instance_id,),
            )
            return await cursor.fetchall()

        found: dict[str, list[str]] = {}
        for server_id, tool in await self._run(read):
            found.setdefault(server_id, []).append(tool)
        return {server_id: tuple(tools) for server_id, tools in found.items()}
