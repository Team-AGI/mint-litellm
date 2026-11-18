"""Opt-in confirmation reuse for exact, approved low-risk URL reads.

Evidence is an immutable allow event where both initial checks were consumed.
Old events without the scope marker cannot acquire reusable authority retroactively.
"""
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

FLAG = "reuse_read_confirmations"
NOTICE = "동일 읽기 요청의 확인 기록을 사용 승인 만료까지 재사용(최대 30일)"

# Used both in the single-snapshot read and in the evidence-write transaction.
# No arguments, URL strings or raw credentials are stored in the new evidence.
# OFFSET 0 keeps point-check subqueries from becoming one large join search;
# even disabled scopes otherwise pay that planning cost on concurrent requests.
PROOFS_SQL = """
SELECT e.event_id::text, a.id::text AS approval_id, c.id::text AS call_id,
       sc.id::text AS confirmation_id, c.org_id, c.principal_id, c.server_id, c.tool,
       c.args_fp, c.fp_key_version, c.policy_version_id, c.contract_id::text,
       sc.requested_by_key_token AS key_id,
       least(a.valid_until, e.inserted_at + interval '30 days',
             coalesce(c.valid_until, a.valid_until)) AS expires_at
FROM mint.call_approvals c
JOIN mint.self_confirmations sc ON sc.instance_id = c.instance_id
  AND sc.consumed_invocation_id IS NOT NULL
  AND sc.org_id = c.org_id AND sc.principal_id = c.principal_id
  AND sc.server_id = c.server_id AND sc.tool = c.tool AND sc.args_fp = c.args_fp
  AND sc.contract_id = c.contract_id AND sc.policy_version_id = c.policy_version_id
  AND sc.fp_key_version = c.fp_key_version
JOIN mint.events e ON e.instance_id = c.instance_id
  AND e.invocation_id = sc.consumed_invocation_id
  AND e.kind = 'decision_evaluated' AND e.payload->>'enforced_action' = 'allow'
  AND e.payload->>'consumed_call_approval_id' = c.id::text
  AND e.payload->>'read_reconfirmation_proof_event_id' IS NULL
JOIN mint.approvals a ON a.instance_id = c.instance_id
  AND a.id::text = e.payload->>'read_reconfirmation_scope'
  AND a.id::text = e.payload->>'selected_approval_id'
WHERE c.instance_id = %(iid)s AND c.principal_type = 'user'
  AND c.principal_id = %(user_id)s AND c.server_id = %(server_id)s AND c.tool = %(tool)s
  AND sc.status = 'consumed' AND sc.confirmed_by_user_id = c.principal_id
  AND sc.requested_by_key_token = %(key_id)s
  AND e.payload->'principal'->>'key_id' = %(key_id)s
  AND sc.exec_contract_sha256 IS NULL AND c.exec_contract_sha256 IS NULL
  AND EXISTS (SELECT 1 FROM mint.settings cfg WHERE cfg.instance_id = a.instance_id
       AND (NOT cfg.require_separate_confirm_key
            OR sc.confirmed_by_key_token <> sc.requested_by_key_token) OFFSET 0)
  AND ((c.status = 'consumed' AND c.valid_until IS NULL
        AND c.consumed_invocation_id = sc.consumed_invocation_id)
       OR (c.status = 'approved' AND c.valid_until IS NOT NULL AND EXISTS (
          SELECT 1 FROM mint.call_approval_uses u WHERE u.call_approval_id = c.id
            AND u.invocation_id = sc.consumed_invocation_id)))
  AND a.scope_type = 'user' AND a.scope_id = c.principal_id AND a.org_id = c.org_id
  AND a.server_id = c.server_id AND c.tool = ANY(a.tools)
  AND a.status = 'active' AND a.recert_held_at IS NULL
  AND a.valid_from <= now() AND a.valid_until > now()
  AND a.conditions->'reuse_read_confirmations' = 'true'::jsonb
  AND a.conditions->'scan_result' IS DISTINCT FROM 'false'::jsonb
  AND coalesce(a.conditions->'allow_input_secrets', '[]'::jsonb) = '[]'::jsonb
  AND NOT (coalesce(a.conditions->'high_risk_tools', '[]'::jsonb) ? c.tool)
  AND EXISTS (SELECT 1 FROM mint.usage_relations r WHERE r.instance_id = a.instance_id
       AND r.id = a.relation_id AND r.status = 'active' OFFSET 0)
  AND EXISTS (SELECT 1 FROM mint.servers srv WHERE srv.instance_id = a.instance_id
       AND srv.server_id = a.server_id AND srv.status = 'approved'
       AND srv.contract_status = 'managed' AND NOT srv.deployment_drift OFFSET 0)
  AND EXISTS (SELECT 1 FROM mint.tool_contracts t WHERE t.instance_id = a.instance_id
       AND t.id = c.contract_id AND t.status = 'approved' AND t.drift = 'none'
       AND t.action_type = 'read' AND t.risk_grade = 'low' OFFSET 0)
  AND EXISTS (SELECT 1 FROM mint.policy_versions pv WHERE pv.instance_id = a.instance_id
       AND pv.id = c.policy_version_id AND pv.status = 'active' OFFSET 0)
  AND least(a.valid_until, e.inserted_at + interval '30 days',
            coalesce(c.valid_until, a.valid_until)) > now()
  AND (%(proof_event_id)s::uuid IS NULL OR e.event_id = %(proof_event_id)s::uuid)
ORDER BY e.inserted_at DESC LIMIT 50
"""


def eligible(snapshot: Any, principal: Any, selected: Any, contract: Any,
             arguments: Mapping[str, Any]) -> bool:
    """No classification downgrade, implicit destinations or parameter-free browser state."""
    if (selected is None or selected.conditions.get(FLAG) is not True
            or principal.principal_type.value != "user" or not principal.key_id
            or selected.scope_type != "user" or selected.scope_id != principal.principal_id
            or snapshot.server is None or snapshot.server.contract_status != "managed"
            or contract is None or contract.action_type != "read" or contract.risk_grade != "low"
            or contract.drift != "none" or not selected.conditions.get("allowed_hosts")
            or selected.conditions.get("scan_result") is False
            or selected.conditions.get("allow_input_secrets")
            or contract.tool in selected.conditions.get("high_risk_tools", ())):
        return False
    try:
        url = arguments.get("url")
        if not isinstance(url, str):
            return False
        parsed = urlsplit(url)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and parsed.hostname.lower().rstrip(".") in {
                    host.lower().rstrip(".") for host in selected.conditions["allowed_hosts"]
                    if isinstance(host, str)
                })
    except ValueError:
        return False


def match(proofs: tuple[Mapping[str, Any], ...], *, now: datetime,
          expected: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for proof in proofs:
        try:
            expiry = datetime.fromisoformat(str(proof["expires_at"]))
            if expiry > now and all(proof.get(k) == v for k, v in expected.items()):
                return proof
        except (KeyError, ValueError, TypeError):
            continue
    return None
