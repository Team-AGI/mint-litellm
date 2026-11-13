"""결과가 보고되지 않은 로컬 서버 호출을 「결과 미확인」으로 남긴다.

허용된 로컬 서버 호출은 호출 뒤 훅의 결과 보고(응답 관측 또는 결과 불명 보고)가 와야 닫힌다.
승인을 소비한 직후 응답이 사라지거나 훅이 죽으면 보고가 오지 않으므로, 기한이 지나도 보고가
없는 호출마다 ``call_outcome_unknown``(사유 ``no_report``)을 한 건 남긴다. 호출 사건은 호출
식별자로 한 건에 수렴하므로 같은 작업이 다시 돌거나 보고가 늦게 와도 중복되지 않는다. 소비된
호출별 승인은 되살리지 않는다(재시도하려면 새 승인이 필요하다).
"""

from datetime import UTC, datetime

import psycopg
from psycopg.types.json import Jsonb

from mint_litellm.types.events import Event, EventKind, call_source_key

# 보고를 기다리는 시간(초). 이 시간이 지난 호출을 결과 미확인으로 본다.
GRACE_SECONDS = 300
# 이 기간(초)보다 오래된 호출은 다시 살피지 않는다(작업이 오래 멈췄다 돌아온 뒤의 상한).
LOOKBACK_SECONDS = 86400

_PENDING_SQL = """
SELECT d.invocation_id, d.attempt_id, d.payload->>'decision_ref' AS decision_ref,
       d.payload->>'consumed_call_approval_id' AS call_approval_id
FROM mint.events d
WHERE d.instance_id = %s AND d.kind = 'decision_evaluated'
  AND d.payload->>'resolved_identity_kind' = 'stdio' AND d.payload->>'enforced_action' = 'allow'
  AND d.inserted_at < now() - make_interval(secs => %s)
  AND d.inserted_at >= now() - make_interval(secs => %s)
  AND NOT EXISTS (
      SELECT 1 FROM mint.events r
      WHERE r.instance_id = d.instance_id AND r.invocation_id = d.invocation_id
        AND r.attempt_id = d.attempt_id
        AND r.kind IN ('call_response_received', 'call_outcome_unknown'))
"""


def scan(conn: psycopg.Connection, instance_id: str) -> int:
    """보고 없이 기한이 지난 허용 호출마다 결과 미확인 사건을 남기고 그 수를 돌려준다."""
    rows = conn.execute(_PENDING_SQL, (instance_id, GRACE_SECONDS, LOOKBACK_SECONDS)).fetchall()
    for invocation_id, attempt_id, decision_ref, call_approval_id in rows:
        payload = {"decision_ref": decision_ref, "cause": "no_report"}
        if call_approval_id is not None:
            payload["call_approval_id"] = call_approval_id
        kind = EventKind.CALL_OUTCOME_UNKNOWN
        event = Event(
            instance_id=instance_id,
            inserted_at=datetime.now(UTC),
            kind=kind,
            source_key=call_source_key(invocation_id, attempt_id, kind),
            invocation_id=invocation_id,
            attempt_id=attempt_id,
            actor="endpoint-result-scan",
            payload=payload,
        )
        conn.execute(
            "INSERT INTO mint.events (event_id, instance_id, inserted_at, kind, source_key,"
            " invocation_id, attempt_id, actor, payload)"
            " SELECT %s::uuid, %s, %s::timestamptz, %s, %s, %s::uuid, %s::integer, %s, %s::jsonb"
            " WHERE mint.claim_event_key(%s, %s, %s::uuid)",
            (event.event_id, instance_id, event.inserted_at, kind.value, event.source_key,
             invocation_id, attempt_id, event.actor, Jsonb(payload),
             instance_id, event.source_key, event.event_id),
        )
    return len(rows)
