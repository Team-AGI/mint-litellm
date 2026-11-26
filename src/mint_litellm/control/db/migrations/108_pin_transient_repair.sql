-- 승인 직후 고정(pin) 응답에서 도구가 일시 오류로 빠져 막힌 서버를 되돌린다.
-- 대상: 한 번도 활성화되지 않았고(승인 대기), 막힌 이유가 고정 불일치 하나뿐이며, 드리프트가 난
-- 도구가 전부 「삭제」(후보 계약 없음)인 서버. 표지를 풀면 다음 동기화가 다시 고정한다.
WITH stuck AS (
    SELECT s.instance_id, s.server_id FROM mint.servers s
     WHERE s.status = 'awaiting_approval'
       AND s.deployment_drift_fields = ARRAY['pin_reapproval']::text[]
       AND NOT EXISTS (SELECT 1 FROM mint.tool_contracts t
                        WHERE t.instance_id = s.instance_id AND t.server_id = s.server_id
                          AND ((t.status = 'approved' AND t.drift NOT IN ('none', 'removed'))
                               OR (t.status = 'candidate' AND t.source = 'pin')))
), cleared AS (
    UPDATE mint.tool_contracts t SET drift = 'none'
      FROM stuck
     WHERE t.instance_id = stuck.instance_id AND t.server_id = stuck.server_id
       AND t.status = 'approved' AND t.drift = 'removed'
)
UPDATE mint.servers s SET deployment_drift = false, deployment_drift_fields = NULL
  FROM stuck
 WHERE s.instance_id = stuck.instance_id AND s.server_id = stuck.server_id;
