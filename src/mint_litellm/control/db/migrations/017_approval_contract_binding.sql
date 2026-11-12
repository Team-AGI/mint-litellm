-- 호출별 승인과 본인 확인을 받은 때의 도구 계약에 묶는다.
-- 계약 관리 서버의 승인은 계약이 교체되면 소비되지 않고, 교체와 같은 트랜잭션에서 만료된다.
-- 계약 식별자는 서버·자격 범위·도구마다 하나이므로 자격 범위도 함께 묶인다.
ALTER TABLE mint.call_approvals ADD COLUMN contract_id uuid;
ALTER TABLE mint.self_confirmations ADD COLUMN contract_id uuid;

DROP TRIGGER call_approvals_2_frozen ON mint.call_approvals;
CREATE TRIGGER call_approvals_2_frozen BEFORE UPDATE ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'org_id', 'principal_type', 'principal_id', 'server_id', 'tool',
        'args_fp', 'fp_key_version', 'policy_version_id', 'contract_version', 'contract_id',
        'requested_by', 'expires_at');

DROP TRIGGER self_confirmations_2_frozen ON mint.self_confirmations;
CREATE TRIGGER self_confirmations_2_frozen BEFORE UPDATE ON mint.self_confirmations
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'org_id', 'principal_id', 'server_id', 'tool', 'args_fp',
        'fp_key_version', 'policy_version_id', 'contract_id', 'purpose', 'requested_by_key_token',
        'expires_at', 'created_at');

GRANT INSERT (contract_id) ON mint.self_confirmations TO mint_plugin;

-- 이전 판본이 남긴 열린 승인은 어느 계약에서 받았는지 알 수 없다. 계약 관리 서버의 것은 닫는다.
UPDATE mint.call_approvals c SET status = 'expired'
FROM mint.servers s
WHERE s.instance_id = c.instance_id AND s.server_id = c.server_id
  AND s.contract_status = 'managed' AND c.status IN ('pending', 'approved');
UPDATE mint.self_confirmations c SET status = 'expired'
FROM mint.servers s
WHERE s.instance_id = c.instance_id AND s.server_id = c.server_id
  AND s.contract_status = 'managed' AND c.status IN ('pending', 'confirmed');

-- 승인된 계약이 승인 상태를 벗어나면(교체·철회) 그 계약에 묶인 열린 승인을 만료한다.
-- 계약을 바꾸는 역할(제어 그룹)이 할 수 있는 전이만 쓴다.
CREATE FUNCTION mint.expire_contract_approvals() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE mint.call_approvals SET status = 'expired'
    WHERE instance_id = OLD.instance_id AND contract_id = OLD.id
      AND status IN ('pending', 'approved');
    UPDATE mint.self_confirmations SET status = 'expired'
    WHERE instance_id = OLD.instance_id AND contract_id = OLD.id
      AND status IN ('pending', 'confirmed');
    RETURN NULL;
END $$;

CREATE TRIGGER tool_contracts_8_expire_approvals AFTER UPDATE ON mint.tool_contracts
    FOR EACH ROW WHEN (OLD.status = 'approved' AND NEW.status <> 'approved')
    EXECUTE FUNCTION mint.expire_contract_approvals();
