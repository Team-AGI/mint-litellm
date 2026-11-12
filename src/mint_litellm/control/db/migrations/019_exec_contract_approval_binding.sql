-- 로컬 실행(stdio) 서버의 호출별 승인과 본인 확인을 받은 때의 실행 계약에 묶는다.
-- 서버의 실행 계약이 바뀌면(재등록) 묶인 열린 승인은 같은 트랜잭션에서 만료되고, 소비는 지금
-- 서버 행의 계약과 같을 때만 된다. 원격 서버의 승인은 이 열이 비어 있다.
ALTER TABLE mint.call_approvals
    ADD COLUMN exec_contract_sha256 text CHECK (exec_contract_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE mint.self_confirmations
    ADD COLUMN exec_contract_sha256 text CHECK (exec_contract_sha256 ~ '^[0-9a-f]{64}$');

DROP TRIGGER call_approvals_2_frozen ON mint.call_approvals;
CREATE TRIGGER call_approvals_2_frozen BEFORE UPDATE ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'org_id', 'principal_type', 'principal_id', 'server_id', 'tool',
        'args_fp', 'fp_key_version', 'policy_version_id', 'contract_version', 'contract_id',
        'exec_contract_sha256', 'requested_by', 'expires_at');

DROP TRIGGER self_confirmations_2_frozen ON mint.self_confirmations;
CREATE TRIGGER self_confirmations_2_frozen BEFORE UPDATE ON mint.self_confirmations
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'org_id', 'principal_id', 'server_id', 'tool', 'args_fp',
        'fp_key_version', 'policy_version_id', 'contract_id', 'exec_contract_sha256', 'purpose',
        'requested_by_key_token', 'expires_at', 'created_at');

GRANT INSERT (exec_contract_sha256) ON mint.self_confirmations TO mint_plugin;

-- 서버의 실행 계약이 바뀌면 이전 계약에 묶인 열린 승인을 만료한다(제어 그룹이 하는 전이만 쓴다).
CREATE FUNCTION mint.expire_exec_contract_approvals() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE mint.call_approvals SET status = 'expired'
    WHERE instance_id = OLD.instance_id AND server_id = OLD.server_id
      AND exec_contract_sha256 = OLD.exec_contract_sha256
      AND status IN ('pending', 'approved');
    UPDATE mint.self_confirmations SET status = 'expired'
    WHERE instance_id = OLD.instance_id AND server_id = OLD.server_id
      AND exec_contract_sha256 = OLD.exec_contract_sha256
      AND status IN ('pending', 'confirmed');
    RETURN NULL;
END $$;

CREATE TRIGGER servers_8_expire_exec_approvals
    AFTER UPDATE OF exec_contract_sha256 ON mint.servers
    FOR EACH ROW WHEN (OLD.exec_contract_sha256 IS NOT NULL
                       AND NEW.exec_contract_sha256 IS DISTINCT FROM OLD.exec_contract_sha256)
    EXECUTE FUNCTION mint.expire_exec_contract_approvals();
