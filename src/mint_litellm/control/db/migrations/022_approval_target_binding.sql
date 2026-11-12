-- 호출별 승인을 받은 때의 대상(target)과 행위(action)에 묶는다. 대상·행위 프로필이 있는 서버의 승인만
-- 값을 가지며, 매칭과 소비가 모두 호출에서 구조적으로 뽑은 값과 완전히 같을 때만 쓴다.
-- 값이 없는 기존 승인은 프로필이 없는 서버에서만 그대로 쓰이고, 프로필이 켜진 서버에서는 맞지 않는다.
ALTER TABLE mint.call_approvals
    ADD COLUMN target text CHECK (target IS NULL OR length(target) BETWEEN 1 AND 300),
    ADD COLUMN action text CHECK (action IS NULL OR length(action) BETWEEN 1 AND 200),
    ADD CONSTRAINT call_approvals_target_needs_action CHECK (target IS NULL OR action IS NOT NULL);

DROP TRIGGER call_approvals_2_frozen ON mint.call_approvals;
CREATE TRIGGER call_approvals_2_frozen BEFORE UPDATE ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'org_id', 'principal_type', 'principal_id', 'server_id', 'tool',
        'args_fp', 'fp_key_version', 'policy_version_id', 'contract_version', 'contract_id',
        'exec_contract_sha256', 'target', 'action', 'requested_by', 'expires_at');

-- 플러그인은 승인된 배포 계약의 URL과 허용 도구로 서버의 대상·행위 프로필을 고른다(읽기만).
GRANT SELECT (instance_id, server_id, url, allowed_tools, status)
    ON mint.deployment_contracts TO mint_plugin;
