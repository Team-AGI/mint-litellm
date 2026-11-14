-- 상시 승인 규칙. 관리자가 정한 범위(조직 전체 또는 특정 주체) × 서버(비우면 승인된 모든 서버) ×
-- 행위 분류(읽기·쓰기) [× 도구 패턴]에 맞는 호출은 호출마다 사람이 승인하지 않고, 규칙이 정한 기간
-- (10분·30분) 동안 쓸 수 있는 기간 승인이 자동으로 열린다. 삭제·외부 전송·자격 접근은 규칙을 만들 수
-- 없다(행위 분류 열이 읽기·쓰기만 받는다).
CREATE TABLE mint.call_approval_rules (
    id             uuid PRIMARY KEY,
    instance_id    mint.ident NOT NULL,
    org_id         mint.ident NOT NULL,
    scope_type     text NOT NULL CHECK (scope_type IN ('org', 'principal')),
    principal_type text CHECK (principal_type IN ('user', 'team_key', 'service_account')),
    scope_id       text CHECK (length(scope_id) BETWEEN 1 AND 256),
    server_id      text,
    action_class   text NOT NULL CHECK (action_class IN ('read', 'write')),
    tool_pattern   text CHECK (tool_pattern ~ '^[A-Za-z0-9_.:*-]{1,128}$'),
    window_minutes smallint NOT NULL CHECK (window_minutes IN (10, 30)),
    valid_until    timestamptz,
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    disabled_by    text,
    disabled_at    timestamptz,
    state_version  bigint NOT NULL DEFAULT 1,
    FOREIGN KEY (instance_id, org_id) REFERENCES mint.orgs (instance_id, org_id),
    FOREIGN KEY (instance_id, server_id) REFERENCES mint.servers (instance_id, server_id),
    CHECK ((scope_type = 'org') = (principal_type IS NULL AND scope_id IS NULL)),
    CHECK ((scope_type = 'principal') = (principal_type IS NOT NULL AND scope_id IS NOT NULL)),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
);

CREATE INDEX call_approval_rules_active
    ON mint.call_approval_rules (instance_id, org_id) WHERE status = 'active';

-- 규칙은 만든 뒤 내용이 바뀌지 않고 해제만 된다.
CREATE TRIGGER call_approval_rules_1_status BEFORE INSERT OR UPDATE ON mint.call_approval_rules
    FOR EACH ROW EXECUTE FUNCTION mint.check_status('active', 'active>disabled');
CREATE TRIGGER call_approval_rules_2_frozen BEFORE UPDATE ON mint.call_approval_rules
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'org_id', 'scope_type', 'principal_type', 'scope_id', 'server_id',
        'action_class', 'tool_pattern', 'window_minutes', 'valid_until', 'created_by',
        'created_at');
CREATE TRIGGER call_approval_rules_3_once BEFORE UPDATE ON mint.call_approval_rules
    FOR EACH ROW EXECUTE FUNCTION mint.set_once('disabled_by', 'disabled_at');
CREATE TRIGGER call_approval_rules_9_version BEFORE UPDATE ON mint.call_approval_rules
    FOR EACH ROW EXECUTE FUNCTION mint.bump_version();

REVOKE ALL ON mint.call_approval_rules FROM PUBLIC;
GRANT SELECT ON mint.call_approval_rules TO mint_plugin;
GRANT SELECT, INSERT, UPDATE ON mint.call_approval_rules TO mint_control;

-- 판정 프로세스가 막힌 호출의 승인 요청을 열 때 맞는 규칙이 있으면 요청을 대기로 남기지 않고 규칙이
-- 정한 기간의 승인으로 연다(승인자는 ``rule:<규칙 식별자>``). 판정 프로세스 역할은 승인 상태로 행을
-- 만들 수 없으므로 이 함수가 그 한 가지 경로를 연다. 규칙이 맞으려면 호출이 승인된 도구 계약에 묶여
-- 있어야 하고(계약이 없는 로컬 실행 서버·행위 분류를 모르는 도구는 맞지 않는다), 계약의 행위 분류가
-- 규칙과 같은 읽기·쓰기여야 한다. 맞는 규칙이 없으면 NULL을 돌려주고 아무것도 쓰지 않는다.
CREATE FUNCTION mint.open_rule_approval(
    p_id uuid, p_instance mint.ident, p_org mint.ident, p_principal_type text,
    p_principal_id text, p_server text, p_tool text, p_args_fp text, p_fp_key_version integer,
    p_policy mint.ident, p_requested_by text, p_minutes integer, p_contract uuid,
    p_exec_sha256 text, p_target text, p_action text, p_display jsonb)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    v_rule  uuid;
    v_window smallint;
BEGIN
    SELECT r.id, r.window_minutes INTO v_rule, v_window
    FROM mint.call_approval_rules r
    JOIN mint.tool_contracts t ON t.instance_id = p_instance AND t.id = p_contract
         AND t.server_id = p_server AND t.tool = p_tool AND t.status = 'approved'
    WHERE r.instance_id = p_instance AND r.org_id = p_org AND r.status = 'active'
      AND (r.valid_until IS NULL OR r.valid_until > clock_timestamp())
      AND (r.scope_type = 'org'
           OR (r.principal_type = p_principal_type AND r.scope_id = p_principal_id))
      AND (r.server_id IS NULL OR r.server_id = p_server)
      AND r.action_class = t.action_type
      AND t.action_type IN ('read', 'write')
      AND (r.tool_pattern IS NULL
           OR p_tool LIKE replace(replace(r.tool_pattern, '_', '\_'), '*', '%'))
    ORDER BY r.created_at, r.id
    LIMIT 1;
    IF v_rule IS NULL THEN
        RETURN NULL;
    END IF;
    INSERT INTO mint.call_approvals
        (id, instance_id, org_id, principal_type, principal_id, server_id, tool, args_fp,
         fp_key_version, policy_version_id, status, requested_by, expires_at, contract_id,
         exec_contract_sha256, target, action, display)
    VALUES (p_id, p_instance, p_org, p_principal_type, p_principal_id, p_server, p_tool,
            p_args_fp, p_fp_key_version, p_policy, 'pending', p_requested_by,
            clock_timestamp() + make_interval(mins => p_minutes), p_contract, p_exec_sha256,
            p_target, p_action, p_display);
    UPDATE mint.call_approvals
    SET status = 'approved', approved_by = 'rule:' || v_rule::text,
        window_minutes = v_window,
        valid_until = clock_timestamp() + make_interval(mins => v_window),
        decided_at = clock_timestamp(), decision_reason = 'rule'
    WHERE instance_id = p_instance AND id = p_id;
    RETURN p_id;
END $$;

REVOKE ALL ON FUNCTION mint.open_rule_approval FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.open_rule_approval TO mint_plugin;
