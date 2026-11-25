-- PC마다 설치 키 하나: 설치 묶음이 제거·재설치를 알리면 그 PC의 키만 해제한다(같은 사람의 다른
-- PC는 그대로). 판정 프로세스 역할은 설치 표를 고칠 수 없으므로 이 함수로만 해제한다.
CREATE FUNCTION mint.endpoint_retire_install(p_instance text, p_key_token text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE k mint.endpoint_installs;
BEGIN
    SELECT * INTO k FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token AND i.revoked_at IS NULL
      FOR UPDATE;
    IF NOT FOUND THEN RETURN 0; END IF;
    UPDATE mint.endpoint_installs SET revoked_at = clock_timestamp()
      WHERE instance_id = p_instance AND key_token = p_key_token;
    UPDATE mint.endpoint_apps SET revoked_at = clock_timestamp(), revoked_by = k.user_id
      WHERE instance_id = p_instance AND install_key_token = p_key_token AND revoked_at IS NULL;
    RETURN 1;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_retire_install(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_retire_install(text, text) TO mint_plugin;

-- 판정 프로세스 역할이 PC 한 대의 연결 해제 사건을 추가할 수 있게 한다.
CREATE OR REPLACE FUNCTION mint.restrict_plugin_events() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF pg_has_role(current_user, 'mint_plugin', 'MEMBER')
       AND NOT pg_has_role(current_user, 'mint_control', 'MEMBER')
       AND NEW.kind NOT IN (
           'decision_evaluated', 'discovery_evaluated', 'call_response_received',
           'call_outcome_unknown',
           'enforcement_unverified', 'enforcement_verified',
           'server_identity_mismatch_observed', 'buffer_overflow', 'buffer_replayed',
           'endpoint_remediated', 'endpoint_offline_call',
           'endpoint_app_created', 'endpoint_app_revoked', 'endpoint_revoked') THEN
        RAISE EXCEPTION 'the plugin role can only append call and system events'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
