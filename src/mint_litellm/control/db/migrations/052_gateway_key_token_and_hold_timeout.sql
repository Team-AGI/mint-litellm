-- 게이트웨이 MCP 전용 키의 토큰 해시(키 값은 두지 않는다). 승인이 바뀔 때 이 키의 LiteLLM 서버
-- 권한을 갱신하고, 키 범위 승인이 이 키를 가리키는 데 쓴다.
ALTER TABLE mint.endpoint_installs ADD COLUMN mcp_key_token text;

-- 승인 대기가 시간 초과로 끝나 호출자가 응답을 받은 시각. 요청은 대기로 남고(호출자가 다시 보낼 수
-- 있다), 승인 화면은 이 값으로 그 사실을 보여 준다.
ALTER TABLE mint.call_approvals ADD COLUMN hold_timed_out_at timestamptz;
GRANT UPDATE (hold_timed_out_at) ON mint.call_approvals TO mint_plugin;

CREATE OR REPLACE FUNCTION mint.restrict_plugin_call_approval() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF pg_has_role(current_user, 'mint_plugin', 'MEMBER')
       AND NOT pg_has_role(current_user, 'mint_control', 'MEMBER')
       AND NOT (OLD.status = 'approved' AND NEW.status = 'consumed'
                AND NEW.consumed_invocation_id IS NOT NULL)
       AND NOT (OLD.status = NEW.status AND NEW.hold_timed_out_at IS NOT NULL) THEN
        RAISE EXCEPTION 'the plugin role can only consume an approved call approval'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
