-- 설치 보고가 남기는 자동 제거 사건을 판정 프로세스 역할이 추가할 수 있게 한다.
-- 이 종류를 거절하면 폐기 서버 항목을 지운 단말의 보고가 영구히 실패한다.
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
           'endpoint_remediated') THEN
        RAISE EXCEPTION 'the plugin role can only append call and system events'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;

-- 제어 평면이 서버 등록 중 경보(버전 미고정 패키지·계약 변경)를 열 수 있게 한다.
GRANT INSERT ON mint.alerts TO mint_control;
GRANT UPDATE (last_at, count) ON mint.alerts TO mint_control;

-- 게이트웨이 MCP 전용 키의 별칭(키 값은 두지 않는다)과 단말이 보고한 Codex 훅 신뢰 상태.
ALTER TABLE mint.endpoint_installs
    ADD COLUMN mcp_key_alias text,
    ADD COLUMN hook_trust text CHECK (hook_trust IN ('trusted', 'untrusted'));
GRANT UPDATE (hook_trust) ON mint.endpoint_installs TO mint_plugin;
