-- 단말이 보고한 AI 도구별 보장 현황·평문 키 위치·검사 실패·장애 중 통과 호출, 그리고 관리자의
-- 연결 중지와 연결 복구 요청. 값은 단말의 주장이다(키 값은 받지 않는다).
ALTER TABLE mint.endpoint_installs
    ADD COLUMN ai_clients jsonb CHECK (ai_clients IS NULL OR jsonb_typeof(ai_clients) = 'array'),
    ADD COLUMN plaintext_keys jsonb
        CHECK (plaintext_keys IS NULL OR jsonb_typeof(plaintext_keys) = 'array'),
    ADD COLUMN scan_errors jsonb CHECK (scan_errors IS NULL OR jsonb_typeof(scan_errors) = 'array'),
    ADD COLUMN offline_calls jsonb
        CHECK (offline_calls IS NULL OR jsonb_typeof(offline_calls) = 'array'),
    ADD COLUMN paused_at timestamptz,
    ADD COLUMN paused_by text,
    ADD COLUMN pause_gen integer NOT NULL DEFAULT 0,
    ADD COLUMN paused_ack integer,
    ADD COLUMN paused_ack_at timestamptz,
    ADD COLUMN reconnect_requested boolean NOT NULL DEFAULT false;

GRANT UPDATE (ai_clients, plaintext_keys, scan_errors, offline_calls, paused_ack, paused_ack_at,
              reconnect_requested) ON mint.endpoint_installs TO mint_plugin;

-- 직원이 「알림에서 제외」한 서버 이름(사용자별).
CREATE TABLE mint.endpoint_ignored_servers (
    instance_id mint.ident NOT NULL,
    user_id text NOT NULL,
    server_name text NOT NULL CHECK (char_length(server_name) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, user_id, server_name)
);
REVOKE ALL ON mint.endpoint_ignored_servers FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON mint.endpoint_ignored_servers TO mint_control;
GRANT SELECT ON mint.endpoint_ignored_servers TO mint_plugin;

-- 직원이 동의하고 올린 서버 신청 요청. 단말 키트가 받아 실제 신청을 올리면 보냄으로 표시된다.
CREATE TABLE mint.endpoint_intake_requests (
    instance_id mint.ident NOT NULL,
    user_id text NOT NULL,
    server_name text NOT NULL CHECK (char_length(server_name) BETWEEN 1 AND 128),
    purpose text NOT NULL CHECK (char_length(purpose) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    PRIMARY KEY (instance_id, user_id, server_name)
);
REVOKE ALL ON mint.endpoint_intake_requests FROM PUBLIC;
GRANT SELECT, INSERT ON mint.endpoint_intake_requests TO mint_control;
GRANT SELECT ON mint.endpoint_intake_requests TO mint_plugin;
GRANT UPDATE (sent_at) ON mint.endpoint_intake_requests TO mint_plugin;

-- 판정 프로세스 역할이 장애 중 통과 사건을 추가할 수 있게 한다.
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
           'endpoint_remediated', 'endpoint_offline_call') THEN
        RAISE EXCEPTION 'the plugin role can only append call and system events'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
