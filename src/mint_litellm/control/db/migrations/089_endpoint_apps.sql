-- 직원이 직접 만든 AI 프로그램(앱)의 자격. 키 값은 저장하지 않고 해시와 별칭만 남긴다.
-- 앱은 사람에게 속하므로 단말 설치 키를 다시 발급해도 유지되고, 연결 해제 때 함께 회수된다.
CREATE TABLE mint.endpoint_apps (
    instance_id mint.ident NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    user_id text NOT NULL,
    team_id text,
    install_key_token text NOT NULL,
    name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    key_alias text NOT NULL,
    key_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by text,
    PRIMARY KEY (instance_id, id)
);
CREATE INDEX endpoint_apps_user ON mint.endpoint_apps (instance_id, user_id, created_at DESC);
REVOKE ALL ON mint.endpoint_apps FROM PUBLIC;
GRANT SELECT, UPDATE (revoked_at, revoked_by) ON mint.endpoint_apps TO mint_control;
GRANT SELECT, INSERT, UPDATE (revoked_at, revoked_by) ON mint.endpoint_apps TO mint_plugin;

-- 판정 프로세스 역할이 앱 자격 발급·회수 사건을 추가할 수 있게 한다.
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
           'endpoint_app_created', 'endpoint_app_revoked') THEN
        RAISE EXCEPTION 'the plugin role can only append call and system events'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END $$;
