-- 단말 설치 묶음에 발급한 사용자 키와 그 단말이 보고한 설치 상태.
-- 행은 콘솔이 키를 발급할 때 만들고(제어 역할), 단말의 보고는 판정 프로세스 역할이 보고 열만
-- 바꾼다. 같은 사용자의 이전 키는 새 묶음을 내려받을 때 해제 시각이 찍힌다.
-- install_mode: managed(관리형), user(사용자 수준, 관리되지 않음), removed(제거 보고).
-- 보고가 아직 없는 행은 install_mode가 비어 있다.
CREATE TABLE mint.endpoint_installs (
    instance_id    mint.ident NOT NULL,
    key_token      text NOT NULL CHECK (length(key_token) BETWEEN 1 AND 128),
    user_id        text NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    team_id        text,
    key_alias      text NOT NULL CHECK (length(key_alias) BETWEEN 1 AND 128),
    issued_by      text NOT NULL,
    issued_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at     timestamptz,
    install_mode   text CHECK (install_mode IN ('managed', 'user', 'removed')),
    kit_version    text CHECK (length(kit_version) <= 128),
    claude_version text CHECK (length(claude_version) <= 64),
    mcp_servers    jsonb CHECK (jsonb_typeof(mcp_servers) = 'array'),
    reported_at    timestamptz,
    PRIMARY KEY (instance_id, key_token),
    UNIQUE (instance_id, key_alias),
    CHECK ((install_mode IS NULL) = (reported_at IS NULL))
);

CREATE INDEX endpoint_installs_by_user ON mint.endpoint_installs (instance_id, user_id, issued_at);

CREATE TRIGGER endpoint_installs_2_frozen BEFORE UPDATE ON mint.endpoint_installs
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'key_token', 'user_id', 'team_id', 'key_alias', 'issued_by', 'issued_at');

GRANT SELECT, INSERT, UPDATE ON mint.endpoint_installs TO mint_control;
GRANT SELECT ON mint.endpoint_installs TO mint_plugin;
GRANT UPDATE (install_mode, kit_version, claude_version, mcp_servers, reported_at)
    ON mint.endpoint_installs TO mint_plugin;
