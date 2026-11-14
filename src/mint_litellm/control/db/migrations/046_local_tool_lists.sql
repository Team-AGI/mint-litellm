-- 단말 실행기가 로컬(stdio) 서버의 ``tools/list`` 응답에서 본 도구 목록(단말의 주장)과, 승인된 계약이
-- 없는 로컬 서버를 위해 그 목록에서 만든 임시 계약.

-- 서버·단말(설치 키)마다 마지막으로 보고된 목록. 같은 목록의 반복 보고는 행을 바꾸지 않는다.
CREATE TABLE mint.endpoint_tool_lists (
    instance_id  mint.ident NOT NULL,
    server_id    text NOT NULL CHECK (length(server_id) BETWEEN 1 AND 128),
    key_token    text NOT NULL,
    tools        jsonb NOT NULL CHECK (jsonb_typeof(tools) = 'array'),
    tools_sha256 text NOT NULL CHECK (tools_sha256 ~ '^[0-9a-f]{64}$'),
    truncated    boolean NOT NULL DEFAULT false,
    reported_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, server_id, key_token),
    FOREIGN KEY (instance_id, key_token)
        REFERENCES mint.endpoint_installs (instance_id, key_token)
);

CREATE INDEX endpoint_tool_lists_by_server
    ON mint.endpoint_tool_lists (instance_id, server_id, reported_at DESC);

-- 임시 계약: 승인된 도구 계약이 없는(또는 관측한 정의가 승인본과 달라진) 도구의 추정 행위 유형·위험
-- 등급과 기본 허용 인자 키. 승인하면 도구 계약으로 옮기고 이 행은 지운다.
CREATE TABLE mint.provisional_contracts (
    instance_id  mint.ident NOT NULL,
    server_id    text NOT NULL,
    tool         text NOT NULL CHECK (length(tool) BETWEEN 1 AND 128),
    action_type  text NOT NULL CHECK (action_type IN (
        'read', 'write', 'delete', 'external_send', 'exec', 'credential_access')),
    risk_grade   text NOT NULL CHECK (risk_grade IN ('low', 'medium', 'high', 'critical')),
    description  text NOT NULL DEFAULT '',
    input_schema jsonb NOT NULL CHECK (jsonb_typeof(input_schema) = 'object'),
    input_keys   text[] NOT NULL,
    reported_by  text,
    observed_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, server_id, tool),
    FOREIGN KEY (instance_id, server_id) REFERENCES mint.servers (instance_id, server_id)
);

REVOKE ALL ON mint.endpoint_tool_lists, mint.provisional_contracts FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.endpoint_tool_lists TO mint_plugin;
GRANT SELECT ON mint.endpoint_tool_lists TO mint_control;
GRANT SELECT, INSERT, UPDATE, DELETE ON mint.provisional_contracts TO mint_worker;
GRANT SELECT, DELETE ON mint.provisional_contracts TO mint_control;
GRANT SELECT ON mint.provisional_contracts TO mint_plugin;
