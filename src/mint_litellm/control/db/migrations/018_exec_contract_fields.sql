-- 서버를 식별하는 방식(identity_kind)과 실행 계약(exec_contract_*)을 URL 칸과 따로 둔다.
-- 로컬 실행(stdio) 서버는 URL이 없으므로 URL 칸에 자리 값을 넣지 않고 비운다. 기존 행은 모두 원격이다.
-- identity_kind 값은 이 CHECK 목록으로만 늘린다. exec_contract_sha256은 실행 계약 정본 문자열의
-- SHA-256이고 exec_contract_version은 그 계약 스키마의 판본이다.
ALTER TABLE mint.servers
    ALTER COLUMN url_sha256 DROP NOT NULL,
    ADD COLUMN identity_kind text NOT NULL DEFAULT 'remote'
        CHECK (identity_kind IN ('remote', 'stdio')),
    ADD COLUMN exec_contract_sha256 text CHECK (exec_contract_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN exec_contract_version integer CHECK (exec_contract_version >= 1),
    ADD CONSTRAINT servers_identity_shape CHECK (
        (identity_kind = 'remote' AND url_sha256 IS NOT NULL
            AND exec_contract_sha256 IS NULL AND exec_contract_version IS NULL)
     OR (identity_kind = 'stdio' AND url_sha256 IS NULL
            AND exec_contract_sha256 IS NOT NULL AND exec_contract_version IS NOT NULL));

DROP TRIGGER servers_2_frozen ON mint.servers;
CREATE TRIGGER servers_2_frozen BEFORE UPDATE ON mint.servers
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns('instance_id', 'server_id', 'identity_kind');

-- 배포 계약도 같은 필드를 가진다. 실행 위치·실행물 출처·권한은 계약의 별개 필드이며, 첫 구현은
-- 비워 둔다(원격·stdio 두 값은 identity_kind가 정한다). 채우는 규칙은 값이 생길 때 CHECK로 더한다.
ALTER TABLE mint.deployment_contracts
    ALTER COLUMN url DROP NOT NULL,
    ALTER COLUMN url_sha256 DROP NOT NULL,
    ADD COLUMN identity_kind text NOT NULL DEFAULT 'remote'
        CHECK (identity_kind IN ('remote', 'stdio')),
    ADD COLUMN exec_contract_sha256 text CHECK (exec_contract_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN exec_contract_version integer CHECK (exec_contract_version >= 1),
    ADD COLUMN exec_location text CHECK (exec_location IS NULL OR length(exec_location) > 0),
    ADD COLUMN artifact_source text CHECK (artifact_source IS NULL OR length(artifact_source) > 0),
    ADD COLUMN permissions jsonb CHECK (permissions IS NULL OR jsonb_typeof(permissions) = 'object'),
    ADD CONSTRAINT deployment_contracts_identity_shape CHECK (
        (identity_kind = 'remote' AND url IS NOT NULL AND url_sha256 IS NOT NULL
            AND exec_contract_sha256 IS NULL AND exec_contract_version IS NULL)
     OR (identity_kind = 'stdio' AND url IS NULL AND url_sha256 IS NULL
            AND exec_contract_sha256 IS NOT NULL AND exec_contract_version IS NOT NULL));

DROP TRIGGER deployment_contracts_2_frozen ON mint.deployment_contracts;
CREATE TRIGGER deployment_contracts_2_frozen BEFORE UPDATE ON mint.deployment_contracts
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'server_id', 'canonical_text', 'sha256', 'url', 'url_sha256',
        'transport', 'auth_type', 'issuer', 'oauth_scopes', 'allowed_tools', 'image_digest',
        'source_commit', 'identity_kind', 'exec_contract_sha256', 'exec_contract_version',
        'exec_location', 'artifact_source', 'permissions');
