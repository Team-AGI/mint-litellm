-- 정책 시험 적용: 후보 판본을 활성 판본 옆에서 평가하고 판정이 달라지는 호출만 센다.
-- 인스턴스마다 한 행이며 시험 판본이 없으면 version_id가 비어 있다. 판본 행은 정책 판본 표에
-- validated로 등록되어 있고, 적용은 평소 활성화 경로를 그대로 쓴다. 바뀔 때마다
-- state_version이 늘어 사건 키가 겹치지 않는다.
CREATE TABLE mint.policy_shadow (
    instance_id   mint.ident PRIMARY KEY,
    version_id    mint.ident,
    bundle_sha256 text CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    set_by        text,
    set_at        timestamptz,
    state_version bigint NOT NULL DEFAULT 1,
    FOREIGN KEY (instance_id, version_id) REFERENCES mint.policy_versions (instance_id, id),
    CHECK ((version_id IS NULL) = (bundle_sha256 IS NULL))
);

-- 판정이 달라진 호출의 개수. (서버, 도구, 활성 결과, 시험 결과, 사유) 조합마다 한 행이고
-- samples에는 처음 만난 호출 식별자를 다섯 개까지만 둔다.
CREATE TABLE mint.policy_shadow_results (
    instance_id   mint.ident NOT NULL,
    version_id    mint.ident NOT NULL,
    server_id     text NOT NULL CHECK (length(server_id) BETWEEN 1 AND 256),
    tool          text NOT NULL CHECK (length(tool) BETWEEN 1 AND 256),
    active_result text NOT NULL CHECK (active_result IN ('Allow', 'Alert', 'RequireApproval', 'Block')),
    shadow_result text NOT NULL CHECK (shadow_result IN ('Allow', 'Alert', 'RequireApproval', 'Block')),
    active_reason text NOT NULL CHECK (length(active_reason) <= 256),
    shadow_reason text NOT NULL CHECK (length(shadow_reason) <= 256),
    calls         bigint NOT NULL CHECK (calls > 0),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    samples       text[] NOT NULL DEFAULT '{}' CHECK (cardinality(samples) <= 5),
    PRIMARY KEY (instance_id, version_id, server_id, tool, active_result, shadow_result,
                 active_reason, shadow_reason),
    FOREIGN KEY (instance_id, version_id) REFERENCES mint.policy_versions (instance_id, id)
);

-- 판본마다 평가한 호출 수, 판정이 같았던 수, 평가하지 못한 수(오류), 건너뛴 수(표본·상한).
CREATE TABLE mint.policy_shadow_stats (
    instance_id mint.ident NOT NULL,
    version_id  mint.ident NOT NULL,
    evaluated   bigint NOT NULL DEFAULT 0 CHECK (evaluated >= 0),
    same        bigint NOT NULL DEFAULT 0 CHECK (same >= 0),
    errors      bigint NOT NULL DEFAULT 0 CHECK (errors >= 0),
    skipped     bigint NOT NULL DEFAULT 0 CHECK (skipped >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, version_id),
    FOREIGN KEY (instance_id, version_id) REFERENCES mint.policy_versions (instance_id, id)
);

CREATE TRIGGER policy_shadow_results_2_frozen BEFORE UPDATE ON mint.policy_shadow_results
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'version_id', 'server_id', 'tool', 'active_result', 'shadow_result',
        'active_reason', 'shadow_reason');
CREATE TRIGGER policy_shadow_stats_2_frozen BEFORE UPDATE ON mint.policy_shadow_stats
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns('instance_id', 'version_id');

REVOKE ALL ON mint.policy_shadow, mint.policy_shadow_results, mint.policy_shadow_stats
    FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.policy_shadow TO mint_control;
GRANT SELECT ON mint.policy_shadow TO mint_plugin;
GRANT SELECT ON mint.policy_shadow_results, mint.policy_shadow_stats TO mint_control;
GRANT SELECT, INSERT, UPDATE ON mint.policy_shadow_results, mint.policy_shadow_stats
    TO mint_plugin;
