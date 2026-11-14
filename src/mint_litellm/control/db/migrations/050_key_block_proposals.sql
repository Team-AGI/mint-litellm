-- LiteLLM 가상 키 차단 제안. MINT가 탐지한 강한 증거를 사람이 승인한 뒤에만 LiteLLM의 차단으로 옮긴다.
-- 증거에는 탐지 종류·건수·사건 식별자만 두고 비밀 값은 두지 않는다.
-- status: proposed(승인 대기) approved(승인됨, 작업 실행기가 차단 중) applied(차단 확인됨)
--         failed(차단 실패) rejected expired unblocking(해제 중) unblocked(해제됨)
CREATE TABLE mint.key_block_proposals (
    id             uuid PRIMARY KEY,
    instance_id    mint.ident NOT NULL,
    status         text NOT NULL DEFAULT 'proposed' CHECK (status IN (
        'proposed', 'approved', 'applied', 'failed', 'rejected', 'expired', 'unblocking',
        'unblocked')),
    signal         text NOT NULL CHECK (length(signal) BETWEEN 1 AND 64),
    key_token      text NOT NULL CHECK (length(key_token) BETWEEN 1 AND 128),
    key_alias      text,
    user_id        text,
    team_id        text,
    team_key_count integer CHECK (team_key_count >= 0),
    team_member_count integer CHECK (team_member_count >= 0),
    evidence       jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    blocked_at_proposal boolean NOT NULL DEFAULT false,
    scope          text NOT NULL DEFAULT 'key' CHECK (scope IN ('key', 'team')),
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    state_version  bigint NOT NULL DEFAULT 1,
    decided_by     text,
    decided_at     timestamptz,
    decision_reason text CHECK (length(decision_reason) <= 500),
    -- MINT가 차단한 표지: 차단을 확인한 시각과 그때 LiteLLM 키 객체의 갱신 시각.
    mint_blocked   boolean NOT NULL DEFAULT false,
    applied_at     timestamptz,
    marker_updated_at text,
    last_error     text CHECK (length(last_error) <= 200),
    unblocked_by   text,
    unblocked_at   timestamptz,
    unblock_reason text CHECK (length(unblock_reason) <= 500),
    unblock_acknowledged boolean NOT NULL DEFAULT false
);

CREATE INDEX key_block_proposals_by_key ON mint.key_block_proposals (instance_id, key_token, created_at);
CREATE UNIQUE INDEX key_block_proposals_open ON mint.key_block_proposals (instance_id, key_token)
    WHERE status IN ('proposed', 'approved', 'unblocking');

CREATE TRIGGER key_block_proposals_2_frozen BEFORE UPDATE ON mint.key_block_proposals
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'signal', 'key_token', 'evidence', 'created_at');
CREATE TRIGGER key_block_proposals_9_version BEFORE UPDATE ON mint.key_block_proposals
    FOR EACH ROW EXECUTE FUNCTION mint.bump_version();

REVOKE ALL ON mint.key_block_proposals FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.key_block_proposals TO mint_control;
