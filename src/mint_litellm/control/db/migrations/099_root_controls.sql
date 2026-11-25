-- Root 통제: Root 표지, 전역 정지 상태, 강제 조치 기록.
-- Root는 역할 값을 늘리지 않고 설정의 운영자 이름 목록으로 둔다. 기본 계정 root는 항상 Root다.
ALTER TABLE mint.settings
    ADD COLUMN root_operators text[] NOT NULL DEFAULT ARRAY['root'],
    ADD COLUMN halt_scope text CHECK (halt_scope IN ('all', 'local', 'freeze')),
    ADD COLUMN halt_reason text CHECK (halt_reason IS NULL OR length(halt_reason) BETWEEN 1 AND 500),
    ADD COLUMN halt_by text,
    ADD COLUMN halt_at timestamptz,
    ADD CONSTRAINT settings_halt_complete CHECK (
        (halt_scope IS NULL) = (halt_reason IS NULL)
        AND (halt_scope IS NULL) = (halt_by IS NULL)
        AND (halt_scope IS NULL) = (halt_at IS NULL));
GRANT UPDATE (root_operators, halt_scope, halt_reason, halt_by, halt_at) ON mint.settings
    TO mint_control;

-- 강제 조치 한 건 = 기록 한 행. 조치가 부른 기존 사건과 영향 수치, 전파 확인 시각을 남긴다.
CREATE TABLE mint.forced_actions (
    id            uuid PRIMARY KEY,
    instance_id   mint.ident NOT NULL,
    action        text NOT NULL CHECK (action IN (
        'halt', 'halt_lift', 'intake_reject', 'server_suspend', 'server_resume',
        'server_terminate', 'person_lockout', 'person_unlock', 'sessions_end')),
    target        text NOT NULL CHECK (length(target) BETWEEN 1 AND 300),
    reason        text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    actor         text NOT NULL,
    impact        jsonb NOT NULL DEFAULT '{}'::jsonb,
    refs          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    verified_at   timestamptz,
    propagation   jsonb NOT NULL DEFAULT '{}'::jsonb,
    undone_by     uuid REFERENCES mint.forced_actions (id),
    state_version bigint NOT NULL DEFAULT 1
);
CREATE INDEX forced_actions_recent ON mint.forced_actions (instance_id, created_at DESC);
CREATE TRIGGER forced_actions_2_frozen BEFORE UPDATE ON mint.forced_actions
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'id', 'instance_id', 'action', 'target', 'reason', 'actor', 'impact', 'refs',
        'created_at');
CREATE TRIGGER forced_actions_9_version BEFORE UPDATE ON mint.forced_actions
    FOR EACH ROW EXECUTE FUNCTION mint.bump_version();
GRANT SELECT, INSERT, UPDATE (verified_at, propagation, undone_by) ON mint.forced_actions
    TO mint_control;
GRANT SELECT ON mint.forced_actions TO mint_plugin;
