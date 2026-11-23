-- MINT 콘솔에서 LiteLLM 화면으로 넘어가는 1회용 인계 코드. 코드는 SHA-256만 저장한다.
-- 소비한 행은 LiteLLM이 연 화면 세션의 기록이기도 하다(MINT 로그아웃 때 그 세션을 지운다).
CREATE TABLE mint.ui_handoffs (
    code_hash    text PRIMARY KEY CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    instance_id  mint.ident NOT NULL,
    session_hash text NOT NULL CHECK (session_hash ~ '^[0-9a-f]{64}$'),
    user_id      text NOT NULL CHECK (length(user_id) > 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,
    revoked_at   timestamptz,
    CHECK (revoked_at IS NULL OR consumed_at IS NOT NULL)
);
CREATE INDEX ui_handoffs_open ON mint.ui_handoffs (instance_id, session_hash)
    WHERE consumed_at IS NOT NULL AND revoked_at IS NULL;

REVOKE ALL ON mint.ui_handoffs FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.ui_handoffs TO mint_control;
