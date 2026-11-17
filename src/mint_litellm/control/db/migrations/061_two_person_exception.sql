-- 예외 승인의 두 번째 승인 대기. 첫 승인자가 낸 결정 값을 담고, 다른 승인자가 확인하면 승인 처리로 넘어간다.
-- status: pending(확인 대기) confirmed(승인됨) rejected(거절) expired(만료) superseded(새 요청으로 대체)
CREATE TABLE mint.exception_holds (
    id             uuid PRIMARY KEY,
    instance_id    mint.ident NOT NULL,
    intake_id      uuid NOT NULL,
    status         text NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'confirmed', 'rejected', 'expired', 'superseded')),
    first_name     text NOT NULL,
    first_role     text NOT NULL,
    first_user_id  text NOT NULL,
    params         jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object'),
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_by      text,
    closed_at      timestamptz
);

CREATE INDEX exception_holds_by_intake ON mint.exception_holds (instance_id, intake_id, created_at);
CREATE UNIQUE INDEX exception_holds_open ON mint.exception_holds (instance_id, intake_id)
    WHERE status = 'pending';

REVOKE ALL ON mint.exception_holds FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON mint.exception_holds TO mint_control;
