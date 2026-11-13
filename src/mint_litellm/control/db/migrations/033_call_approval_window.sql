-- 호출별 승인의 사용 기간. 승인할 때 1회(기본, 열이 비어 있음)·10분·30분 중 고른다.
-- 기간을 고른 승인은 소비되지 않고 valid_until까지 같은 결속(주체·서버·도구·인자 지문·계약·대상)의
-- 호출에 되풀이해 쓰이며, 쓸 때마다 사용 표에 호출 식별자별 한 행이 남는다. 승인 행은 쓸 때 바뀌지
-- 않으므로 상태 버전과 상태 세대도 움직이지 않고, 취소·만료만 행을 바꾼다.
ALTER TABLE mint.call_approvals
    ADD COLUMN window_minutes smallint CHECK (window_minutes IN (10, 30)),
    ADD COLUMN valid_until timestamptz,
    ADD CONSTRAINT call_approvals_window_pair
        CHECK ((window_minutes IS NULL) = (valid_until IS NULL)),
    ADD CONSTRAINT call_approvals_window_state
        CHECK (valid_until IS NULL
               OR (status IN ('approved', 'cancelled', 'expired') AND approved_by IS NOT NULL));

-- 기간은 대기에서 승인으로 넘어가는 전이에서만 정해지고, 한 번 정해지면 바뀌지 않는다.
CREATE FUNCTION mint.check_call_approval_window() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.valid_until IS DISTINCT FROM OLD.valid_until
        OR NEW.window_minutes IS DISTINCT FROM OLD.window_minutes)
       AND NOT (OLD.status = 'pending' AND NEW.status = 'approved') THEN
        RAISE EXCEPTION 'the validity window can only be set when approving'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER call_approvals_4_window BEFORE UPDATE ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.check_call_approval_window();

DROP TRIGGER call_approvals_3_once ON mint.call_approvals;
CREATE TRIGGER call_approvals_3_once BEFORE UPDATE ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.set_once(
        'approved_by', 'consumed_invocation_id', 'window_minutes', 'valid_until');

-- 기간 승인의 사용 기록. 추가만 되고 고치거나 지울 수 없으며 한 호출은 한 번만 기록된다.
CREATE TABLE mint.call_approval_uses (
    instance_id      mint.ident NOT NULL,
    call_approval_id uuid NOT NULL REFERENCES mint.call_approvals (id),
    invocation_id    uuid NOT NULL,
    used_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (instance_id, invocation_id)
);
CREATE INDEX call_approval_uses_by_approval ON mint.call_approval_uses (call_approval_id);

CREATE TRIGGER call_approval_uses_1_append_only BEFORE UPDATE OR DELETE
    ON mint.call_approval_uses
    FOR EACH ROW EXECUTE FUNCTION mint.reject_mutation();
CREATE TRIGGER call_approval_uses_2_truncate BEFORE TRUNCATE ON mint.call_approval_uses
    FOR EACH STATEMENT EXECUTE FUNCTION mint.reject_mutation();

REVOKE ALL ON mint.call_approval_uses FROM PUBLIC;
GRANT SELECT, INSERT ON mint.call_approval_uses TO mint_plugin;
GRANT SELECT ON mint.call_approval_uses TO mint_control;
