-- 기간 승인은 만료가 가까울 때 같은 기간만큼 한 번 연장할 수 있다. 연장한 사람과 시각을 행에 남기고,
-- 한 번 채워진 값은 바뀌지 않는다. 만료 시각은 승인할 때와 이 연장에서만 바뀐다.
ALTER TABLE mint.call_approvals
    ADD COLUMN extended_by text,
    ADD COLUMN extended_at timestamptz,
    ADD CONSTRAINT call_approvals_extended_pair
        CHECK ((extended_by IS NULL) = (extended_at IS NULL)),
    ADD CONSTRAINT call_approvals_extended_window
        CHECK (extended_at IS NULL OR window_minutes IS NOT NULL);

CREATE OR REPLACE FUNCTION mint.check_call_approval_window() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.window_minutes IS DISTINCT FROM OLD.window_minutes
       AND NOT (OLD.status = 'pending' AND NEW.status = 'approved') THEN
        RAISE EXCEPTION 'the validity window can only be set when approving'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.valid_until IS DISTINCT FROM OLD.valid_until
       AND NOT (OLD.status = 'pending' AND NEW.status = 'approved')
       AND NOT (OLD.status = 'approved' AND NEW.status = 'approved'
                AND OLD.extended_at IS NULL AND NEW.extended_at IS NOT NULL
                AND NEW.valid_until > OLD.valid_until) THEN
        RAISE EXCEPTION 'the validity window can only be set when approving or extended once'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER call_approvals_3_once ON mint.call_approvals;
CREATE TRIGGER call_approvals_3_once BEFORE UPDATE ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.set_once(
        'approved_by', 'consumed_invocation_id', 'window_minutes', 'extended_by', 'extended_at');
