-- 검사 중인 신청도 철회할 수 있게 「검사 중 → 결정」을 열면서(081) 검사를 건너뛴 승인·반려까지
-- 열렸다. 검사 중에는 철회로만 닫는다. 승인·반려는 검사 결과가 나온 뒤에 한다.
CREATE OR REPLACE FUNCTION mint.guard_intake_early_close() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,mint AS $$ BEGIN
    IF OLD.status='received' AND NEW.status='decided'
       AND NEW.decision IS DISTINCT FROM 'withdrawn' AND NEW.decision IS DISTINCT FROM 'rejected'
    THEN RAISE EXCEPTION 'unreviewed application can only be rejected or withdrawn' USING ERRCODE='check_violation'; END IF;
    IF OLD.status='checking' AND NEW.status='decided' AND NEW.decision IS DISTINCT FROM 'withdrawn'
    THEN RAISE EXCEPTION 'an application under checking can only be withdrawn' USING ERRCODE='check_violation'; END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE TRIGGER intakes_0_early_close BEFORE UPDATE ON mint.intakes
    FOR EACH ROW EXECUTE FUNCTION mint.guard_intake_early_close();
