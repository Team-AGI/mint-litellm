-- 하네스 내장 도구(셸·파일 편집·웹)의 호출별 승인. 내장 도구는 서버 행 없이 가상 서버
-- (builtin:claude, builtin:codex) 아래에서 판정하므로, 호출별 승인의 서버 외래 키를 같은 보장의
-- 트리거로 바꾼다: 등록된 서버이거나 가상 서버여야 한다.
DO $$
DECLARE
    v_name text;
BEGIN
    SELECT c.conname INTO v_name
    FROM pg_constraint c
    WHERE c.conrelid = 'mint.call_approvals'::regclass AND c.contype = 'f'
      AND c.confrelid = 'mint.servers'::regclass;
    IF v_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE mint.call_approvals DROP CONSTRAINT %I', v_name);
    END IF;
END $$;

CREATE FUNCTION mint.check_call_approval_server() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.server_id NOT IN ('builtin:claude', 'builtin:codex') AND NOT EXISTS (
        SELECT 1 FROM mint.servers
        WHERE instance_id = NEW.instance_id AND server_id = NEW.server_id) THEN
        RAISE EXCEPTION 'call_approvals.server_id % is not a registered server', NEW.server_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER call_approvals_0_server BEFORE INSERT ON mint.call_approvals
    FOR EACH ROW EXECUTE FUNCTION mint.check_call_approval_server();
