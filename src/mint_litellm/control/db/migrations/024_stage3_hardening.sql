-- 사건 서명과 강등 표지.
--
-- 1) 봉인 배치의 끝 해시를 내보내기 키로 서명한다. 해시 연쇄만으로는 DB를 쓸 수 있는 쪽이 연쇄를
--    통째로 다시 계산할 수 있지만, 서명은 키 없이 만들 수 없다. 서명이 없는 옛 배치는 그대로 둔다.
ALTER TABLE mint.seal_batches
    ADD COLUMN tail_sig   bytea CHECK (tail_sig IS NULL OR length(tail_sig) = 32),
    ADD COLUMN sig_key_id text CHECK (sig_key_id IS NULL OR sig_key_id ~ '^[0-9a-f]{16}$'),
    ADD CONSTRAINT seal_batches_sig_pair CHECK ((tail_sig IS NULL) = (sig_key_id IS NULL));

-- 2) 운영자 강등 표지: 역할 순위가 내려간 UPDATE가 강등 시각을 남긴다. 승격해도 지우지 않는다
--    (되돌림 복원이 승격·연장을 되살리지 않고 부정 방향만 적용하는 규칙과 같은 방향이다).
--    복원이 파일의 표지를 채울 때는 값이 이미 바뀌어 있으므로 덮어쓰지 않는다.
ALTER TABLE mint.operators ADD COLUMN demoted_at timestamptz;

CREATE FUNCTION mint.mark_operator_demotion() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
BEGIN
    IF mint.operator_rank(NEW.role) < mint.operator_rank(OLD.role)
       AND NEW.demoted_at IS NOT DISTINCT FROM OLD.demoted_at THEN
        NEW.demoted_at := now();
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION mint.mark_operator_demotion() FROM PUBLIC;

CREATE TRIGGER operators_1_demotion BEFORE UPDATE OF role ON mint.operators
    FOR EACH ROW EXECUTE FUNCTION mint.mark_operator_demotion();

-- 되돌림 판정이 읽는 운영자 상태에 표지를 더한다(열 끝에 덧붙인다).
CREATE OR REPLACE VIEW mint.operator_state AS
    SELECT instance_id, name, role, user_id, expires_at, state_version,
           CASE WHEN expires_at IS NULL
                THEN encode(sha256(convert_to(token_hash, 'UTF8')), 'hex') END AS token_fp,
           demoted_at
    FROM mint.operators;
