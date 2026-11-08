-- 운영자 삭제(만료 설정·앞당김)와 역할 강등을 부정 상태로 내보낸다.
-- DB를 옛 시점으로 되돌렸을 때 권한을 잃었던 운영자가 되살아나는 일을 되돌림 판정이 잡게 한다.
-- 운영자 표는 세대 트리거가 없으므로 내보내기 작업을 만들기 전에 세대를 올려 내보내기 키가 새로
-- 만들어지게 한다.

-- 역할 순위: admin > approver > viewer
CREATE FUNCTION mint.operator_rank(p_role text) RETURNS integer
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE p_role WHEN 'admin' THEN 3 WHEN 'approver' THEN 2 ELSE 1 END
$$;

REVOKE ALL ON FUNCTION mint.operator_rank(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.operator_rank(text) TO mint_plugin, mint_control;

CREATE FUNCTION mint.enqueue_export_operator() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = mint, pg_catalog AS $$
DECLARE
    ep bigint;
BEGIN
    INSERT INTO mint.state_epoch AS e (instance_id, epoch) VALUES (NEW.instance_id, 1)
    ON CONFLICT (instance_id) DO UPDATE SET epoch = e.epoch + 1
    RETURNING e.epoch INTO ep;
    INSERT INTO mint.jobs (id, instance_id, kind, target_ref, idempotency_key)
    VALUES (gen_random_uuid(), NEW.instance_id, 'export_negative_state', 'negative_state',
            'export_negative:' || ep)
    ON CONFLICT (instance_id, idempotency_key) DO NOTHING;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER operators_zz_export AFTER UPDATE ON mint.operators
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN ((OLD.expires_at IS NULL AND NEW.expires_at IS NOT NULL)
          OR NEW.expires_at < OLD.expires_at
          OR mint.operator_rank(NEW.role) < mint.operator_rank(OLD.role))
    EXECUTE FUNCTION mint.enqueue_export_operator();

-- 되돌림 판정(플러그인 포함)이 읽는 운영자 상태. 토큰 해시는 뺀다.
CREATE VIEW mint.operator_state AS
    SELECT instance_id, name, role, user_id, expires_at, state_version FROM mint.operators;
GRANT SELECT ON mint.operator_state TO mint_plugin, mint_control;
