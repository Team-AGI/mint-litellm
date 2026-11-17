-- 같은 직원 세션의 동시 요청이 세션 갱신에서 교착하지 않게 한다.
-- staff_active_session()이 행을 FOR SHARE로 잡은 뒤 UPDATE하면, 두 요청이 서로의 공유 잠금 때문에
-- 배타 잠금으로 올라가지 못해 교착한다. 다른 요청이 잡고 있는 행은 건너뛴다(그 요청이 갱신한다).
CREATE OR REPLACE FUNCTION mint.staff_touch_session(p_id_hash text, p_idle_expiry timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
BEGIN
    PERFORM mint.staff_active_session();
    IF p_id_hash IS DISTINCT FROM current_setting('mint.staff_session_id_hash', true)
       OR p_idle_expiry IS NULL OR p_idle_expiry <= clock_timestamp() THEN
        RAISE EXCEPTION 'invalid session renewal' USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE mint.console_sessions
    SET last_seen_at = clock_timestamp(), idle_expiry = least(p_idle_expiry, absolute_expiry)
    WHERE id_hash = (SELECT id_hash FROM mint.console_sessions WHERE id_hash = p_id_hash
                     FOR UPDATE SKIP LOCKED);
END $$;
