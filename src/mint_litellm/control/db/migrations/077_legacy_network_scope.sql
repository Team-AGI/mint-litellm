-- 이전 신청(네트워크를 직원이 정하지 않은 값)의 서버 이름. 단말에 내려주는 계약에서 network none을 뺀다.
CREATE FUNCTION mint.endpoint_legacy_network(p_instance text, p_key_token text)
RETURNS TABLE (server_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mint.endpoint_installs i
                   WHERE i.instance_id = p_instance AND i.key_token = p_key_token
                     AND i.revoked_at IS NULL) THEN RETURN; END IF;
    RETURN QUERY
    SELECT l.server_id::text FROM (
        SELECT DISTINCT ON (t.server_id) t.server_id, t.network_legacy FROM mint.intakes t
        WHERE t.instance_id = p_instance AND t.source = 'endpoint'
        ORDER BY t.server_id, t.created_at DESC) l
    WHERE l.network_legacy;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_legacy_network(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_legacy_network(text,text) TO mint_plugin;
