-- 단말이 받은 결정 버전을 그대로 받아 그 버전에 남긴다(버전이 없으면 최신 버전).
DROP FUNCTION mint.endpoint_record_delivery(text,text,text,text[]);
CREATE FUNCTION mint.endpoint_record_delivery(p_instance text, p_key_token text, p_stage text,
                                              p_servers text[], p_versions jsonb DEFAULT NULL)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE k mint.endpoint_installs; n integer;
BEGIN
    IF p_stage NOT IN ('device_received', 'started', 'discovered', 'first_response') THEN
        RAISE EXCEPTION 'unknown delivery stage' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO k FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token AND i.revoked_at IS NULL;
    IF NOT FOUND THEN RETURN 0; END IF;
    INSERT INTO mint.delivery_receipts (instance_id, intake_id, decision_version, stage, target)
    SELECT DISTINCT r.instance_id, r.intake_id, r.decision_version, p_stage, p_key_token
    FROM mint.approvals a
    JOIN mint.delivery_receipts r ON r.instance_id = a.instance_id AND r.stage = 'approved'
      AND r.intake_id::text = a.basis->>'intake_id'
    WHERE a.instance_id = p_instance AND a.status = 'active' AND a.valid_until > now()
      AND a.server_id = ANY (p_servers)
      AND ((a.scope_type = 'key' AND a.scope_id = p_key_token)
        OR (a.scope_type = 'user' AND a.scope_id = k.user_id)
        OR (a.scope_type = 'team' AND a.scope_id = k.team_id))
      AND r.decision_version = COALESCE((p_versions->>a.server_id)::bigint,
        (SELECT max(r2.decision_version) FROM mint.delivery_receipts r2
          WHERE r2.instance_id = r.instance_id AND r2.intake_id = r.intake_id
            AND r2.stage = 'approved'))
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_record_delivery(text,text,text,text[],jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_record_delivery(text,text,text,text[],jsonb) TO mint_plugin;

-- 이 키의 범위에 닿는 서버별 최신 결정 버전(단말에 내려주는 목록에 싣는다).
CREATE FUNCTION mint.endpoint_decision_versions(p_instance text, p_key_token text, p_servers text[])
RETURNS TABLE (server_id text, decision_version bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE k mint.endpoint_installs;
BEGIN
    SELECT * INTO k FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token AND i.revoked_at IS NULL;
    IF NOT FOUND THEN RETURN; END IF;
    RETURN QUERY
    SELECT a.server_id::text, max(r.decision_version)
    FROM mint.approvals a
    JOIN mint.delivery_receipts r ON r.instance_id = a.instance_id AND r.stage = 'approved'
      AND r.intake_id::text = a.basis->>'intake_id'
    WHERE a.instance_id = p_instance AND a.status = 'active' AND a.valid_until > now()
      AND a.server_id = ANY (p_servers)
      AND ((a.scope_type = 'key' AND a.scope_id = p_key_token)
        OR (a.scope_type = 'user' AND a.scope_id = k.user_id)
        OR (a.scope_type = 'team' AND a.scope_id = k.team_id))
    GROUP BY a.server_id;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_decision_versions(text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_decision_versions(text,text,text[]) TO mint_plugin;
