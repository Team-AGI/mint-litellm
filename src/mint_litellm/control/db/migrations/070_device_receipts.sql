-- 단말 보고로 확인한 적용 단계를 그 키 범위의 승인 신청 최신 결정 버전에 남긴다.
CREATE FUNCTION mint.endpoint_record_delivery(p_instance text, p_key_token text, p_stage text,
                                              p_servers text[])
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
      AND r.decision_version = (SELECT max(r2.decision_version) FROM mint.delivery_receipts r2
        WHERE r2.instance_id = r.instance_id AND r2.intake_id = r.intake_id
          AND r2.stage = 'approved')
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_record_delivery(text,text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_record_delivery(text,text,text,text[]) TO mint_plugin;
