-- 단말이 로컬 서버가 시작되지 않았다고 알리면 그 사유를 영수증 단계로 남긴다.
ALTER TABLE mint.delivery_receipts DROP CONSTRAINT delivery_receipts_stage_check;
ALTER TABLE mint.delivery_receipts ADD CONSTRAINT delivery_receipts_stage_check
    CHECK (stage IN ('approved', 'registry_active', 'key_applied', 'device_received', 'started',
                     'start_failed', 'discovered', 'first_response'));
ALTER TABLE mint.delivery_receipts ADD COLUMN reason text CHECK (length(reason) <= 80);

DROP FUNCTION mint.endpoint_record_delivery(text,text,text,text[],jsonb);
CREATE FUNCTION mint.endpoint_record_delivery(p_instance text, p_key_token text, p_stage text,
                                              p_servers text[], p_versions jsonb DEFAULT NULL,
                                              p_reasons jsonb DEFAULT NULL)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE k mint.endpoint_installs; n integer;
BEGIN
    IF p_stage NOT IN ('device_received', 'started', 'start_failed', 'discovered',
                       'first_response') THEN
        RAISE EXCEPTION 'unknown delivery stage' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO k FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token AND i.revoked_at IS NULL;
    IF NOT FOUND THEN RETURN 0; END IF;
    INSERT INTO mint.delivery_receipts (instance_id, intake_id, decision_version, stage, target,
                                        reason)
    SELECT DISTINCT r.instance_id, r.intake_id, r.decision_version, p_stage, p_key_token,
           left(p_reasons->>a.server_id, 80)
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
REVOKE ALL ON FUNCTION mint.endpoint_record_delivery(text,text,text,text[],jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_record_delivery(text,text,text,text[],jsonb,jsonb)
    TO mint_plugin;
