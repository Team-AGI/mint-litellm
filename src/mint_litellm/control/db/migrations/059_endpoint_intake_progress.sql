-- 단말 신청 목록에 진행 단계와 막힌 검사·사유 코드를 더한다.
GRANT SELECT ON mint.intake_checks TO mint_endpoint_owner;

DROP FUNCTION mint.endpoint_my_intakes(text, text);
CREATE FUNCTION mint.endpoint_my_intakes(p_instance text, p_key_token text)
RETURNS TABLE(id uuid, server_id text, status text, decision text, reason text,
              created_at timestamptz, check_name text, reason_code text, pack_ready boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
#variable_conflict use_column
DECLARE k mint.endpoint_installs;
BEGIN
    SELECT * INTO k FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token;
    IF NOT FOUND OR k.revoked_at IS NOT NULL
       OR (k.expires_at IS NOT NULL AND k.expires_at <= clock_timestamp()) THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    SELECT t.id, t.server_id, t.status, t.decision, t.decision_reason, t.created_at,
           c."check", c.reason_code,
           EXISTS (SELECT 1 FROM mint.deployment_contracts d
                   WHERE d.instance_id = t.instance_id AND d.server_id = t.server_id
                     AND d.pack_sha256 IS NOT NULL)
    FROM mint.intakes t
    LEFT JOIN LATERAL (
        SELECT x."check", x.reason_code FROM mint.intake_checks x
        WHERE x.instance_id = t.instance_id AND x.intake_id = t.id AND x.result <> 'pass'
          AND x.attempt = (SELECT max(y.attempt) FROM mint.intake_checks y
                           WHERE y.instance_id = t.instance_id AND y.intake_id = t.id)
        ORDER BY (x.result = 'fail') DESC, x.ran_at LIMIT 1) c ON true
    WHERE t.instance_id = p_instance AND t.requested_by = k.user_id
      AND t.source IN ('staff', 'endpoint');
END $$;

GRANT CREATE ON SCHEMA mint TO mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_endpoint_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.endpoint_my_intakes(text,text) OWNER TO mint_endpoint_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_endpoint_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_my_intakes(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_my_intakes(text,text) TO mint_plugin;
