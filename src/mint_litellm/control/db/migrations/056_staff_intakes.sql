ALTER TABLE mint.intakes DROP CONSTRAINT intakes_source_check;
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_source_check
    CHECK (source IN ('submission', 'operator', 'staff'));
ALTER TABLE mint.intakes ADD COLUMN staff_request_sha256 text
    CHECK (staff_request_sha256 IS NULL OR staff_request_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE mint.intakes ADD COLUMN staff_registry_required boolean NOT NULL DEFAULT false;

-- 직원 로그인에는 표 권한을 주지 않고, 신청 생성만 하는 함수의 소유 역할을 확장한다.
GRANT SELECT ON mint.intakes, mint.deployment_contracts TO mint_staff_owner;
GRANT INSERT(id,instance_id,org_id,server_id,source,purpose,data_grade,allowed_resources,
    provider,owner_user_id,readiness,data_return_terms,requested_by,staff_request_sha256,
    staff_registry_required) ON mint.intakes TO mint_staff_owner;
GRANT INSERT(id,instance_id,server_id,canonical_text,sha256,url,url_sha256,transport,auth_type,
    proposed_by) ON mint.deployment_contracts TO mint_staff_owner;
GRANT INSERT(id,instance_id,server_id,status,url_sha256,transport,auth_type,registered_by)
    ON mint.servers TO mint_staff_owner;
GRANT INSERT(id,instance_id,kind,target_ref,idempotency_key) ON mint.jobs TO mint_staff_owner;

CREATE FUNCTION mint.staff_submit_intake(p_id uuid, p_payload jsonb, p_contract text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    s mint.console_sessions := mint.staff_active_session();
    iid text := mint.staff_instance();
    uid text := mint.staff_user();
    sid text := p_payload->>'server_id';
    target_url text := p_payload->>'url';
    transport text := p_payload->>'transport';
    orgs text[];
    org text;
    previous mint.intakes;
    server mint.servers;
    registry_required boolean := false;
    request_hash text := encode(sha256(convert_to(p_payload::text, 'UTF8')), 'hex');
    url_hash text := encode(sha256(convert_to(target_url, 'UTF8')), 'hex');
BEGIN
    IF s.last_verified_at <= clock_timestamp() - make_interval(secs =>
        coalesce(nullif(current_setting('mint.staff_verify_window_seconds', true), '')::int, 600))
    THEN RAISE EXCEPTION 'staff session needs verification' USING ERRCODE='insufficient_privilege';
    END IF;
    IF p_id IS NULL OR sid IS NULL OR sid !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
       OR transport NOT IN ('http', 'sse') OR transport IS NULL
       OR target_url IS NULL OR length(target_url) > 2048
       OR target_url !~ '^https?://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$'
       OR length(btrim(coalesce(p_payload->>'purpose',''))) NOT BETWEEN 1 AND 256
       OR coalesce(p_payload->>'data_grade','') NOT IN ('public','internal','confidential','restricted')
       OR jsonb_typeof(p_payload->'allowed_resources') IS DISTINCT FROM 'array'
       OR length(btrim(coalesce(p_payload->>'provider',''))) NOT BETWEEN 1 AND 256
       OR length(btrim(coalesce(p_payload->>'data_return_terms',''))) NOT BETWEEN 1 AND 2000
       OR length(btrim(coalesce(p_payload#>>'{readiness,credential_notice}',''))) NOT BETWEEN 1 AND 1000
       OR length(btrim(coalesce(p_payload#>>'{readiness,revocation_record}',''))) NOT BETWEEN 1 AND 1000
       OR (p_payload#>>'{readiness,audit_access_days}') !~ '^[0-9]{1,4}$'
       OR p_payload#>>'{readiness,audit_access_days}' IS NULL
       OR (p_payload#>>'{readiness,audit_access_days}')::int NOT BETWEEN 1 AND 3650
       OR p_payload->'readiness' IS NULL
    THEN RAISE EXCEPTION 'invalid intake input' USING ERRCODE='check_violation'; END IF;
    IF p_contract::jsonb IS DISTINCT FROM jsonb_build_object(
        'url',target_url,'transport',transport,'auth_type','none','issuer',NULL,
        'oauth_scopes','[]'::jsonb,'allowed_tools',NULL,'image_digest',NULL,'source_commit',NULL)
    THEN RAISE EXCEPTION 'invalid deployment proposal' USING ERRCODE='check_violation'; END IF;

    -- 같은 제출의 재전송만 재사용하며 다른 직원의 신청을 반환하지 않는다.
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':staff-intake:' || p_id, 0));
    SELECT * INTO previous FROM mint.intakes
      WHERE instance_id=iid AND id=p_id AND requested_by=uid AND source='staff';
    IF FOUND THEN
        IF previous.staff_request_sha256 IS DISTINCT FROM request_hash THEN
            RAISE EXCEPTION 'request identifier reused with different input' USING ERRCODE='check_violation';
        END IF;
        RETURN previous.id;
    END IF;
    SELECT array_agg(org_id ORDER BY org_id) INTO orgs FROM mint.org_bindings
      WHERE instance_id=iid AND subject_type='user' AND subject_id=uid;
    IF orgs IS NULL THEN
        SELECT array_agg(DISTINCT org_id ORDER BY org_id) INTO orgs FROM mint.org_bindings
          WHERE instance_id=iid AND subject_type='team'
          AND subject_id IN (SELECT jsonb_array_elements_text(s.team_ids));
    END IF;
    IF orgs IS NULL THEN
        SELECT ARRAY[default_org_id::text] INTO orgs FROM mint.settings WHERE instance_id=iid;
    END IF;
    IF cardinality(orgs) IS DISTINCT FROM 1 OR orgs[1] IS NULL THEN
        RAISE EXCEPTION 'one active organization is required' USING ERRCODE='insufficient_privilege';
    END IF;
    org := orgs[1];
    PERFORM 1 FROM mint.orgs WHERE instance_id=iid AND org_id=org AND status='active' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'inactive organization' USING ERRCODE='insufficient_privilege'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':staff-server:' || sid, 0));
    SELECT * INTO server FROM mint.servers WHERE instance_id=iid AND server_id=sid FOR SHARE;
    IF FOUND THEN
        IF server.status NOT IN ('pending','awaiting_approval','rejected')
           OR server.url_sha256 IS DISTINCT FROM url_hash
           OR server.transport IS DISTINCT FROM transport OR server.auth_type <> 'none'
        THEN RAISE EXCEPTION 'server cannot accept this introduction request' USING ERRCODE='check_violation'; END IF;
    ELSE
        registry_required := true;
        INSERT INTO mint.servers(id,instance_id,server_id,status,url_sha256,transport,auth_type,registered_by)
          VALUES(gen_random_uuid(),iid,sid,'pending',url_hash,transport,'none',uid);
    END IF;
    INSERT INTO mint.intakes(id,instance_id,org_id,server_id,source,purpose,data_grade,
      allowed_resources,provider,owner_user_id,readiness,data_return_terms,requested_by,staff_request_sha256,staff_registry_required)
      VALUES(p_id,iid,org,sid,'staff',p_payload->>'purpose',p_payload->>'data_grade',
      p_payload->'allowed_resources',p_payload->>'provider',uid,p_payload->'readiness',
      p_payload->>'data_return_terms',uid,request_hash,registry_required);
    INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,sha256,
      url,url_sha256,transport,auth_type,proposed_by)
      VALUES(p_id,iid,sid,p_contract,encode(sha256(convert_to(p_contract,'UTF8')),'hex'),
      target_url,url_hash,transport,'none',uid);
    INSERT INTO mint.jobs(id,instance_id,kind,target_ref,idempotency_key)
      VALUES(gen_random_uuid(),iid,'intake_run',p_id::text || '/staff','intake_run:' || p_id || ':1');
    PERFORM mint.staff_event('intake_received','intake',p_id::text,1,uid,
      jsonb_build_object('intake_id',p_id,'server_id',sid,'source','staff','requested_by',uid));
    RETURN p_id;
END $$;
GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.staff_submit_intake(uuid,jsonb,text) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.staff_submit_intake(uuid,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_submit_intake(uuid,jsonb,text) TO mint_staff;
