-- 저장소 주소로 신청하는 로컬 MCP: 신청 명세에 저장소 출처(git·npm)를 받고, 직원 화면 세션으로도
-- 로컬 신청을 만든다. 신청 출처는 단말 신청(endpoint)과 같아 검사·묶음·승인·PC 반영이 그대로
-- 이어진다. 화면에서 만든 신청에는 단말 키가 없다.
ALTER TABLE mint.intakes DROP CONSTRAINT intakes_endpoint_key_shape;
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_endpoint_key_shape
    CHECK (source = 'endpoint' OR endpoint_key_token IS NULL);

GRANT INSERT(identity_kind) ON mint.servers TO mint_staff_owner;
GRANT INSERT(identity_kind, pack_spec) ON mint.deployment_contracts TO mint_staff_owner;
GRANT EXECUTE ON FUNCTION mint.endpoint_payload_valid(jsonb), mint.endpoint_env_valid(jsonb,jsonb)
    TO mint_staff_owner;

CREATE OR REPLACE FUNCTION mint.endpoint_payload_valid(p jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE spec jsonb; e jsonb; net text;
BEGIN
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR octet_length(p::text) > 262144 THEN RETURN false; END IF;
    IF coalesce(p->>'server_id', '') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' THEN RETURN false; END IF;
    IF jsonb_typeof(p->'purpose') IS DISTINCT FROM 'string'
       OR length(btrim(p->>'purpose')) NOT BETWEEN 1 AND 256 THEN RETURN false; END IF;
    IF coalesce(p->>'data_grade', '') NOT IN ('public', 'internal', 'confidential', 'restricted')
    THEN RETURN false; END IF;
    IF p ? 'resources' AND (jsonb_typeof(p->'resources') IS DISTINCT FROM 'array'
       OR length(p->>'resources') > 4000) THEN RETURN false; END IF;
    spec := p->'spec';
    IF jsonb_typeof(spec) IS DISTINCT FROM 'object'
       OR coalesce(spec->>'index', '') NOT IN ('pypi', 'git', 'npm')
       OR coalesce(spec->>'name', '') !~ '^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$'
       OR coalesce(spec->>'version', '') !~ '^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$'
       OR coalesce(spec->>'command', '') !~ '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,127}$'
    THEN RETURN false; END IF;
    -- 저장소 출처는 코드 호스트의 저장소 주소와 40자 커밋으로 고정한 것만 받는다.
    IF spec->>'index' IN ('git', 'npm') AND (
       coalesce(spec->>'git', '') !~
         '^https://(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$'
       OR spec->>'version' !~ '^[0-9a-f]{40}$') THEN RETURN false; END IF;
    IF spec ? 'extras' THEN
        IF jsonb_typeof(spec->'extras') IS DISTINCT FROM 'array' OR jsonb_array_length(spec->'extras') > 16
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(spec->'extras') LOOP
            IF jsonb_typeof(e) <> 'string' OR (e #>> '{}') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
            THEN RETURN false; END IF;
        END LOOP;
    END IF;
    IF spec ? 'argv' THEN
        IF jsonb_typeof(spec->'argv') IS DISTINCT FROM 'array' OR jsonb_array_length(spec->'argv') > 64
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(spec->'argv') LOOP
            IF jsonb_typeof(e) <> 'string' OR length(e #>> '{}') > 4096
            THEN RETURN false; END IF;
        END LOOP;
    END IF;
    IF p ? 'file_access' THEN
        IF jsonb_typeof(p->'file_access') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'file_access') > 64
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(p->'file_access') LOOP
            IF jsonb_typeof(e) <> 'object' OR jsonb_typeof(e->'path') IS DISTINCT FROM 'string'
               OR length(e->>'path') NOT BETWEEN 1 AND 1024
               OR coalesce(e->>'mode', 'ro') NOT IN ('ro', 'rw') THEN RETURN false; END IF;
        END LOOP;
    END IF;
    net := p->>'network';
    IF net IS NOT NULL AND net NOT IN ('none', 'hosts') THEN RETURN false; END IF;
    IF p ? 'allowed_hosts' AND (jsonb_typeof(p->'allowed_hosts') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p->'allowed_hosts') > 64) THEN RETURN false; END IF;
    IF (net IS NOT DISTINCT FROM 'hosts') <> (coalesce(jsonb_array_length(p->'allowed_hosts'), 0) > 0) THEN RETURN false; END IF;
    FOR e IN SELECT * FROM jsonb_array_elements(coalesce(p->'allowed_hosts', '[]')) LOOP
        IF jsonb_typeof(e) <> 'string' OR length(e #>> '{}') NOT BETWEEN 1 AND 255
        THEN RETURN false; END IF;
    END LOOP;
    IF p ? 'env_names' THEN
        IF jsonb_typeof(p->'env_names') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'env_names') > 64
        THEN RETURN false; END IF;
        FOR e IN SELECT * FROM jsonb_array_elements(p->'env_names') LOOP
            IF jsonb_typeof(e) <> 'string' OR (e #>> '{}') !~ '^[A-Za-z_][A-Za-z0-9_]{0,127}$'
            THEN RETURN false; END IF;
        END LOOP;
    END IF;
    IF p ? 'observed_tools' AND (jsonb_typeof(p->'observed_tools') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p->'observed_tools') > 200) THEN RETURN false; END IF;
    IF p ? 'env' AND NOT mint.endpoint_env_valid(p->'env', p->'file_access') THEN RETURN false; END IF;
    RETURN true;
END $$;

CREATE FUNCTION mint.staff_submit_local_intake(p_id uuid, p_payload jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    s mint.console_sessions := mint.staff_active_session();
    iid text := mint.staff_instance();
    uid text := mint.staff_user();
    sid text := p_payload->>'server_id';
    orgs text[];
    org text;
    previous mint.intakes;
    server mint.servers;
    pack jsonb;
    running integer;
    request_hash text := encode(sha256(convert_to(p_payload::text, 'UTF8')), 'hex');
BEGIN
    IF s.last_verified_at <= clock_timestamp() - make_interval(secs =>
        coalesce(nullif(current_setting('mint.staff_verify_window_seconds', true), '')::int, 600))
    THEN RAISE EXCEPTION 'staff session needs verification' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_id IS NULL OR NOT mint.endpoint_payload_valid(p_payload)
    THEN RAISE EXCEPTION 'invalid intake input' USING ERRCODE = 'check_violation'; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':staff-intake:' || p_id, 0));
    SELECT * INTO previous FROM mint.intakes
      WHERE instance_id = iid AND id = p_id AND requested_by = uid AND source = 'endpoint';
    IF FOUND THEN
        IF previous.staff_request_sha256 IS DISTINCT FROM request_hash THEN
            RAISE EXCEPTION 'request identifier reused with different input'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN previous.id;
    END IF;
    SELECT array_agg(org_id ORDER BY org_id) INTO orgs FROM mint.org_bindings
      WHERE instance_id = iid AND subject_type = 'user' AND subject_id = uid;
    IF orgs IS NULL THEN
        SELECT array_agg(DISTINCT org_id ORDER BY org_id) INTO orgs FROM mint.org_bindings
          WHERE instance_id = iid AND subject_type = 'team'
          AND subject_id IN (SELECT jsonb_array_elements_text(s.team_ids));
    END IF;
    IF orgs IS NULL THEN
        SELECT ARRAY[default_org_id::text] INTO orgs FROM mint.settings WHERE instance_id = iid;
    END IF;
    IF cardinality(orgs) IS DISTINCT FROM 1 OR orgs[1] IS NULL THEN
        RAISE EXCEPTION 'one active organization is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    org := orgs[1];
    PERFORM 1 FROM mint.orgs WHERE instance_id = iid AND org_id = org AND status = 'active' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'inactive organization' USING ERRCODE = 'insufficient_privilege'; END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-server:' || sid, 0));
    SELECT * INTO server FROM mint.servers WHERE instance_id = iid AND server_id = sid FOR SHARE;
    IF FOUND THEN
        IF server.identity_kind <> 'stdio'
           OR server.status NOT IN ('pending', 'awaiting_approval', 'rejected')
           OR EXISTS (SELECT 1 FROM mint.intakes WHERE instance_id = iid AND server_id = sid
                      AND status <> 'decided')
        THEN RAISE EXCEPTION 'server cannot accept this introduction request'
            USING ERRCODE = 'unique_violation'; END IF;
    END IF;
    SELECT count(*) INTO running FROM mint.intakes WHERE instance_id = iid AND requested_by = uid
      AND source IN ('staff', 'endpoint') AND status IN ('received', 'checking');
    IF running >= 3 THEN
        RAISE EXCEPTION 'MINT-QUOTA: intake limit reached' USING ERRCODE = 'check_violation';
    END IF;

    IF server.id IS NULL THEN
        INSERT INTO mint.servers(id, instance_id, server_id, status, transport, auth_type,
          identity_kind, registered_by)
          VALUES (gen_random_uuid(), iid, sid, 'pending', 'stdio', 'none', 'stdio', uid);
    END IF;
    pack := (p_payload->'spec') || jsonb_build_object(
        'file_access', coalesce(p_payload->'file_access', '[]'::jsonb),
        'network', p_payload->>'network',
        'allowed_hosts', coalesce(p_payload->'allowed_hosts', '[]'::jsonb),
        'env_names', coalesce(p_payload->'env_names', '[]'::jsonb),
        'env', coalesce(p_payload->'env', '{}'::jsonb),
        'observed_tools', coalesce(p_payload->'observed_tools', '[]'::jsonb));
    INSERT INTO mint.intakes(id, instance_id, org_id, server_id, source, purpose, data_grade,
      allowed_resources, provider, owner_user_id, readiness, data_return_terms, requested_by,
      staff_request_sha256)
      VALUES (p_id, iid, org, sid, 'endpoint', btrim(p_payload->>'purpose'),
      p_payload->>'data_grade', coalesce(p_payload->'resources', '[]'::jsonb),
      p_payload->'spec'->>'index', uid,
      jsonb_build_object('credential_notice', '자격 증명이 바뀌면 관리자에게 알립니다',
        'revocation_record', '철회는 MINT 기록으로 남깁니다', 'audit_access_days', 90),
      '사용을 끝내면 단말에서 서버를 제거합니다', uid, request_hash);
    INSERT INTO mint.deployment_contracts(id, instance_id, server_id, canonical_text, sha256,
      url, url_sha256, transport, auth_type, proposed_by, identity_kind, pack_spec)
      VALUES (p_id, iid, sid, pack::text, encode(sha256(convert_to(pack::text, 'UTF8')), 'hex'),
      NULL, NULL, 'stdio', 'none', uid, 'stdio', pack);
    INSERT INTO mint.jobs(id, instance_id, kind, target_ref, idempotency_key)
      VALUES (gen_random_uuid(), iid, 'intake_run', p_id::text || '/endpoint',
      'intake_run:' || p_id || ':1');
    PERFORM mint.staff_event('intake_received', 'intake', p_id::text, 1, uid,
      jsonb_build_object('intake_id', p_id, 'server_id', sid, 'source', 'endpoint',
                         'requested_by', uid));
    RETURN p_id;
END $$;

GRANT CREATE ON SCHEMA mint TO mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_staff_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.staff_submit_local_intake(uuid,jsonb) OWNER TO mint_staff_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_staff_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_staff_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.staff_submit_local_intake(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.staff_submit_local_intake(uuid,jsonb) TO mint_staff;
