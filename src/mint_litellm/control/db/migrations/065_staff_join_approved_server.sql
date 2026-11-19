-- A staff request for an already approved server joins it (no new checks, no new contract).
CREATE OR REPLACE FUNCTION mint.staff_submit_intake(p_id uuid, p_payload jsonb, p_contract text)
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
    joining boolean := false;
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
        -- 이미 승인된 서버는 검사 없이 이 직원의 이용 범위를 더하는 신청으로 이어진다.
        joining := server.status = 'approved';
        IF (NOT joining AND server.status NOT IN ('pending','awaiting_approval','rejected'))
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
    IF NOT joining THEN
        INSERT INTO mint.deployment_contracts(id,instance_id,server_id,canonical_text,sha256,
          url,url_sha256,transport,auth_type,proposed_by)
          VALUES(p_id,iid,sid,p_contract,encode(sha256(convert_to(p_contract,'UTF8')),'hex'),
          target_url,url_hash,transport,'none',uid);
    END IF;
    INSERT INTO mint.jobs(id,instance_id,kind,target_ref,idempotency_key)
      VALUES(gen_random_uuid(),iid,'intake_run',p_id::text || '/staff','intake_run:' || p_id || ':1');
    PERFORM mint.staff_event('intake_received','intake',p_id::text,1,uid,
      jsonb_build_object('intake_id',p_id,'server_id',sid,'source','staff','requested_by',uid));
    RETURN p_id;
END $$;

-- Same for requests that come from the endpoint key.
CREATE OR REPLACE FUNCTION mint.endpoint_submit_remote_intake(p_key_token text, p_request_id uuid, p_payload jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    k mint.endpoint_installs;
    matches integer;
    iid text; uid text; org text;
    sid text := p_payload->>'server_id';
    target_url text := p_payload->>'url';
    transport text := p_payload->>'transport';
    contract text := p_payload->>'contract';
    url_hash text;
    joining boolean := false;
    previous mint.intakes;
    server mint.servers;
    registry_required boolean := false;
    request_hash text;
    today date := (clock_timestamp() AT TIME ZONE 'UTC')::date;
    user_today integer; org_today integer; running integer;
BEGIN
    IF p_key_token IS NULL OR p_request_id IS NULL OR jsonb_typeof(p_payload) IS DISTINCT FROM 'object'
       OR sid IS NULL OR sid !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
       OR transport IS NULL OR transport NOT IN ('http', 'sse')
       OR target_url IS NULL OR length(target_url) > 2048
       OR target_url !~ '^https?://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$'
       OR length(btrim(coalesce(p_payload->>'purpose', ''))) NOT BETWEEN 1 AND 256
       OR coalesce(p_payload->>'data_grade', '') NOT IN ('public', 'internal', 'confidential', 'restricted')
       OR jsonb_typeof(p_payload->'resources') IS DISTINCT FROM 'array'
       OR length(btrim(coalesce(p_payload->>'provider', ''))) NOT BETWEEN 1 AND 256
       OR contract IS NULL
       OR contract::jsonb IS DISTINCT FROM jsonb_build_object(
            'url', target_url, 'transport', transport, 'auth_type', 'none', 'issuer', NULL,
            'oauth_scopes', '[]'::jsonb, 'allowed_tools', NULL, 'image_digest', NULL,
            'source_commit', NULL)
    THEN RAISE EXCEPTION 'MINT-INVALID: invalid intake input' USING ERRCODE = 'check_violation'; END IF;
    request_hash := encode(sha256(convert_to(p_payload::text, 'UTF8')), 'hex');
    url_hash := encode(sha256(convert_to(target_url, 'UTF8')), 'hex');

    SELECT count(*) INTO matches FROM mint.endpoint_installs WHERE key_token = p_key_token;
    IF matches <> 1 THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO k FROM mint.endpoint_installs WHERE key_token = p_key_token FOR SHARE;
    IF NOT FOUND OR k.revoked_at IS NOT NULL
       OR (k.expires_at IS NOT NULL AND k.expires_at <= clock_timestamp()) THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    iid := k.instance_id; uid := k.user_id;

    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-intake:' || p_request_id, 0));
    SELECT * INTO previous FROM mint.intakes WHERE id = p_request_id;
    IF FOUND THEN
        IF previous.instance_id = iid AND previous.requested_by = uid
           AND previous.staff_request_sha256 = request_hash THEN RETURN previous.id; END IF;
        RAISE EXCEPTION 'MINT-CONFLICT: request identifier reused' USING ERRCODE = 'unique_violation';
    END IF;

    -- 같은 사람이 같은 주소를 진행 중인 신청이 있으면 새 번호를 만들지 않고 그 신청으로 합친다.
    SELECT t.* INTO previous FROM mint.intakes t
      JOIN mint.deployment_contracts d ON d.instance_id = t.instance_id AND d.id = t.id
      WHERE t.instance_id = iid AND t.server_id = sid AND t.requested_by = uid
        AND t.source = 'staff' AND t.status <> 'decided' AND d.url_sha256 = url_hash
      ORDER BY t.created_at DESC LIMIT 1;
    IF FOUND THEN RETURN previous.id; END IF;

    org := mint.endpoint_org(iid, k.team_id, uid);
    IF org IS NULL THEN
        RAISE EXCEPTION 'MINT-KEY: no active organization' USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM mint.orgs WHERE instance_id = iid AND org_id = org AND status = 'active' FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'MINT-KEY: no active organization' USING ERRCODE = 'insufficient_privilege';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-server:' || sid, 0));
    SELECT * INTO server FROM mint.servers WHERE instance_id = iid AND server_id = sid FOR SHARE;
    IF FOUND THEN
        -- 이미 승인된 서버는 검사 없이 이 사용자의 이용 범위를 더하는 신청으로 이어진다.
        joining := server.status = 'approved';
        IF (NOT joining AND server.status NOT IN ('pending', 'awaiting_approval', 'rejected'))
           OR server.url_sha256 IS DISTINCT FROM url_hash
           OR server.transport IS DISTINCT FROM transport OR server.auth_type <> 'none' THEN
            RAISE EXCEPTION 'MINT-CONFLICT: server already registered' USING ERRCODE = 'unique_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM mint.intakes WHERE instance_id = iid AND server_id = sid
                   AND status <> 'decided') THEN
            RAISE EXCEPTION 'MINT-CONFLICT: server request in progress' USING ERRCODE = 'unique_violation';
        END IF;
    ELSE
        registry_required := true;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-quota-org:' || org, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-quota-user:' || uid, 0));
    SELECT coalesce(sum(q.count) FILTER (WHERE q.user_id = uid), 0),
           coalesce(sum(q.count) FILTER (WHERE q.org_id = org), 0)
      INTO user_today, org_today FROM mint.endpoint_intake_quota q
      WHERE q.instance_id = iid AND q.day = today AND (q.user_id = uid OR q.org_id = org);
    SELECT count(*) INTO running FROM mint.intakes WHERE instance_id = iid AND requested_by = uid
      AND source IN ('endpoint', 'staff') AND status IN ('received', 'checking');
    IF user_today >= 20 OR org_today >= 100 OR running >= 3 THEN
        RAISE EXCEPTION 'MINT-QUOTA: intake limit reached' USING ERRCODE = 'MT429';
    END IF;
    INSERT INTO mint.endpoint_intake_quota(instance_id, org_id, user_id, day, count)
        VALUES (iid, org, uid, today, 1)
        ON CONFLICT (instance_id, org_id, user_id, day)
        DO UPDATE SET count = mint.endpoint_intake_quota.count + 1;

    IF server.id IS NULL THEN
        INSERT INTO mint.servers(id, instance_id, server_id, status, url_sha256, transport,
          auth_type, registered_by)
          VALUES (gen_random_uuid(), iid, sid, 'pending', url_hash, transport, 'none', uid);
    END IF;
    INSERT INTO mint.intakes(id, instance_id, org_id, server_id, source, purpose, data_grade,
      allowed_resources, provider, owner_user_id, readiness, data_return_terms, requested_by,
      staff_request_sha256, staff_registry_required)
      VALUES (p_request_id, iid, org, sid, 'staff', btrim(p_payload->>'purpose'),
      p_payload->>'data_grade', p_payload->'resources', p_payload->>'provider', uid,
      jsonb_build_object('credential_notice', '자격 증명이 바뀌면 관리자에게 알립니다',
        'revocation_record', '철회는 MINT 기록으로 남깁니다', 'audit_access_days', 90),
      '사용을 끝내면 서버에 남은 자료를 삭제합니다', uid, request_hash, registry_required);
    IF NOT joining THEN
        INSERT INTO mint.deployment_contracts(id, instance_id, server_id, canonical_text, sha256,
          url, url_sha256, transport, auth_type, proposed_by)
          VALUES (p_request_id, iid, sid, contract, encode(sha256(convert_to(contract, 'UTF8')), 'hex'),
          target_url, url_hash, transport, 'none', uid);
    END IF;
    INSERT INTO mint.jobs(id, instance_id, kind, target_ref, idempotency_key)
      VALUES (gen_random_uuid(), iid, 'intake_run', p_request_id::text || '/staff',
      'intake_run:' || p_request_id || ':1');
    INSERT INTO mint.events(event_id, instance_id, kind, source_key, actor, payload)
      SELECT s.e, iid, 'intake_received', s.k, uid,
             jsonb_build_object('intake_id', p_request_id, 'server_id', sid, 'source', 'staff',
                                'requested_by', uid)
      FROM (SELECT gen_random_uuid() AS e,
                   'intake:' || p_request_id || ':1:intake_received' AS k) s
      WHERE mint.claim_event_key(iid, s.k, s.e);
    RETURN p_request_id;
END $$;
