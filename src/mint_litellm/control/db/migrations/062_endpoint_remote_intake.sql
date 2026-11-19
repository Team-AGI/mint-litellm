-- 단말 키로 올리는 원격 서버 신청. 직원 웹 신청과 같은 신청(출처 staff, 같은 검사·승인 경로)을
-- 만들되 신원은 키가 정한다. 본문의 신원 값은 쓰지 않는다.
-- 오류: MINT-KEY(키 없음·폐기·만료) MINT-INVALID(형식) MINT-CONFLICT(식별자 재사용·진행 중·승인됨)
--       MINT-QUOTA(한도, SQLSTATE MT429).
GRANT INSERT (staff_registry_required) ON mint.intakes TO mint_endpoint_owner;
GRANT INSERT (url_sha256) ON mint.servers TO mint_endpoint_owner;

CREATE FUNCTION mint.endpoint_submit_remote_intake(p_key_token text, p_request_id uuid, p_payload jsonb)
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
        IF server.status NOT IN ('pending', 'awaiting_approval', 'rejected')
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
    INSERT INTO mint.deployment_contracts(id, instance_id, server_id, canonical_text, sha256,
      url, url_sha256, transport, auth_type, proposed_by)
      VALUES (p_request_id, iid, sid, contract, encode(sha256(convert_to(contract, 'UTF8')), 'hex'),
      target_url, url_hash, transport, 'none', uid);
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

GRANT CREATE ON SCHEMA mint TO mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_endpoint_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.endpoint_submit_remote_intake(text,uuid,jsonb) OWNER TO mint_endpoint_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_endpoint_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_submit_remote_intake(text,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_submit_remote_intake(text,uuid,jsonb) TO mint_plugin;
