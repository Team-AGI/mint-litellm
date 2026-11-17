-- 단말이 키로 올리는 로컬(stdio) 서버 신청.
-- 신청 출처 endpoint, 로컬 배포 후보(신청 명세·실행 묶음·실행 계약), 신청 한도 집계,
-- 키로 신원을 정하는 신청 함수와 키별 승인 범위 함수를 둔다.

ALTER TABLE mint.intakes DROP CONSTRAINT intakes_source_check;
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_source_check
    CHECK (source IN ('submission', 'operator', 'staff', 'endpoint'));
ALTER TABLE mint.intakes ADD COLUMN endpoint_key_token text
    CHECK (endpoint_key_token IS NULL OR length(endpoint_key_token) BETWEEN 1 AND 128);
ALTER TABLE mint.intakes ADD CONSTRAINT intakes_endpoint_key_shape
    CHECK ((source = 'endpoint') = (endpoint_key_token IS NOT NULL));

-- 로컬 신청 검사 이름
ALTER TABLE mint.intake_checks DROP CONSTRAINT intake_checks_check_check;
ALTER TABLE mint.intake_checks ADD CONSTRAINT intake_checks_check_check CHECK ("check" IN (
    'url_guard', 'oauth_issuer_allowlist', 'connection', 'definitions',
    'description_scan', 'risk_grade', 'termination_readiness', 'supply_chain',
    'exec_shape', 'pack_build', 'inspection'));

-- 로컬 서버는 실행 계약이 정해지기 전(묶음을 만들기 전)에도 서버 행과 배포 후보가 있어야 한다.
-- 승인 이후(approved 등)에는 계약 해시가 반드시 있다.
ALTER TABLE mint.servers DROP CONSTRAINT servers_identity_shape;
ALTER TABLE mint.servers ADD CONSTRAINT servers_identity_shape CHECK (
    (identity_kind = 'remote' AND url_sha256 IS NOT NULL
        AND exec_contract_sha256 IS NULL AND exec_contract_version IS NULL)
 OR (identity_kind = 'stdio' AND url_sha256 IS NULL
        AND (exec_contract_sha256 IS NULL) = (exec_contract_version IS NULL)
        AND (exec_contract_sha256 IS NOT NULL
             OR status IN ('pending', 'validating', 'awaiting_approval', 'rejected'))));

ALTER TABLE mint.deployment_contracts
    ADD COLUMN pack_spec jsonb CHECK (pack_spec IS NULL OR jsonb_typeof(pack_spec) = 'object'),
    ADD COLUMN pack_sha256 text CHECK (pack_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN pack_manifest jsonb
        CHECK (pack_manifest IS NULL OR jsonb_typeof(pack_manifest) = 'object'),
    ADD COLUMN exec_contract jsonb
        CHECK (exec_contract IS NULL OR jsonb_typeof(exec_contract) = 'object');
ALTER TABLE mint.deployment_contracts DROP CONSTRAINT deployment_contracts_identity_shape;
ALTER TABLE mint.deployment_contracts ADD CONSTRAINT deployment_contracts_identity_shape CHECK (
    (identity_kind = 'remote' AND url IS NOT NULL AND url_sha256 IS NOT NULL
        AND exec_contract_sha256 IS NULL AND exec_contract_version IS NULL)
 OR (identity_kind = 'stdio' AND url IS NULL AND url_sha256 IS NULL
        AND (exec_contract_sha256 IS NULL) = (exec_contract_version IS NULL)
        AND (exec_contract_sha256 IS NOT NULL OR pack_spec IS NOT NULL)));

-- 실행 계약 해시와 묶음 열은 후보인 동안만 채우거나 바꾼다. 승인된 뒤에는 고정이다.
DROP TRIGGER deployment_contracts_2_frozen ON mint.deployment_contracts;
CREATE TRIGGER deployment_contracts_2_frozen BEFORE UPDATE ON mint.deployment_contracts
    FOR EACH ROW EXECUTE FUNCTION mint.freeze_columns(
        'instance_id', 'server_id', 'canonical_text', 'sha256', 'url', 'url_sha256',
        'transport', 'auth_type', 'issuer', 'oauth_scopes', 'allowed_tools', 'image_digest',
        'source_commit', 'identity_kind', 'exec_location', 'artifact_source', 'permissions');
CREATE FUNCTION mint.guard_pack_columns() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, mint AS $$
BEGIN
    IF OLD.status <> 'candidate' AND (
        OLD.exec_contract_sha256, OLD.exec_contract_version, OLD.pack_spec, OLD.pack_sha256,
        OLD.pack_manifest, OLD.exec_contract)
       IS DISTINCT FROM (
        NEW.exec_contract_sha256, NEW.exec_contract_version, NEW.pack_spec, NEW.pack_sha256,
        NEW.pack_manifest, NEW.exec_contract)
    THEN RAISE EXCEPTION 'deployment_contracts pack columns cannot be changed after review'
        USING ERRCODE = 'check_violation'; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER deployment_contracts_4_pack_frozen BEFORE UPDATE ON mint.deployment_contracts
    FOR EACH ROW EXECUTE FUNCTION mint.guard_pack_columns();

-- 신청 한도 집계(사용자·날짜별). 조직 합계는 조직 열로 더한다.
CREATE TABLE mint.endpoint_intake_quota (
    instance_id mint.ident NOT NULL,
    org_id      mint.ident NOT NULL,
    user_id     text NOT NULL CHECK (length(user_id) BETWEEN 1 AND 256),
    day         date NOT NULL,
    count       integer NOT NULL CHECK (count >= 0),
    PRIMARY KEY (instance_id, org_id, user_id, day)
);
CREATE INDEX endpoint_intake_quota_by_user ON mint.endpoint_intake_quota (instance_id, user_id, day);
GRANT SELECT ON mint.endpoint_intake_quota TO mint_control;

-- ---------------------------------------------------------------------------
-- 함수 소유 역할: 신청 생성과 범위 조회에 필요한 권한만 가진다(승인·서버 상태 변경 없음).
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'mint_endpoint_owner') THEN
        CREATE ROLE mint_endpoint_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;
END $$;

-- 읽기. FOR SHARE 잠금은 표의 열 하나에 UPDATE 권한을 요구하므로 변경에 쓰이지 않는 열 하나만 연다.
GRANT USAGE ON SCHEMA mint TO mint_endpoint_owner;
GRANT SELECT ON mint.orgs, mint.org_bindings, mint.settings, mint.servers, mint.usage_relations,
    mint.approvals, mint.denials, mint.deployment_contracts, mint.endpoint_installs,
    mint.intakes TO mint_endpoint_owner;
GRANT UPDATE (state_version) ON mint.orgs, mint.servers TO mint_endpoint_owner;
GRANT UPDATE (kit_version) ON mint.endpoint_installs TO mint_endpoint_owner;
-- 쓰기: 신청·서버·배포 후보·작업·한도·사건 추가
GRANT INSERT (id, instance_id, org_id, server_id, source, purpose, data_grade, allowed_resources,
    provider, owner_user_id, readiness, data_return_terms, requested_by, staff_request_sha256,
    endpoint_key_token) ON mint.intakes TO mint_endpoint_owner;
GRANT INSERT (id, instance_id, server_id, status, transport, auth_type, identity_kind,
    registered_by) ON mint.servers TO mint_endpoint_owner;
GRANT INSERT (id, instance_id, server_id, canonical_text, sha256, url, url_sha256, transport,
    auth_type, proposed_by, identity_kind, pack_spec)
    ON mint.deployment_contracts TO mint_endpoint_owner;
GRANT INSERT (id, instance_id, kind, target_ref, idempotency_key) ON mint.jobs TO mint_endpoint_owner;
GRANT INSERT (event_id, instance_id, kind, source_key, actor, payload)
    ON mint.events TO mint_endpoint_owner;
GRANT SELECT, INSERT, UPDATE (count) ON mint.endpoint_intake_quota TO mint_endpoint_owner;
GRANT EXECUTE ON FUNCTION mint.claim_event_key(text, text, uuid) TO mint_endpoint_owner;
GRANT SELECT ON mint.events TO mint_endpoint_owner;  -- 1판 로컬 계약은 등록 사건에서 읽는다

-- 키의 조직: 팀이 있으면 팀 바인딩만, 없으면 사용자 바인딩, 없으면 기본 조직(플러그인 판정과 같다).
-- 닫힌 조직이면 비어 있다.
CREATE FUNCTION mint.endpoint_org(p_instance text, p_team text, p_user text)
RETURNS text LANGUAGE plpgsql STABLE SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE org text;
BEGIN
    IF p_team IS NOT NULL THEN
        SELECT b.org_id INTO org FROM mint.org_bindings b
          WHERE b.instance_id = p_instance AND b.subject_type = 'team' AND b.subject_id = p_team;
    ELSIF p_user IS NOT NULL THEN
        SELECT b.org_id INTO org FROM mint.org_bindings b
          WHERE b.instance_id = p_instance AND b.subject_type = 'user' AND b.subject_id = p_user;
    END IF;
    IF org IS NULL THEN
        SELECT s.default_org_id INTO org FROM mint.settings s WHERE s.instance_id = p_instance;
    END IF;
    IF org IS NULL OR NOT EXISTS (SELECT 1 FROM mint.orgs o WHERE o.instance_id = p_instance
        AND o.org_id = org AND o.status = 'active') THEN RETURN NULL; END IF;
    RETURN org;
END $$;

-- 신청 본문 형식 검사. 신원·소유자 값은 보지 않는다(받지 않는다).
CREATE FUNCTION mint.endpoint_payload_valid(p jsonb) RETURNS boolean
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
       OR spec->>'index' IS DISTINCT FROM 'pypi'
       OR coalesce(spec->>'name', '') !~ '^[A-Za-z0-9]([A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$'
       OR coalesce(spec->>'version', '') !~ '^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$'
       OR coalesce(spec->>'command', '') !~ '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,127}$'
    THEN RETURN false; END IF;
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
    IF net IS NULL OR net NOT IN ('none', 'hosts') THEN RETURN false; END IF;
    IF p ? 'allowed_hosts' AND (jsonb_typeof(p->'allowed_hosts') IS DISTINCT FROM 'array'
       OR jsonb_array_length(p->'allowed_hosts') > 64) THEN RETURN false; END IF;
    IF (net = 'hosts') <> (coalesce(jsonb_array_length(p->'allowed_hosts'), 0) > 0) THEN RETURN false; END IF;
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
    RETURN true;
END $$;

-- 키로 신원을 정하는 신청 생성. 본문에 신원 값이 있어도 쓰지 않는다.
-- 오류: MINT-KEY(키 없음·폐기·만료) MINT-INVALID(형식) MINT-CONFLICT(식별자 재사용·진행 중·승인됨)
--       MINT-QUOTA(한도, SQLSTATE MT429).
CREATE FUNCTION mint.endpoint_submit_intake(p_key_token text, p_request_id uuid, p_payload jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, mint, pg_temp AS $$
DECLARE
    k mint.endpoint_installs;
    matches integer;
    iid text; uid text; org text;
    sid text := p_payload->>'server_id';
    pack jsonb;
    previous mint.intakes;
    server mint.servers;
    request_hash text;
    today date := (clock_timestamp() AT TIME ZONE 'UTC')::date;
    user_today integer; org_today integer; running integer;
BEGIN
    IF p_key_token IS NULL OR p_request_id IS NULL OR NOT mint.endpoint_payload_valid(p_payload)
    THEN RAISE EXCEPTION 'MINT-INVALID: invalid intake input' USING ERRCODE = 'check_violation'; END IF;
    request_hash := encode(sha256(convert_to(p_payload::text, 'UTF8')), 'hex');

    SELECT count(*) INTO matches FROM mint.endpoint_installs WHERE key_token = p_key_token;
    IF matches <> 1 THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 잠가 읽어 폐기와 겹치지 않게 하고, 폐기·만료를 이 트랜잭션에서 다시 확인한다.
    SELECT * INTO k FROM mint.endpoint_installs WHERE key_token = p_key_token FOR SHARE;
    IF NOT FOUND OR k.revoked_at IS NOT NULL
       OR (k.expires_at IS NOT NULL AND k.expires_at <= clock_timestamp()) THEN
        RAISE EXCEPTION 'MINT-KEY: key not accepted' USING ERRCODE = 'insufficient_privilege';
    END IF;
    iid := k.instance_id; uid := k.user_id;

    -- 같은 제출의 재전송만 재사용하며 다른 사용자의 신청을 알려 주지 않는다.
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-intake:' || p_request_id, 0));
    SELECT * INTO previous FROM mint.intakes WHERE id = p_request_id;
    IF FOUND THEN
        IF previous.instance_id = iid AND previous.requested_by = uid AND previous.source = 'endpoint'
           AND previous.staff_request_sha256 = request_hash THEN RETURN previous.id; END IF;
        RAISE EXCEPTION 'MINT-CONFLICT: request identifier reused' USING ERRCODE = 'unique_violation';
    END IF;

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
        IF server.identity_kind <> 'stdio'
           OR server.status NOT IN ('pending', 'awaiting_approval', 'rejected') THEN
            RAISE EXCEPTION 'MINT-CONFLICT: server already registered' USING ERRCODE = 'unique_violation';
        END IF;
        IF EXISTS (SELECT 1 FROM mint.intakes WHERE instance_id = iid AND server_id = sid
                   AND status <> 'decided') THEN
            RAISE EXCEPTION 'MINT-CONFLICT: server request in progress' USING ERRCODE = 'unique_violation';
        END IF;
    END IF;

    -- 한도: 조직·사용자 순으로 잠가 집계와 증가를 한 번에 한다.
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-quota-org:' || org, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended(iid || ':endpoint-quota-user:' || uid, 0));
    SELECT coalesce(sum(q.count) FILTER (WHERE q.user_id = uid), 0),
           coalesce(sum(q.count) FILTER (WHERE q.org_id = org), 0)
      INTO user_today, org_today FROM mint.endpoint_intake_quota q
      WHERE q.instance_id = iid AND q.day = today AND (q.user_id = uid OR q.org_id = org);
    SELECT count(*) INTO running FROM mint.intakes WHERE instance_id = iid AND requested_by = uid
      AND source = 'endpoint' AND status IN ('received', 'checking');
    IF user_today >= 20 OR org_today >= 100 OR running >= 3 THEN
        RAISE EXCEPTION 'MINT-QUOTA: intake limit reached' USING ERRCODE = 'MT429';
    END IF;
    INSERT INTO mint.endpoint_intake_quota(instance_id, org_id, user_id, day, count)
        VALUES (iid, org, uid, today, 1)
        ON CONFLICT (instance_id, org_id, user_id, day)
        DO UPDATE SET count = mint.endpoint_intake_quota.count + 1;

    IF server.id IS NULL THEN
        INSERT INTO mint.servers(id, instance_id, server_id, status, transport, auth_type,
          identity_kind, registered_by)
          VALUES (gen_random_uuid(), iid, sid, 'pending', 'stdio', 'none', 'stdio', uid);
    END IF;
    -- 신청 명세는 평평한 한 객체이다: 패키지 명세(index·name·version·extras·command·argv)와
    -- 선언 권한(file_access·network·allowed_hosts·env_names), 단말이 본 참고 도구 목록.
    pack := (p_payload->'spec') || jsonb_build_object(
        'file_access', coalesce(p_payload->'file_access', '[]'::jsonb),
        'network', p_payload->>'network',
        'allowed_hosts', coalesce(p_payload->'allowed_hosts', '[]'::jsonb),
        'env_names', coalesce(p_payload->'env_names', '[]'::jsonb),
        'observed_tools', coalesce(p_payload->'observed_tools', '[]'::jsonb));
    INSERT INTO mint.intakes(id, instance_id, org_id, server_id, source, purpose, data_grade,
      allowed_resources, provider, owner_user_id, readiness, data_return_terms, requested_by,
      staff_request_sha256, endpoint_key_token)
      VALUES (p_request_id, iid, org, sid, 'endpoint', btrim(p_payload->>'purpose'),
      p_payload->>'data_grade', coalesce(p_payload->'resources', '[]'::jsonb), 'pypi', uid,
      jsonb_build_object('credential_notice', '자격 증명이 바뀌면 관리자에게 알립니다',
        'revocation_record', '철회는 MINT 기록으로 남깁니다', 'audit_access_days', 90),
      '사용을 끝내면 단말에서 서버를 제거합니다', uid, request_hash, p_key_token);
    INSERT INTO mint.deployment_contracts(id, instance_id, server_id, canonical_text, sha256,
      url, url_sha256, transport, auth_type, proposed_by, identity_kind, pack_spec)
      VALUES (p_request_id, iid, sid, pack::text, encode(sha256(convert_to(pack::text, 'UTF8')), 'hex'),
      NULL, NULL, 'stdio', 'none', uid, 'stdio', pack);
    INSERT INTO mint.jobs(id, instance_id, kind, target_ref, idempotency_key)
      VALUES (gen_random_uuid(), iid, 'intake_run', p_request_id::text || '/endpoint',
      'intake_run:' || p_request_id || ':1');
    INSERT INTO mint.events(event_id, instance_id, kind, source_key, actor, payload)
      SELECT s.e, iid, 'intake_received', s.k, uid,
             jsonb_build_object('intake_id', p_request_id, 'server_id', sid, 'source', 'endpoint',
                                'requested_by', uid)
      FROM (SELECT gen_random_uuid() AS e,
                   'intake:' || p_request_id || ':1:intake_received' AS k) s
      WHERE mint.claim_event_key(iid, s.k, s.e);
    RETURN p_request_id;
END $$;

-- 이 키에 닿는 승인된 로컬(묶음) 서버. 호출 판정과 같은 규칙으로 범위를 정한다:
-- 유효한 승인(활성·기간·이용 관계 활성·재확인 보류 아님)의 범위가 키(게이트웨이 키 포함)·소유자·
-- 팀·조직에 닿고, 서버 전체에 걸린 해제되지 않은 거부가 없다.
CREATE FUNCTION mint.endpoint_scope(p_instance text, p_key_token text)
RETURNS TABLE(server_id text, pack_sha256 text, pack_manifest jsonb, exec_contract jsonb,
              permit_until timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, mint, pg_temp AS $$
#variable_conflict use_column
DECLARE
    k mint.endpoint_installs;
    org text;
    hours integer := 24;
    setting text := nullif(current_setting('mint.endpoint_permit_hours', true), '');
BEGIN
    SELECT * INTO k FROM mint.endpoint_installs i
      WHERE i.instance_id = p_instance AND i.key_token = p_key_token;
    IF NOT FOUND OR k.revoked_at IS NOT NULL
       OR (k.expires_at IS NOT NULL AND k.expires_at <= clock_timestamp()) THEN RETURN; END IF;
    org := mint.endpoint_org(p_instance, k.team_id, k.user_id);
    IF org IS NULL THEN RETURN; END IF;
    IF setting ~ '^[0-9]{1,4}$' AND setting::integer > 0 THEN hours := setting::integer; END IF;
    RETURN QUERY
    SELECT s.server_id, d.pack_sha256, d.pack_manifest,
           coalesce(d.exec_contract, ev.contract),
           least(m.until, now() + make_interval(hours => hours))
    FROM mint.servers s
    LEFT JOIN mint.deployment_contracts d ON d.instance_id = s.instance_id
         AND d.server_id = s.server_id AND d.status = 'approved' AND d.pack_sha256 IS NOT NULL
    -- 묶음이 없는 로컬 서버(1판 계약)는 등록 사건의 계약을 쓴다.
    LEFT JOIN LATERAL (
        SELECT e.payload -> 'exec_contract' AS contract FROM mint.events e
        WHERE e.instance_id = s.instance_id AND e.kind = 'server_registered'
          AND e.payload ->> 'server_id' = s.server_id
          AND e.payload ->> 'exec_contract_sha256' = s.exec_contract_sha256
        ORDER BY e.inserted_at DESC LIMIT 1) ev ON d.id IS NULL
    CROSS JOIN LATERAL (
        SELECT max(a.valid_until) AS until
        FROM mint.approvals a
        JOIN mint.usage_relations r ON r.id = a.relation_id AND r.instance_id = a.instance_id
        WHERE a.instance_id = p_instance AND a.server_id = s.server_id AND a.org_id = org
          AND a.status = 'active' AND a.recert_held_at IS NULL
          AND a.valid_from <= now() AND now() < a.valid_until AND r.status = 'active'
          AND ((a.scope_type = 'key' AND a.scope_id IN (k.key_token, k.mcp_key_token))
            OR (a.scope_type = 'user' AND a.scope_id = k.user_id)
            OR (a.scope_type = 'team' AND a.scope_id = k.team_id)
            OR (a.scope_type = 'org' AND a.scope_id = org))
    ) m
    WHERE s.instance_id = p_instance AND s.identity_kind = 'stdio' AND s.status = 'approved'
      AND s.exec_contract_sha256 IS NOT NULL AND m.until IS NOT NULL
      AND coalesce(d.exec_contract, ev.contract) IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM mint.denials n
        WHERE n.instance_id = p_instance AND n.lifted_at IS NULL AND n.tools IS NULL
          AND (n.server_id IS NULL OR n.server_id = s.server_id)
          AND (n.org_id IS NULL OR n.org_id = org)
          AND ((n.scope_type = 'key' AND n.scope_id IN (k.key_token, k.mcp_key_token))
            OR (n.scope_type = 'user' AND n.scope_id = k.user_id)
            OR (n.scope_type = 'team' AND n.scope_id = k.team_id)
            OR (n.scope_type = 'org' AND n.scope_id = org)
            OR (n.scope_type = 'server' AND n.scope_id = s.server_id)))
    ORDER BY s.server_id;
END $$;

-- 키 소유자의 신청(직원·단말 출처). 정렬·건수 제한은 호출 쪽이 한다.
CREATE FUNCTION mint.endpoint_my_intakes(p_instance text, p_key_token text)
RETURNS TABLE(id uuid, server_id text, status text, decision text, reason text,
              created_at timestamptz)
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
    SELECT t.id, t.server_id, t.status, t.decision, t.decision_reason, t.created_at
    FROM mint.intakes t
    WHERE t.instance_id = p_instance AND t.requested_by = k.user_id
      AND t.source IN ('staff', 'endpoint');
END $$;

-- 직원 철회는 단말 신청도 다룬다(신청자 본인만).
CREATE OR REPLACE FUNCTION mint.withdraw_intake_row(iid text,p_id uuid,uid text,p_version bigint,
    p_reason text,p_actor text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,mint,pg_temp AS $$
DECLARE r mint.intakes; s mint.servers;
BEGIN
    IF uid IS NULL OR p_actor IS NULL OR length(btrim(coalesce(p_reason,''))) NOT BETWEEN 1 AND 500
    THEN RAISE EXCEPTION 'withdrawal reason and identity required' USING ERRCODE='check_violation'; END IF;
    SELECT * INTO r FROM mint.intakes WHERE instance_id=iid AND id=p_id FOR UPDATE;
    IF NOT FOUND OR r.requested_by IS DISTINCT FROM uid OR r.source NOT IN ('staff','operator','endpoint')
    THEN RAISE EXCEPTION 'only the requester may withdraw this application' USING ERRCODE='insufficient_privilege'; END IF;
    IF r.decision='withdrawn' THEN RETURN jsonb_build_object('changed',false,'intake',to_jsonb(r)); END IF;
    IF p_version IS NULL OR r.state_version<>p_version OR r.status NOT IN ('received','passed','indeterminate')
    THEN RAISE EXCEPTION 'application state changed or not withdrawable' USING ERRCODE='check_violation'; END IF;
    IF EXISTS(SELECT 1 FROM mint.jobs WHERE instance_id=iid AND kind='intake_run'
        AND split_part(target_ref,'/',1)=p_id::text AND status='running')
    THEN RAISE EXCEPTION 'validation is running; retry after completion' USING ERRCODE='check_violation'; END IF;
    SELECT * INTO s FROM mint.servers WHERE instance_id=iid AND server_id=r.server_id FOR UPDATE;
    IF NOT FOUND OR s.status NOT IN ('pending','awaiting_approval','rejected') OR s.contract_status='managed'
    THEN RAISE EXCEPTION 'an approved or managed server cannot be withdrawn' USING ERRCODE='check_violation'; END IF;
    UPDATE mint.intakes SET status='decided',decision='withdrawn',decided_by=p_actor,
        decision_reason=btrim(p_reason),decided_at=clock_timestamp() WHERE id=p_id RETURNING * INTO r;
    UPDATE mint.tool_contracts SET status='superseded' WHERE instance_id=iid AND server_id=r.server_id
        AND status='candidate' AND source='intake';
    UPDATE mint.deployment_contracts SET status='superseded' WHERE instance_id=iid AND server_id=r.server_id
        AND status='candidate';
    -- Unapproved registration remains in place, and no usage permission is issued.
    IF s.status='awaiting_approval' THEN
        UPDATE mint.servers SET status='rejected' WHERE instance_id=iid AND server_id=r.server_id;
    END IF;
    RETURN jsonb_build_object('changed',true,'intake',to_jsonb(r));
END $$;

CREATE OR REPLACE FUNCTION mint.staff_withdraw_intake(p_id uuid,p_version bigint,p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,mint,pg_temp AS $$
DECLARE s mint.console_sessions := mint.staff_active_session(); result jsonb; r jsonb;
BEGIN
    IF s.last_verified_at<=clock_timestamp()-make_interval(secs=>coalesce(
        nullif(current_setting('mint.staff_verify_window_seconds',true),'')::int,600))
    THEN RAISE EXCEPTION 'staff session needs verification' USING ERRCODE='insufficient_privilege'; END IF;
    IF NOT EXISTS(SELECT 1 FROM mint.intakes WHERE instance_id=mint.staff_instance()
        AND id=p_id AND requested_by=mint.staff_user() AND source IN ('staff','endpoint'))
    THEN RAISE EXCEPTION 'application not owned by this employee' USING ERRCODE='insufficient_privilege'; END IF;
    result:=mint.withdraw_intake_row(mint.staff_instance(),p_id,mint.staff_user(),p_version,p_reason,mint.staff_user());
    r:=result->'intake';
    IF (result->>'changed')::boolean THEN
        PERFORM mint.staff_event('intake_decided','intake',p_id::text,(r->>'state_version')::bigint,mint.staff_user(),
          jsonb_build_object('intake_id',p_id,'server_id',r->>'server_id','decision','withdrawn',
            'reason',r->>'decision_reason','decided_by',mint.staff_user(),'automatic',false));
    END IF;
    RETURN result;
END $$;

-- 소유 역할을 옮긴다(슈퍼유저가 아닌 실행자는 잠시 역할 전환 권한이 필요하다).
GRANT CREATE ON SCHEMA mint TO mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('GRANT mint_endpoint_owner TO %I WITH SET TRUE',current_user);
    END IF;
END $$;
ALTER FUNCTION mint.endpoint_org(text,text,text) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_payload_valid(jsonb) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_submit_intake(text,uuid,jsonb) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_scope(text,text) OWNER TO mint_endpoint_owner;
ALTER FUNCTION mint.endpoint_my_intakes(text,text) OWNER TO mint_endpoint_owner;
REVOKE CREATE ON SCHEMA mint FROM mint_endpoint_owner;
DO $$ BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
        EXECUTE format('REVOKE SET OPTION FOR mint_endpoint_owner FROM %I',current_user);
    END IF;
END $$;
REVOKE ALL ON FUNCTION mint.endpoint_org(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_payload_valid(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_submit_intake(text,uuid,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_scope(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION mint.endpoint_my_intakes(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mint.endpoint_org(text,text,text), mint.endpoint_payload_valid(jsonb)
    TO mint_endpoint_owner;
GRANT EXECUTE ON FUNCTION mint.endpoint_submit_intake(text,uuid,jsonb) TO mint_plugin;
GRANT EXECUTE ON FUNCTION mint.endpoint_scope(text,text) TO mint_plugin;
GRANT EXECUTE ON FUNCTION mint.endpoint_my_intakes(text,text) TO mint_plugin;
